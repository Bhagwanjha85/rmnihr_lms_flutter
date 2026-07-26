from django.test import TestCase, Client
from django.contrib.auth.models import User
from reports.models import Report, ReportTest, TestConfig, UserProfile
from django.urls import reverse

class ReportTestModelTests(TestCase):
    def setUp(self):
        self.report = Report.objects.create(
            lab_id="9999",
            patient_name="TEST PATIENT",
            age_value=30,
            age_unit="Y",
            sex="M",
            test_method="ELISA",
            sample_type="BLOOD",
            receiving_date="2026-06-25",
            reporting_date="2026-06-25",
            ref_by="TEST LAB"
        )

    def test_standard_elisa_cutoffs(self):
        t1 = ReportTest.objects.create(report=self.report, test_name="Dengue IgM", result_value="5.0")
        t2 = ReportTest.objects.create(report=self.report, test_name="Dengue IgM", result_value="10.0")
        t3 = ReportTest.objects.create(report=self.report, test_name="Dengue IgM", result_value="12.0")
        
        self.assertEqual(t1.interpretation_text, "Negative")
        self.assertEqual(t2.interpretation_text, "Equivocal")
        self.assertEqual(t3.interpretation_text, "Positive")
        self.assertEqual(t1.interpretation_range, "Negative &lt; 9.00 | Equivocal 9.00-11.00 | Positive &gt; 11.00")

    def test_hbsag_elisa_cutoffs(self):
        t1 = ReportTest.objects.create(report=self.report, test_name="HBsAg", result_value="0.100")
        t2 = ReportTest.objects.create(report=self.report, test_name="HBsAg", result_value="0.191")
        t3 = ReportTest.objects.create(report=self.report, test_name="HBsAg", result_value="0.250")
        
        self.assertEqual(t1.interpretation_text, "Non-Reactive")
        self.assertEqual(t2.interpretation_text, "Reactive")
        self.assertEqual(t3.interpretation_text, "Reactive")
        self.assertEqual(t1.interpretation_range, "Non-Reactive &lt; 0.191 | Reactive &ge; 0.191")

    def test_hcv_antibody_elisa_cutoffs(self):
        t1 = ReportTest.objects.create(report=self.report, test_name="HCV Antibody", result_value="0.300")
        t2 = ReportTest.objects.create(report=self.report, test_name="HCV Antibody", result_value="0.361")
        t3 = ReportTest.objects.create(report=self.report, test_name="HCV Antibody", result_value="0.450")
        
        self.assertEqual(t1.interpretation_text, "Non-Reactive")
        self.assertEqual(t2.interpretation_text, "Reactive")
        self.assertEqual(t3.interpretation_text, "Reactive")
        self.assertEqual(t1.interpretation_range, "Non-Reactive &lt; 0.361 | Reactive &ge; 0.361")

    def test_qualitative_interpretation_preservation(self):
        config = TestConfig.objects.create(
            test_name="Zika Virus IgM",
            test_method="ELISA",
            result_type="select"
        )
        t = ReportTest.objects.create(
            report=self.report,
            test_name="Zika Virus IgM",
            result_value="-",
            interpretation_text="Positive",
            test_method="ELISA"
        )
        self.assertEqual(t.interpretation_text, "Positive")

    def test_reactive_non_reactive_config(self):
        config = TestConfig.objects.create(
            test_name="HIV Screening",
            test_method="RAPID",
            result_type="reactive_non_reactive"
        )
        t = ReportTest.objects.create(
            report=self.report,
            test_name="HIV Screening",
            result_value="Reactive",
            test_method="RAPID"
        )
        self.assertEqual(t.interpretation_text, "Reactive")
        self.assertEqual(t.interpretation_range, "Reactive / Non-Reactive")

    def test_custom_dropdown_config(self):
        config = TestConfig.objects.create(
            test_name="Special Custom Test",
            test_method="ELISA",
            result_type="custom_dropdown",
            custom_options="Weak Positive, Strong Positive, Negative"
        )
        t = ReportTest.objects.create(
            report=self.report,
            test_name="Special Custom Test",
            result_value="Strong Positive",
            test_method="ELISA"
        )
        self.assertEqual(t.interpretation_text, "Strong Positive")

class TestConfigBackupRestoreTests(TestCase):
    def test_backup_and_restore_cycle(self):
        import os
        from reports.models import TestConfig
        import reports.backup_utils
        
        # Override the path with a test file path
        original_path = reports.backup_utils.BACKUP_FILE_PATH
        test_path = original_path.replace('.json', '_test.json')
        reports.backup_utils.BACKUP_FILE_PATH = test_path
        
        try:
            # Ensure start with no backup file (clean slate)
            if os.path.exists(test_path):
                os.remove(test_path)
                
            # Create a config
            tc = TestConfig.objects.create(
                test_name="Test Backup ELISA",
                test_method="ELISA",
                result_type="numeric",
                cutoff_value=1.5
            )
            
            # Verify backup file got created by signal
            self.assertTrue(os.path.exists(test_path))
            
            # Empty the database config table simulating external loss (without triggering delete signals)
            from django.db.models.signals import post_delete, post_save
            from reports.models import handle_test_config_write
            post_save.disconnect(handle_test_config_write, sender=TestConfig)
            post_delete.disconnect(handle_test_config_write, sender=TestConfig)
            
            TestConfig.objects.all().delete()
            self.assertEqual(TestConfig.objects.count(), 0)
            
            # Reconnect signals
            post_save.connect(handle_test_config_write, sender=TestConfig)
            post_delete.connect(handle_test_config_write, sender=TestConfig)
            
            # Call restore
            reports.backup_utils.restore_test_configs_from_backup_if_needed(force=True)
            
            # Verify it got restored successfully
            self.assertEqual(TestConfig.objects.count(), 1)
            restored = TestConfig.objects.first()
            self.assertEqual(restored.test_name, "Test Backup ELISA")
            self.assertEqual(restored.cutoff_value, 1.5)
        finally:
            # Clean up the test backup file
            if os.path.exists(test_path):
                os.remove(test_path)
            # Restore original path
            reports.backup_utils.BACKUP_FILE_PATH = original_path

class LoginGeofencingTests(TestCase):
    def setUp(self):
        self.username = "admin"
        self.password = "password123"
        self.user = User.objects.create_superuser(
            username=self.username,
            password=self.password,
            email="admin@test.com"
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.profile.is_admin_added_by_superadmin = True
        self.profile.save()
        self.client = Client()

    def test_login_without_geofencing(self):
        # Post to login page without latitude/longitude parameters should succeed
        login_url = reverse('login')
        response = self.client.post(login_url, {
            'username': self.username,
            'password': self.password
        })
        self.assertEqual(response.status_code, 302) # Redirect to dashboard
        self.assertRedirects(response, reverse('dashboard'))


class SuperAdminPanelTests(TestCase):
    def setUp(self):
        self.superadmin = User.objects.create_superuser(
            username="superadmin",
            password="password123",
            email="superadmin@test.com"
        )
        self.superadmin_profile, _ = UserProfile.objects.get_or_create(user=self.superadmin)
        self.superadmin_profile.is_super_admin = True
        self.superadmin_profile.save()
        
        # Create 15 test configs
        for i in range(15):
            TestConfig.objects.create(
                test_name=f"Test Config {i}",
                test_method="ELISA",
                result_type="numeric",
                cutoff_value=1.0
            )
            
        # Create 15 admins
        for i in range(15):
            u = User.objects.create_user(
                username=f"admin_user_{i}",
                password="password123",
                email=f"admin_{i}@test.com"
            )
            profile, _ = UserProfile.objects.get_or_create(user=u)
            profile.is_admin_added_by_superadmin = True
            profile.save()
            
        self.client = Client()
        self.client.login(username="superadmin", password="password123")

    def test_super_admin_panel_pagination(self):
        # Default page 1
        response = self.client.get(reverse('super_admin_panel'))
        self.assertEqual(response.status_code, 200)
        self.assertIn('configs', response.context)
        self.assertIn('added_admins', response.context)
        
        # Test pagination page sizes (should show 10 configs and 10 admins)
        self.assertEqual(len(response.context['configs'].object_list), 10)
        self.assertEqual(len(response.context['added_admins'].object_list), 10)
        
        # Page 2 of configs
        response = self.client.get(reverse('super_admin_panel') + "?page=2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['configs'].object_list), 5)
        
        # Page 2 of admins
        response = self.client.get(reverse('super_admin_panel') + "?admin_page=2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['added_admins'].object_list), 5)


class ReportPrintTemplateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser(
            username="rmnihr",
            password="rmnihr03072026",
            email="rmnihr@test.com"
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.profile.is_super_admin = True
        self.profile.save()
        
        self.report = Report.objects.create(
            lab_id="1234",
            patient_name="John Doe",
            age_value=45,
            age_unit="Y",
            sex="M",
            test_method="ELISA",
            sample_type="BLOOD",
            receiving_date="2026-07-20",
            reporting_date="2026-07-20",
            ref_by="Referrer",
            show_prepared_by=True,
            show_technician=True,
            show_scientist=True,
            show_vc=True,
            prepared_by_name="Prep Agent",
            technician_name="Tech Agent",
            scientist_name="Scientist Agent",
            vc_name="Dr. I/C",
            vc_title="Signature of I/C"
        )
        
        ReportTest.objects.create(
            report=self.report,
            test_name="Dengue IgM",
            result_value="12.0",
            test_method="ELISA",
            interpretation_text="Positive"
        )
        
        self.client = Client()
        self.client.login(username="rmnihr", password="rmnihr03072026")

    def test_colored_report_print(self):
        response = self.client.get(reverse('view_report', kwargs={'pk': self.report.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "John Doe")
        self.assertContains(response, "Prep Agent")
        self.assertContains(response, "Dr. I/C")

    def test_bw_report_print(self):
        response = self.client.get(reverse('view_report_bw', kwargs={'pk': self.report.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "John Doe")
        self.assertContains(response, "Prep Agent")
        self.assertContains(response, "Dr. I/C")

    def test_aiims_report_print(self):
        response = self.client.get(reverse('view_report_aiims', kwargs={'pk': self.report.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "John Doe")
        self.assertContains(response, "Patient Name:")
        self.assertContains(response, "Dr. I/C")


class PublicReportPortalTests(TestCase):
    def setUp(self):
        self.report = Report.objects.create(
            lab_id="RMRIMS/2026/101",
            patient_name="PATIENT PUBLIC",
            age_value=35,
            age_unit="Y",
            sex="F",
            test_method="ELISA",
            sample_type="BLOOD",
            receiving_date="2026-07-20",
            reporting_date="2026-07-21",
            ref_by="Patna Medical College"
        )
        ReportTest.objects.create(
            report=self.report,
            test_name="Dengue IgM",
            result_value="15.2",
            test_method="ELISA",
            interpretation_text="Positive"
        )
        self.client = Client()

    def test_public_report_portal_accessible_without_login(self):
        response = self.client.get('/report/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Search Your Diagnostic Report")
        self.assertContains(response, "Public Patient Report Portal")
        self.assertContains(response, "Total Reports Generated:")

    def test_public_report_search_success(self):
        response = self.client.post('/report/', {
            'lab_id': 'RMRIMS/2026/101',
            'age_value': '35',
            'age_unit': 'Y',
            'sex': 'F'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Patient Public")
        self.assertContains(response, "RMRIMS/2026/101")
        self.assertContains(response, "Dengue IgM")
        self.assertContains(response, "POSITIVE")
        self.assertContains(response, "Download Report PDF")

    def test_public_report_search_case_insensitive_lab_id(self):
        response = self.client.post('/report/', {
            'lab_id': 'rmrims/2026/101',
            'age_value': '35',
            'age_unit': 'Y',
            'sex': 'F'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Patient Public")

    def test_public_report_search_not_found(self):
        response = self.client.post('/report/', {
            'lab_id': 'RMRIMS/2026/101',
            'age_value': '99',
            'age_unit': 'Y',
            'sex': 'F'
        })
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No report found matching Lab ID")

    def test_public_report_read_only_protection(self):
        response = self.client.post('/report/', {
            'lab_id': 'RMRIMS/2026/101',
            'age_value': '35',
            'age_unit': 'Y',
            'sex': 'F'
        })
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "edit_report")
        self.assertNotContains(response, "delete_report")
        self.assertNotContains(response, "bulk-upload")


class BulkUploadAgeUnitTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser(
            username="bulk_admin",
            password="password123",
            email="bulk@test.com"
        )
        self.client = Client()
        self.client.login(username="bulk_admin", password="password123")

    def test_bulk_upload_ignores_age_unit_as_test_name(self):
        import openpyxl
        from io import BytesIO
        from django.core.files.uploadedfile import SimpleUploadedFile

        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Lab ID", "Patient Name", "Age", "Age Unit", "Sex", "Ref By", "Sample Type", "Test Method", "Dengue IgM"])
        ws.append(["LAB-001", "Jane Doe", 28, "Years", "F", "Self", "Blood", "ELISA", "12.5"])

        file_stream = BytesIO()
        wb.save(file_stream)
        file_stream.seek(0)

        uploaded_file = SimpleUploadedFile("bulk_test.xlsx", file_stream.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

        response = self.client.post(reverse('bulk_upload'), {'excel_file': uploaded_file})
        self.assertEqual(response.status_code, 302)

        report = Report.objects.get(lab_id="LAB-001")
        self.assertEqual(report.patient_name, "Jane Doe")
        self.assertEqual(report.age_value, 28)
        self.assertEqual(report.age_unit, "Y")

        # Verify ReportTest only contains Dengue IgM, NOT Age Unit
        test_names = list(report.tests.values_list('test_name', flat=True))
        self.assertIn("Dengue IgM", test_names)
        self.assertNotIn("Age Unit", test_names)
        self.assertNotIn("age unit", [t.lower() for t in test_names])

    def test_bulk_upload_clears_dashboard_cache_immediately(self):
        import openpyxl
        from io import BytesIO
        from django.core.files.uploadedfile import SimpleUploadedFile

        # Visit dashboard first to prime cache with 0 reports
        dash_initial = self.client.get(reverse('dashboard'))
        self.assertEqual(dash_initial.context['total_count'], 0)

        # Now bulk upload 1 report
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Lab ID", "Patient Name", "Age", "Age Unit", "Sex", "Ref By", "Sample Type", "Test Method", "Dengue IgM"])
        ws.append(["LAB-002", "John Smith", 40, "Years", "M", "Self", "Blood", "ELISA", "15.0"])

        file_stream = BytesIO()
        wb.save(file_stream)
        file_stream.seek(0)
        uploaded_file = SimpleUploadedFile("bulk_test2.xlsx", file_stream.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

        self.client.post(reverse('bulk_upload'), {'excel_file': uploaded_file})

        # Immediately visit dashboard again in same session
        dash_after = self.client.get(reverse('dashboard'))
        self.assertEqual(dash_after.context['total_count'], 1)
        self.assertEqual(dash_after.context['positive_count'], 1)


class PublicReportAccessTest(TestCase):
    def setUp(self):
        self.report = Report.objects.create(
            lab_id="PUB-100",
            patient_name="Public Patient",
            age_value=30,
            age_unit="Y",
            sex="F"
        )
        self.client = Client()

    def test_public_report_access_tracks_unique_lab_id_once(self):
        url = reverse('public_report_search')
        
        # Initial access before search should reflect total Report count in db (1 created in setUp)
        res1 = self.client.get(url)
        self.assertEqual(res1.context['total_reports_count'], 1)

        # First successful search for PUB-100
        res2 = self.client.post(url, {
            'lab_id': 'PUB-100',
            'age_value': 30,
            'age_unit': 'Y',
            'sex': 'F'
        })
        self.assertEqual(res2.status_code, 200)
        self.assertIsNotNone(res2.context['report'])
        self.assertEqual(res2.context['total_reports_count'], 1)

        # Repeated search for same lab_id PUB-100
        res3 = self.client.post(url, {
            'lab_id': 'PUB-100',
            'age_value': 30,
            'age_unit': 'Y',
            'sex': 'F'
        })
        self.assertEqual(res3.status_code, 200)
        self.assertEqual(res3.context['total_reports_count'], 1)





