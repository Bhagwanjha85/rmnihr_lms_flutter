from django.core.management.base import BaseCommand
from reports.models import Report, TestConfig
from reports.firebase_sync import (
    sync_report_to_firebase,
    sync_config_to_firebase,
    restore_data_from_firebase,
    get_firestore_client
)

class Command(BaseCommand):
    help = 'Synchronize all Django reports and test configurations with Firebase Cloud Firestore'

    def handle(self, *args, **options):
        self.stdout.write("Initializing Firebase client...")
        client = get_firestore_client()
        if not client:
            self.stderr.write("Firebase client could not be initialized. Check FIREBASE_CREDENTIALS or firebase_credentials.json.")
            return

        # Step 1: If local database has data, push all to Firebase
        reports_count = Report.objects.count()
        configs_count = TestConfig.objects.count()

        if reports_count > 0 or configs_count > 0:
            self.stdout.write(f"Found {reports_count} reports and {configs_count} configs in database. Uploading to Firebase...")
            
            for config in TestConfig.objects.all():
                sync_config_to_firebase(config)
            self.stdout.write(self.style.SUCCESS(f"Successfully synced {configs_count} test configurations to Firebase."))

            for report in Report.objects.prefetch_related('tests').all():
                sync_report_to_firebase(report)
            self.stdout.write(self.style.SUCCESS(f"Successfully synced {reports_count} reports to Firebase."))

        else:
            self.stdout.write("Local database is empty. Attempting to restore from Firebase Firestore...")
            restore_data_from_firebase()
            restored_reports = Report.objects.count()
            restored_configs = TestConfig.objects.count()
            self.stdout.write(self.style.SUCCESS(f"Restoration complete: {restored_reports} reports, {restored_configs} configs."))
