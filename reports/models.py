from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class Report(models.Model):
    SEX_CHOICES = [
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    ]
    
    lab_id = models.CharField(max_length=50, verbose_name="Lab ID -S-", blank=True, null=True, db_index=True)
    sample_type = models.CharField(max_length=50, default="BLOOD", blank=True, null=True)
    patient_name = models.CharField(max_length=150, blank=True, null=True, db_index=True)
    receiving_date = models.DateField(default=timezone.now, blank=True, null=True, db_index=True)
    reporting_date = models.DateField(default=timezone.now, blank=True, null=True, db_index=True)
    age_value = models.IntegerField(default=0, blank=True, null=True)
    age_unit = models.CharField(max_length=10, choices=[('Y', 'Years'), ('M', 'Months'), ('D', 'Days')], default='Y', blank=True, null=True)
    sex = models.CharField(max_length=1, choices=SEX_CHOICES, default='F', blank=True, null=True)
    ref_by = models.CharField(max_length=150, default="", blank=True, null=True, db_index=True)
    test_method = models.CharField(max_length=100, default="ELISA", blank=True, null=True, db_index=True)
    
    # Bottom Note
    notes = models.TextField(
        default="This report is not valid for any medico-legal purpose. Result reflect to the sample as received. Interpretation can be done by Clinician. Please contact the Lab for any clarification/re-evalutation of the result."
    )
    
    # Signature configurations
    show_prepared_by = models.BooleanField(default=True)
    show_technician = models.BooleanField(default=True)
    show_scientist = models.BooleanField(default=True)
    show_vc = models.BooleanField(default=True)
    
    prepared_by_name = models.CharField(max_length=100, default="Report Prepared by")
    technician_name = models.CharField(max_length=100, default="Lab Technician / RA")
    scientist_name = models.CharField(max_length=100, default="Research Scientist")
    vc_name = models.CharField(max_length=100, default="Dr. G.C Sahoo")
    vc_title = models.CharField(max_length=100, default="Signature of I/C")
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_reports')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if self.patient_name:
            self.patient_name = self.patient_name.strip().title()
        super().save(*args, **kwargs)

    @property
    def has_rtpcr_value(self):
        return self.tests.filter(test_method='RT-PCR').exclude(result_value__in=[None, '', '-', 'None']).exists()

    def __str__(self):
        return f"{self.lab_id} - {self.patient_name}"

    class Meta:
        ordering = ['-created_at']


def determine_interpretation(test_name, test_method, result_value, config=None):
    if result_value is None or str(result_value).strip() == '':
        return ""

    res_str = str(result_value).strip()
    val_clean = res_str.lower()
    
    qualitative_mapping = {
        'positive': 'Positive',
        'pos': 'Positive',
        '+': 'Positive',
        '(+)': 'Positive',
        'p': 'Positive',
        'detected': 'Positive',
        'present': 'Positive',
        'abnormal': 'Positive',
        'high': 'Positive',
        'pos(+)': 'Positive',
        'positive(+)': 'Positive',
        'reactive': 'Reactive',
        'react': 'Reactive',
        'r': 'Reactive',
        'negative': 'Negative',
        'neg': 'Negative',
        '-': 'Negative',
        '(-)': 'Negative',
        'n': 'Negative',
        'not detected': 'Negative',
        'notdetected': 'Negative',
        'absent': 'Negative',
        'normal': 'Negative',
        'low': 'Negative',
        'neg(-)': 'Negative',
        'negative(-)': 'Negative',
        'non-reactive': 'Non-Reactive',
        'nonreactive': 'Non-Reactive',
        'non reactive': 'Non-Reactive',
        'nr': 'Non-Reactive',
        'equivocal': 'Equivocal',
        'eq': 'Equivocal',
        '+/-': 'Equivocal',
        '(+/-)': 'Equivocal',
        'borderline': 'Equivocal',
        'indeterminant': 'Equivocal',
        'indeterminate': 'Equivocal',
        'invalid': 'Invalid',
    }
    
    name_lower = (test_name or '').lower()
    is_reactive_test = any(x in name_lower for x in ['hbs', 'hcv', 'antibody', 'ag', 'reactive'])

    # 1. Check exact qualitative mapping
    if val_clean in qualitative_mapping:
        interp = qualitative_mapping[val_clean]
        if is_reactive_test:
            if interp == 'Positive':
                return 'Reactive'
            elif interp == 'Negative':
                return 'Non-Reactive'
        return interp

    # 2. Check TestConfig rule if provided
    if config:
        result_type = config.get('result_type') if isinstance(config, dict) else getattr(config, 'result_type', 'numeric')
        cutoff_val = config.get('cutoff_value') if isinstance(config, dict) else getattr(config, 'cutoff_value', None)
        cutoff_val_upper = config.get('cutoff_value_upper') if isinstance(config, dict) else getattr(config, 'cutoff_value_upper', None)

        if result_type == 'numeric':
            try:
                import re
                nums = re.findall(r'[-+]?\d*\.\d+|\d+', res_str)
                if nums:
                    val = float(nums[0])
                    if cutoff_val_upper is not None and cutoff_val is not None:
                        if val < cutoff_val:
                            return "Non-Reactive" if is_reactive_test else "Negative"
                        elif val > cutoff_val_upper:
                            return "Reactive" if is_reactive_test else "Positive"
                        else:
                            return "Equivocal"
                    elif cutoff_val is not None:
                        if val >= cutoff_val:
                            return "Reactive" if is_reactive_test else "Positive"
                        else:
                            return "Non-Reactive" if is_reactive_test else "Negative"
            except ValueError:
                pass
        elif result_type in ['positive_negative', 'select', 'reactive_non_reactive', 'custom_dropdown']:
            if val_clean in qualitative_mapping:
                return qualitative_mapping[val_clean]
            return res_str

    # 3. Substring qualitative check
    if any(x in val_clean for x in ['non-reactive', 'nonreactive', 'not detected', 'notdetected', 'absent', 'non reactive']):
        return 'Non-Reactive' if is_reactive_test else 'Negative'
    if any(x in val_clean for x in ['reactive', 'detected', 'present']):
        return 'Reactive' if is_reactive_test else 'Positive'
    if any(x in val_clean for x in ['positive', 'pos']):
        if 'neg' in val_clean or 'non' in val_clean:
            return 'Non-Reactive' if is_reactive_test else 'Negative'
        return 'Reactive' if is_reactive_test else 'Positive'
    if any(x in val_clean for x in ['negative', 'neg']):
        return 'Non-Reactive' if is_reactive_test else 'Negative'
    if any(x in val_clean for x in ['equivocal', 'borderline']):
        return 'Equivocal'

    # 3. Universal numerical evaluation fallback
    try:
        import re
        nums = re.findall(r'[-+]?\d*\.\d+|\d+', res_str)
        if nums:
            val = float(nums[0])
            if 'hbs' in name_lower or 'hbsag' in name_lower:
                return "Reactive" if val >= 0.191 else "Non-Reactive"
            elif 'hcv' in name_lower:
                return "Reactive" if val >= 0.361 else "Non-Reactive"
            elif 'hiv' in name_lower:
                return "Reactive" if val >= 1.0 else "Non-Reactive"
            else:
                method_upper = (test_method or '').upper()
                if method_upper == 'ELISA' or any(x in name_lower for x in ['igm', 'igg', 'dengue', 'chik', 'je', 'measles', 'mumps', 'rubella', 'scrub']):
                    if val < 9.0:
                        return "Negative"
                    elif val > 11.0:
                        return "Positive"
                    else:
                        return "Equivocal"
                else:
                    if val >= 1.0:
                        return "Positive"
                    elif val < 0.9:
                        return "Negative"
                    else:
                        return "Equivocal"
    except ValueError:
        pass

    return res_str.title() if res_str else ""


class ReportTest(models.Model):
    TEST_CHOICES = [
        ('Anti-HBc IgM', 'Anti-HBc IgM'),
        ('Anti-HBc Total', 'Anti-HBc Total'),
        ('Anti-HBe', 'Anti-HBe'),
        ('Anti-HBs', 'Anti-HBs'),
        ('Calicivirus','Calicivirus'  ),
        ('Chikungunya', 'Chikungunya'),
        ('Chikungunya IgG', 'Chikungunya IgG'),
        ('Chikungunya IgM', 'Chikungunya IgM'),
        ('Dengue', 'Dengue'),
        ('Dengue IgG', 'Dengue IgG'),
        ('Dengue IgM', 'Dengue IgM'),
        ('Dengue NS1', 'Dengue NS1'),
        ('HAV IgG', 'HAV IgG'),
        ('HAV IgM', 'HAV IgM'),
        ('HBeAg', 'HBeAg'),
        ('HBsAg', 'HBsAg'),
        ('HBV DNA', 'HBV DNA'),
        ('HCV Antibody', 'HCV Antibody'),
        ('HCV RNA','HCV RNA' ),
        ('HEV IgG', 'HEV IgG'),
        ('HEV IgM', 'HEV IgM'),
        ('Influenza H1N1', 'Influenza H1N1'),
        ('Influenza H3N2', 'Influenza H3N2'),
        ('JE IgM (Blood)', 'JE IgM (Blood)'),
        ('JE IgM (CSF)', 'JE IgM (CSF)'),
        ('Leptospira', 'Leptospira'),
        ('Leptospira IgM', 'Leptospira IgM'),
        ('Leptospira', 'Leptospira'),
        ('Measles', 'Measles'),
        ('Measles IgG', 'Measles IgG'),
        ('Measles IgM', 'Measles IgM'),
        ('Mumps', 'Mumps'),
        ('Mumps IgG', 'Mumps IgG'),
        ('Mumps IgM', 'Mumps IgM'),
        ('Scrub Typhus (ST)', 'Scrub Typhus (ST)'),
        ('Scrub Typhus IgM', 'Scrub Typhus IgM'),
        ('VZV IgG', 'VZV IgG'),
        ('VZV IgM', 'VZV IgM'),
        ('Zika Virus IgM', 'Zika Virus IgM'),
        ('Zika Virus RNA', 'Zika Virus RNA'),
        ('Influenza VICTORIA', 'Influenza VICTORIA'),
    ]
    report = models.ForeignKey(Report, related_name='tests', on_delete=models.CASCADE)
    test_method = models.CharField(max_length=50, default='ELISA', db_index=True)
    test_name = models.CharField(max_length=100, db_index=True)
    result_value = models.CharField(max_length=50, blank=True, null=True)
    interpretation_text = models.CharField(max_length=50, blank=True, null=True, db_index=True)

    @property
    def interpretation_range(self):
        method = (self.test_method or '').upper()
        name = self.test_name
        
        # Check database configurations first
        from reports.backup_utils import restore_test_configs_from_backup_if_needed
        restore_test_configs_from_backup_if_needed()
        
        config = TestConfig.objects.filter(test_name=name, test_method=method).first()
        if config:
            if config.result_type == 'numeric':
                if config.cutoff_value_upper is not None:
                    return f"Negative &lt; {config.cutoff_value:.2f} | Equivocal {config.cutoff_value:.2f}-{config.cutoff_value_upper:.2f} | Positive &gt; {config.cutoff_value_upper:.2f}"
                elif config.cutoff_value is not None:
                    if any(x in name.lower() for x in ['hbs', 'hcv', 'antibody', 'ag', 'reactive']):
                        return f"Non-Reactive &lt; {config.cutoff_value:.3f} | Reactive &ge; {config.cutoff_value:.3f}"
                    else:
                        return f"Negative &lt; {config.cutoff_value:.2f} | Positive &ge; {config.cutoff_value:.2f}"
            elif config.result_type == 'positive_negative':
                return "Positive / Negative"
            elif config.result_type == 'select':
                return "Positive / Negative / Equivocal"
            elif config.result_type == 'reactive_non_reactive':
                return "Reactive / Non-Reactive"
            elif config.result_type == 'custom_dropdown' and config.custom_options:
                return " / ".join([opt.strip() for opt in config.custom_options.split(',') if opt.strip()])
            return "" # qualitative has no range
            
        # Fallback to existing hardcoded values
        if method == 'ELISA':
            if self.test_name == 'HBsAg':
                return "Non-Reactive &lt; 0.191 | Reactive &ge; 0.191"
            elif self.test_name == 'HCV Antibody':
                return "Non-Reactive &lt; 0.361 | Reactive &ge; 0.361"
            else:
                return "Negative &lt; 9.00 | Equivocal 9.00-11.00 | Positive &gt; 11.00"
        return ""

    def save(self, *args, **kwargs):
        method = (self.test_method or '').upper()
        name = self.test_name or ''
        config = TestConfig.objects.filter(test_name=name, test_method=method).first()
        
        if not self.interpretation_text:
            calculated_interp = determine_interpretation(name, method, self.result_value, config=config)
            if calculated_interp:
                self.interpretation_text = calculated_interp
            
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.test_name}: {self.result_value} ({self.interpretation_text}) [{self.test_method}]"


from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    passcode = models.CharField(max_length=50, blank=True, null=True, default='')
    is_super_admin = models.BooleanField(default=False)
    is_admin_added_by_superadmin = models.BooleanField(default=False)
    otp_code = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} Profile"


class TestConfig(models.Model):
    RESULT_TYPE_CHOICES = [
        ('numeric', 'Numeric Range'),
        ('positive_negative', 'Positive/Negative'),
        ('select', 'Select (Positive/Negative/Equivocal)'),
        ('reactive_non_reactive', 'Reactive/Non-Reactive'),
        ('custom_dropdown', 'Custom Dropdown Choices'),
    ]
    
    test_name = models.CharField(max_length=100, db_index=True)
    test_method = models.CharField(max_length=100, default='ELISA')
    
    cutoff_value = models.FloatField(blank=True, null=True, help_text="e.g. 0.191 or 9.0")
    cutoff_value_upper = models.FloatField(blank=True, null=True, help_text="e.g. 11.0 (optional)")
    
    result_type = models.CharField(max_length=30, choices=RESULT_TYPE_CHOICES, default='numeric')
    custom_options = models.CharField(max_length=255, blank=True, null=True, help_text="Comma-separated custom dropdown options (e.g. Option1, Option2, Option3)")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('test_name', 'test_method')
        ordering = ['test_method', 'test_name']
        
    def __str__(self):
        return f"{self.test_method} - {self.test_name}"


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if not hasattr(instance, 'profile'):
        UserProfile.objects.create(user=instance)
    instance.profile.save()


class SystemLogo(models.Model):
    name = models.CharField(max_length=150)
    image_base64 = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Visitor(models.Model):
    ip_address = models.GenericIPAddressField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address


class TemplateConfig(models.Model):
    dept_main = models.CharField(max_length=255, default="Viral Research & Diagnostic Laboratories")
    dept_sub = models.CharField(max_length=255, default="Department of Virology")
    dept_sponsor = models.CharField(max_length=255, default="(Dept. of Health Research Sponsored Medical College Level VRDL)")
    dept_address = models.CharField(max_length=255, default="Agamkuan, Patna, Bihar – 800007")
    logo = models.ForeignKey(SystemLogo, on_delete=models.SET_NULL, null=True, blank=True)

    @classmethod
    def get_solo(cls):
        obj, created = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return "Template Configuration"


class PublicReportAccess(models.Model):
    lab_id = models.CharField(max_length=100, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Public Access: {self.lab_id}"


# Cache Invalidation & Backup Signals
from django.core.cache import cache

@receiver([post_save, post_delete], sender=SystemLogo)
@receiver([post_save, post_delete], sender=TemplateConfig)
@receiver([post_save, post_delete], sender=Report)
@receiver([post_save, post_delete], sender=ReportTest)
@receiver([post_save, post_delete], sender=PublicReportAccess)
def clear_cache_on_write(sender, instance, **kwargs):
    cache.clear()

@receiver([post_save, post_delete], sender=TestConfig)
def handle_test_config_write(sender, instance, **kwargs):
    cache.clear()
    from reports.backup_utils import save_test_configs_to_backup
    save_test_configs_to_backup()



