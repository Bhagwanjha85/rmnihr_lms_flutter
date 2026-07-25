import os
import json
from django.conf import settings

BACKUP_FILE_PATH = os.path.join(settings.BASE_DIR, 'reports', 'test_configs_backup.json')

def save_test_configs_to_backup():
    try:
        from reports.models import TestConfig
        configs = TestConfig.objects.all().order_by('id')
        data = []
        for tc in configs:
            data.append({
                'test_name': tc.test_name,
                'test_method': tc.test_method,
                'cutoff_value': tc.cutoff_value,
                'cutoff_value_upper': tc.cutoff_value_upper,
                'result_type': tc.result_type,
                'custom_options': tc.custom_options
            })
        
        # Write to JSON file
        with open(BACKUP_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving test configs to backup: {e}")

def restore_test_configs_from_backup_if_needed():
    # Automatic creation of test configs disabled. Only superadmin can create test configs.
    pass
