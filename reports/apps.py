from django.apps import AppConfig


class ReportsConfig(AppConfig):
    name = 'reports'

    def ready(self):
        try:
            import reports.signals  # noqa
            from django.db import connection
            if 'reports_testconfig' in connection.introspection.table_names():
                from reports.backup_utils import restore_test_configs_from_backup_if_needed
                restore_test_configs_from_backup_if_needed()
                from reports.firebase_sync import restore_data_from_firebase
                restore_data_from_firebase()
        except Exception:
            pass

