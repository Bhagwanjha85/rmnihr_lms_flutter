import os
import json
import logging
from datetime import datetime, date

logger = logging.getLogger(__name__)

_db = None

def get_firestore_client():
    global _db
    if _db is not None:
        return _db

    try:
        import firebase_admin
        from firebase_admin import credentials, firestore

        if firebase_admin._apps:
            _db = firestore.client()
            return _db

        creds_json = os.environ.get('FIREBASE_CREDENTIALS')
        creds_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'firebase_credentials.json')

        cred = None
        if creds_json:
            try:
                cred_dict = json.loads(creds_json)
                cred = credentials.Certificate(cred_dict)
            except Exception as e:
                logger.error(f"Failed to parse FIREBASE_CREDENTIALS environment variable: {e}")
        elif os.path.exists(creds_file_path):
            try:
                cred = credentials.Certificate(creds_file_path)
            except Exception as e:
                logger.error(f"Failed to read firebase_credentials.json file: {e}")

        if cred:
            firebase_admin.initialize_app(cred)
            _db = firestore.client()
            logger.info("Firebase Firestore client successfully initialized.")
            return _db
        else:
            logger.warning("No valid Firebase credentials found (env var FIREBASE_CREDENTIALS or firebase_credentials.json missing).")
            return None
    except Exception as e:
        logger.error(f"Error initializing Firebase SDK: {e}")
        return None


def serialize_val(val):
    if isinstance(val, (datetime, date)):
        return val.isoformat()
    return val


def sync_report_to_firebase(report):
    try:
        client = get_firestore_client()
        if not client:
            return

        doc_ref = client.collection('reports').document(str(report.id))
        data = {
            'id': report.id,
            'lab_id': getattr(report, 'lab_id', ''),
            'patient_name': getattr(report, 'patient_name', ''),
            'age_value': getattr(report, 'age_value', None),
            'age_unit': getattr(report, 'age_unit', 'Y'),
            'sex': getattr(report, 'sex', 'M'),
            'ref_by': getattr(report, 'ref_by', ''),
            'sample_type': getattr(report, 'sample_type', ''),
            'test_method': getattr(report, 'test_method', ''),
            'receiving_date': serialize_val(getattr(report, 'receiving_date', None)),
            'reporting_date': serialize_val(getattr(report, 'reporting_date', None)),
            'created_at': serialize_val(getattr(report, 'created_at', None)),
            'updated_at': serialize_val(getattr(report, 'updated_at', None)),
        }

        tests_data = []
        from reports.models import ReportTest
        tests = ReportTest.objects.filter(report_id=report.id)
        for test in tests:
            tests_data.append({
                'id': test.id,
                'test_method': getattr(test, 'test_method', ''),
                'test_name': getattr(test, 'test_name', ''),
                'result_value': getattr(test, 'result_value', ''),
                'interpretation_text': getattr(test, 'interpretation_text', ''),
            })
        data['tests'] = tests_data

        doc_ref.set(data, merge=True)
    except Exception as e:
        logger.error(f"Error syncing report {getattr(report, 'id', None)} to Firebase: {e}")


def delete_report_from_firebase(report_id):
    try:
        client = get_firestore_client()
        if not client:
            return
        client.collection('reports').document(str(report_id)).delete()
    except Exception as e:
        logger.error(f"Error deleting report {report_id} from Firebase: {e}")


def sync_config_to_firebase(config):
    try:
        client = get_firestore_client()
        if not client:
            return
        doc_ref = client.collection('test_configs').document(str(config.id))
        data = {
            'id': config.id,
            'test_name': getattr(config, 'test_name', ''),
            'test_method': getattr(config, 'test_method', ''),
            'cutoff_value': getattr(config, 'cutoff_value', None),
            'cutoff_value_upper': getattr(config, 'cutoff_value_upper', None),
            'result_type': getattr(config, 'result_type', 'numeric'),
            'custom_options': getattr(config, 'custom_options', None),
        }
        doc_ref.set(data)
    except Exception as e:
        logger.error(f"Error syncing test config {getattr(config, 'id', None)} to Firebase: {e}")


def delete_config_from_firebase(config_id):
    try:
        client = get_firestore_client()
        if not client:
            return
        client.collection('test_configs').document(str(config_id)).delete()
    except Exception as e:
        logger.error(f"Error deleting test config {config_id} from Firebase: {e}")


def sync_public_access_to_firebase(access_obj):
    try:
        client = get_firestore_client()
        if not client:
            return
        doc_ref = client.collection('public_report_access').document(str(access_obj.lab_id))
        data = {
            'lab_id': access_obj.lab_id,
            'accessed_at': serialize_val(getattr(access_obj, 'accessed_at', datetime.now())),
        }
        doc_ref.set(data, merge=True)
    except Exception as e:
        logger.error(f"Error syncing public report access {getattr(access_obj, 'lab_id', '')} to Firebase: {e}")


def restore_data_from_firebase():
    """
    Restores reports, test configs, and public report access from Firebase Firestore if local Django database is empty on boot.
    """
    try:
        client = get_firestore_client()
        if not client:
            return

        from reports.models import Report, ReportTest, TestConfig, PublicReportAccess

        # 1. Restore TestConfigs if DB is empty
        if not TestConfig.objects.exists():
            configs_docs = client.collection('test_configs').stream()
            for doc in configs_docs:
                d = doc.to_dict()
                if not d:
                    continue
                TestConfig.objects.update_or_create(
                    id=d.get('id'),
                    defaults={
                        'test_name': d.get('test_name'),
                        'test_method': d.get('test_method'),
                        'cutoff_value': d.get('cutoff_value'),
                        'cutoff_value_upper': d.get('cutoff_value_upper'),
                        'result_type': d.get('result_type', 'numeric'),
                        'custom_options': d.get('custom_options'),
                    }
                )
            logger.info("Restored TestConfigs from Firebase Firestore.")

        # 2. Restore Reports if DB is empty
        if not Report.objects.exists():
            reports_docs = client.collection('reports').stream()
            for doc in reports_docs:
                d = doc.to_dict()
                if not d:
                    continue
                rec_date = datetime.fromisoformat(d['receiving_date']).date() if d.get('receiving_date') else None
                rep_date = datetime.fromisoformat(d['reporting_date']).date() if d.get('reporting_date') else None

                report, created = Report.objects.update_or_create(
                    id=d.get('id'),
                    defaults={
                        'lab_id': d.get('lab_id'),
                        'patient_name': d.get('patient_name'),
                        'age_value': d.get('age_value'),
                        'age_unit': d.get('age_unit', 'Y'),
                        'sex': d.get('sex', 'M'),
                        'ref_by': d.get('ref_by'),
                        'sample_type': d.get('sample_type'),
                        'test_method': d.get('test_method'),
                        'receiving_date': rec_date,
                        'reporting_date': rep_date,
                    }
                )
                tests = d.get('tests', [])
                for t in tests:
                    ReportTest.objects.update_or_create(
                        id=t.get('id'),
                        defaults={
                            'report': report,
                            'test_method': t.get('test_method', 'ELISA'),
                            'test_name': t.get('test_name', ''),
                            'result_value': t.get('result_value', ''),
                            'interpretation_text': t.get('interpretation_text', ''),
                        }
                    )
            logger.info("Restored Reports from Firebase Firestore.")

        # 3. Restore PublicReportAccess if DB is empty
        if not PublicReportAccess.objects.exists():
            access_docs = client.collection('public_report_access').stream()
            for doc in access_docs:
                d = doc.to_dict()
                if not d or not d.get('lab_id'):
                    continue
                PublicReportAccess.objects.get_or_create(
                    lab_id=d.get('lab_id').strip().upper()
                )
            logger.info("Restored PublicReportAccess from Firebase Firestore.")
    except Exception as e:
        logger.error(f"Error restoring data from Firebase Firestore: {e}")


def ensure_database_hydrated():
    """
    Checks if local database has reports and public access records.
    If empty (e.g. after container restart), auto-restores data from Firebase Firestore.
    """
    try:
        from reports.models import Report, PublicReportAccess
        if not Report.objects.exists() or not PublicReportAccess.objects.exists():
            restore_data_from_firebase()
    except Exception as e:
        logger.error(f"Auto-hydration check error: {e}")
