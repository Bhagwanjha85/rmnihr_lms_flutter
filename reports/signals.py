from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from .models import Report, TestConfig
from .firebase_sync import (
    sync_report_to_firebase,
    delete_report_from_firebase,
    sync_config_to_firebase,
    delete_config_from_firebase
)

@receiver(post_save, sender=Report)
def report_saved(sender, instance, **kwargs):
    sync_report_to_firebase(instance)

@receiver(post_delete, sender=Report)
def report_deleted(sender, instance, **kwargs):
    if hasattr(instance, 'id') and instance.id:
        delete_report_from_firebase(instance.id)

@receiver(post_save, sender=TestConfig)
def config_saved(sender, instance, **kwargs):
    sync_config_to_firebase(instance)

@receiver(post_delete, sender=TestConfig)
def config_deleted(sender, instance, **kwargs):
    if hasattr(instance, 'id') and instance.id:
        delete_config_from_firebase(instance.id)
