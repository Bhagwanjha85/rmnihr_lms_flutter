#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install dependencies
pip install -r requirements.txt

# Gather static files
python manage.py collectstatic --noinput
# Run migrations
python manage.py migrate

# Create or update the primary superuser with correct UserProfile configuration
python manage.py create_superuser_rmnihr --force-update

# Sync database with Firebase Cloud Firestore
python manage.py sync_firebase
