# Generated by Django 5.0.4 on 2024-05-15 04:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('student_panel', '0002_rename_studen_credentials_studentcredentials'),
    ]

    operations = [
        migrations.RenameField(
            model_name='studentcredentials',
            old_name='studend_id',
            new_name='student_id',
        ),
    ]
