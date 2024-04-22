# Generated by Django 5.0.4 on 2024-04-21 07:44

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('console', '0025_remove_create_lesson_lesson_banner_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='leadmodel',
            name='faculty',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='console.employee_model'),
        ),
        migrations.AlterField(
            model_name='create_lesson',
            name='lesson_status',
            field=models.BooleanField(default=True),
        ),
    ]
