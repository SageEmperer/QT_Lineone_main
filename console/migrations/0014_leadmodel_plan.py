# Generated by Django 5.0.4 on 2024-04-17 16:06

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('console', '0013_leadmodel_sql_description'),
    ]

    operations = [
        migrations.AddField(
            model_name='leadmodel',
            name='plan',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='console.plan'),
        ),
    ]