# Generated by Django 5.0.4 on 2024-04-20 03:54

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('console', '0020_sub_category_crn_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='course',
            name='sub_category',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='console.sub_category'),
        ),
    ]