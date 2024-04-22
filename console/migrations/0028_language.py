# Generated by Django 5.0.4 on 2024-04-21 16:33

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('console', '0027_upipayments_upi_qr_code'),
    ]

    operations = [
        migrations.CreateModel(
            name='Language',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('language', models.CharField(max_length=100)),
                ('crn_number', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='languages', to='console.register_model')),
            ],
        ),
    ]