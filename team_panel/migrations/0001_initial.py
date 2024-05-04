# Generated by Django 5.0.4 on 2024-04-28 12:19

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('console', '0050_alter_job_post_post_date_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Employee_credentials',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=100)),
                ('crn', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='employee_credentials', to='console.register_model')),
                ('employee', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='console.employee_model')),
            ],
        ),
    ]