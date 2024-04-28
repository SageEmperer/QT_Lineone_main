# Generated by Django 5.0.4 on 2024-04-28 05:28

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('console', '0047_alter_job_post_post_date_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Studen_credentials',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(max_length=100)),
                ('password', models.CharField(max_length=100)),
                ('is_active', models.BooleanField(default=True)),
                ('crn', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='student_credentials', to='console.register_model')),
                ('studend_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='console.leadmodel')),
            ],
        ),
    ]
