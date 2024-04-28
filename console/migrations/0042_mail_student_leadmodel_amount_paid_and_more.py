# Generated by Django 5.0.4 on 2024-04-27 09:04

import datetime
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('console', '0041_employee_model_salary_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Mail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('sent', 'Sent')], max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='Student',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
            ],
        ),
        migrations.AddField(
            model_name='leadmodel',
            name='amount_paid',
            field=models.DecimalField(decimal_places=2, max_digits=9, null=True),
        ),
        migrations.AlterField(
            model_name='leadmodel',
            name='token_generated_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 4, 27, 14, 34, 57, 509347)),
        ),
        migrations.AlterField(
            model_name='student_payment',
            name='date_of_payment',
            field=models.DateTimeField(default=datetime.datetime(2024, 4, 27, 14, 34, 57, 510347)),
        ),
        migrations.CreateModel(
            name='Bouncedstudents',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fullname', models.CharField(max_length=100)),
                ('email', models.CharField(max_length=100)),
                ('mobilenumber', models.CharField(max_length=100)),
                ('organization', models.CharField(max_length=100)),
                ('startdate', models.CharField(max_length=100)),
                ('enddate', models.CharField(max_length=100)),
                ('certifictateid', models.CharField(max_length=100, null=True)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='console.course')),
                ('crn_number', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='BouncedStudent', to='console.register_model')),
                ('specialization', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='console.specialization')),
            ],
        ),
        migrations.CreateModel(
            name='Certification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('course_title', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='console.course')),
                ('crn_number', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='certifications', to='console.register_model')),
                ('specialization', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='console.specialization')),
            ],
        ),
        migrations.CreateModel(
            name='creatstudents',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fullname', models.CharField(max_length=100)),
                ('email', models.CharField(max_length=100)),
                ('mobilenumber', models.CharField(max_length=100)),
                ('organization', models.CharField(max_length=100)),
                ('startdate', models.CharField(max_length=100)),
                ('enddate', models.CharField(max_length=100)),
                ('certifictateid', models.CharField(max_length=100, null=True)),
                ('cerficate_sent', models.BooleanField(default=False)),
                ('course', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='console.course')),
                ('crn_number', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='CreateStudent', to='console.register_model')),
                ('specialization', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='console.specialization')),
            ],
        ),
    ]
