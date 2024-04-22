# Generated by Django 5.0.4 on 2024-04-22 06:11

import datetime
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('console', '0028_language'),
    ]

    operations = [
        migrations.CreateModel(
            name='Create_Topic',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('topic_title', models.CharField(max_length=80)),
                ('topic_duration', models.CharField(max_length=30)),
                ('topic_vedio_url', models.CharField(max_length=50)),
                ('topic_description', models.TextField()),
                ('topic_status', models.BooleanField(default=False)),
                ('topic_date', models.DateTimeField(default=datetime.datetime.now)),
                ('chapter_title', models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, to='console.create_chapter')),
                ('course_title', models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, to='console.course')),
                ('crn_number', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='topics', to='console.register_model')),
                ('language_name', models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, to='console.language')),
                ('lesson_title', models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, to='console.create_lesson')),
                ('spec_title', models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, to='console.specialization')),
                ('sub_cat_title', models.ForeignKey(default=True, on_delete=django.db.models.deletion.CASCADE, to='console.sub_category')),
            ],
        ),
    ]