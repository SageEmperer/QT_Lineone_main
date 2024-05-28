from django.db import models
from console.models import *

# Create your models here.
class StudentCredentials(models.Model):
    crn = models.ForeignKey(Register_model, on_delete=models.CASCADE, related_name='student_credentials')
    student_id = models.ForeignKey(LeadModel, on_delete=models.CASCADE)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)


# one time profile for the student
class StudentOneTimeProfile(models.Model):
    student = models.ForeignKey(LeadModel,on_delete=models.CASCADE)
    gender = models.CharField(max_length=100,null=True)
    Qualification = models.ForeignKey(Qualification,on_delete=models.SET_NULL,null=True)
    linkedin = models.CharField(max_length=100,null=True)
    country = models.CharField(max_length=100,null=True)
    state = models.CharField(max_length=100,null=True)
    city = models.CharField(max_length=100,null=True)
    education_data = models.CharField(max_length=2000,null=True)
    project_data = models.CharField(max_length=2000,null=True)
    certification_data = models.CharField(max_length=2000,null=True)
    permanent_country = models.CharField(max_length=100)
    permanent_state = models.CharField(max_length=100)
    permanent_city = models.CharField(max_length=100)