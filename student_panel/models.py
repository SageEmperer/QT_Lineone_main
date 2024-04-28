from django.db import models
from console.models import *

# Create your models here.
class Studen_credentials(models.Model):
    crn = models.ForeignKey(Register_model, on_delete=models.CASCADE, related_name='student_credentials')
    studend_id = models.ForeignKey(LeadModel, on_delete=models.CASCADE)
    email = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
