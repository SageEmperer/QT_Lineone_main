from django.db import models
from console.models import *




class Employee_credentials(models.Model):
  crn = models.ForeignKey(Register_model, on_delete=models.CASCADE ,related_name='employee_credentials')
  employee = models.ForeignKey(Employee_model, on_delete=models.CASCADE)
  email = models.EmailField()
  password = models.CharField(max_length=100)

  def __str__(self):
    return self.email
