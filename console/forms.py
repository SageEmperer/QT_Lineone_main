from django import forms 
from .models import LeadModel

class Traning_type_import_form(forms.Form):
    training_file = forms.FileField()



class BranchForm(forms.Form):
    branch_file = forms.FileField()


class RegulationForm(forms.Form):
    regulation_file = forms.FileField()

class calender_import_form(forms.Form):
    calender_file = forms.FileField()


class complaint_import_form(forms.Form):
    complaint_file=forms.FileField()    


class Forum_import_form(forms.Form):
    Forum_file = forms.FileField()

class purpose_import_form(forms.Form):
    purpose_file = forms.FileField()

class prospect_type_import_form(forms.Form):
    prospect_file = forms.FileField()

class vendor_import_form(forms.Form):
    vendor_file = forms.FileField()


class Employee_type_import_form(forms.Form):
    employeetype_file = forms.FileField()

class Course_import_form(forms.Form):
    cos_file = forms.FileField()
class Department_import_form(forms.Form):
    file = forms.FileField()

class Specialization_import_form(forms.Form):
    sep_file = forms.FileField()

class Designation_import_form(forms.Form):
    des_file = forms.FileField()

class Plan_import_form(forms.Form):
    pal_file = forms.FileField()

class Upipayments_import_form(forms.Form):
    upi_file=forms.FileField()

class Batchtype_import_form(forms.Form):
    batch_file=forms.FileField()


class Netbanking_import_form(forms.Form):
    net_file=forms.FileField()


class LeadForm(forms.ModelForm):
    class Meta:
        model = LeadModel
        fields = '__all__'

class Lead_import_form(forms.Form):
    Leads_file=forms.FileField()   

class Demo_import_form(forms.Form):
    demo_file=forms.FileField()

class course_manage_import_form(forms.Form):
    import_file=forms.FileField()

class EmployeeForm(forms.Form):
    employee_file = forms.FileField()

class Job_type_import_form(forms.Form):
    Jobs_file=forms.FileField()  

class category_import_form(forms.Form):
    Category_file=forms.FileField()
    
class qualification_import_form(forms.Form):
    qualification_file=forms.FileField()

class jobrole_import_form(forms.Form):
    jobrole_file = forms.FileField()    



class classroom_import_form(forms.Form):
    classroom_file = forms.FileField()    



class createstudent_import_form(forms.Form):
    createstudent_file = forms.FileField()

class certification_import_form(forms.Form):
    certification_file = forms.FileField()
