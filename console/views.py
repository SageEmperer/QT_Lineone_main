import csv
from django.http import FileResponse
from datetime import date, timedelta
from django.utils.safestring import mark_safe
from django.db.models import Count
from django.utils.html import strip_tags

import smtplib, ssl
import io
from django.conf import settings
from team_panel.models import *
from django.http import FileResponse, Http404, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render,redirect,reverse
from .models import *
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect, get_object_or_404
from .forms import *
from .helpers import *
from xhtml2pdf import pisa
from django.template.loader import render_to_string
import os
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login as auth_login
from functools import wraps
from django.utils.dateformat import format
from django.utils.timezone import make_aware
from django.db.models import Q
import re
from django.utils.dateparse import parse_datetime ,parse_date
from django.core import serializers
from django.utils.timezone import now
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.db.models.functions import TruncMonth
from django.core.exceptions import ObjectDoesNotExist
from student_panel.models import *
from django.conf import settings
from email.message import EmailMessage

# decorator for admin login
def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.session.get('admin_user'):
            # If admin user session exists, allow access to the view
            return view_func(request, *args, **kwargs)
        else:
            # If admin user session doesn't exist, redirect to login
            return redirect('login')
    return wrapper



def admin_login(request):
    adim_user = request.session.get('admin_user')
    if adim_user:
        return redirect('dashboard')
    if request.method == 'POST':
        email_id = request.POST.get('email_id')
        password = request.POST.get('password')
        admin_user_log = Register_model.objects.filter(email_id=email_id, password=password).first()
        if admin_user_log:
            print(admin_user_log.crn)
            print(admin_user_log.email_id)
            print(admin_user_log.password)
            print(admin_user_log.phone_number)
            print(admin_user_log.pin)
            print(admin_user_log.otp)
            request.session['admin_user'] = {
                'email_id': admin_user_log.email_id,
                'password': admin_user_log.password,
                'crn': admin_user_log.crn,
                'full_name': admin_user_log.full_name,
                'phone_number': admin_user_log.phone_number,
                'pin': admin_user_log.pin,
                'otp': admin_user_log.otp,
                'id': admin_user_log.id,
                'company_name':admin_user_log.company_name,
                'company_short_name':admin_user_log.company_short_name,
                'terms_and_conditions':admin_user_log.terms_and_conditions,
                'register_date':admin_user_log.register_date.isoformat()
            }
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid email or password')
            return redirect('login')
    return render(request, 'accounts/login.html')




    
def register_page(request):
    if request.method == 'POST':
      full_name= request.POST.get('full_name')
      email_id= request.POST.get('email_id')
      phone_number = request.POST.get('phone_number')
      pin=request.POST.get('pin')
      password = request.POST.get('password')
      company_name = request.POST.get('company_name')
      company_short_name = request.POST.get('company_short_name') 
      checkbox_value  = request.POST.get('check_box') 
      terms_and_conditions = checkbox_value  == 'on' 
      print("terms",terms_and_conditions)


      if Register_model.objects.filter(phone_number=phone_number).exists():
        messages.error(request, 'Phone number already exists')
        return redirect('register')
      if Register_model.objects.filter(email_id=email_id).exists():
        messages.error(request, 'Email id already exists')
        return redirect('register')

      if Register_model.objects.filter(company_short_name=company_short_name).exists():
        messages.error(request, 'Company short name already exists')
        return redirect('register')  


      otp=send_otp_to_phone(phone_number)
      if not otp:
        messages.error(request, 'Failed to send OTP. Please try again later.')
        return redirect('register')
      request.session['otp'] = otp
      request.session['register_data']={
        'full_name':full_name,
        'email_id':email_id,
        'phone_number':phone_number,
        'pin':pin,
        'password':password,
        'company_name':company_name,
        'company_short_name':company_short_name,
        'terms_and_conditions':terms_and_conditions
      }
      return redirect('otp_page')
    else:  
      return render(request, 'accounts/register.html')


def register_resend_otp(request):
  mobile_number = request.session.get('register_data').get('phone_number')
  otp = send_otp_to_phone(mobile_number)
  if otp:
    request.session['otp'] = otp
    messages.success(request, 'OTP resent successfully.')
    return redirect('otp_page')
  else:
    messages.error(request, 'Failed to send OTP. Please try again later.')
    return redirect('register')



def otp_page(request):
  if request.method=='POST':
    entered_otp=request.POST.get('otp')
    session_otp = request.session.get('otp')
    if entered_otp == session_otp:
      register_data=request.session.get('register_data')
      hash_password=register_data['password']
      user=Register_model.objects.create(
        full_name=register_data['full_name'],
        email_id=register_data['email_id'],
        phone_number=register_data['phone_number'],
        pin=register_data['pin'],
        password=hash_password,
        company_name = register_data['company_name'],
        company_short_name = register_data['company_short_name'],
        terms_and_conditions = register_data['terms_and_conditions'],
        otp=entered_otp
      )
      user.save()
      del request.session['register_data']
      del request.session['otp']
      subject='Registeration Successful'
      message=f'Thanks for registering with us. Your  Registration Number {user.crn}'
      email_from=settings.EMAIL_HOST_USER
      recipient_list=[user.email_id]
      send_mail(subject,message,email_from,recipient_list)
      messages.success(request, 'Registration Successful')
      return redirect('login')
    else:
      messages.error(request, 'Invalid OTP')
      return redirect('otp_page')
  else:

    return render(request, 'accounts/otp_page.html')  


# logout
@admin_required
def logout_page(request):
  del request.session['admin_user']
  return redirect('login')
  




# terms and condition create here
@admin_required
def create_terms_and_conditions(request):
    if request.method == "POST":
        # Check if any terms and conditions exist
        existing_terms = Terms_and_conditions.objects.first()
        
        # If terms exist, update them
        if existing_terms:
            existing_terms.delete()
        
        # Create new terms and conditions
        terms = request.POST.get('terms')
        Terms_and_conditions.objects.create(terms=terms)
        messages.success(request, 'Terms and conditions created successfully')
        return redirect('create_terms_and_conditions')

    return render(request, 'accounts/create_terms_and_conditions.html')


    
def terms_and_conditions(request):
  terms = Terms_and_conditions.objects.first()
  print(terms)
  context = {
    'terms':terms
  }
  return render(request,'accounts/terms_and_conditions.html',context)  



# forgot password function for the admin
# forgot password
def forgot_password(request):
 if request.method == "POST":
  email = request.POST.get('email_id')
  if Register_model.objects.filter(email_id=email).exists():
    user = Register_model.objects.get(email_id=email)
    message = f'Your password is {user.password}'
    send_mail('Forgot Password', message, settings.EMAIL_HOST_USER, [email])
    messages.success(request, 'Password sent to your email')
    return redirect('login')
  else:
    messages.error(request,'Email does not exists')
    return redirect('forgot_password')


 return render(request,'accounts/forgot_password.html')











# Dashboard page
@admin_required  
def dashboard(request):
    return render(request,'dashboard.html')

    
  


# Settings Page
@admin_required
def settings_page(request):
  return render(request,'settings_page/settings_page.html')

  
  




# Departments page
@admin_required
def departments(request):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        dep = register_user.departments.all().order_by("-id")

    else:
        dep = Department.objects.none() 

    if request.method == "POST":
        department_name = request.POST.get('department_name')
        if register_user.departments.filter(department_name=department_name.strip().title()).exists():
            messages.error(request, f'{department_name.strip().title()} already exists')
        else:
            Department.objects.create(
                crn_number=register_user,  
                department_name=department_name.strip().title(),
            )
            messages.success(request, f'{department_name.strip().title()} created successfully')
        return redirect('departments')

    short_form_list = []
    for department in dep:
        # Split department name by space and capitalize the first letter of each word
        department_words = [word[0].upper() for word in department.department_name.split()]
        # Join the capitalized first letters to form the short form
        short_form = ''.join(department_words)
        short_form_list.append(short_form)
        print(short_form)
    #  context = {
    #     "departments": zip(departments, short_form_list),
    # } 
    departments = register_user.departments.all().order_by("-id")   
    context = {
        "dep": zip(dep, short_form_list),
        "departments":departments

    }

    return render(request, 'settings_page/departments.html', context)








# department status
@admin_required
def department_status(request, id):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
            dep = register_user.departments.get(id=id)
        except Department.DoesNotExist:
            messages.error(request, 'Department not found')
            return redirect('departments')
    else:
        messages.error(request, 'Invalid User Session')
        return redirect('departments')

    if dep:
        if dep.status == "Active":
            dep.status = "Deactive"
        else:
            dep.status = "Active"
        dep.save()
        return redirect('departments')
    else:
        messages.error(request, 'Department not found')
        return redirect('departments')  







# department edit
@admin_required
def department_edit(request, id):
    if request.method == "POST":
      crn=request.session.get('admin_user').get('crn')
      register_user=Register_model.objects.get(crn=crn)

      department_name = request.POST.get('editdepartment')
      if register_user.departments.filter(id=id).exists():
        if register_user.departments.filter(department_name=department_name.strip().title()).exclude(id=id).exists():
          messages.error(request, f'{department_name.strip().title()} already exists')
          return redirect('departments')
        else:
          register_user.departments.filter(id=id).update(
          department_name = department_name.strip().title()
          )
          messages.success(request, f"{department_name.strip().title()} updated successfully")
          return redirect('departments')
      else:
        messages.error(request, 'Department not found')
        return redirect('departments')



# department delete
@admin_required
def department_delete(request, id):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
            dep = register_user.departments.get(id=id)
        except Department.DoesNotExist:
            messages.error(request, 'Department not found')
            return redirect('departments')
    else:
        messages.error(request, 'Invalid User Session')
        return redirect('departments')

    if request.method == "POST":
        department_name = dep.department_name.strip().title()
        dep.delete()
        messages.success(request, f'{department_name.strip().title()} deleted successfully')
        return redirect('departments')

    context = {
        'dep': dep,
    }
    return render(request, 'settings_page/department_delete.html', context)






@admin_required
def department_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_departments=request.POST.get('selected_departments')
    selected_list=selected_departments.split(",")
    register_user.departments.filter(id__in=selected_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('departments')

  else:
     return redirect('departments')







# department export
@admin_required
def department_export(request):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        dep = register_user.departments.all()
    else:
        messages.error(request, 'Invalid User Session')
        return redirect('departments')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="departments.csv"'
    writer = csv.writer(response)
    writer.writerow(['S.No', 'Department Name'])

    i = 0
    for d in dep:
        i += 1
        writer.writerow([i, d.department_name])

    return response




# department import
@admin_required
def dep_import(request):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
    else:
        messages.error(request, 'Invalid User Session')
        return redirect('departments')

    if request.method == 'POST':
        form = Department_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 2
                imported = False
                for row in reader:
                    
                    if len(row) != expected_headers:
                        messages.error(request, f'File should have {expected_headers} columns')
                        return redirect('departments')
                    dep_import = row[1]
                    if not dep_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", dep_import):
                        continue
                    
                    if register_user.departments.filter(department_name=dep_import.strip().title()).exists():
                        continue
                    else:
                        Department.objects.create(
                            crn_number=register_user,
                            department_name=dep_import.strip().title()
                        )
                        imported = True
                if imported:        
                    messages.success(request, 'File imported successfully')
                else:
                    messages.error(request, 'Failed to import the file')
                return redirect('departments')
            except Exception as e:
                messages.error(request, 'File Should be only in CSV Format')
                return redirect('departments')

    dep = register_user.departments.all().order_by("-id")
    context = {
        'dep': dep
    }
    return render(request, 'settings_page/departments.html', context)






# Designations page
@admin_required
def designations(request):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        designations = register_user.designations.all().order_by("-id")
        departments = register_user.departments.all().order_by("-id")
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    if request.method == "POST":
        designation = request.POST.get('designation_name')
        department_id = request.POST.get('department_name')
        
        
        department = Department.objects.get(pk=department_id)

        if register_user.designations.filter(department_name=department, designation_name=designation.strip().title()).exists():
            messages.error(request, f'{designation} already exists')
        else:
            Designation.objects.create(
                crn_number=register_user,
                department_name=department,
                designation_name=designation.strip().title(),
            )
            messages.success(request, f"{designation.strip().title()} created successfully")
        return redirect('designations')

    context ={
        'designations': designations,
        'departments': departments,
    }
    return render(request, 'settings_page/designations.html', context)




# Designation status
@admin_required
def designation_status(request, id):
    crn = request.session.get('admin_user').get('crn')
    
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        des = register_user.designations.filter(id=id).first()
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    if des:
        if des.status == "Active":
            des.status = "Deactive"
        else:
            des.status = "Active"
        des.save()
        return redirect('designations')
    else:
        messages.error(request, 'Designation not found')
        return redirect('designations')



# Designation edit
@admin_required
def designation_edit(request, id):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            department_name = request.POST.get('editdepartment')
            designation = request.POST.get('editdesignation')
            

            department_obj = register_user.departments.get(pk=department_name)
            designation_obj = register_user.designations.filter(id=id, crn_number=register_user).first()
            if designation_obj:
                if register_user.designations.exclude(id=id).filter(department_name=department_obj, designation_name=designation.strip().title(), crn_number=register_user).exists():
                    messages.error(request, f'{designation.strip().title()} already exists')
                    return redirect('designations')
                else:
                    designation_obj.department_name = department_obj
                    designation_obj.designation_name = designation.strip().title()
                    designation_obj.save()
                    messages.success(request, f"{designation.strip().title()} updated successfully")
                    return redirect('designations')
            else:
                messages.error(request, 'Designation not found')
                return redirect('designations')
        else:
            pass
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')





# Designation delete
@admin_required
def designation_delete(request, id):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            designation_obj = register_user.designations.get(id=id)
            if designation_obj:
                designation_name = designation_obj.designation_name
                designation_obj.delete()
                messages.success(request, f"{designation_name} deleted successfully")
                return redirect('designations')
            else:
                messages.error(request, 'Designation does not exist')
                return redirect('designations')
        else:
            
            pass
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')
         



@admin_required
def designation_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_designations=request.POST.get('selected_designations')
    print(selected_designations)
    selected_list=selected_designations.split(",")
    register_user.designations.filter(id__in=selected_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('designations')






# Designation export
@admin_required
def designation_export(request):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        designations = register_user.designations.all()
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="designation.csv"'
    writer = csv.writer(response)
    writer.writerow(['S.No', 'Department Name', 'Designation Name'])

    for i, designation in enumerate(designations, start=1):
        writer.writerow([i, designation.department_name.department_name, designation.designation_name])

    return response








@admin_required
def designation_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        form = Designation_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['des_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 3
                imported = False
                
                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'File Should Have {expected_headers} Columns')
                        return redirect('designations')
                    dep_import = row[1]
                    des_import = row[2]
                    des_instance = register_user.departments.filter(department_name=dep_import).first()
                    if not des_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", des_import):
                        continue
                    des_import.strip().title()
                    if register_user.designations.filter(department_name=des_instance, designation_name=des_import.strip().title()).exists():
                        continue
                    else:
                        Designation.objects.create(
                            department_name=des_instance,
                            designation_name=des_import.strip().title(),
                            crn_number=register_user
                        )
                        imported = True
                if imported:        
                    messages.success(request, 'File imported successfully')
                else:
                    messages.error(request,'Designation Already Exists')    
                return redirect('designations')
            except Exception as e:
                messages.error(request, 'File Should be only in CSV Format')
                return redirect('designations')

    des = register_user.designations.all().order_by("-id")
    dep = register_user.departments.all().order_by("-id")
    context = {
        'des': des,
        'dep': dep,
    }
    return render(request, 'settings_page/designations.html', context)





# Branches Page
@admin_required
def branches(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    branch = register_user.branches.all().order_by('-id')
    for branchs in branch:
        branchs.generate_qr_code()  

    if request.method == 'POST':
        
        branch_name = request.POST.get('branch_name')
        if register_user.branches.filter(branch_name=branch_name.strip().title()).exists():
            messages.error(request, f'{branch_name.strip().title()} branch already exists')
        else:
            new_branch = register_user.branches.create(branch_name=branch_name.strip().title())
            new_branch.generate_qr_code()  
            messages.success(request, f"{branch_name.strip().title()} branch created successfully")
        return redirect('branches')

    context = {
        'branch': branch,
    }
    return render(request, 'settings_page/branches.html', context)


def inquery_form(request, id, crn):
    try:
      register_user = Register_model.objects.get(crn=crn)
    except Exception as e:
      return redirect('branch_error')
    if not register_user:
       return redirect('branch_error')
    course = register_user.course_manage.filter(branch_id=id).all()
    specialization = register_user.specializations.filter(status="Active").all()
    training_types = register_user.training_types.filter(status="Active").all()
    prospect_types = register_user.prospect_types.filter(status="Active").all()
    print("this is course",course)

    branch = register_user.branches.get(id=id)
    if branch.status == "Deactive":
        return redirect('branch_error')
    if not branch:
        return redirect('branch_error')

    context = {
        'courses': course,
        'specializations': specialization,
        'branch': branch,
        'training_types': training_types,
        'prospect_types': prospect_types,
        'crn': crn,
        'id': id
    }
    return render(request, 'branch_qr/create_lead.html', context)

def branch_error(request):
    return render(request, 'branch_qr/branch_error.html')

def create_lead(request):
    id = None  
    crn = None 

    if request.method == "POST":
        # Handle POST request
        try:
            # Retrieve form data
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            mobile_number = request.POST.get('mobile_number')
            email = request.POST.get('email')
            course_name = request.POST.get('course_name')
            branch_name = request.POST.get('branch_id')
            training_type = request.POST.get('training_type')
            lead_sourse = request.POST.get('lead_type')
            crn = request.POST.get('crn')
            id = request.POST.get('id')
            print("first_name", first_name)
            print("last_name", last_name)
            print("mobile_number", mobile_number)
            print("email", email)
            print("course_name", course_name)
            print("branch_name", branch_name)
            print("training_type", training_type)
            print("lead_type", lead_sourse)
            print("crn", crn)
            print("id", id)
            register_user = Register_model.objects.get(crn=crn)
            print(register_user)

            
            print("registeruser")
            

            if not register_user.branches.filter(id=id).exists():
                  messages.error(request, 'Branch not found')
                  return redirect('branch_error')
            print("branch")
            if branch_name:
               branch_stauts = register_user.branches.filter(id=id)

               if branch_stauts.first().status == "Deactive":
                  messages.error(request, 'Branch not found')
                  return redirect('branch_error')
            print("filter branch")  

            if register_user.leads.filter((Q(mobile_number=mobile_number) | Q(email=email)) & Q(branch_name=branch_name)).exists():
                messages.error(request, 'Lead with the same mobile number or email already exists in this branch')
                return redirect(reverse('inquiry_form', kwargs={'id': id, 'crn': crn}))
            print("filter all")    
            if register_user.leads.filter(mobile_number=mobile_number).exists():
                messages.error(request, 'Lead with the same mobile number already exists')
                return redirect(reverse('inquiry_form', kwargs={'id': id, 'crn': crn}))
            print("filter mobile")    
            if register_user.leads.filter(email=email).exists():
                messages.error(request, 'Lead with the same email already exists')
                return redirect(reverse('inquiry_form', kwargs={'id': id, 'crn': crn}))
            print("filter email")

            
            otp = send_otp_to_phone(mobile_number)
            print(otp)
            if otp:
                request.session['otp'] = otp
                request.session['lead_data'] = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'mobile_number': mobile_number,
                    'email': email,
                    'course_name': course_name,
                    'branch_name': branch_name,
                    'training_type': training_type,
                    'lead_sourse': lead_sourse,
                    'crn': crn
                }
                print(request.session['lead_data'])

                return redirect('opt_page')
            else:
                messages.error(request, 'Failed to send OTP')
        except Register_model.DoesNotExist:
            messages.error(request, 'User with provided CRN does not exist')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')

    # Handle GET request
    
    if id is None or crn is None:
        return redirect('branch_error')

    else:
        return redirect(reverse('inquiry_form', kwargs={'id': id, 'crn': crn}))



def opt_page(request):
   return render(request,'branch_qr/verify_otp.html')




def verify_otp(request):
    crn = request.session.get('lead_data').get('crn')
    branch_name_id = request.session.get('lead_data').get('branch_name')
    if request.method == "POST":
        try:
            otp_entered = request.POST.get('otp')
            otp_generated = request.session.get('otp')

            lead_data = request.session.get('lead_data')
            register_user = Register_model.objects.get(crn=lead_data.get('crn'))

            if otp_entered == otp_generated:
              
                
                    lead = LeadModel.objects.create(
                        first_name=lead_data.get('first_name'),
                        last_name=lead_data.get('last_name'),
                        mobile_number=lead_data.get('mobile_number'),
                        email=lead_data.get('email'),
                        course_name=register_user.course_manage.get(pk=lead_data.get('course_name')),
                        branch_name=register_user.branches.get(pk=lead_data.get('branch_name')),
                        training_type=register_user.training_types.get(pk=lead_data.get('training_type')),
                        lead_sourse=register_user.prospect_types.get(pk=lead_data.get('lead_sourse')),
                        crn_number=register_user
                    )
                    lead.generate_token()
                    subject = 'Registration Successful'
                    message = (
                    f"Hello {lead_data.get('first_name')},\n\n"
                    "Thank you for registering with us. We are excited to have you join our community. "
                    "Here are your registration details:\n\n"
                    f"Registration Number: {lead.token_id}\n"
                    f"Course Enrolled: {lead.course_name.course_name}.\n"
                    "\nWe look forward to providing you with a quality learning experience. "
                    "Should you have any questions or need further information, please do not hesitate to contact us.\n\n"
                    "Best Regards,\n"
                    
                    "Contact Information"
                    )
                    email_from = settings.EMAIL_HOST_USER
                    recipient_list = [lead_data.get('email')]
                    send_mail(subject, message, email_from, recipient_list)                    

                    del request.session['otp']
                    del request.session['lead_data']



                    return redirect(reverse('receipt', kwargs={'token_num': lead.token_id, 'crn_number': crn}))
            else:
                context = {'error': 'Invalid OTP'}
                return render(request, 'branch_qr/verify_otp.html', context)
        except ObjectDoesNotExist:
            messages.error(request, 'User with provided CRN does not exist')
            return redirect('create_lead')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
            return redirect('create_lead')
    context={
       'crn':crn,
       'branch_name_id':branch_name_id
    }  
    return render(request, 'branch_qr/verify_otp.html',context)





def resend_otp(request):
    lead_data = request.session.get('lead_data')
    if lead_data:
        mobile_number = lead_data.get('mobile_number')
        otp = send_otp_to_phone(mobile_number)
        if otp:
            request.session['otp'] = otp
            messages.success(request, 'OTP resent successfully.')
        else:
            messages.error(request, 'Failed to resend OTP.')
    else:
        messages.error(request, 'No lead data found in the session.')

    return redirect('verify_otp')

def receipt(request,token_num,crn_number):
    # Retrieve lead data from query parameters
    token = request.GET.get('token')
    first_name = request.GET.get('first_name')
    last_name = request.GET.get('last_name')
    mobile_number = request.GET.get('mobile_number')
    email = request.GET.get('email')
    course_name = request.GET.get('course_name')
    branch_name = request.GET.get('branch_name')
    training_type = request.GET.get('training_type')
    lead_type = request.GET.get('lead_type')
    register_user = Register_model.objects.get(crn=crn_number)
    lead_data = register_user.leads.filter(token_id=token_num).first()
    context = {
        'lead_data': lead_data,
    }
        

    return render(request, 'branch_qr/receipt.html', context)

def receipt_pdf(request, token_id):
    recipt = LeadModel.objects.filter(token_id=token_id).first()
    print("recipt", recipt)
    html_template = render_to_string('branch_qr/receipt_pdf.html', {'recipt': recipt})
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="receipt.pdf"'
    pisa_status = pisa.CreatePDF(html_template, dest=response)

    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html_template + '</pre>')

    return response





# branch status
@admin_required
def branches_status(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
            branch = register_user.branches.get(id=id)
            if branch:
                if branch.status == "Active":
                    branch.status = "Deactive"
                else:
                    branch.status = "Active"
                branch.save()
        except BranchModel.DoesNotExist:
            messages.error(request, 'Branch not found')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    return redirect('branches')




# Delete branch
@admin_required
def branch_delete(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
            branch = register_user.branches.get(id=id)
            branch_name = branch.branch_name
            branch.delete()
            messages.success(request, f"{branch_name.strip().title()} Deleted Successfully")
        except BranchModel.DoesNotExist:
            messages.error(request, 'Branch Not Found')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    return redirect('branches')



def branches_del_all(request):
    crn = request.session.get('admin_user', {}).get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
        selected_branches = request.POST.get('selected_branches')
        selected_list = selected_branches.split(",")
       
        
        
        register_user.branches.filter(id__in=selected_list).delete()
        messages.success(request, 'Records deleted successfully')
        
        

    return redirect('branches')





# Update branch
@admin_required
def branch_update(request, id):
    if request.method == "POST":
        crn = request.session.get('admin_user', {}).get('crn')
        if crn:
            register_user = Register_model.objects.get(crn=crn)
            branch_name_edit = request.POST.get('branch_name_edit')
            try:
                branch = register_user.branches.get(id=id)
                if register_user.branches.filter(branch_name=branch_name_edit.strip().title()).exclude(id=id).exists():
                    messages.error(request, f'{branch_name_edit.strip().title()} Already Exists')
                else:
                    branch.branch_name = branch_name_edit.strip().title()
                    branch.save()
                    messages.success(request, f'{branch_name_edit} Updated Successfully')
            except BranchModel.DoesNotExist:
                messages.error(request, 'Branch not found')
        else:
            messages.error(request, 'CRN not found in session.')
            return redirect('login')

    return redirect('branches')




@admin_required
def branch_export(request):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        branches = register_user.branches.all().order_by('-id')

        if branches.exists():
         
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="branch.csv"'
            writer = csv.writer(response)
            writer.writerow(['S.No', 'Branch Name'])
            for i, branch in enumerate(branches, start=1):
                writer.writerow([i, branch.branch_name])
            return response
        else:
            messages.warning(request, "No data exists for the related CRN number.")
            return redirect('branches')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')






# Branch import
@admin_required
def branch_import(request):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            form = BranchForm(request.POST, request.FILES)
            if form.is_valid():
                try:
                    csv_file = request.FILES['branch_file']
                    decoded_file = csv_file.read().decode('utf-8')
                    reader = csv.reader(decoded_file.splitlines())
                    headers = next(reader)
                    expected_headers = 2
                    imported = False
                    for row in reader:
                        if len(row) != expected_headers:
                            messages.error(request, f'File do not match the columns')
                            return redirect('branches')
                        branch_import = row[1]

                        if not branch_import:
                            continue
                        if not re.match(r"^[a-zA-Z\s]{3,50}$", branch_import):
                           continue
                        if register_user.branches.filter(branch_name=branch_import.strip().title()).exists():
                            continue
                        else:
                            BranchModel.objects.create(
                                branch_name=branch_import.strip().title(),
                                crn_number=register_user
                            )
                            imported = True
                    if imported:        
                      messages.success(request, f'File imported successfully')
                    else:
                       messages.error(request,'Branch Already Exists')
                    return redirect('branches')
                    
                except Exception as e:
                    messages.error(request, f'File format not valid')
                    return redirect('branches')

        branches = register_user.branches.all().order_by('-id')
        context = {'branch': branches}
        return render(request, 'settings_page/branches.html', context)
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')




# batch types
@admin_required
def batch_types(request):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            batchtype = request.POST.get('batchtype_name')
            if register_user.batch_type.filter(batchtype_name=batchtype.strip().title()).exists():
                messages.error(request, f'{batchtype.strip().title()} Already Exists')
            else:
                Batchtype.objects.create(
                    batchtype_name=batchtype.strip().title(),
                    crn_number=register_user
                )
                messages.success(request, f'{batchtype.strip().title()} Created Successfully')
            return redirect('batch_type')

        batch = register_user.batch_type.all().order_by("-id")
        context = {
            'batch': batch,
        }
        return render(request, 'settings_page/batch_type.html', context)
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')



# batch status
@admin_required
def batch_status(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
            batch = register_user.batch_type.get(id=id)
            if batch:
                batch.status = "Deactive" if batch.status == "Active" else "Active"
                batch.save()

            else:
                messages.error(request, f'Batch Type Not Found')
        except Batchtype.DoesNotExist:
            messages.error(request, f'Batch Type Not Found')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    return redirect('batch_type')


# Batch edit view
@admin_required
def batch_edit(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            batch_name = request.POST.get('editbatchname')
            try:
                batch = register_user.batch_type.get(id=id)
                if batch:
                    if register_user.batch_type.filter(batchtype_name=batch_name.strip().title()).exclude(id=batch.id).exists():
                        messages.error(request, f'{batch_name.strip().title()} Already Exists')
                        return redirect('batch_type')
                    else:
                        batch.batchtype_name = batch_name.strip().title()
                        batch.save()
                        messages.success(request, f'{batch_name.strip().title()} Updated Successfully')
                else:
                    messages.error(request, f'Batch Type Not Found')
            except Batchtype.DoesNotExist:
                messages.error(request, f'Batch Type Not Found')
        else:
            messages.error(request, 'CRN not found in session.')
            return redirect('login')
    return redirect('batch_type')



@admin_required
def batch_delete(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
            batch = register_user.batch_type.get(id=id)
            if batch:
                batch_name = batch.batchtype_name
                batch.delete()
                messages.success(request, f'{batch_name} Deleted Successfully')
            else:
                messages.error(request, f'Batch Type Not Found')
        except Batchtype.DoesNotExist:
            messages.error(request, f'Batch Type Not Found')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

    return redirect('batch_type')



@admin_required
def batch_all(request):
    crn = request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == 'POST':
      selected_ids=request.POST.get('selected_ids')
      selected_ids_list=selected_ids.split(',')
      register_user.batch_type.filter(id__in=selected_ids_list).delete()
      messages.success(request, 'Records deleted successfully')
      return redirect('batch_type')






# Batch export view
@admin_required
def batch_export(request):
    try:
        crn = request.session.get('admin_user', {}).get('crn')
        register_user=Register_model.objects.get(crn=crn)
        batchtypes = register_user.batch_type.all().order_by('-id')
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="List_of_batchtype.csv"'
        writer = csv.writer(response)
        writer.writerow(['S.no', 'Batch Name'])
        for i, batchtype in enumerate(batchtypes, start=1):
            writer.writerow([i, batchtype.batchtype_name])
        return response
    except Exception as e:
        messages.error(request, f'Error occurred while exporting batch types: {str(e)}')
        return redirect('batch_type')




# batch import
@admin_required
def batch_import(request):
    if request.method == 'POST':
        form = Batchtype_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                crn = request.session.get('admin_user').get('crn')
                csv_file = request.FILES['batch_file']
                register_user=Register_model.objects.get(crn=crn)
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 2
                imported = False
                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'File should have {expected_headers} columns')
                        return redirect('batch_type')
                    batch_import = row[1]
                    
                    if not batch_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", batch_import):
                      continue
                    if Batchtype.objects.filter(batchtype_name=batch_import.strip().title(), crn_number=register_user).exists():
                        continue
                    else:
                        Batchtype.objects.create(
                            batchtype_name=batch_import.strip().title(),
                            crn_number=register_user
                        )
                        imported = True
                if imported:        
                  messages.success(request, 'File imported successfully')
                else:
                  messages.error(request,'Batch Type Already Exists')  
                return redirect('batch_type')
            except Exception as e:
                messages.error(request, 'File should be only in CSV Format')
                return redirect('batch_type')

    batch = Batchtype.objects.filter(crn_number=request.session.get('admin_user').get('crn'))
    context = {
        'batch': batch
    }
    return render(request, 'settings_page/batch_type.html', context)

  




# training type
def training_type(request):
    crn = request.session.get('admin_user', {}).get('crn')
    
    if crn:
        try:
            register_user = Register_model.objects.get(crn=crn)
            training_types = TrainingType.objects.filter(crn_number=register_user).order_by('-id')
        except Register_model.DoesNotExist:
            messages.error(request, 'CRN not found in database.')
            return redirect('login')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')
    
    if request.method == "POST":
        training_type_name = request.POST.get('training_type_name')
        if register_user.training_types.filter(TrainingTypeName=training_type_name.strip().title()).exists():
            messages.error(request, f"{training_type_name.strip().title()} already exists")
        else:
            TrainingType.objects.create(
                TrainingTypeName=training_type_name.strip().title(),
                crn_number=register_user
            )
            messages.success(request, f"{training_type_name.strip().title()} added successfully")
        return redirect('training_type')
        
    return render(request, 'settings_page/training_types.html', {'training_type': training_types})




# update training type
@admin_required
def training_type_update(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            training_type = request.POST.get('edit_training_type_name')
            if TrainingType.objects.filter(id=id, crn_number=register_user).exists():
                if TrainingType.objects.exclude(id=id).filter(TrainingTypeName=training_type.strip().title(), crn_number=register_user).exists():
                    messages.error(request, f'{training_type.strip().title()} training type name already exists')
                    return redirect('training_type')
                else:
                    TrainingType.objects.filter(id=id, crn_number=register_user).update(
                        TrainingTypeName=training_type.strip().title()
                    )
                    messages.success(request, f'{training_type.strip().title()} traiing type name updated successfully')
                    return redirect('training_type')
            else:
                messages.error(request, 'Training Type Does Not Exist')
                return redirect('training_type')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')

  



# training type status change
@admin_required
def training_type_status(request, id):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        try:
            training = TrainingType.objects.get(id=id, crn_number__crn=crn)
        except TrainingType.DoesNotExist:
            messages.error(request, 'Training type does not exist')
            return redirect('training_type')
        
        if training.status == "Active":
            training.status = "Deactive"
        else:
            training.status = "Active"

        training.save()

        return redirect('training_type')
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('login')





# training type delete 
@admin_required
def training_type_delete(request, id):
    try:
        training = TrainingType.objects.get(id=id)
    except TrainingType.DoesNotExist:
        messages.error(request, 'type does not exist')
        return redirect('training_type')

    training.delete()
    messages.success(request, f'{training.TrainingTypeName} training type name deleted successfully')
    return redirect('training_type')






@admin_required
def training_type_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.training_types.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('training_type')







# training type export
@admin_required
def training_type_export(request):
    crn=request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        training_types=register_user.training_types.all()
    else:
        messages.error(request, 'CRN not found in session.')
        return redirect('training_type')
    response = HttpResponse(content_type='csv')
    response['Content-Disposition'] = 'attachment; filename="training_types.csv"'
    writer = csv.writer(response)
    writer.writerow(['S.No','Training Type Name'])
    i = 0
    for training in training_types:
        i += 1
        writer.writerow([i,training.TrainingTypeName])

    return response  
    
        







@admin_required
def training_type_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == 'POST':
        form = Traning_type_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['training_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                next(reader)  # Skip the header row

                for row in reader:
                    if len(row) != 2:
                        messages.error(request, 'File should have 2 columns: S.No and Training Type Name')
                        return redirect('training_type')

                    training_import = row[1]
                    imported = False
                    if not training_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", training_import):
                        continue

                    if register_user.training_types.filter(TrainingTypeName=training_import.strip().title()).exists():
                        continue
                    else:
                        TrainingType.objects.create(TrainingTypeName=training_import.strip().title(), crn_number=register_user)
                        imported = True
                if imported:
                   messages.success(request, 'File imported successfully')
                else:
                   messages.error(request,'Training Type Already Exists')   
                return redirect('training_type')
                           


            except Exception as e:
                print(e)
                messages.error(request, 'An error occurred while processing the file')
    else:
        messages.error(request, 'Invalid request method')

    return redirect('training_type')





   

#  Regulations
@admin_required
def regulations(request):
    # getting the regulations data
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    regulations = register_user.regulations.all().order_by('-id')
    courses = register_user.courses.all().filter(status="Active")
    specializations = register_user.specializations.all().filter(status="Active")
    regulation_specialization_ids = {
        regulation.id: regulation.spec_id.id for regulation in regulations
    }

    if request.method == "POST":
        course_name = request.POST.get('course_id')
        specialization_name = request.POST.get('specialization_id')
        batch_num = request.POST.get('batch_number')
        if register_user.regulations.filter(course_id=course_name, spec_id=specialization_name, batch_number=batch_num.strip().title()).exists():
            messages.error(request, f'A Regulation Already Exists For The Selected Course, Specialization, And Batch Number')    
            return redirect('regulations')
        else:
            Regulations.objects.create(
                course_id=register_user.courses.get(pk=course_name),
                spec_id=register_user.specializations.get(
                    pk=specialization_name),
                batch_number=batch_num.strip().title(),
                crn_number=register_user
            )
            messages.success(request, f'Regulation Created Successfully For {batch_num.strip().title()} Batch')
            return redirect('regulations')


    context = {
        'regulations': regulations,
        'courses': courses,
        'specializations': specializations,
        'regulation_specialization_ids': regulation_specialization_ids
    }
    return render(request, 'settings_page/regulations.html', context)




# regulation status
@admin_required
def regulations_status(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    
    

    try:
        regulation = register_user.regulations.get(id=id)
    except TrainingType.DoesNotExist:
        messages.error(request, 'Regulations does not exist')
        return redirect('regulations')

    if regulation.status == "Active":
        regulation.status = "Deactive"
    else:
        regulation.status = "Active"

    regulation.save()
    
    return redirect('regulations')


    

# regulation update
@admin_required
def regulation_update(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
        edit_course_name=register_user.courses.get(pk=request.POST.get('edit_course_name'))
        edit_specialization_name=register_user.specializations.get(pk=request.POST.get('edit_specialization_name'))
        edit_batch_num=request.POST.get('edit_batch_num')
        if register_user.regulations.filter(course_id=edit_course_name, spec_id=edit_specialization_name,  batch_number=edit_batch_num.strip().title()).exclude(id=id).exists():
            messages.error(request, f'A Regulation Already Exists For The Selected Course, Specialization, And Batch Number')
            return redirect('regulations')
        else:
            register_user.regulations.filter(id=id).update(
                course_id=edit_course_name,
                spec_id=edit_specialization_name,
                batch_number=edit_batch_num.strip().title()
                )
            messages.success(request, f'Regulation Updated Successfully For {edit_batch_num.strip().title()} Batch')
            return redirect('regulations')




# regulation delete
@admin_required
def regulation_delete(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    regulation=register_user.regulations.get(id=id)
    if not register_user.regulations.filter(id=id).exists():
        messages.error(request, 'Regulation does not exist')
        return redirect('regulations')
    else:
      register_user.regulations.filter(id=id).delete()
      messages.success(request, f'Regulation Deleted Successfully For {regulation.batch_number} Batch')
      return redirect('regulations')


@admin_required
def regulations_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_regulation = request.POST.get('selected_ids')
    selected_regulation_list = selected_regulation.split(',')
    register_user.regulations.filter(id__in=selected_regulation_list).delete()
    messages.success(request, 'Regulations deleted successfully')
    return redirect('regulations')








# regulation export
@admin_required
def regulation_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    regulations = register_user.regulations.all().order_by('-id')
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="regulations.csv"'
    writer = csv.writer(response)
    writer.writerow(['S.No','COURSE NAME', 'SPECIALIZATION NAME', 'BATCH NUMBER'
                      ])
    i=0
    for regu in regulations:
        i+=1
        writer.writerow([i,regu.course_id.course_name, regu.spec_id.specilalization_name, 
                        regu.batch_number])
    return response



# regulation import
@admin_required
def regulation_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == "POST":
        form = RegulationForm(request.POST, request.FILES)
        print("regulation form",form)
        if form.is_valid():
            print("regulation form valid")
            try:
                csv_file = request.FILES.get('regulation_file')
                if not csv_file:
                    messages.error(request, 'No CSV file uploaded.')
                    return redirect('regulations')
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                expected_headers = 4
                header = next(reader)
                if len(header) != expected_headers:
                    messages.error(request, 'Invalid CSV file format. Expected columns: S.No, COURSE NAME, SPECIALIZATION NAME, BATCH NUMBER')
                    return redirect('regulations')

                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'Each row should have {expected_headers} columns.')
                        return redirect('regulations')
                    
                    course_name = row[1]
                    specialization_name = row[2]
                    batch_number = row[3]

                    try:
                        course_id = register_user.courses.get(course_name=course_name)
                        specialization_id = register_user.specializations.get(specilalization_name=specialization_name)
                    except (Register_model.DoesNotExist, Register_model.MultipleObjectsReturned) as e:
                        messages.error(request, f'Invalid course or specialization: {course_name}, {specialization_name}')
                        return redirect('regulations')

                    if not batch_number or not re.match(r"^[a-zA-Z0-9\s]{3,50}$", batch_number):
                        continue

                    if register_user.regulations.filter(batch_number=batch_number, course_id=course_id, spec_id=specialization_id).exists():
                        continue
                    else:
                        Regulations.objects.create(batch_number=batch_number, course_id=course_id, spec_id=specialization_id, crn_number=register_user)

                messages.success(request, 'CSV File imported successfully.')
                return redirect("regulations")

            except Exception as e:
                messages.error(request, f'{e} Error processing CSV file.')
                return redirect('regulations')

    else:
        messages.error(request, 'Invalid Request')
        return redirect('regulations')

    return redirect('regulations')







    

@admin_required
def get_regulations(request, course_id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    course = register_user.courses.get(pk=course_id)
    specializations = register_user.specializations.filter(course_name=course, status='Active')
    regulation_data = [
        {
            'id': specialization.id,
            'specilalization_name': specialization.specilalization_name
        }
        for specialization in specializations
    ]
    return JsonResponse({'specialization_data': regulation_data})
   



# regulation dropdown dependency
@admin_required
def get_specializations(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    course_id = request.GET.get('course_id')
    specializations = register_user.specializations.filter(course_name_id=course_id).values('id', 'specilalization_name')
    return JsonResponse({'specializations': list(specializations)})


@admin_required
def get_specializations_for_regulation(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    course_id = request.GET.get('course_id')
    regulation_id = request.GET.get('regulation_id')
    regulation = register_user.regulations.get(id=regulation_id)
    specializations = register_user.specializations.objects.filter(course_name_id=course_id).exclude(id=regulation.spec_id.id).values('id', 'specilalization_name')
    return JsonResponse({'specializations': list(specializations)})



# upi payments
@admin_required
def upi_payments(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  upi = register_user.upi.all()
  if request.method == "POST":
    upipayments_name= request.POST.get('upipayments_name')
    Mobilenumber=request.POST.get('mobilenumber')
    Upiid=request.POST.get('upiid')
    up_qr_code_img = request.FILES.get('up_qr_code_img')
    print("qr code",up_qr_code_img)
    if register_user.upi.filter(upiid=Upiid).exists():
      messages.error(request, f'{Upiid} Already Exists')
      return redirect('upi_payments')
    else:
      upipayments.objects.create(
        upipayments_name = upipayments_name  ,
        mobilenumber=Mobilenumber,
        upiid=Upiid,
        crn_number=register_user,
        upi_qr_code = up_qr_code_img
      )
      messages.success(request, f'{Upiid} Added Successfully')
      return redirect('upi_payments')
    
  context ={
    'upi':upi,
  }
  return render(request,'settings_page/upi_payments.html',context)




# upi status
@admin_required
def upi_status(request,id):
    crn=number=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    upi=register_user.upi.get(id=id)
    if upi:
      if upi.status== "Active":
         upi.status= "Deactive"
      else:
          upi.status = "Active"
      upi.save()
      return redirect('upi_payments')
    else:
        messages.error(request, f'upi not found')
        return redirect('upi_payments')
    
    



    
# upi edit
@admin_required
def upi_edit(request,id):
    if request.method == "POST":
        upi= request.POST.get('upitype')
        Mobilenumber= request.POST.get('mobilenumber')
        Upiid=request.POST.get('upiid')
        crn=request.session.get('admin_user').get('crn')
        register_user=Register_model.objects.get(crn=crn)
        up_qr_code_img_edit = request.FILES.get('up_qr_code_img_edit')
        
        if register_user.upi.filter(upiid=Upiid).exclude(id=id).exists():
            messages.error(request, f'{Upiid} is already exists')
            return redirect('upi_payments')

        else:
            register_user.upi.filter(id=id).update(
                upipayments_name= upi,
                mobilenumber=Mobilenumber,
                upiid=Upiid ,
                upi_qr_code = up_qr_code_img_edit
            )


            messages.success(request, f'{Upiid} Updated Successfully')

    return redirect('upi_payments')
        







# upi delete
@admin_required
def upi_delete(request,id):
   if request.method == "POST":
      crn=request.session.get('admin_user').get('crn')
      register_user=Register_model.objects.get(crn=crn)
      upi=register_user.upi.get(id=id)
      if register_user.upi.filter(id=id).exists():
          upi.delete()
          messages.success(request, f'{upi.upiid} Deleted Successfully')
          return redirect('upi_payments')
      else:
          messages.error(request, f'upi not found')
          return redirect('upi_payments')   



@admin_required
def upi_payment_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  selected_ids=request.POST.get('selected_ids')
  selected_ids_list=selected_ids.split(',')
  register_user.upi.filter(id__in=selected_ids_list).delete()
  messages.success(request, 'Records deleted successfully')
  return redirect('upi_payments')







# upi export
@admin_required
def upi_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  upis=register_user.upi.all()
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.No','upitype', 'Mobilenumber','UPIid'])
  i = 0
  for upi in upis:
      i += 1
      writer.writerow([i,upi.upipayments_name, upi.mobilenumber,upi.upiid])

  response['Content-Disposition'] = 'attachment; filename="List_of_upipayments.csv"'
  return response



@admin_required
def upi_import(request):
  if request.method=='POST':
    form=Upipayments_import_form(request.POST,request.FILES)
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)

    if form.is_valid():
      try:
        csv_file=request.FILES['upi_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 4
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('upi_payments')
          Upitype=row[1]
          Mobilenumber=row[2]
          Upiid=row[3]  
          if not re.match(r"^[a-zA-Z\s]{3,50}$", Upitype):
             continue
          if not re.match(r"^[0-9]{10,11}$", Mobilenumber):
             continue
          # if not re.match(r"^[a-zA-Z0-9]{10,50}$", Upiid):
          #    continue
                  
          if not Upiid or not  Upitype or not Mobilenumber :
             continue
          if register_user.upi.filter(upiid=Upiid).exists():
           continue
          
          else:
            register_user.upi.create(
                upipayments_name=Upitype,mobilenumber=Mobilenumber,upiid=Upiid,crn_number=register_user)
            imported = True
        if imported:
          messages.success(request, f'File imported successfully')      
        else:
          messages.error(request,'File failed to importe')  

        return redirect('upi_payments')
      except Exception as e:
        messages.error(request, f'File Should be only in CSV Format ')
        return redirect('upi_payments')
           
  upi=register_user.upi.all()
  context={
      'upi':upi
  }
  return render(request, 'settings_page/upi_payments.html', context)




# sub category
@admin_required
def sub_category(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)

  if request.method == 'POST':
    sub_category = request.POST.get('sub_category')
    if register_user.sub_category.filter(sub_cat_title=sub_category.strip().title()).exists():
      messages.error(request, f'{sub_category.strip().title()} sub category already exists.')
      return redirect('sub_category')
    else:
      register_user.sub_category.create(
        sub_cat_title=sub_category.strip().title(),
        crn_number = register_user
      )
      messages.success(request, f'{sub_category.strip().title()} sub category created successfully.')
      return redirect('sub_category')
  sub_categories = register_user.sub_category.all()
  context = {
    'sub_categories':sub_categories
  }  

     
  return render(request,'settings_page/sub_category.html',context)



# sub category edit
def sub_category_edit(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
     
    sub_category = request.POST.get('edit_sub_category')
    if register_user.sub_category.filter(id=id).exists():
      register_user.sub_category.filter(id=id).update(
        sub_cat_title=sub_category.strip().title(),
      )
      messages.success(request, f"{sub_category.strip().title()} updated successfully.")
      return redirect('sub_category')
    else:
      messages.error(request, f"Sub category not found")
      return redirect('sub_category')
  else:
     messages.error(request, "Invalid request method")
     return redirect('sub_category')    

     
     


def sub_category_delete(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    if register_user.sub_category.filter(id=id).exists():
      register_user.sub_category.filter(id=id).delete()
      messages.success(request,'Sub category deleted successfully')
      return redirect('sub_category')
    else:
      messages.error(request,'Sub category not found')
      return redirect('sub_category')
  else:
    messages.success(request,'Invalid request method')
    return redirect('sub_category')      


# sub category status
def sub_category_status(request,id):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   
   if register_user.sub_category.filter(id=id).exists():
      sub_category = register_user.sub_category.get(id=id)
      
      if sub_category.sub_cat_status:
         register_user.sub_category.filter(id=id).update(
            sub_cat_status = False
         )
         return redirect('sub_category')
      else:
         register_user.sub_category.filter(id=id).update(
            sub_cat_status = True
         )   
         return redirect('sub_category')
   else:
      messages.error(request,'Sub category not found')
      return redirect('sub_category')
           









# course page
@admin_required
def courses(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)

  cos =register_user.courses.all().order_by("-id")
  sub_categories = register_user.sub_category.filter(sub_cat_status=True).order_by("-id")

  if request.method=="POST":
    course = request.POST.get('course_name')
    sub_category = request.POST.get('sub_category_name')
    if register_user.courses.filter(course_name=course.strip().title(),sub_category=sub_category).exists():
      messages.error(request, f'{course.strip().title()} course already exists for {register_user.sub_category.get(id=sub_category).sub_cat_title} sub category.')
      return redirect('courses')
    else:
      register_user.courses.create(
        course_name= course.strip().title(),
        sub_category = register_user.sub_category.get(pk=sub_category),
      )
      messages.success(request, f'{course.strip().title()} course created Successfully.')
      return redirect('courses')
  context={
    'cos':cos,
    'sub_categories':sub_categories
  }
  return render(request,'settings_page/course.html',context)




# course status
@admin_required
def course_status(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    cos = register_user.courses.get(id=id)
    if cos:
        if cos.status == "Active":
            cos.status = "Deactive"
        else:
            cos.status = "Active"
        cos.save()
        return redirect('courses')
    else:
        messages.error(request, 'Course not found')
        return redirect('courses')




# course update
@admin_required
def course_edit(request,id):
    if request.method == "POST":
      crn=request.session.get('admin_user').get('crn')
      register_user=Register_model.objects.get(crn=crn)

      course = request.POST.get('editcourse')
      sub_category_edit = request.POST.get('sub_category_edit')
      if register_user.courses.filter(id=id).exists():
        if register_user.courses.filter(course_name=course.strip().title(),sub_category=sub_category_edit).exclude(id=id).exists():
          messages.error(request, f'{course.strip().title()} course already exists for {register_user.sub_category.get(id=sub_category_edit).sub_cat_title} sub category.')
          return redirect('courses')
        else:
            register_user.courses.filter(id=id).update(
                course_name=course.strip().title(),
                sub_category = register_user.sub_category.get(pk=sub_category_edit),

            )
            messages.success(request, f'{course.strip().title()} course updated successfully for {register_user.sub_category.get(id=sub_category_edit).sub_cat_title} sub category.')
            return redirect('courses')
      else:
        messages.error(request, f'Course does not exist.')
        return redirect('courses')        
           





# course delete
@admin_required
def course_delete(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == "POST":
      
      if register_user.courses.filter(id=id).exists():
        course = register_user.courses.get(id=id)
        course.delete()
        messages.success(request,f'{course.course_name} course deleted successfully')
        return redirect('courses')
      else:
         messages.error(request,'Course does not exists')
         return redirect('courses')
    else:
        return redirect('courses')
           




@admin_required
def course_all(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == "POST":
        selected_ids = request.POST.get('selected_ids')
        
        # Split the selected IDs into a list
        selected_ids_list = selected_ids.split(",")
        
        # Delete all courses with the selected IDs
        register_user.courses.filter(id__in=selected_ids_list).delete()
        
        # Add success message
        messages.success(request, 'Records deleted successfully')
        
        return redirect('courses')
    





#course export 
@admin_required
def course_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.No',"Sub_category",'Course Name'])
  i=0
  for course in register_user.courses.all():
    i+=1
    writer.writerow([i,course.sub_category.sub_cat_title,course.course_name])

  response['Content-Disposition'] = 'attachment; filename="course.csv"'
  return response








@admin_required
def course_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=Course_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['cos_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 3
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('courses')
          sub_cat_import=row[1]
          cos_import=row[2]
          sub_cat_instance=register_user.sub_category.filter(sub_cat_title=sub_cat_import).first()
          if not cos_import:
             continue
          
          if not re.match(r"^[^\d]{2,50}$", cos_import):
             continue
          

          if register_user.courses.filter(course_name=cos_import.strip().title(),sub_category=sub_cat_instance).exists():
           continue
          
          else:
            Course.objects.create(
                course_name=cos_import.strip().title(),crn_number=register_user,sub_category=sub_cat_instance)
            imported = True
        if imported:    
          messages.success(request, f'File imported successfully')   
        else:
          messages.error(request,f'Failed to import')     
        return redirect('courses')
      except Exception as e:
        messages.error(request, f'File Should be only in CSV Format ')
        return redirect('courses')
           
  cos=Course.objects.all()
  context={
      'cos': cos ,
  }
  return render(request, 'settings_page/course.html', context) 





# specialization page
@admin_required
def specialization(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    sep = register_user.specializations.all().order_by("-id")
    cos = register_user.courses.filter(status = "Active").all()
    if request.method == "POST":
        specialization_name = request.POST.get('specialization_name') 
        course = register_user.courses.get(pk=request.POST.get('course_name'))
        if register_user.specializations.filter(specilalization_name=specialization_name.strip().title(), course_name=course).exists():  
            messages.error(request, f'{specialization_name.strip().title()} already exists')
            return redirect('specialization')
        else:
            Specialization.objects.create(
                specilalization_name=specialization_name.strip().title(),  
                course_name=course,
                crn_number=register_user
            )
            messages.success(request, f'{specialization_name.strip().title()} specialization created successfully')
            return redirect('specialization')
    context ={
        'sep': sep,
        'cos': cos,
    }
    return render(request, 'settings_page/specialization.html', context)


def spec_jason(rquest,id):
    
    specialization = Specialization.objects.filter(course_name_id=id).values('id', 'specilalization_name')
    specializations = [{'id': spec['id'], 'specilalization_name': spec['specilalization_name']} for spec in specialization]
    return JsonResponse(specializations, safe=False)








@admin_required
def specialization_status(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    sep = register_user.specializations.get(id=id)
    if sep:
      if sep.status == "Active":
          sep.status = "Deactive"
      else:
          sep.status = "Active"
      sep.save()
      return redirect('specialization')
    else:
       messages.error(request, 'Specialization Does Not Exists')
       return redirect('specialization')



@admin_required
def specialization_edit(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == "POST":
        course_id = request.POST.get('editcourse').strip().title()
        course = register_user.courses.get(pk=course_id)
        specialization = request.POST.get('editspecialization').strip().title()

        if register_user.specializations.filter(id=id).exists():
            if register_user.specializations.filter(specilalization_name=specialization.strip().title(), course_name=course).exclude(id=id).exists():
                messages.error(request, f'{specialization.strip().title()} Specialization For {course.course_name} Course Already Exists.')
                return redirect('specialization')
            else:
                register_user.specializations.filter(id=id).update(
                    course_name=course,
                    specilalization_name=specialization.strip().title(),
                )
                messages.success(request, f'{specialization.strip().title()} specialization updated successfully')
                return redirect('specialization')
        else:
            messages.error(request, f'{specialization.strip().title()} Specialization does not exist.')
            return redirect('specialization')



@admin_required
def specialization_delete(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == "POST":
      specialization = register_user.specializations.get(id=id)
      specialization.delete()
      messages.success(request, f'{specialization.specilalization_name} specialization deleted successfully')
    return redirect('specialization')
    



@admin_required
def specialization_all(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.specializations.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('specialization')
    
    



@admin_required    
def specialization_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.No','Course Name','Specialization Name'])
  i=0
  for sep in register_user.specializations.all():
    i+=1
    writer.writerow([i,sep.course_name,sep.specilalization_name])

  response['Content-Disposition'] = 'attachment; filename="specializations.csv"'
  return response




@admin_required
def specialization_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        form = Specialization_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['sep_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 3

                if len(headers) != expected_headers:
                    messages.error(request, f'File should have {expected_headers} columns')
                    return redirect('specialization')

                imported = False
                for row in reader:
                    if len(row) != expected_headers:
                        continue  # Skip rows with incorrect number of columns

                    cos_import = row[1].strip().title()
                    sep_import = row[2].strip().title()
                    sep_instance = Course.objects.filter(course_name=cos_import).first()

                    if not sep_import or not cos_import.strip().title():
                        continue
                      

                    if Specialization.objects.filter(specilalization_name=sep_import.strip().title(), crn_number=register_user).exists():
                        continue

                    if not re.match(r"^[a-zA-Z\s]{3,50}$", sep_import):
                        continue


                    else:
                        Specialization.objects.create(
                            course_name=sep_instance,
                            specilalization_name=sep_import.strip().title(),
                            crn_number=register_user
                        )
                        imported = True

                if imported:
                    messages.success(request, f'File imported successfully')
                else:
                    messages.error(request, 'Failed to import file')

                return redirect('specialization')

            except Exception as e:
                messages.error(request, f'File Should be only in CSV Format ')
                return redirect('specialization')

    sep = register_user.specializations.objects.all()
    cos = register_user.courses.objects.all()
    context = {
        'sep': sep,
        'cos': cos,
    }

    return render(request, 'settings_page/specialization.html', context)








# video player, topic content, lesson video
def video_player(request):
   return render(request,'settings_page/video_player.html')


# Questoning Path

# Quiz
def quiz(request):
   return render(request,'settings_page/quiz.html')

def sample_course(request):
  return render(request,'sample_course.html')   

def create_quiz(request):
   return render(request,'settings_page/create_quiz.html')
def edit_quiz(request):
   return render(request,'settings_page/edit_quiz_question.html')

# Worksheets
def worksheet(request):
   return render(request,'settings_page/worksheet.html')
def create_worksheet(request):
   return render(request,'settings_page/create_worksheet.html')
def edit_worksheet(request):
   return render(request,'settings_page/edit_worksheet.html')

# Assessments
def assessment(request):
   return render(request,'settings_page/assessment.html')
def create_assessment(request):
   return render(request,'settings_page/create_assessment.html')
def edit_assessment(request):
   return render(request,'settings_page/edit_assessment.html')



def get_courses_for_ch(request, specialization_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    courses = register_user.courses.filter(specialization__id=specialization_id,status = 'Active' )
    data = [{'id': course.id, 'course_name': course.course_name} for course in courses]
    return JsonResponse(data, safe=False)

def get_sub_categories(request, course_id):
    
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    sub_categories = register_user.sub_category.filter(course__id=course_id,sub_cat_status = True)
    data = [{'id': sub_category.id, 'sub_cat_title': sub_category.sub_cat_title} for sub_category in sub_categories]
    return JsonResponse(data, safe=False)

def get_specializations_ch(request, chapter_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    chapter = register_user.chapters.get(id=chapter_id)
    specialization = chapter.spec_title
    if specialization.status == 'Active':
        data = [{'id': specialization.id, 'name': specialization.specilalization_name}]
    else:
        data = []
    return JsonResponse(data, safe=False)


def get_chapters(request, lesson_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    try:
        lesson = register_user.lessons.get(id=lesson_id)
        chapters = register_user.chapters.filter(course_title=lesson.course_title)
        data = [{'id': chapter.id, 'name': chapter.chapter_title} for chapter in chapters]
        return JsonResponse(data, safe=False)
    except Create_Lesson.DoesNotExist:
        return JsonResponse([], safe=False)  # Return empty list if lesson doesn't exist













@admin_required
def chapters(request):
    crn = request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    sub_categories = register_user.sub_category.filter(sub_cat_status=True).all().order_by("-id")
    courses = register_user.courses.filter(status="Active").all().order_by("-id")
    specializations = register_user.specializations.filter(status="Active").all().order_by("-id")
    chapters = register_user.chapters.all().order_by("-id")
    if request.method == "POST":
        sub_category = request.POST.get('sub_category_name')
        course = request.POST.get('course_name')
        specialization = request.POST.get('specialization_name')
        chapter_title = request.POST.get('chapter_title')
        chapter_logo = request.FILES.get('chapter_logo')
        chapter_image = request.FILES.get('chapter_image')
        short_description = request.POST.get('short_description')
        if register_user.chapters.filter(chapter_title=chapter_title).exists():
            messages.error(request, f'{chapter_title} already exists')
            return redirect('chapters')


        register_user.chapters.create(
            sub_cat_title = register_user.sub_category.get(pk=sub_category),
            course_title = register_user.courses.get(pk=course),
            spec_title = register_user.specializations.get(pk=specialization),
            chapter_title = chapter_title,
            chapter_logo = chapter_logo,
            chapter_image = chapter_image,
            chapter_description = short_description,
            crn_number=register_user
        )
        return redirect('chapters')
    context = {
        'sub_categories': sub_categories,
        'courses': courses,
        'specializations': specializations,
        "chapters":chapters
    }
    

    return render(request,'settings_page/chapters.html',context)




# chapter status 
@admin_required
def chapter_status(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  chapter = register_user.chapters.get(id=id)
  if chapter:
    if chapter.chapter_status:
      chapter.chapter_status = False
    else:
      chapter.chapter_status = True
    chapter.save()
    return redirect('chapters')
  else:
    messages.error(request, f'Chapter Not Found')
    return redirect('chapters')


# chapter update
@admin_required
def chapter_update(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    sub_category_edit = request.POST.get('sub_category_edit')
    course_name_edit = request.POST.get('course_name_edit')
    specialization_edit = request.POST.get('specialization_edit')
    chapter_title_edit = request.POST.get('chapter_title_edit')
    chapter_logo_edit = request.FILES.get('chapter_logo_edit')
    chapter_image_edit = request.FILES.get('chapter_image_edit')
    short_description_edit = request.POST.get('short_description_edit')
    chapter = register_user.chapters.get(id=id)
  

    if register_user.chapters.exclude(id=id).filter(chapter_title=chapter_title_edit).exists():
       messages.error(request,'Chapter already exists')
       return redirect('chapters')
       
    if chapter:
      chapter.sub_cat_title = register_user.sub_category.get(pk=sub_category_edit) 
      chapter.course_title = register_user.courses.get(pk=course_name_edit)
      chapter.spec_title = register_user.specializations.get(pk=specialization_edit)
      chapter.chapter_title = chapter_title_edit
      chapter.chapter_logo = chapter_logo_edit
      chapter.chapter_image = chapter_image_edit
      chapter.chapter_description = short_description_edit
      chapter.save()
      messages.success(request, f'Chapter updated successfully')
      return redirect('chapters')
    else:
      messages.error(request, f'Chapter Not Found')
      return redirect('chapters')
  else:
    messages.error(request,'Invalid request')  





# chapter delete
@admin_required
def chapter_delete(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    if register_user.chapters.filter(id=id).exists():
        register_user.chapters.get(id=id).delete()
        messages.success(request,'Chapter deleted successfully')
        return redirect('chapters')
    else:
        messages.error(request,'Chapter not found')  
        return redirect('chapters')
  else:
    messages.error(request,'Invalid request')
    return redirect('chapters')     
      
   

@admin_required
def chapters_all(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.chapters.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('chapters')
    
    



# Lesson Title
def lesson_title(request):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   sub_categories = register_user.sub_category.filter(sub_cat_status=True).all().order_by("-id")
   courses = register_user.courses.filter(status="Active").all().order_by("-id")
   specializations = register_user.specializations.filter(status="Active").all().order_by("-id")
   chapters = register_user.chapters.all().order_by("-id")  
   lessons = register_user.lessons.all().order_by("-id")
   
   if request.method == "POST":
      sub_category = request.POST.get('sub_category_name')
      course_name = request.POST.get('course_name')
      specialization_name = request.POST.get('specialization_name')
      chapter_name = request.POST.get('chapter_name')
      lesson_title = request.POST.get('lesson_title')
      lesson_logo = request.FILES.get('lesson_logo')
      lesson_image = request.FILES.get('lesson_image')
      short_description = request.POST.get('short_description')


      if register_user.lessons.filter(lesson_title=lesson_title).exists():
         messages.error(request,'Lesson title already exists')
         return redirect('lesson_title')
      else:
         Create_Lesson.objects.create(
          sub_cat_title_id=sub_category,
          course_title_id=course_name,
          spec_title_id=specialization_name,
          chapter_title_id=chapter_name,
          lesson_title=lesson_title,
          lesson_logo=lesson_logo,
          lesson_image=lesson_image,
          lesson_description=short_description,
          crn_number=register_user
         )
         return redirect('lesson_title')


   context = {
      
      'sub_categories':sub_categories,
      'courses':courses,
      'specializations':specializations,
      'chapters':chapters,
      'lessons':lessons
     } 

   
   return render(request,'settings_page/lesson_title.html',context)



# lesson status
def lesson_status(request,id):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   if register_user.lessons.filter(id=id).exists():
      lesson = register_user.lessons.get(id=id)
      print("lesson status",lesson.lesson_status)
      if lesson.lesson_status:
         lesson.lesson_status = False
         lesson.save()
         return redirect('lesson_title')
      else:
         lesson.lesson_status = True
         lesson.save()
         return redirect('lesson_title')
   else:
      messages.error(request,'Lesson not found')
      return redirect('lesson_title')      




# lesson edit
def lesson_edit(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    sub_category_edit = request.POST.get('sub_category_edit')
    course_name_edit = request.POST.get('course_name_edit')
    specialization_edit = request.POST.get('specialization_edit')
    chapter_name_edit = request.POST.get('chapter_name_edit')
    lesson_title_edit = request.POST.get('lesson_title_edit')
    lesson_logo_edit = request.FILES.get('lesson_logo_edit')
    lesson_image_edit = request.FILES.get('lesson_image_edit')
    short_description_edit = request.POST.get('short_description_edit')
    print("sub_category_edit",sub_category_edit)
    print("course_name_edit",course_name_edit)
    print("specialization_edit",specialization_edit)
    print("chapter_name_edit",chapter_name_edit)
    print("lesson_title_edit",lesson_title_edit)
    print("lesson_logo_edit",lesson_logo_edit)
    print("lesson_image_edit",lesson_image_edit)
    print("short_description_edit",short_description_edit)

    if register_user.lessons.filter(id=id).exists():

      if register_user.lessons.exclude(id=id).filter(lesson_title=lesson_title_edit,sub_cat_title=sub_category_edit,course_title=course_name_edit,spec_title=specialization_edit,chapter_title=chapter_name_edit).exists():
        messages.error(request,'Lesson already exists')
        return redirect('lesson_title')
      else:
         lesson = register_user.lessons.get(id=id)
         
         lesson.sub_cat_title = register_user.sub_category.get(pk=sub_category_edit)
         lesson.course_title = register_user.courses.get(pk=course_name_edit)
         lesson.spec_title = register_user.specializations.get(pk=specialization_edit)
         lesson.chapter_title = register_user.chapters.get(pk=chapter_name_edit)
         lesson.lesson_title = lesson_title_edit
         lesson.lesson_logo = lesson_logo_edit
         lesson.lesson_image = lesson_image_edit
         lesson.lesson_description = short_description_edit
         lesson.save()
         messages.success(request, f'Lesson updated successfully')
         return redirect('lesson_title')
         
  messages.error(request,'Invalid request')
  return redirect('lesson_title')





# lesson delete
def lesson_delete(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    if register_user.lessons.filter(id=id).exists():
      lesson = register_user.lessons.get(id=id)
      lesson.delete()
      messages.success(request, f'Lesson deleted successfully')
      return redirect('lesson_title')
    else:
      messages.error(request,'Lesson not found')
      return redirect('lesson_title')
  else:
    messages.error(request,'Invalid request')
    return redirect('lesson_title')



# language
def language(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
     language_name = request.POST.get('language_name')
     register_user.languages.create(
      crn_number = register_user,
      language = language_name
     )
     return redirect('language')
  return render(request,'settings_page/language.html')




# Topics
def topics(request):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   sub_categories = register_user.sub_category.filter(sub_cat_status=True).all().order_by("-id")
   courses = register_user.courses.filter(status="Active").all().order_by("-id")
   specializations = register_user.specializations.filter(status="Active").all().order_by("-id")
   chapters = register_user.chapters.all().order_by("-id")  
   lessons = register_user.lessons.all().order_by("-id")
   laguages = register_user.languages.all().order_by("-id")
   topics = register_user.topics.all().order_by('-id')


   if request.method == "POST":
      lesson_title = request.POST.get('lesson_title')
      course_name = request.POST.get('course_name')
      specialization_name = request.POST.get('specialization_name')
      chapter_name = request.POST.get('chapter_name')
      sub_category_name = request.POST.get('sub_category_name')
      language_name = request.POST.get('language_name')
      topic_name = request.POST.get('topic_name')
      durations = request.POST.get('durations')
      video_url = request.POST.get('video_url')
      short_description = request.POST.get('short_description')

      if register_user.topics.filter(sub_cat_title=sub_category_name,spec_title=specialization_name,chapter_title=chapter_name,lesson_title=lesson_title,topic_title=topic_name,topic_vedio_url=video_url,topic_duration=durations).exists():
         messages.error(request,'Topic already exists')
         return redirect('topics')
      else:
         Create_Topic.objects.create(
            crn_number = register_user,
            sub_cat_title = register_user.sub_category.get(pk=sub_category_name),
            spec_title = register_user.specializations.get(pk=specialization_name),
            course_title = register_user.courses.get(pk=course_name),
            chapter_title = register_user.chapters.get(pk=chapter_name),
            lesson_title = register_user.lessons.get(pk=lesson_title),
            language_name = register_user.languages.get(pk=language_name),
            topic_title = topic_name,
            topic_duration = durations,
            topic_vedio_url = video_url,
            topic_description = short_description,
         )
         messages.success(request, f'Topic created successfully')
         return redirect('topics')
   context = {
      
      'sub_categories':sub_categories,
      'courses':courses,
      'specializations':specializations,
      'chapters':chapters,
      'lessons':lessons,
      'laguages':laguages,
      'topics':topics
     } 

      
   return render(request,'settings_page/topics.html',context)



         
def topics_edit(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
      lesson_title = request.POST.get('lesson_title')
      course_name = request.POST.get('course_name')
      specialization_name = request.POST.get('specialization_name')
      chapter_name = request.POST.get('chapter_name')
      sub_category_name = request.POST.get('sub_category_name')
      language_name = request.POST.get('language_name')
      topic_name = request.POST.get('topic_name')
      durations = request.POST.get('durations')
      video_url = request.POST.get('video_url')
      short_description = request.POST.get('short_description')
      if register_user.topics.exclude(id=id).filter(sub_cat_title=sub_category_name,spec_title=specialization_name,chapter_title=chapter_name,lesson_title=lesson_title,topic_title=topic_name,topic_vedio_url=video_url,topic_duration=durations).exists():
         messages.error(request,'Topic already exists')
         return redirect('topics')      
      else:
         register_user.topics.update(
            sub_cat_title = register_user.sub_category.get(pk=sub_category_name),
            spec_title = register_user.specializations.get(pk=specialization_name),
            course_title = register_user.courses.get(pk=course_name),
            chapter_title = register_user.chapters.get(pk=chapter_name),
            lesson_title = register_user.lessons.get(pk=lesson_title),
            language_name = register_user.languages.get(pk=language_name),
            topic_title = topic_name,
            topic_duration = durations,
            topic_vedio_url = video_url,
            topic_description = short_description,
         )
         messages.success(request, f'Topic updated successfully')
         return redirect('topics')

  return redirect('topics')
            











# plans page
@admin_required
def plans(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)

  pal =register_user.plans.all().order_by("-id")
  if request.method == "POST":
    plan = request.POST.get('plan_name')
    if register_user.plans.filter(plan_name=plan.strip().title()).exists():
      messages.error(request, f'{plan.strip().title()} plan already exists')
      return redirect('plans')
    else:
      Plan.objects.create(
        plan_name = plan.strip().title(),
        crn_number = register_user
      )
      messages.success(request, f'{plan.strip().title()} plan created successfully')
      return redirect('plans')
  context ={
    'pal':pal,
  }
  return render(request,'settings_page/plans.html',context)




# plans status
@admin_required
def plans_status(request,id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    pal = register_user.plans.get(id=id)
    if pal:
      if pal.status == "Active":
          pal.status = "Deactive"
      else:
          pal.status = "Active"
      pal.save()
      return redirect('plans')
    else:
       messages.error(request, 'Plan does not exists')
       return redirect('plans')





# plans update
@admin_required
def plans_update(request,id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
      plan = request.POST.get('plan')
      if register_user.plans.exclude(id=id).filter(plan_name=plan.strip().title()).exists():
        messages.error(request,f'{plan.strip().title()} plan already exists')
        return redirect('plans')
      if register_user.plans.filter(id=id).exists():
        register_user.plans.filter(id=id).update(
            plan_name=plan.strip().title(),
        )
        messages.success(request,f"{plan.strip().title()} plan updated successfully")
        return redirect('plans')
      else:
         messages.error(request,'Plan does not exists')
         return redirect('plans')





# plans delete
@admin_required
def plans_delete(request,id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
      plan = register_user.plans.get(id=id)
      if plan:
        plan.delete()
        messages.success(request, f'{plan.plan_name} plan deleted successfully')
        return redirect('plans')
      else:
        messages.error(request, 'Plan does not exists')
        return redirect('plans')
    



@admin_required
def plans_all(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
      selected_ids = request.POST.get('selected_ids')
      selected_ids_list = selected_ids.split(',')
      register_user.plans.filter(id__in=selected_ids_list).delete()
      messages.success(request, 'Records deleted successfully')
      return redirect('plans')







# plans export
@admin_required
def plans_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.no','Plan Name'])
  i=0
  for p in register_user.plans.all():
    i+=1
    writer.writerow([i, p.plan_name])

  response['Content-Disposition'] = 'attachment; filename="plans.csv"'
  return response



@admin_required
def plans_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=Plan_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['pal_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 2
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('plans')
          pal_import=row[1]
          if not pal_import:
             continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$", pal_import):
                        continue
          if register_user.plans.filter(plan_name=pal_import.strip().title()).exists():
           continue
          
          else:
            Plan.objects.create(
                plan_name=pal_import.strip().title(),crn_number=register_user
                )
            imported = True
        if imported:
          messages.success(request, f'File imported successfully')      
        else:
          messages.error(request,'File failed to import')  
               
        return redirect('plans')
      except Exception as e:
        messages.error(request, f'File should be only in CSV format ')
        return redirect('plans')
           
  pal=Plan.objects.all().order_by("-id")
  context={
      'pal': pal ,
  }
  return render(request, 'settings_page/plans.html', context) 










# net banking page
@admin_required
def net_banking(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  net=register_user.net_banking.all().order_by("-id")
  if request.method == "POST":
    accountname = request.POST.get('Accountname').strip().title()
    accountnumber=request.POST.get('Accountnumber')
    ifscode=request.POST.get('IFSCode')
    accounttype=request.POST.get('Accounttype').strip().title()
    bankname=request.POST.get('Bankname').strip().title()
    branchname=request.POST.get('Branchname').strip().title()
    if register_user.net_banking.filter( accountnumber=accountnumber).exists():
      messages.error(request, f'{accountnumber} accountnumber already exists')
      return redirect('net_banking')
    else:
      netbanking.objects.create(
      netbanking_name =accountname,
      accountnumber=accountnumber,
      ifscode=ifscode,
      accounttype=accounttype,
      bankname=bankname,
      branchname=branchname,
      crn_number=register_user
      )
      messages.success(request,"Net banking added successfully")
      return redirect('net_banking')
  context ={
    'net':net,
  }
  return render(request,'settings_page/net_banking.html',context)





# net status
@admin_required
def net_status(request,id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    net = register_user.net_banking.get(id=id)
    if net:
      if net.status== "Active":
         net.status= "Deactive"
      else:
          net.status = "Active"
      net.save()
      return redirect('net_banking')
    else:
       messages.error(request, 'Net banking does not exists')
       return redirect('net_banking')




# net edit
@admin_required
def net_edit(request,id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
        net= request.POST.get('accountname').strip().title()
        Accountnumber= request.POST.get('accountnumber')
        IFSCode=request.POST.get('ifscode')
        Accounttype=request.POST.get('accounttype').strip().title()
        Bankname=request.POST.get('bankname').strip().title()
        Branchname= request.POST.get('branchname').strip().title()
        if register_user.net_banking.filter(id=id).exists():
          
            netbanking.objects.filter(id=id).update(
                netbanking_name= net,
                accountnumber=Accountnumber,
                ifscode=IFSCode,
                accounttype=Accounttype,
                bankname=Bankname,
                branchname=Branchname,
                crn_number=register_user        

            )
            messages.success(request,f"{net} net banking updated Successfully")
            return redirect('net_banking')
        else:
           messages.error(request,'Net banking is not found')
           return redirect('net_banking')
    return redirect('net_banking')








# net delete
@admin_required
def net_delete(request,id):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   if request.method == "POST":
      if register_user.net_banking.filter(id=id).exists():
        net = register_user.net_banking.get(id=id) 
        net.delete()
        messages.success(request, f'{net.netbanking_name} net banking deleted successfully')
        return redirect('net_banking')
      else:
         messages.error(request,'Net banking is found')
         return redirect('net_banking')







@admin_required
def net_banking_delete_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.net_banking.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('net_banking')







# net export
@admin_required
def net_export(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.No','accountname','accountnumber','ifscode' ,'Account Type' ,'bankname','branchname'])
  i = 0
  for net in register_user.net_banking.all():
      i += 1
      writer.writerow([i,net.netbanking_name,net.accountnumber,net.ifscode, net.accounttype,net.bankname, net.branchname])

  response['Content-Disposition'] = 'attachment; filename="List_of_netbanking.csv"'
  return response





@admin_required
def net_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=Netbanking_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['net_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 7
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('net_banking')
          accountname=row[1].strip().title()
          accountnumber=row[2]
          ifs = row[3].strip().upper()
          accountType=row[4].strip().title()
          bankname=row[5].strip().title()
          branchname=row[6].strip().title()
          if not ifs or not accountname or not accountnumber or not bankname or not branchname:
             continue
          if not re.match(r'^[\d.]{9,18}$', accountnumber):
             continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$", accountname):
             continue
          # if not re.match(r'^[A-Z]{4}[0][A-Z0-9]{6}$',ifs):
          #   continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$",branchname):
            continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$",accountType):
            continue

             
          if register_user.net_banking.filter(netbanking_name=accountname,accountnumber=accountnumber,ifscode=ifs,accounttype=accountType,bankname=bankname,branchname=branchname).exists():
           continue
          
          else:
            netbanking.objects.create(
                netbanking_name=accountname,accountnumber=accountnumber,ifscode=ifs,bankname=bankname,branchname=branchname,crn_number=register_user)
            imported = True
        if imported:
          messages.success(request, f'File imported successfully')      
        else:
          messages.error(request,f'Failed to import file')  

        return redirect('net_banking')
      except Exception as e:
        messages.error(request, f'{e} File Should be only in CSV Format ')
        return redirect('net_banking')
           
  net=register_user.net_banking.all()
  context={
      'net':net
  }
  return render(request, 'settings_page/net_banking.html',context)


# vendor page
@admin_required
def vendor(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  data = register_user.vendors.all().order_by('-id')
  if request.method == 'POST':

    vendor_name = request.POST.get('vendor_name')
    if register_user.vendors.filter(vendor_name=vendor_name.strip().title()).exists():
      messages.error(request, f'{vendor_name} vendor type name already exists')
      return redirect('vendor')
    else:
        vendorModel.objects.create(
                vendor_name=vendor_name.strip().title(),
                crn_number=register_user
            )
        messages.success(request, f" {vendor_name.strip().title()} vendor type name created successfully.")
        return redirect('vendor')

    
  
  return render(request,'settings_page/vendor.html',{ 'data':data })




# @login_required(login_url='login_page')
@admin_required
def vendor_status(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    vendor = register_user.vendors.get(id=id)
    if vendor:
        if vendor.status == "Active":
            vendor.status = "Deactive"
            # messages.success(request, f" {vendor.vendor_name}  has been Deactivated.")
        else:
            vendor.status = "Active"
            # messages.success(request, f" {vendor.vendor_name}  has been Activated.")

        vendor.save()
        return redirect('vendor')
    else:
        messages.error(request, "Vendor not found")
        return redirect('vendor')
# vendor update



@admin_required
def vendor_update(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    vendor=register_user.vendors.get(id=id)
    if request.method == "POST":
        print('noting')
        vname = request.POST.get('vendor_name_edit')
        print(vname)
        if register_user.vendors.filter(vendor_name=vname.strip().title()).exists():
            messages.error(request,f"{vname.strip().title()} vendor type name already exists")
            return redirect('vendor')
        
        register_user.vendors.filter(id=id).update(vendor_name=vname.strip().title())
        messages.success(request, f" {vname.strip().title()} vendor type name updated successfully.")   
          
        return redirect('vendor')

    return redirect('vendor')

# vendor delete

@admin_required
def vendor_delete(request,id):    
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    vendor = register_user.vendors.get(id=id)
    if vendor:
    
      vendor.delete()

      messages.success(request, f"{vendor.vendor_name} vendor type name deleted successfully.")
      return redirect('vendor')
    else:
        messages.error(request, "Vendor not found")
        return redirect('vendor')





@admin_required
def vendor_all(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.vendors.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('vendor')








# vendor export


@admin_required
def vendor_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vendor_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['S.No','Vendors'])

    vendors = register_user.vendors.all().order_by('-id')
    i=0
    for vendor in vendors:
        i+=1
        writer.writerow([i,vendor.vendor_name])

    return response




@admin_required
def vendor_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method=='POST':
        form=vendor_import_form(request.POST,request.FILES)
        if form.is_valid():
            
            try:
                csv_file=request.FILES['vendor_file']
                decoded_file=csv_file.read().decode('utf-8')
                reader=csv.reader(decoded_file.splitlines())
                headers=next(reader)
                expected_headers = 2
                imported = False
                for row in reader:
                    if len(row)!=expected_headers:
                        messages.error(request, f'File do not match the columns')
                        return redirect('vendor')
                    
                    vendor_import=row[1]
                    
                    
                    if not vendor_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", vendor_import):
                        continue
                    
                    if register_user.vendors.filter(vendor_name=vendor_import.strip().title()).exists():
                        continue
                    else:
                         register_user.vendors.create(
                             vendor_name=vendor_import.strip().title(),status="Active",crn_number=register_user)
                         imported = True
                if imported:         
                  messages.success(request, f'File imported successfully')
                else:
                  messages.error(request, f'Failed to import file')  
                return redirect('vendor')
           
            except Exception as e:
                print(e)
                messages.error(request, f'File Should be only in CSV Format ')
                return redirect('vendor')
    vendor=register_user.vendors.all().order_by('-id')
    context={
        'vendor':vendor
    }
    return render(request,'vendor.html',context)








# purpose of 
@admin_required
def purposeOfVisit(request):
  crn=request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  data = register_user.purpose.all().order_by('-id')
  if request.method == 'POST':

    purposeOfVisit1 = request.POST.get('purpose')
    print(purposeOfVisit1)
    if register_user.purpose.filter(purpose=purposeOfVisit1.strip().title()).exists():
      messages.error(request, f'{purposeOfVisit1.strip().title()} purpose already exists')
      return redirect('purpose_of_visit')
    else:
        Purpose_of_visit_model.objects.create(
                purpose=purposeOfVisit1.strip().title(),
                crn_number=register_user
            )
        messages.success(request, f" {purposeOfVisit1} purpose created successfully.")
        return redirect('purpose_of_visit')
  return render(request,'settings_page/purpose_of_visit.html',{"data":data})



  
@admin_required
def purpose_status(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    purpose1 = register_user.purpose.get(id=id)
    if purpose1:
      if purpose1.status == "Active":
          purpose1.status = "Deactive"
          # messages.success(request, f" {vendor.vendor_name}  has been Deactivated.")
      else:
          purpose1.status = "Active"
          # messages.success(request, f" {vendor.vendor_name}  has been Activated.")
  
      purpose1.save()
      return redirect('purpose_of_visit')
    else:
        messages.error(request, "Purpose of visit not Found")
        return redirect('purpose_of_visit')


# purpose update
@admin_required
def purpose_update(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    purpose1 = register_user.purpose.get(id=id)
 
    if request.method == "POST":
        
        purpose= request.POST.get('purpose_edit')
        
        if register_user.purpose.filter(purpose=purpose.strip().title()).exists():
            messages.error(request,f"{purpose.strip().title()} purpose already exists")
        
            return redirect('purpose_of_visit')
       
        register_user.purpose.filter(id=id).update(purpose=purpose.strip().title())
        
        messages.success(request, f" {purpose} purpose updated to successfully.")  
        
         
        return redirect('purpose_of_visit')
    
    return redirect('purpose_of_visit')


# purpose delete
@admin_required
def purpose_delete(request,id):    
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
      purpose = register_user.purpose.get(id=id)
      if purpose:
         purpose_name =purpose.purpose
         purpose.delete()
         messages.success(request,f'{purpose_name} purpose deleted successfully')
         return redirect('purpose_of_visit')
      else:
         messages.error(request,'Purpose does not exists')
         return redirect('purpose_of_visit')
    else:
       messages.error(request,'invalid request method')
       return redirect('purpose_of_visit')

       
@admin_required
def purpose_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  selected_ids = request.POST.get('selected_ids')
  selected_ids_list = selected_ids.split(',')
  register_user.purpose.filter(id__in=selected_ids_list).delete()
  messages.success(request, 'Records deleted successfully')
  return redirect('purpose_of_visit')









@admin_required
def purpose_import(request):
    
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method=='POST':
        
        
        form=purpose_import_form(request.POST,request.FILES)
        if form.is_valid():

            try:

                csv_file=request.FILES['purpose_file']
                decoded_file=csv_file.read().decode('utf-8')
                reader=csv.reader(decoded_file.splitlines())
                headers=next(reader)
                expected_headers = 2
                imported = False
                for row in reader:
                    if len(row)!=expected_headers:
                        messages.error(request, f'File do not match the columns')
                        return redirect('purpose_of_visit')
                    
                    purpose_import=row[1]
                    # vendor_status=row[1]
                    if not purpose_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", purpose_import):
                        continue
                    if register_user.purpose.filter(purpose=purpose_import.strip().title()).exists():
                        continue
                    else:
                         Purpose_of_visit_model.objects.create(
                             purpose=purpose_import.strip().title(),status="Active",crn_number=register_user)
                         imported = True
                if imported:
                    messages.success(request, f'File imported successfully')
                else:
                   messages.error(request,f'Purpose alreadyy exists')    
                            
                return redirect('purpose_of_visit')
           
            except Exception as e:
                messages.error(request, f'File Should be only in CSV Format ')
                return redirect('purpose_of_visit')
    
    vendor=register_user.purpose.all().order_by('-id')
    context={
        'data':vendor
    }

    return render(request,'purpose_of_visit.html',context)




# Forum export
@admin_required
def purpose_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    # for export the data to csv file
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="purpose_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['S.No''Purpose_of_Visit'])
    i=0
    purpose = register_user.purpose.all().order_by('-id')
    for purpose1 in purpose:
        i+=1
        writer.writerow([i,purpose1.purpose])

    return response



# prospect type
@admin_required
def prospect_type(request):
  crn=request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  data = register_user.prospect_types.all().order_by('-id')
  if request.method == 'POST':

    prospect_type = request.POST.get('prospect_type')
    if register_user.prospect_types.filter(prospect_type=prospect_type.strip().title()).exists():
      messages.error(request, f'{prospect_type.strip().title()} prospect type already exists')
      return redirect('prospect_type')
    else:
        ProspectType_model.objects.create(
                prospect_type=prospect_type.strip().title(),
                crn_number=register_user
            )
        messages.success(request, f" {prospect_type.strip().title()} prospect type created successfully.")
        return redirect('prospect_type')
  return render(request,'settings_page/prospect_type.html',{ 'data':data })




@admin_required
def prospect_status(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    prospect = register_user.prospect_types.get(id=id)
    if prospect:
      if prospect.status == "Active":
          prospect.status = "Deactive"
          # messages.success(request, f" {vendor.vendor_name}  has been Deactivated.")
      else:
          prospect.status = "Active"
          # messages.success(request, f" {vendor.vendor_name}  has been Activated.")

      prospect.save()
      return redirect('prospect_type')
    else:
        messages.error(request, "Prospect Not Found")
        return redirect('prospect_type')
    




# Prospect update
@admin_required
def Prospect_update(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    prospect=register_user.prospect_types.get(id=id)
    if prospect:
      if request.method == "POST":
          prospect_type= request.POST.get('prospect_type_edit')

          if register_user.prospect_types.filter(prospect_type=prospect_type.strip().title()).exists():
              messages.error(request,f"{prospect_type.strip().title()} prospect type already exists")
              return redirect('prospect_type')

          register_user.prospect_types.filter(id=id).update(prospect_type=prospect_type.strip().title())
          messages.success(request, f" {prospect_type.strip().title()} prospect type updated successfully.")   

          return redirect('prospect_type')

      return redirect('prospect_type')
    else:
        messages.error(request, "Prospect not found")
        return redirect('prospect_type')




# Prospect delete
@admin_required
def prospect_delete(request,id):    
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    Prospect= register_user.prospect_types.get(id=id)
    if Prospect:
      Prospect.delete()

      messages.success(request, f"{Prospect.prospect_type} prospect type deleted successfully.")
      return redirect('prospect_type')
    else:
        messages.error(request, "Prospect Not Found")
        return redirect('prospect_type')

      




@admin_required
def prospect_type_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.prospect_types.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('prospect_type')












# prospect type export
@admin_required
def prospect_type_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="prospect_type_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['S.NO','PROSPECT TYPE'])
    i=0
    prospects = register_user.prospect_types.all().order_by('-id')
    for prospect in prospects:
        i+=1
        writer.writerow([i,prospect.prospect_type])

    return response



@admin_required
def prospect_type_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
       form=prospect_type_import_form(request.POST, request.FILES)
       if form.is_valid():
          try:
            csv_file = request.FILES['prospect_file']
            decoded_file = csv_file.read().decode('utf-8')
            reader = csv.reader(decoded_file.splitlines())
            imported = False
            next(reader)

            for row in reader:
              if len(row)!=2:
                messages.error(request, 'File should have 2 columns: S.No and Prospect Type')
                return redirect('prospect_type')
              prospect_type_import=row[1]

              if not prospect_type_import:
                 continue
              if not re.match(r"^[a-zA-Z\s]{3,50}$", prospect_type_import.strip().title()):
                        continue
              if register_user.prospect_types.filter(prospect_type=prospect_type_import.strip().title()).exists():
                 continue
              else:
                register_user.prospect_types.create(
                    prospect_type=prospect_type_import.strip().title(),
                    status="Active",
                    crn_number=register_user
                ) 
                imported = True
            if imported:    
                messages.success(request, 'File imported successfully')
            else:
                messages.error(request,'File already exists')    
            return redirect('prospect_type')

          except Exception as e:
             print(e)
             messages.error(request, 'An error occured while processing the file')
             return redirect('prospect_type')

    else:
        messages.success(request, 'Invalid request method')
    return redirect('prospect_type')



# forum category
@admin_required
def forum_category(request):
  crn=request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  data = register_user.forumcategories.all().order_by('-id')
  if request.method == 'POST':

    forum_category = request.POST.get('forum_category')
    if register_user.forumcategories.filter(forum_category=forum_category.strip().title()).exists():
      messages.error(request, f'{forum_category.strip().title()}  forum catefory already exists')
      return redirect('forum_category')
    else:
        Forumcategories_model.objects.create(
                forum_category=forum_category.strip().title(),
                crn_number=register_user
            )
        messages.success(request, f" {forum_category.strip().title()} forum catoegory created successfully.")
        return redirect('forum_category')
  return render(request,'settings_page/forum_category.html',{'data':data})



# forum category status
@admin_required
def Forum_status(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    forum = register_user.forumcategories.get(id=id)
    if forum:
      if forum.status == "Active":
          forum.status = "Deactive"
      else:
          forum.status = "Active"

      forum.save()
      return redirect('forum_category')
    else:
        messages.error(request, "Forum category not found")
        return redirect('forum_category')





# forum category delete
@admin_required
def Forum_delete(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)  
    if request.method == "POST":
      if register_user.forumcategories.filter(id=id).exists():
          forum = register_user.forumcategories.get(id=id)
          forum.delete()
          messages.success(request, 'Forum category deleted successfully')
          return redirect('forum_category')
      else:
          messages.error(request, "Forum category not found")
          return redirect('forum_category')
    else:
        messages.error(request, "Invalid request method")
        return redirect('forum_category')  



@admin_required
def Forum_all(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == "POST":
        selected_ids=request.POST.get('selected_ids')
        selected_ids_list=selected_ids.split(',')
        register_user.forumcategories.filter(id__in=selected_ids_list).delete()
        messages.success(request, 'Records deleted successfully')
        return redirect('forum_category')









# forum category update
@admin_required
def Forum_update(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)

    forum = register_user.forumcategories.get(id=id)
    if forum:

      if request.method == "POST":

          forum1= request.POST.get('forum_edit')

          if register_user.forumcategories.exclude(id=id).filter(forum_category=forum1.strip().title()).exists():
              messages.error(request,f"{forum1.strip().title()} forum category already exists")

              return redirect('forum_category')

          register_user.forumcategories.filter(id=id).update(forum_category=forum1.strip().title())

          messages.success(request, f" {forum1.strip().title()} forum category updated successfully.")   


          return redirect('forum_category')

      return redirect('forum_category')
    else:
        messages.error(request, "Forum category not found")
        return redirect('forum_category')




# forum category export
@admin_required
def Forum_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    # for export the data to csv file
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="Forum_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['S.No','Forum Category'])
    i=0
    forum = register_user.forumcategories.all().order_by('-id')
    for forum1 in forum:
        i+=1
        writer.writerow([i,forum1.forum_category])

    return response




# forum category import
@admin_required
def Forum_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    
    if request.method=='POST':
    
        
        form=Forum_import_form(request.POST,request.FILES)
        if form.is_valid():
    
            try:
    
                csv_file=request.FILES['Forum_file']
                decoded_file=csv_file.read().decode('utf-8')
                reader=csv.reader(decoded_file.splitlines())
                headers=next(reader)
                expected_headers = 2
                imported = False
                for row in reader:
                    if len(row)!=expected_headers:
                        messages.error(request, f'File do not match the columns')
                        return redirect('forum_category')
                    
                    Forum_import=row[1]
                    # vendor_status=row[1]
                    if not Forum_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", Forum_import):
                        continue
                    if register_user.forumcategories.filter(forum_category=Forum_import.strip().title()).exists():
                        continue
                    else:
                         Forumcategories_model.objects.create(
                             forum_category=Forum_import.strip().title(),crn_number=register_user)
                         imported = True
                if imported:
                    messages.success(request, f'File imported successfully')
                else:
                  messages.error(request,f'Failed to import forum category')    

                return redirect('forum_category')
           
            except Exception as e:
    
                
                messages.error(request, f'File Should be only in CSV Format ')
                return redirect('forum_category')
    
    vendor=register_user.forumcategories.all().order_by('-id')
    context={
        'data':vendor
    }
    
    return render(request,'forum_category.html',context)


# employee Type
@admin_required
def employee_type(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  data = register_user.employee_types.all().order_by('-id')
  if request.method == 'POST':

    employee_type = request.POST.get('employee_type')
    if register_user.employee_types.filter(employee_type=employee_type.strip().title()).exists():
      messages.error(request, f'{employee_type.strip().title()} employee type already exists')
      return redirect('employee_type')
    else:
        EmployeeType_model.objects.create(
                employee_type=employee_type.strip().title(),
                crn_number=register_user
            )
        messages.success(request, f" {employee_type.strip().title()} created successfully.")
        return redirect('employee_type')
  return render(request,'settings_page/employee_type.html',{ 'data':data })



# employee_type status
@admin_required
def employee_status(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    employee_type = register_user.employee_types.get(id=id)
    if employee_type:
      if employee_type.status == "Active":
          employee_type.status = "Deactive"
          # messages.success(request, f" {vendor.vendor_name}  has been Deactivated.")
      else:
          employee_type.status = "Active"
          # messages.success(request, f" {vendor.vendor_name}  has been Activated.")

      employee_type.save()
      return redirect('employee_type')
    else:
       messages.error(request, "Employee Type Not Found")




# employee_type delete
@admin_required
def employee_type_delete(request,id): 
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)   
    
    employee_type = register_user.employee_types.get(id=id)
    if employee_type:
      employee_type.delete()

      messages.success(request, f"{employee_type.employee_type} employee type deleted successfully.")
      return redirect('employee_type')
    else:
        messages.error(request, "Employee Type Not Found")
        return redirect('employee_type')




@admin_required
def employee_type_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.employee_types.filter(id__in=selected_ids_list).delete()
    messages.success(request, f" Records deleted successfully.")
    return redirect('employee_type')





# employee update
@admin_required
def employeetype_update(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    employee_type = register_user.employee_types.get(id=id)
    if employee_type:
        if request.method == "POST":
            employee_type1= request.POST.get('employee_type_edit')

            if register_user.employee_types.filter(employee_type=employee_type1.strip().title()).exists():
                messages.error(request,f"{employee_type1} employee type already exists")
                return redirect('employee_type')

            register_user.employee_types.filter(id=id).update(employee_type=employee_type1.strip().title())
            messages.success(request, f" {employee_type1} updated successfully.")   

            return redirect('employee_type')

        return redirect('employee_type')
    else:
        messages.error(request, "Employee Type Not Found")
        return redirect('employee_type')



#Employee import
@admin_required
def Employee_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method=='POST':

        form=Employee_type_import_form(request.POST,request.FILES)
        if form.is_valid():

            try:
                csv_file=request.FILES['employeetype_file']
                decoded_file=csv_file.read().decode('utf-8')
                reader=csv.reader(decoded_file.splitlines())
                headers=next(reader)
                expected_headers = 2
                imported = False
                for row in reader:
                    if len(row)!=expected_headers:
                        messages.error(request, f'File must have 2 columns [S.No , Employee Type]')
                        return redirect('employee_type')
                    
                    Employee_import=row[1]
                    

                    if not Employee_import:
                        continue
                    if not re.match(r"^[a-zA-Z\s]{3,50}$", Employee_import):
                        continue
                    if register_user.employee_types.filter(employee_type=Employee_import.strip().title()).exists():
                        continue
                    else:
                         EmployeeType_model.objects.create(
                             employee_type=Employee_import.strip().title(),status='Active',crn_number=register_user)
                         imported = True
                if imported:
                    messages.success(request, f'File imported successfully')
                else:
                    messages.error(request,f'File could not be imported')    
                            
                return redirect('employee_type')
           
            except Exception as e:

                print(e)
                messages.error(request, f'File should be only in CSV format')
                return redirect('employee_type')


    return redirect('employee_type')        

# Emloyee type export
@admin_required
def emplpoyee_type_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)

    # for export the data to csv file
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="Employee_type_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['S.No','Employee TYPE'])
    i=0
    employee_type = register_user.employee_types.all().order_by('-id')
    for employee_type in employee_type:
        i+=1
        writer.writerow([i,employee_type.employee_type])

    return response



# class rooms start here
# Class room
def classroom(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  table=class_room.objects.all()
  branches=BranchModel.objects.all()
  
  if request.method=='POST':
    room=request.POST['class_room']
    floor=request.POST['floor']
    capacity=request.POST['capacity']
    address=request.POST['address']
    branch=request.POST['branch_id']
    if register_user.class_rooms.filter(branch_id=branch).exists() and register_user.class_rooms.filter(class_room=room).exists():
      messages.error(request,f'Branch Name and class room is already existes')
      return redirect('class_room')
    else:
      form=class_room(class_room=room,floor=floor,capacity=capacity,address=address,branch_id=branch,crn_number=register_user)
      form.save()
      messages.success(request,f'Class room :{room} added successfully')
      return redirect('class_room')

  context={'class':table,'branches':branches}
  return render(request,'settings_page/class_room.html',context)


# class edit

def classroomedit(request, pk):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == 'POST':
        room = request.POST.get('class_room2')
        floor = request.POST.get('floor2')
        capacity = request.POST.get('capacity2')
        address = request.POST.get('address2')
        branch2 = request.POST.get('branch_id2')
        try:
            branch1 = register_user.branches.get(pk=branch2)
        except ObjectDoesNotExist:
            messages.error(request, f'Branch does not exist')
            return redirect('class_room')
        edit = register_user.class_rooms.get(id=pk)
        edit.class_room = room
        edit.floor = floor
        edit.capacity = capacity
        edit.address = address
        edit.branch = branch1

        if register_user.class_rooms.filter(class_room=room).exclude(id=pk).exists() and register_user.class_rooms.filter(branch=branch1).exclude(id=pk).exists():
            messages.error(request, f'Class Room and Branch already exists')
            return redirect('class_room')
        # Check if any other class room is associated with the selected branch
        else:
        # Save the changes if all validations pass
          edit.save()
          messages.success(request, f'Updated successfully')
          return redirect('class_room')


# classroom delete
def classroomdelete(request, pk):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  table = register_user.class_rooms.get(id=pk)
  if table:
    class_room_name = table.class_room 
    table.delete()
    messages.success(request, f'Class Room "{class_room_name}" deleted successfully.')
  else:
    messages.error(request, 'Class Room not found.')  
  return redirect('class_room')



# classroom export
def classroom_export(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  response=HttpResponse(content_type='text/csv')
  writer=csv.writer(response)
  writer.writerow(['S.no','Class Room No.','Floor No.','Seating Capacity','Branch','Address'])
  i=0
  for classroom in register_user.class_rooms.all():
    i+=1
    writer.writerow([i,classroom.class_room,classroom.floor,classroom.capacity,classroom.branch,classroom.address])
  response['Content-Disposition'] = 'attachment; filename="List_of_class_room.csv"'
  return response




# class room import
def classroom_import(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=classroom_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['classroom_file']#input field name
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 6
        for row in reader:
          if len(row)!=expected_headers:
            messages.error(request, f'File should have {expected_headers} columns')
            return redirect('class_room')
          class_room=row[1]
          floor=row[2]
          capacity=row[3]
          branch=row[4]
          branch_instance_name=register_user.branches.filter(branch_name=branch).first()
          address=row[5]
          if not class_room or not floor or not capacity or not branch_instance_name or not address:
            continue
          if register_user.class_rooms.filter(class_room=class_room,branch=branch_instance_name).exists():
            continue
          
          
          else:
            class_room.objects.create(
                class_room=class_room,
                floor=floor,
                capacity=capacity,
                branch=branch_instance_name,
                address=address,
                crn_number=register_user
                )
        messages.success(request, f'File Imported Successfully')      
        return redirect('class_room')
      except Exception as e:
        messages.error(request, f'{e}File Should be only in CSV Format ')
        return redirect('class_room')
  return render(request, 'settings_page/class_room.html')











# complaints page
@admin_required
def complaints(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    complaints = register_user.complaints.all().order_by('-id')
    if request.method == 'POST':
        complaint_name = request.POST.get('complaint_name')
        complaint_subject=request.POST.get('complaint_subject')
        complaint_discription=request.POST.get('complaint_description')
        if register_user.complaints.filter(complaint_name=complaint_name.strip().title(),complaint_subject=complaint_subject.capitalize()).exists():
            messages.error(request, 'Complaint already exists')
            return redirect('complaints')
        else:    
            Complaints.objects.create(
                complaint_name=complaint_name.strip().title(),
                complaint_subject =complaint_subject.capitalize(),  
                complaint_discription=complaint_discription.capitalize(),
                crn_number=register_user
            )
            messages.success(request,f'{complaint_name.strip().title()} complaint added successfully')
            return redirect('complaints')
    context = {
        'complaints': complaints
    }  
    return render(request,'settings_page/complaints.html',context)



# complaints status
@admin_required
def complaints_status(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    complain = register_user.complaints.get(id=id)
    if complain:
        if complain.status == "Active":
            complain.status = "Deactive"
        else:
            complain.status = "Active"
        complain.save()
        return redirect('complaints')
    else:
        messages.error(request, "Complaint not found")
        return redirect('complaints')




# complaints update
@admin_required
def complaints_update(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)


    if register_user.complaints.get(id=id):
       
        if request.method == "POST":
            complaint_name = request.POST.get('complaint_name_edit')
            complaint_subject=request.POST.get('complaint_subject_edit')
            complaint_discription=request.POST.get('complaint_discription_edit')
            if register_user.complaints.exclude(id=id).filter(complaint_name=complaint_name.strip().title(),complaint_subject=complaint_subject.capitalize()).exists():
                messages.error(request, 'Complaint already exists')
                return redirect('complaints')
            else:
                complain = register_user.complaints.get(id=id)
                complain.complaint_name = complaint_name.strip().title()
                complain.complaint_subject =complaint_subject.capitalize()
                complain.complaint_discription =complaint_discription.capitalize()
                complain.save()
                messages.success(request,f'{complaint_name.strip().title()} complaint updated successfully')
                return redirect('complaints')
    else:
        messages.error(request, "Complaint not found")
        return redirect('complaints')        






# complaints delete
@admin_required
def complaint_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if register_user.complaints.get(id=id):
      if request.method=="POST":
        if register_user.complaints.filter(id=id).exists():
            complaint=register_user.complaints.get(id=id)
            complaint.delete()
            messages.success(request,f"{complaint.complaint_name} complaint deleted successfully")
            return redirect('complaints')
        else:
           messages.success(request,"Complaint not found")
           return redirect('complaints')  
  else:
    messages.error(request, "Complaint Not Found")
    return redirect('complaints')      

      


@admin_required
def complaint_all(request):
  crn= request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.complaints.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted Successfully')
    return redirect('complaints')







# complaints export
@admin_required
def complaints_export(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    response = HttpResponse(content_type='csv')
    response['Content-Disposition'] = 'attachment; filename="complain.csv"'
    writer = csv.writer(response)
    writer.writerow(['S.No','complaint_name','complaint_subject','complaint_discription'])
    i=0
    complains = register_user.complaints.all().order_by('-id')
    for complain in complains:
        i+=1
        writer.writerow([i,complain.complaint_name, complain.complaint_subject,complain.complaint_discription])
    return response




@admin_required
def complain_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)

    if request.method=='POST':
      form = complaint_import_form(request.POST,request.FILES)
      if form.is_valid():
        try:
          csv_file=request.FILES['complaint_file']
          decoded_file=csv_file.read().decode('utf-8')
          reader=csv.reader(decoded_file.splitlines())
          headers=next(reader)
          expected_headers = 4
          imported = False
          for row in reader:
            if len(row)!=expected_headers:
              messages.error(request,f'File do not match the columns')
              return redirect('complaints')
            complaint_import=row[1]
            complaint_subject=row[2]
            complaint_discription=row[3]
          
            if not complaint_import or not complaint_subject or not complaint_discription:
              continue

            if not re.match(r"^[a-zA-Z\s]{3,50}$", complaint_import):
              continue
            if not re.match(r"^[a-zA-Z0-9\s]{3,50}$",complaint_subject):
              continue

            if not re.match(r"^(.|\s){20,1000}$",complaint_discription):
              continue
              
            if register_user.complaints.filter(complaint_name=complaint_import.strip().title(),complaint_subject=complaint_subject.capitalize()).exists():
              continue
            else:
              Complaints.objects.create(
                complaint_name=complaint_import.strip().title(),
                complaint_subject =complaint_subject.capitalize(),
                complaint_discription=complaint_discription.capitalize(),
                crn_number=register_user
              )
              imported = True
          if imported:      
             messages.success(request, f'File imported successfully')
          else:
             messages.error(request,f'Failed to import file')   
          return redirect('complaints')
        except Exception as e:
          messages.error(request, f'File format not valid')
          return redirect('complaints')
    complaints=register_user.complaints.all().order_by('-id')
    context={
      'complaints':complaints
    }
    return render(request,'settings_page/complaints.html',context)
      
      






# Calender page
@admin_required
def calender(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    title=request.POST.get('title')
    date_time=request.POST.get('date_time')
    category=request.POST.get('category')
    branch=register_user.branches.get(pk=request.POST.get('branch'))
    message=request.POST.get('message')
    
    if register_user.calenders.filter(title=title.strip().title(),date_time=date_time,category=category,branch=branch).exists():
      messages.error(request, f'Calender already exists for this date and time')
      return redirect('calender')
    else:
      CalenderModel.objects.create(
        title=title.strip().title(),
        date_time=date_time,
        category=category.strip().title(),
        branch=branch,
        message=message.capitalize(),
        crn_number=register_user
      )
      messages.success(request,f"{title.strip().title()} added successfully ")
      return redirect('calender')
  calander=register_user.calenders.all().order_by('-id')
  branch=register_user.branches.all().order_by('-id')
  context={
    'calander':calander,
    'branch':branch
  }
      
    
  return render(request,'settings_page/calender.html',context) 





@admin_required
def calander_status(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  
  calander=register_user.calenders.get(id=id)
  if calander:
    if calander.status=="Active":
      calander.status="Deactive"
    else:
      calander.status="Active"
    calander.save()
    return redirect('calender')
  else:
    messages.error(request, 'Calender not found')
    return redirect('calender')


@admin_required
def calander_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if register_user.calenders.get(id=id):
     if register_user.calenders.filter(id=id).exists():
       calender=register_user.calenders.get(id=id)
       calender.delete()
       messages.success(request,f'{calender.title} calender deleted successfully')
       return redirect('calender')
     else:
       messages.error(request, 'Calender not found')
       return redirect('calender')
  else:
    messages.error(request, 'Calender not found')
    return redirect('calender')




@admin_required
def calander_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.calenders.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted Successfully')
    return redirect('calender')










@admin_required  
def calander_update(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if register_user.calenders.get(id=id):
      if request.method=='POST':
        event_title_edit=request.POST.get('event_title_edit')
        event_date_edit=request.POST.get('event_date_edit')
        event_category_edit=request.POST.get('event_category_edit')
        event_branch_edit=register_user.branches.get(pk=request.POST.get('event_branch_edit'))
        event_message_edit=request.POST.get('event_message_edit')
        if register_user.calenders.filter(title=event_title_edit.strip().title(),date_time=event_date_edit,category=event_category_edit,branch=event_branch_edit).exclude(id=id).exists():
          messages.error(request,'Calender already exists')
          return redirect('calender')
        else:
          CalenderModel.objects.filter(id=id).update(
            title=event_title_edit.strip().title(),
            date_time=event_date_edit,
            category=event_category_edit.strip().title(),
            branch=event_branch_edit,
            message=event_message_edit.capitalize(),
            crn_number=register_user
          )
          messages.success(request,f"{event_title_edit.strip().title()} updated successfully")
          return redirect('calender')
  else:
      messages.error(request, 'Calender not found')
      return redirect('calender')
  


@admin_required
def calander_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  calander=register_user.calenders.all().order_by('-id')
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="calender.csv"'
  writer = csv.writer(response)
  writer.writerow(['S.No','TITLE', 'DATE_TIME', 'CATEGORY','BRANCH','MESSAGE'])
  i=0
  for cal in calander:
    i+=1
    writer.writerow([i,cal.title, cal.date_time, cal.category, cal.branch, cal.message])
  return response



def calender_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        form = calender_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['calender_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 6
                imported = False
                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, "File does not match the columns")
                        return redirect('calender')

                    title = row[1]
                    date_time_str = row[2]
                    category = row[3]
                    branch_name = row[4]
                    message = row[5]

                    try:
                        date_time = parse_datetime(date_time_str)
                    except ValueError:
                        messages.error(request, f"Invalid date format for row: {row}")
                        continue

                    branch_instance = register_user.branches.filter(branch_name__iexact=branch_name.strip()).first()
                    if not branch_instance:
                        continue

                    if not all([title, category, message]):
                        continue

                    if not re.match(r"^[a-zA-Z\s]{3,50}$", title):
                        continue

                    if not re.match(r"^[a-zA-Z\s]{3,50}$", category):
                        continue

                    if len(message.strip()) < 20:
                        continue

                    if register_user.calenders.filter(title__iexact=title.strip(), date_time=date_time,
                                                       category__iexact=category.strip(), branch=branch_instance).exists():
                     
                        continue

                    CalenderModel.objects.create(
                        title=title.strip().title(),
                        date_time=date_time,
                        category=category.strip().title(),
                        branch=branch_instance,
                        message=message.capitalize(),
                        crn_number=register_user
                    )
                    imported = True


                if imported:    
                  messages.success(request, 'File imported successfully')
                else:
                  messages.error(request, 'Failed to import file')  

                return redirect('calender')
            except Exception as e:
                messages.error(request, f'Error occurred during import: {e}')
                return redirect('calender')

    calander = register_user.calenders.all().order_by('-id')
    branch = register_user.branches.all().order_by('-id')
    context = {'calander': calander, 'branch': branch}

    return render(request, 'settings_page/calender.html', context)








def get_specializations(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    course_id = request.GET.get('course_id')
    if course_id:
        specializations = register_user.specializations.filter(course_id=course_id).values('id', 'specialization_name')
        return JsonResponse(list(specializations), safe=False)
    return JsonResponse([], safe=False)



@admin_required
def getting_batch_numbers(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    course_id = request.GET.get('course_id')
    specialization_id = request.GET.get('specialization_id')

    if course_id and specialization_id:
        course = register_user.courses.get(pk=course_id)
        specialization = register_user.specializations.get(pk=specialization_id)
        batch_numbers = register_user.regulations.filter(
            course=course, specialization=specialization
        ).values('id', 'batch_number')
        return JsonResponse(list(batch_numbers), safe=False)
    
    return JsonResponse([], safe=False)





# lead stage
@admin_required
def Leads(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  data = register_user.leadstages.all().order_by('-id')
  if request.method == 'POST':
    leads= request.POST.get('Lead_stage')
    if register_user.leadstages.filter(Leadstage_name=leads.strip().title()).exists():
      messages.error(request, f'{leads.strip().title()} Lead stage already exists')
      return redirect('Leads')
    else:
      Leadstage.objects.create(
      Leadstage_name=leads.strip().title(),
      crn_number=register_user
      )
      messages.success(request, f" {leads} Lead stage created successfully.")
      return redirect('Leads')
  context={
    'data':data,
  }
  return render(request,'settings_page/Leads_stage.html' ,context)




# #Lead_status
@admin_required
def Leads_status(request, id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)  
  if register_user.leadstages.filter(id=id).exists():

    data = Leadstage.objects.get(id=id)
    if data.status == "Active":
      data.status = "Deactive"
      # messages.success(request, f" {vendor.vendor_name}  has been Deactivated.")
    else:
      data.status = "Active"
      # messages.success(request, f" {vendor.vendor_name}  has been Activated.")
    data.save()
    return redirect('Leads')
  else:
    messages.error(request, 'Lead stage not found')
    return redirect('Leads')



#Lead edit
@admin_required
def Leads_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    leads = request.POST.get('editLeadname')
    if register_user.leadstages.filter(id=id).exists():
      if register_user.leadstages.filter(Leadstage_name=leads).exclude(id=id).exists():
        messages.error(request, f'{leads} Lead stage is already exists')
        return redirect('Leads')
      else:
        register_user.leadstages.filter(id=id).update(
          Leadstage_name=leads.strip().title(),
        )
        messages.success(request, f"{leads.strip().title()} Lead stage updated successfully")    
      return redirect('Leads')
    else:
      messages.error(request,'Lead stage not found')
      return redirect('Leads')


#Lead delete
@admin_required
def Leads_delete(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if register_user.leadstages.filter(id=id).exists():
       if request.method == "POST":
         Leads = Leadstage.objects.get(id=id)
         Leads.delete()
         messages.success(request, f'{Leads.Leadstage_name.strip().title()} Lead stage deleted successfully')
         return redirect('Leads')
       else:
          messages.error(request, f'Lead stage not found')
          return redirect('Leads')
    else:
      messages.error(request, f'Lead stage not found')
      return redirect('Leads')



@admin_required
def leads_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.leadstages.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted Successfully')
    return redirect('Leads')








#Lead export
@admin_required
def Leads_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.no','Lead Name'])
  i = 0
  for Leads in register_user.leadstages.all():
    i += 1
    writer.writerow([i, Leads.Leadstage_name])

  response['Content-Disposition'] = 'attachment; filename="List_of_Leads.csv"'
  return response




#Lead import
@admin_required
def Leads_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=Lead_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['Leads_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 2
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('Leads')
          Leads_import=row[1]
          if not Leads_import:
            continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$", Leads_import):
            continue
          if register_user.leadstages.filter(Leadstage_name=Leads_import).exists():
           continue
          
          else:
            Leadstage.objects.create(
              Leadstage_name=Leads_import.strip().title(),crn_number=register_user)
        messages.success(request, f'File imported successfully')      
        return redirect('Leads')
      except Exception as e:
        messages.error(request, f'File Should be only in CSV Format ')
        return redirect('Leads')
           
  leads=register_user.leadstages.all()
  context={
      'data':leads
  }
  return render(request, 'settings_page/Leads_stage.html', context)

      



# demo management
@admin_required
def demo(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method =='POST':
    demotitle= request.POST.get('demotitle')
    demosessiontype=register_user.training_types.get(pk=request.POST.get('demosessiontype'))
    course=register_user.courses.get(pk=request.POST.get('course'))
    specialization=register_user.specializations.get(pk=request.POST.get('specialization'))
    faculty=register_user.employee.get(pk=request.POST.get('faculty'))
    courseplan=register_user.plans.get(pk=request.POST.get('courseplan'))
    branchlocation=register_user.branches.get(pk=request.POST.get('branchlocation'))
    batchno=register_user.regulations.get(pk=request.POST.get('batchno'))
    meetinglink=request.POST.get('meetinglink')
    meetingid=request.POST.get('meetingid')
    passcode=request.POST.get('passcode')
    datestartat=request.POST.get('demostartat')
    dateendat=request.POST.get('demoendat')
    demoimage=request.FILES.get('demoimage')
    demobannerimage=request.FILES.get('demobannerimage')
    demodescription=request.POST.get('demodescription')
    if register_user.demo.filter(demotitle=demotitle,batchno=batchno,).exists():
      messages.error(request, f'{demotitle} Already Exists')
      return redirect('demo')
    else:
      Demo.objects.create(
        demotitle=demotitle,
        demosessiontype=demosessiontype,
        course=course,
        specialization=specialization,
        faculty=faculty,
        courseplan=courseplan,
        branchlocation=branchlocation,
        batchno=batchno,
        meetinglink=meetinglink,
        meetingid=meetingid,
        passcode=passcode,
        datestartat=datestartat,
        dateendat=dateendat,
        demoimage=demoimage,
        demobannerimage=demobannerimage,
        demodescription=demodescription,
        crn_number=register_user

      )
      messages.success(request,"Demo Added Successfully")
      return redirect('demo')
  demo=register_user.demo.all().order_by('-id')
  demosession=register_user.training_types.all()
  coursename=register_user.courses.all()
  specialization=register_user.specializations.all()
  courseplan=register_user.plans.all()
  branchlocation=register_user.branches.all()
  batchno=register_user.regulations.all()
  faculty=register_user.employee.all()
  context={
     'demo':demo,
     'demosession':demosession,
     'coursename':coursename,
     'specialization':specialization,
     'courseplan':courseplan,
     'branchlocation':branchlocation,
     'batchno': batchno,
     'faculty':faculty,
  }  
  return render(request,'demo/demo.html',context) 
 



# demo status
@admin_required
def demo_status(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  demo=register_user.demo.get(id=id)
  if demo:
    if demo.status=="Active":
      demo.status="Deactive"
    else:
      demo.status="Active"
    demo.save()
    return redirect('demo')
  else:
     messages.error(request, f'Demo Not Found')
     return redirect('demo')





# demo edit

@admin_required
def demo_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    demotitle= request.POST.get('Demotitle')
    demosessiontype=request.POST.get('Demosessiontype')
    course=request.POST.get('Course')
    specialization=request.POST.get('Specialization')
    faculty=request.POST.get('Faculty')
    courseplan=request.POST.get('Courseplan')
    branchlocation=request.POST.get('Branchlocation')
    batchno=request.POST.get('Batchno')
    meetinglink=request.POST.get('Meetinglink')
    meetingid=request.POST.get('Meetingid')
    passcode=request.POST.get('Passcode')
    datestartat=request.POST.get('Demostartat')
    dateendat=request.POST.get('Demoendat')
    demoimage=request.FILES.get('Demoimage')
    demobannerimage=request.FILES.get('Demobannerimage')
    demodescription=request.POST.get('Demodescription')
    if 'Demoimage' in request.FILES:
      demoimage = request.FILES['Demoimage']
      if demoimage:
        demo = register_user.demo.get(id=id)
        demo.demoimage=demoimage
        demo.save()
    if 'Demobannerimage' in request.FILES:
      demobannerimage = request.FILES['Demobannerimage']
      if demobannerimage:
        demo = register_user.demo.get(id=id)
        demo.demobannerimage=demobannerimage
        demo.save()
    if register_user.demo.filter(demotitle=demotitle,course=course).exclude(id=id).exists():
      messages.error(request, f'{demo} Demo Alraedy Exists.')    
      return redirect('demo')
    else:
      register_user.demo.filter(id=id).update(
        demotitle=demotitle,
        demosessiontype=demosessiontype,
        course=course,
        specialization=specialization,
        faculty=faculty,
        courseplan=courseplan,
        branchlocation=branchlocation,
        batchno=batchno,
        meetinglink=meetinglink,
        meetingid=meetingid,
        passcode=passcode,
        datestartat=datestartat,
        dateendat=dateendat,
        demodescription=demodescription,
      )
      messages.success(request, f'{demo} Demo updated successfully')    
      return redirect('demo')

# demo delete
@admin_required
def demo_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    if register_user.demo.filter(id=id).exists():
      demo = register_user.demo.get(id=id)
      demo.delete()
      messages.success(request, f'{demo.demotitle}  deleted successfully')
      return redirect('demo')
    else:
      messages.error(request, f'demo not found')
      return redirect('demo')




@admin_required
def demo_all(request):
   crn=request.session.get('admin_user').get('crn')
   register_user=Register_model.objects.get(crn=crn)
   if request.method == "POST":
      selected_ids = request.POST.get('selected_ids')
      print(selected_ids)
      selected_ids_list = selected_ids.split(',')
      print(selected_ids_list)
      register_user.demo.filter(id__in=selected_ids_list).delete()
      messages.success(request, 'Records deleted successfully')
      return redirect('demo')
  
   messages.error(request,'Invalid request')
   return redirect('demo')






# demo export  
@admin_required  
def demo_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  demo=register_user.demo.all().order_by('-id')
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="demo.csv"'
  writer = csv.writer(response)
  writer.writerow(['S.No','Demo Title','Demo Session','Course','Specialization','Faculty','Course Plan','Branch Location','Batch No','Meeting Link','Meeting ID','Passcode','Demo Starting','Demo Ending','Demo Image','Demo Banner','Demo Description'])
  i=0
  for d in demo:
    i+=1
    writer.writerow([i,d.demotitle,d.demosessiontype,d.course,d.specialization,d.faculty,d.courseplan,d.branchlocation, d.batchno,d.meetinglink,d.meetingid,d.passcode,d.datestartat,d.dateendat,d.demoimage,d.demobannerimage,d.demodescription])
  return response




# demo import
@admin_required
def demo_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == 'POST':
        form = Demo_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['demo_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 17
                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'File should have {expected_headers} columns')
                        return redirect('demo')
                    print(row)
                    demotitle = row[1]
                    demosessiontype = row[2]
                    demosessiontype_instance = register_user.training_types.get_or_create(TrainingTypeName=demosessiontype)[0]
                    course = row[3]
                    course_instance = register_user.courses.get_or_create(course_name=course)[0]
                    specialization = row[4]
                    specialization_instance = register_user.specializations.get_or_create(specilalization_name=specialization)[0]
                    faculty = row[5]
                    faculty_instance=register_user.employee.get(first_name = faculty )
                    courseplan = row[6]
                    courseplan_instance = register_user.plans.get_or_create(plan_name=courseplan)[0]
                    branchlocation = row[7]
                    branchlocation_instance = register_user.branches.get_or_create(branch_name=branchlocation)[0]
                    batchno = row[8]
                    batchno_instance = register_user.regulations.get_or_create(batch_number=batchno)[0]
                    meetinglink = row[9]
                    meetingid = row[10]
                    passcode = row[11]
                    datestartat = row[12]
                    dateendat = row[13]
                    demoimage = row[14]
                    demobannerimage = row[15]
                    demodescription = row[16]
                    
                    # Create Demo object if all required fields are available
                    if demotitle and demosessiontype_instance and course_instance and specialization_instance and faculty_instance and courseplan_instance and branchlocation_instance and batchno_instance and meetinglink and meetingid and passcode and datestartat and dateendat and demodescription:
                        # Check if Demo already exists
                        if not Demo.objects.filter(demotitle=demotitle, course=course_instance).exists():
                            Demo.objects.create(
                                demotitle=demotitle,
                                demosessiontype=demosessiontype_instance,
                                course=course_instance,
                                specialization=specialization_instance,
                                faculty=faculty_instance,
                                courseplan=courseplan_instance,
                                branchlocation=branchlocation_instance,
                                batchno=batchno_instance,
                                meetinglink=meetinglink,
                                meetingid=meetingid,
                                passcode=passcode,
                                datestartat=datestartat,
                                dateendat=dateendat,
                                demoimage=demoimage,
                                demobannerimage=demobannerimage,
                                demodescription=demodescription,
                                crn_number=register_user
                            )
                    else:
                        messages.error(request, 'Some required fields are missing for creating Demo. Skipping this entry.')
                
                messages.success(request, 'File imported successfully')
                return redirect('demo')
            except Exception as e:
                print(e)
                messages.error(request, f'{e}. File should be in CSV format')
                return redirect('demo')
                
    return render(request, 'settings_page/demo.html', {})



# demo print
@admin_required
def demo_views(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    recipt = register_user.demo.filter(id=id).first()
    print("recipt", recipt)
    html_template = render_to_string('demo/demo_pdf.html', {'recipt': recipt})
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="receipt.pdf"'
    pisa_status = pisa.CreatePDF(html_template, dest=response)

    if pisa_status.err:
      return HttpResponse('We had some errors <pre>' + html_template + '</pre>')

    return response 


@admin_required
def load_dependencies(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    course_id = request.GET.get('course_id')
    spec_id = request.GET.get('spec_id')
    
    specializations = register_user.specializations.none()
    batch_numbers = register_user.regulations.none()
    
    if course_id:
        specializations = register_user.specializations.filter(course_name_id=course_id,status='Active')
    
    if course_id and spec_id:
        batch_numbers = register_user.regulations.filter(course_id=course_id, spec_id=spec_id,status='Active')
    
    specializations_data = list(specializations.values('id', 'specilalization_name'))
    batch_numbers_data = list(batch_numbers.values('id', 'batch_number'))
    
    return JsonResponse({
        'specializations': specializations_data,
        'batch_numbers': batch_numbers_data,
    })


def load_specializations_and_batches(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    course_id = request.GET.get('course_id')
    spec_id = request.GET.get('spec_id')
    
    specializations = register_user.specializations.none()
    batch_numbers = register_user.regulations.none()
    
    if course_id:
        specializations = register_user.specializations.filter(course_name_id=course_id,status='Active')
    
    if spec_id:
        batch_numbers = register_user.regulations.filter(course_id=course_id, spec_id=spec_id,status='Active')
    
    specializations_data = list(specializations.values('id', 'specilalization_name'))
    batch_numbers_data = list(batch_numbers.values('id', 'batch_number'))
    
    return JsonResponse({
        'specializations': specializations_data,
        'batch_numbers': batch_numbers_data,
    })







@admin_required
def course_manage(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method =='POST': 
    title= request.POST.get('course_title').strip().title()
    cos_plan=register_user.plans.get(pk=request.POST.get('course_plan'))
    cos_name=register_user.courses.get(pk=request.POST.get('course_name'))
    cos_specialization=register_user.specializations.get(pk=request.POST.get('specialization'))
    teaching_faculty=register_user.employee.get(pk=request.POST.get('faculty'))
    cos_type=register_user.batch_type.get(pk=request.POST.get('batch_type'))
    cos_duration=request.POST.get('duration')
    course_fee=request.POST.get('fee')
    discount=request.POST.get('discount')
    final_price=request.POST.get('price')
    cos_branch=register_user.branches.get(pk=request.POST.get('branch'))
    curriculum=request.FILES.get('curriculum')
    course_image=request.FILES.get('image')
    course_banner=request.FILES.get('banner')
    hardware=request.POST.get('hard').capitalize()
    software=request.POST.get('soft').capitalize()
    short_description=request.POST.get('short').capitalize()
    long_description=request.POST.get('long').capitalize()
    if register_user.course_manage.filter(course_name=cos_name,specialization=cos_specialization).exists():
      messages.error(request, f'{cos_name} with {cos_specialization}  already exists')
      return redirect('course_manage')
    else:
      CourseManage.objects.create(
        course_title=title,
        course_plan=cos_plan,
        course_name=cos_name,
        specialization=cos_specialization,
        teaching_faculty=teaching_faculty,
        batch_type=cos_type,
        duration=cos_duration,
        course_fee=course_fee,
        discount=discount,
        final_price=final_price,
        branch=cos_branch,
        curriculum=curriculum,
        course_image=course_image,
        course_banner=course_banner,
        hardware=hardware,
        software=software,
        short_description=short_description,
        long_description=long_description,
        crn_number=register_user
      )
      messages.success(request,f'{cos_name} with {cos_specialization} details created successfully')
      return redirect('course_manage')
  manage=register_user.course_manage.all().order_by('-id')
  plan=register_user.plans.all()
  name=register_user.courses.all()
  special=register_user.specializations.all()
  type=register_user.batch_type.all()
  branch_type=register_user.branches.all()
  faculty=register_user.employee.all()
  context={
    'manage':manage,
    'plan':plan,
    'name':name,
    'special':special,
    'type':type,
    'branch_type':branch_type,
    'faculty':faculty,
  }  
  return render(request,'Course/course_manage.html',context)


@admin_required
def course_manage_edit(request,id):
  if request.method == "POST":
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    title= request.POST.get('editcourse_title').strip().title()
    cos_plan=request.POST.get('editcourse_plan')
    course_id = request.POST.get('editcourse_name').strip().title()
    cos_name = register_user.courses.get(pk=course_id)
    specization_id = request.POST.get('editspecialization').strip().title()
    cos_specialization = register_user.specializations.get(pk=specization_id)
    teaching_faculty=request.POST.get('editfaculty')
    cos_type=request.POST.get('editbatch_type')
    cos_duration=request.POST.get('editduration')
    course_fee=request.POST.get('editfee')
    discount=request.POST.get('editdiscount')
    final_price=request.POST.get('editprice')
    cos_branch=request.POST.get('editbranch')
    curriculum=request.FILES.get('editcurriculum')
    course_image=request.FILES.get('editimage')
    course_banner=request.FILES.get('editbanner')
    hardware=request.POST.get('edithard').capitalize()
    software=request.POST.get('editsoft').capitalize()
    short_description=request.POST.get('editshort').capitalize()
    long_description=request.POST.get('editlong').capitalize()
    if 'editcurriculum' in request.FILES:
      curriculum = request.FILES['editcurriculum']
      if curriculum:
        manage = register_user.course_manage.get(id=id)
        manage.curriculum = curriculum  # Assign the InMemoryUploadedFile object directly
        manage.save()  # Save the model instance to update the file field
    if 'editimage' in request.FILES:
      course_image = request.FILES['editimage']
      if course_image:
        manage = register_user.course_manage.get(id=id)
        manage.course_image = course_image
        manage.save()
    if 'editbanner' in request.FILES:
      course_banner = request.FILES['editbanner']
      if course_banner:
        manage = register_user.course_manage.get(id=id)
        manage.course_banner = course_banner
        manage.save()
      if register_user.course_manage.filter(course_name=cos_name,specialization=cos_specialization,).exclude(id=id).exists():
        messages.error(request, f'{cos_name} with {cos_specialization} already exists')
        return redirect('course_manage')
      else:
        register_user.course_manage.filter(id=id).update(
          course_title=title,
          course_plan=cos_plan,
          course_name=cos_name,
          specialization=cos_specialization,
          teaching_faculty=teaching_faculty,
          batch_type=cos_type,
          duration=cos_duration,
          course_fee=course_fee,
          discount=discount,
          final_price=final_price,
          branch=cos_branch,
          hardware=hardware,
          software=software,
          short_description=short_description,
          long_description=long_description,
          crn_number=register_user
        )
        messages.success(request,f"{cos_name} with {cos_specialization} details updated successfully")
        return redirect('course_manage')

  

@admin_required
def course_manage_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    if not register_user.course_manage.filter(id=id).exists():
      messages.error(request, f'Course Management Not Found')
      return redirect('course_manage')
    if register_user.course_manage.filter(id=id).exists():
      manage = register_user.course_manage.get(id=id)
      manage.delete()
      messages.success(request,f'{manage.course_name} with {manage.specialization} details deleted successfully')
      return redirect('course_manage')
    else:
      messages.error(request,f"{manage.course_name} with {manage.specialization} course does not exist")
      return redirect('course_manage')



@admin_required
def course_manage_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.course_manage.filter(id__in=selected_ids_list).delete()
    messages.success(request, f' Records Deleted Successfully')
    return redirect('course_manage')


@admin_required
def course_manage_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  manage = register_user.course_manage.all()
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="course_manage.csv"'
  writer = csv.writer(response)
  writer.writerow(['S.no','Subject','Course Plan','Course Name','Specialization','Batch Types','Branch','Faculty Name','Course Duration','Course Fee','Discount','Final Price','Curriculum','Course Image','Course Banner','Hardware','Software','Short Description','Long Description'])
  i=0
  for d in manage:
    i+=1
    writer.writerow([i,d.course_title,d.course_plan,d.course_name,d.specialization,d.batch_type,d.branch,d.teaching_faculty,d.duration,d.course_fee,d.discount,d.final_price,d.curriculum,d.course_image,d.course_banner,d.hardware,d.software,d.short_description,d.long_description])
  return response


@admin_required
def course_manage_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=course_manage_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['import_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 19
        for row in reader:
          if len(row)!=expected_headers:
            messages.error(request,f"file do not match the columns")
            return redirect('course_manage')
          course_title=row[1]
          course_plan=row[2]
          course_plan_instance=register_user.plans.filter(plan_name=course_plan).first()
          course_name=row[3]
          course_name_instance=register_user.courses.filter(course_name=course_name).first()
          specialization=row[4]
          specialization_instance=register_user.specializations.filter(specilalization_name=specialization).first()
          batch_type=row[5] 
          batch_type_instance=register_user.batch_type.filter(batchtype_name=batch_type).first()
          branch=row[6]
          branch_instance=register_user.branches.filter(branch_name=branch).first()
          teaching_faculty=row[7]
          teaching_instance = register_user.employee.filter(first_name = teaching_faculty).first()
          duration=row[8]
          course_fee=row[9]
          discount=row[10]
          final_price=row[11]
          curriculum=row[12]
          course_image=row[13]
          course_banner=row[14]
          hardware=row[15]
          software=row[16]
          short_description=row[17]
          long_description=row[18]
          if not course_title or not course_plan_instance or not course_name_instance or not specialization_instance or not teaching_instance or not batch_type_instance or not duration or not course_fee or not discount or not final_price or not curriculum or not course_image or not course_banner or not branch_instance or not hardware or not software:
             continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$", course_title):
            continue
          course_title.strip().title()
          teaching_faculty.strip().title()
          if not re.match(r"^[0-9]+$", duration):
            continue
          duration.strip().title()
          if not re.match(r"^[0-9]+(\.[0-9]+)?$", course_fee):
            continue
          course_fee.strip().title()
          if not re.match(r"^[0-9]+$", discount):
            continue
          discount.strip().title()
          if not re.match(r"^[0-9]+(\.[0-9]+)?$", final_price):
            continue
          final_price.strip().title()
          if register_user.course_manage.filter(course_name=course_name_instance,specialization=specialization_instance,).exists():
            continue
          else:
            CourseManage.objects.create(
              course_title=course_title.strip().title(),
              course_plan=course_plan_instance,
              course_name=course_name_instance,
              specialization=specialization_instance,
              branch=branch_instance,
              batch_type=batch_type_instance,
              teaching_faculty= teaching_instance,
              duration=duration,
              course_fee=course_fee,
              discount=discount,
              final_price=final_price,
              curriculum=curriculum,
              course_image=course_image,
              course_banner=course_banner,
              hardware=hardware,
              software=software,
              short_description=short_description,
              long_description=long_description,
              crn_number=register_user
            )
        messages.success(request, f'File Imported Successfully')
        return redirect('course_manage')
      except Exception as e:
        messages.error(request, f'{e} File format not valid')
        return redirect('course_manage')
        
  manage=register_user.course_manage.all().order_by('-id')
  course_plan=register_user.plans.all()
  course_name=register_user.courses.all()
  specialization=register_user.specializations.all()
  batch_type=register_user.Batchtype.all()
  branch=register_user.branches.all()
  teaching_faculty=register_user.employee.all()
  
  context={
    'manage':manage,
    'course_plan':course_plan,
    'course_name':course_name,
    'specialization':specialization,
    'batch_type':batch_type,
    'branch':branch,
    'teaching_faculty':teaching_faculty,
  }
  return render(request,'Course/course_manage.html',context)



@admin_required
def manage_views(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  recipt = register_user.course_manage.filter(id=id).first()
  html_template = render_to_string('Course/manage_pdf.html', {'recipt': recipt})
  response = HttpResponse(content_type='application/pdf')
  response['Content-Disposition'] = 'attachment; filename="course_manage.pdf"'
  pisa_status = pisa.CreatePDF(html_template, dest=response)

  if pisa_status.err:
    return HttpResponse('We had some errors <pre>' + html_template + '</pre>')
  return response




# Dependances from Courses to Specialization

@admin_required
def depnd_specilization(request, id_course):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  course = register_user.courses.get(id=id_course)
  display_spec = register_user.specializations.filter(course_name=course,status='Active')
  specialization_list = [{'id': spec.id, 'name': spec.specilalization_name} for spec in display_spec]
  
  return JsonResponse({'specialization_list': specialization_list})






# employee start here

#Employee function
@admin_required
def employee_list(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    first_name=request.POST.get('first_name')
    last_name=request.POST.get('last_name')
    personal_number=request.POST.get('personal_number')
    alternative_number=request.POST.get('alternative_number')
    personal_email=request.POST.get('personal_email')
    professional_email=request.POST.get('professional_email')
    blood_group=request.POST.get('blood_group')
    gender=request.POST.get('gender')
    date_of_birth=request.POST.get('date_of_birth')
    nationality=request.POST.get('nationality')
    religion=request.POST.get('religion')
    caste=request.POST.get('caste')
    Employee_id=request.POST.get('Employee_id')
    employee_type=register_user.employee_types.get(id=request.POST.get('employee_type'))
    department_name=register_user.departments.get(id=request.POST.get('department_name'))
    designation_name=register_user.designations.get(id=request.POST.get('designation_name'))
    branch=register_user.branches.get(id=request.POST.get('branch'))
    course_id=request.POST.get('course_id')
    specialization_id=request.POST.get('specialization_id')
    # course_id=register_user.courses.get(id=request.POST.get('course_id'))
    # specialization_id=register_user.specializations.get(id=request.POST.get('specialization_id'))
    salary=request.POST.get('salary')
    profile_image=request.FILES.get('profile_image')
    country=request.POST.get('country')
    state=request.POST.get('state')
    city=request.POST.get('city')
    pincode=request.POST.get('pincode')
    address=request.POST.get('address')
    aadhar_card=request.POST.get('aadhar_card')
    pan_card=request.POST.get('pan_card')
    aadhar_card_pdf=request.FILES.get('aadhar_card_pdf')
    pan_card_pdf=request.FILES.get('pan_card_pdf')
    rand_password=generate_password()
   
   
    
    if register_user.employee.filter(personal_number=personal_number).exists():
      messages.error(request, f'{personal_number} is already exists')
      return redirect('employees')
    if register_user.employee.filter(personal_email=personal_email).exists():
      messages.error(request, f'{personal_email} is already exists')
      return redirect('employees')
    if alternative_number:
      if register_user.employee.filter(alternative_number=alternative_number).exists():
        messages.error(request, f'{alternative_number} is already exists')
        return redirect('employees')
    if professional_email:
      if register_user.employee.filter(professional_email=professional_email).exists():
        messages.error(request, f'{professional_email} is already exists')
        return redirect('employees')
    if aadhar_card:
      if register_user.employee.filter(aadhar_card=aadhar_card).exists():
        messages.error(request, f'{aadhar_card} is already exists')
        return redirect('employees')
    if pan_card:
      if register_user.employee.filter(pan_card=pan_card).exists():
        messages.error(request, f'{pan_card} is already exists')
        return redirect('employees')
   
    
    else:
      if course_id and specialization_id:
        course=register_user.courses.get(id=course_id)
        specialization=register_user.specializations.get(id=specialization_id)
      employee=register_user.employee.create(
      first_name=first_name,
      last_name=last_name,
      personal_number=personal_number,
      alternative_number=alternative_number,
      personal_email=personal_email,
      professional_email=professional_email,
      blood_group=blood_group,
      gender=gender,
      date_of_birth=date_of_birth,
      nationality=nationality,
      religion=religion,
      caste=caste,
      Employee_id=Employee_id,
      employee_type=employee_type,
      department_name=department_name,
      designation_name=designation_name,
      branch=branch,
      course_id=course if course_id else None,
      specialization_id= specialization if specialization_id else None,
      
      salary=salary,
      profile_image=profile_image,
      country=country,
      state=state,
      city=city,
      pincode=pincode,
      address=address,
      aadhar_card=aadhar_card,
      pan_card=pan_card,
      aadhar_card_pdf=aadhar_card_pdf,
      pan_card_pdf=pan_card_pdf,
      # password=rand_password,
      crn_number=register_user
      )
      if course_id and specialization_id:
        subject = f'{request.session.get("admin_user").get("company_name")}'
        message = (
          f'Hi {first_name} {last_name},\n\n'
          f'Thank You for joining {request.session.get("admin_user").get("company_name")}. we are happy to have you onboard. Your Employee Id is {employee.Employee_id}. Your Department is {department_name}. Your Designation is {designation_name}.\n\n'
          f'Your Details: \n\n'
          f'Course: {course.course_name}\n'
          f'Specialization: {specialization.specilalization_name}\n'
          f'Salary: Rs.{salary}\n'
          f'Username: {personal_email}\n'
          f'Password: {rand_password}\n\n'
          f'To Login Click here URL: {settings.URL_DOMAI}\n\n'
          f'Regards,\n'
          f'{request.session.get("admin_user").get("company_name")}'
          f'\n')
        email_from=settings.EMAIL_HOST_USER
        email_to=[personal_email]
        send_mail(subject, message, email_from, email_to)
      else:
        subject = f'{request.session.get("admin_user").get("company_name")}'
        message = (
          f'Hi {first_name} {last_name},\n\n'
          f'Thank You for joining {request.session.get("admin_user").get("company_name")}. we are happy to have you onboard. Your Employee Id is {employee.Employee_id}. Your Department is {department_name}. Your Designation is {designation_name}.\n\n'
          f'Your Details: \n\n'
          f'Salary: Rs.{salary}\n'
          f'Username: {personal_email}\n'
          f'Password: {rand_password}\n\n'
          f'To Login Click here URL: {settings.URL_DOMAI}\n\n'
          f'Regards,\n'
          f'{request.session.get("admin_user").get("company_name")}'
          
        )
        email_from=settings.EMAIL_HOST_USER
        email_to=[personal_email]
        send_mail(subject, message, email_from, email_to)
      

      messages.success(request, f'Employee is added successfully')
      return redirect('employees')
      
      
      
  employee=register_user.employee.all().order_by('-id')
  employee_type=register_user.employee_types.all().order_by('-id')
  department=register_user.departments.all().order_by('-id')
  designation=register_user.designations.all().order_by('-id')
  courses = register_user.courses.filter(status='Active')
  specializations = register_user.specializations.filter(status="Active").order_by('-id')
  branch=register_user.branches.all().order_by('-id')
  context={
      'employee':employee,
      'employee_type':employee_type,
      'department':department,
      'designation':designation,
      'courses':courses,
      'specializations':specializations,
      'branch':branch
    }
    
  

  return render(request,'employee_management/employee_list.html',context)





def get_specialization_for_emp(request, id):
    specialization = Specialization.objects.filter(course_name=id, status="Active")
    specialization_list = [{'id': spc.id, 'specialization': spc.specilalization_name} for spc in specialization]
    return JsonResponse({'specialization_list': specialization_list})







@admin_required
def employee_status1(request, id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    employee = register_user.employee.get(id=id)
    if employee.status == "Active":
        employee.status = "Deactive"
    else:
      employee.status = "Active"
    employee.save()
    return redirect('employees')


  

@admin_required
def employee_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)

  if register_user.employee.filter(id=id).exists():
    register_user.employee.filter(id=id).delete()
    messages.success(request, f'Employee deleted successfully')
    return redirect('employees')
  else:
    messages.error(request, f'Employee not found')
    return redirect('employees')





@admin_required
def employee_list_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.employee.filter(id__in=selected_ids_list).delete()
    messages.success(request, f'Employee Deleted Successfully')
    return redirect('employees')

@admin_required
def employee_infos(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee=register_user.employee.get(id=id)
  # department=register_user.departments.all().order_by('-id')
  # short_list=[]
  # for departments in department:
  #   # Split department name by space and capitalize the first letter of each word
  #       department_words = [word[0].upper() for word in departments.department_name.split()]
  #       # Join the capitalized first letters to form the short form
  #       short_form = ''.join(department_words)
  #       short_list.append(short_form)
    
  
  context={
    'employee':employee,
    # 'department':zip(department,short_list)
    
  }
  return render(request,'employee_management/employee_info.html',context)

@admin_required
def employee_schedules(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee=register_user.employee.get(id=id)
  context={
    'employee':employee
  }
  return render(request,'employee_management/employee_schudles.html',context)
@admin_required
def employee_schedules_mock(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee=register_user.employee.get(id=id)
  context={
    'employee':employee
  }
  return render(request,'employee_management/employee_schudles_mock.html',context)
@admin_required
def employee_complaints(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee=register_user.employee.get(id=id)
  context={
    'employee':employee
  }
  return render(request,'employee_management/employee_complaints.html',context)

@admin_required
def employee_history(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee=register_user.employee.get(id=id)
  context={
    'employee':employee
  }
  return render(request,'employee_management/employee_histroy.html',context)
@admin_required
def employee_leaves(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee=register_user.employee.get(id=id)
  context={
    'employee':employee
  }
  return render(request,'employee_management/employee_leaves.html',context)


@admin_required
def employee_update(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=="POST":
    first_name=request.POST.get('first_name_edit').capitalize()
    last_name=request.POST.get('last_name_edit').capitalize()
    personal_number=request.POST.get('personal_number_edit')
    alternative_number=request.POST.get('alternative_number_edit')
    personal_email=request.POST.get('personal_email_edit')
    professional_email=request.POST.get('professional_email_edit')
    blood_group=request.POST.get('blood_group_edit')
    gender=request.POST.get('gender_edit')
    date_of_birth=request.POST.get('date_of_birth_edit')
    nationality=request.POST.get('nationality_edit')
    religion=request.POST.get('religion_edit')
    caste=request.POST.get('caste_edit')
    Employee_id=request.POST.get('Employee_id_edit')
    employee_type=register_user.employee_types.get(pk=request.POST.get('employee_type_edit'))
    department_name=register_user.departments.get(pk=request.POST.get('department_name_edit'))
    designation_name=register_user.designations.get(pk=request.POST.get('designation_name_edit'))
    # specialization_id =  Specialization.objects.get(pk=request.POST.get('specialization_id'))
    # course_id =  Course.objects.get(pk=request.POST.get('course_id'))
    course_id=request.POST.get('course_id_edit')
    specialization_id=request.POST.get('specialization_id_edit')
    branch=register_user.branches.get(pk=request.POST.get('branch_edit'))
    profile_image=request.FILES.get('profile_image_edit')
    salary=request.POST.get('salary_edit')
    country=request.POST.get('country_edit')
    state=request.POST.get('state_edit')
    city=request.POST.get('city_edit')
    pincode=request.POST.get('pincode_edit')
    address=request.POST.get('address_edit')
    aadhar_card=request.POST.get('aadhar_card_edit')
    pan_card=request.POST.get('pan_card_edit')
    aadhar_card_pdf=request.FILES.get('aadhar_card_pdf_edit')
    pan_card_pdf=request.FILES.get('pan_card_pdf_edit')
    rand_password=generate_password()
    
    if register_user.employee.filter(personal_number=personal_number).exclude(id=id).exists():
      messages.error(request, 'Employee Personal number already exists')
      return redirect('employees')
    if alternative_number:
      if register_user.employee.filter(alternative_number=alternative_number).exclude(id=id).exists():
        messages.error(request, 'Employee Alternative number already exists')
        return redirect('employees')
    if register_user.employee.filter(personal_email=personal_email).exclude(id=id).exists():
      messages.error(request, 'Employee Personal email already exists')
      return redirect('employees')
    if professional_email:
      if register_user.employee.filter(professional_email=professional_email).exclude(id=id).exists():
        messages.error(request, 'Employee Professional email already exists')
        return redirect('employees')
    if register_user.employee.filter(aadhar_card=aadhar_card).exclude(id=id).exists():
      messages.error(request, 'Employee Aadhar card already exists')
      return redirect('employees')
    if pan_card:
      if register_user.employee.filter(pan_card=pan_card).exclude(id=id).exists():
        messages.error(request, 'Employee Pan card already exists')
        return redirect('employees')
    
       
    
    
   
    if 'profile_image_edit' in request.FILES:
      profile_image = request.FILES['profile_image_edit']
      if profile_image:
        employee = register_user.employee.get(id=id)
        employee.profile_image = profile_image  # Assign the InMemoryUploadedFile object directly
        employee.save()  # Save the model instance to update the file field
    if 'aadhar_card_pdf_edit' in request.FILES:
      aadhar_card_pdf = request.FILES['aadhar_card_pdf_edit']
      if aadhar_card_pdf:
        employee = register_user.employee.get(id=id)
        employee.aadhar_card_pdf = aadhar_card_pdf
        employee.save()
    if 'pan_card_pdf_edit' in request.FILES:
      pan_card_pdf = request.FILES['pan_card_pdf_edit']
      if pan_card_pdf:
        employee = register_user.employee.get(id=id)
        employee.pan_card_pdf = pan_card_pdf
        employee.save()
        
      
      
        
    else:
      if course_id and specialization_id:
        info=register_user.employee.filter(id=id).update(
          course_id=register_user.courses.get(pk=course_id),
          specialization_id=register_user.specializations.get(pk=specialization_id),
        )
      register_user.employee.filter(id=id).update(
      first_name=first_name,
      last_name=last_name,
      personal_number=personal_number,
      alternative_number=alternative_number,
      personal_email=personal_email,
      professional_email=professional_email,
      blood_group=blood_group,
      gender=gender,
      date_of_birth=date_of_birth,
      nationality=nationality,
      religion=religion,
      caste=caste,
      
      employee_type=employee_type,
      department_name=department_name,
      designation_name=designation_name,
      branch=branch,
      salary=salary,
      country=country,
      state=state,
      city=city,
      pincode=pincode,
      address=address,    
      aadhar_card=aadhar_card,
      pan_card=pan_card,
      password=rand_password,
      crn_number=register_user)
      if course_id and specialization_id:
        subject = f'{request.session.get("admin_user").get("company_name")}'
        message = (
          f'Hi {first_name} {last_name},\n\n'
          f'Thank You for joining {request.session.get("admin_user").get("company_name")}. we are happy to have you onboard. Your Employee Id is {employee.Employee_id}. Your Department is {department_name}. Your Designation is {designation_name}.\n\n'
          f'Your Details: \n\n'
          f'Course: {course_id}\n'
          f'Specialization: {specialization_id}\n'
          f'Salary: Rs.{salary}\n'
          f'Username: {personal_email}\n'
          f'Password: {rand_password}\n\n'
          f'To Login Click here URL: {settings.URL_DOMAI}\n\n'
          f'Regards,\n'
          f'{request.session.get("admin_user").get("company_name")}'
          )
        email_from=settings.EMAIL_HOST_USER
        email_to=[personal_email]
        send_mail(subject, message, email_from, email_to)
      else:
        subject = f'{request.session.get("admin_user").get("company_name")}'
        message = (
          f'Hi {first_name} {last_name},\n\n'
          f'Thank You for joining {request.session.get("admin_user").get("company_name")}. we are happy to have you onboard. Your Employee Id is {employee.Employee_id}. Your Department is {department_name}. Your Designation is {designation_name}.\n\n'
          f'Your Details: \n\n'
          f'Salary: Rs.{salary}\n'
          f'Username: {personal_email}\n'
          f'Password: {rand_password}\n\n'
          f'To Login Click here URL: {settings.URL_DOMAI}\n\n'
          f'Regards,\n'
          f'{request.session.get("admin_user").get("company_name")}'
          
        )
        email_from=settings.EMAIL_HOST_USER
        email_to=[personal_email]
        send_mail(subject, message, email_from, email_to)
      
    
        
      

    messages.success(request, f'Employee updated successfully')
    return redirect('employees')
      








@admin_required
def employee_detail(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee = register_user.employee.get(id=id)
  context={
    'employee':employee
  }
  html_template = render_to_string('employee_management/employee_detail.html',context)
  response = HttpResponse(content_type ='application/pdf')
  response['Content-Disposition']= 'filename="Employee.pdf"'
  
  pisa_status = pisa.CreatePDF(html_template,dest=response)
  
  if pisa_status.err:
    messages.error(request,f'Error Rendering PDF')
  return response







@admin_required
def employee_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  employee= register_user.employee.all().order_by('-id')
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="employee.csv"'
  writer = csv.writer(response)
  writer.writerow(['S.No','First Name','Last Name','Personal Number','Alternative Number','Personal Email','Professional Email','Blood Group','Gender','Date of Birth','Nationality','Religion','Caste','Employee Type','Depeartment Name','Designation Name','Branch','Country','State','City','Pincode','Address','Aadhar Card','Pan Card'])
  i=0
  for emp in employee:
    i+=1
    writer.writerow([i,emp.first_name,emp.last_name,emp.personal_number,emp.alternative_number,emp.personal_email,emp.professional_email,emp.blood_group,emp.gender,emp.date_of_birth,emp.nationality,emp.religion,emp.caste,emp.employee_type,emp.department_name,emp.designation_name,emp.branch,emp.country,emp.state,emp.city,emp.pincode,emp.address,emp.aadhar_card,emp.pan_card])
  return response
    
  
  


def employee_upload(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        form = EmployeeForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['employee_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 24
                imported = False

                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'File should have {expected_headers} columns')
                        return redirect('employees')

                    first_name = row[1]
                    last_name = row[2]
                    personal_number = row[3]
                    alternative_number = row[4]
                    personal_email = row[5]
                    professional_email = row[6]
                    blood_group = row[7]
                    gender = row[8]
                    date_formats = ['%Y/%m/%d', '%Y-%m-%d', '%m/%d/%Y', '%m-%d-%Y', '%d-%m-%Y']
                    date_of_birth = None
                    for date_format in date_formats:
                        try:
                            date_of_birth = datetime.strptime(row[9], date_format).date()
                            break  # Break the loop if successfully parsed
                        except ValueError:
                            pass  # Continue trying other formats

                    if date_of_birth is None:
                        continue

                    nationality = row[10]
                    religion = row[11]
                    caste = row[12]
                    employee_type = row[13]
                    department_name = row[14]
                    designation_name = row[15]
                    branch = row[16]
                    country = row[17]
                    state = row[18]
                    city = row[19]
                    pincode = row[20]
                    address = row[21]
                    aadhar_card = row[22]
                    pan_card = row[23]

                    employee_type_instance = register_user.employee_types.filter(employee_type=employee_type).first()
                    department_name_instance = register_user.departments.filter(department_name=department_name).first()
                    designation_name_instance = register_user.designations.filter(designation_name=designation_name).first()
                    branch_instance = register_user.branches.filter(branch_name=branch).first()

                    if not personal_number or not personal_email or not employee_type_instance \
                            or not department_name_instance or not designation_name_instance or not branch_instance:
                        continue

                   
                    if not re.match(r"^[a-zA-Z\s]{3,50}$",first_name):
                      continue
                    first_name.strip().title()
                    if not re.match(r"^[a-zA-Z\s]{3,50}$",last_name):
                      continue
                    last_name.strip().title()
                    if not re.match(r"^[^\.][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", personal_email):
                        continue
                    if professional_email:  
                        if not re.match(r"^[^\.][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", professional_email):
                            continue
                      
                    if not re.match(r"^(?:(?:\+|0{0,2})91)?[6-9]\d{9}$",personal_number):
                        continue
                    if alternative_number:
                        if not re.match(r"^(?:(?:\+|0{0,2})91)?[6-9]\d{9}$",alternative_number):
                            continue
                    if not re.match(r"^[2-9]\d{11}$",aadhar_card):
                        continue
                    if pan_card:
                       if not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]{1}$",pan_card):
                         continue
                    if register_user.employee.filter(personal_number=personal_number).exists():
                        continue
                    if alternative_number:
                        if register_user.employee.filter(alternative_number=alternative_number).exists():
                            continue
                    
                    if register_user.employee.filter(personal_email=personal_email).exists():
                        continue
                    if professional_email:
                        if register_user.employee.filter(professional_email=professional_email).exists():
                            continue
                    if register_user.employee.filter(aadhar_card=aadhar_card).exists():
                        continue
                    if pan_card:
                        if register_user.employee.filter(pan_card=pan_card).exists():
                            continue
                    else:
                        Employee_model.objects.create(
                            first_name= first_name.strip().title(),
                            last_name=last_name.strip().title(),
                            personal_number=personal_number,
                            alternative_number=alternative_number,
                            personal_email=personal_email,
                            professional_email=professional_email,
                            blood_group=blood_group,
                            gender=gender.capitalize(),
                            date_of_birth=date_of_birth,
                            nationality=nationality.capitalize(),
                            religion=religion.capitalize(),
                            caste=caste.upper(),
                            employee_type=employee_type_instance,
                            department_name=department_name_instance,
                            designation_name=designation_name_instance,
                            branch=branch_instance,
                            country=country.capitalize(), 
                            state=state.capitalize(),
                            city=city.capitalize(),
                            pincode=pincode,
                            address=address,
                            aadhar_card=aadhar_card,
                            pan_card=pan_card,
                            crn_number=register_user)
                        imported = True

                if imported:
                    messages.success(request, 'Employees added successfully')
                else:
                    messages.error(request, 'File failed to import')

                return redirect('employees')

            except Exception as e:
                messages.error(request, f'Error occurred during import: {e}')
                return redirect('employees')

    employee = register_user.employee.all().order_by('-id')
    department = register_user.departments.all().order_by('-id')
    designation = register_user.designations.all().order_by('-id')
    employee_type = register_user.employee_type.all().order_by('-id')
    branch = register_user.branches.all().order_by('-id')
    context = {'employee': employee, 'department': department, 'designation': designation,
               'employee_type': employee_type, 'branch': branch}

    return render(request, 'employee_management/employee_list.html', context)          
        

@admin_required
def get_department(request, department_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    department = register_user.departments.get(pk=department_id)
    designation = register_user.designations.filter(department_name=department, status='Active')
    department_data = [{'id': designation.id, 'designation_name': designation.designation_name} for designation in designation]
    return JsonResponse({'designation_data': department_data})




@admin_required
def get_designation(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  department_id = request.GET.get('department_id')
  designation = register_user.designations.filter(department_name=department_id,status='Active')
  return JsonResponse({'designation':list(designation)})





#Jobtype
def Job_type(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  data = register_user.job_types.all().order_by('-id')
  if request.method == 'POST':
     jobs= request.POST.get('Job_Type')
     if register_user.job_types.filter(JobType_name=jobs.strip().title()).exists():
       messages.error(request, f'{jobs.strip().title()} job type name already exists')
       return redirect('Job_type')
     else:
       Jobtype.objects.create(
       JobType_name=jobs.strip().title(),
       crn_number=register_user
       )
       messages.success(request, f" {jobs.strip().title()} job type name created successfully.")
       return redirect('Job_type')
  context={
     'data': data
  }
  return render(request,'settings_page/job_type.html',context)






#Job status
def Job_status(request, id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  data = register_user.job_types.get(id=id)
  if data:
    if data.status == "Active":
      data.status = "Deactive"
      # messages.success(request, f" {vendor.vendor_name}  has been Deactivated.")
    else:
      data.status = "Active"
      # messages.success(request, f" {vendor.vendor_name}  has been Activated.")
    data.save()
    return redirect('Job_type')
  else:
     messages.error(request,f'Job type not found')
     return redirect('Job_type')


#Job edit
def Job_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  
  if request.method == "POST":
    jobs = request.POST.get('editJobtype')
    if register_user.job_types.filter(id=id).exists():
      if register_user.job_types.exclude(id=id).filter(JobType_name=jobs.strip().title).exists():
        messages.error(request, f'{jobs.strip().title()} job already exists')
        return redirect('Job_type')
      else:
        register_user.job_types.filter(id=id).update(
          JobType_name=jobs.strip().title(), 
        )
        messages.success(request, f"{jobs.strip().title()} job type updated successfully")    
        return redirect('Job_type')
    else:
      messages.error(request,'Job type not found')
      return redirect('Job_type')
          

#Job delete
def Job_delete(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    
    if request.method == "POST":
      Job_type = register_user.job_types.get(id=id)
      if Job_type:
        Job_type.delete()
        messages.success(request, f'{Job_type.JobType_name} job type deleted successfully')
        return redirect('Job_type')
      else:
        messages.error(request, f'Job type not found')
        return redirect('Job_type')




@admin_required
def job_type_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.job_types.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('Job_type')




#Job export
def Job_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.no','Job type'])
  i = 0
  for Job_type in register_user.job_types.all():
    i += 1
    writer.writerow([i, Job_type.JobType_name])

  response['Content-Disposition'] = 'attachment; filename="Job_type.csv"'
  return response

#Job import
def Job_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=Job_type_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['Jobs_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 2
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('Job_type')
          Job_type_import=row[1]
          if not Job_type_import:
            continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$", Job_type_import):
              continue
          if register_user.job_types.filter(JobType_name=Job_type_import.strip().title()).exists():
           continue

          
          else:
            Jobtype.objects.create(
              JobType_name=Job_type_import.strip().title(),
              crn_number=register_user)
        messages.success(request, f'File imported successfully')      
        return redirect('Job_type')
      except Exception as e:
        messages.error(request, f'File Should be only in CSV Format ')
        return redirect('Job_type')
           
  jobs=Jobtype.objects.all()
  context={
      'data':jobs
  }
  return render(request, 'settings_page/job_type.html', context)





#Job category
def job_category(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  data = register_user.job_category.all().order_by('-id')
  if request.method == 'POST':
    cat= request.POST.get('Job_category')
    if register_user.job_category.filter(Jobcategory_name=cat.strip().title()).exists():
      messages.error(request, f'{cat.strip().title()} category already exists')
      return redirect('job_category')
    else:
      Job_Category.objects.create(
      Jobcategory_name=cat.strip().title(),
      crn=register_user
      )
      messages.success(request, f" {cat.strip().title()} category created successfully.")
      return redirect('job_category')
  context={
    'data': data
  }
  return render(request,'settings_page/jobcategory.html',context)






#job status
def job_category_status(request, id):
  crn = request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  data = register_user.job_category.get(id=id)
  if data:
    if data.status == "Active":
      data.status = "Deactive"
    else:
      data.status = "Active"
    data.save()
    return redirect('job_category')
  else:
     messages.error(request, f'Job category not found')
     return redirect('job_category')





# category edit
def job_category_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    cat = request.POST.get('editJobcategory')
    if register_user.job_category.filter(id=id).exists():
      if register_user.job_category.exclude(id=id).filter(Jobcategory_name=cat.strip().title()).exists():
        messages.error(request, f'{cat.strip().title()} job category is already exists')
        return redirect('job_category')
      else:
        register_user.job_category.filter(id=id).update(
          Jobcategory_name=cat.strip().title(), 
        )
        messages.success(request, f"{cat.strip().title()} job category updated successfully")    
        return redirect('job_category')
    else:
      messages.error(request,'Jobtype not found')
      return redirect('job_category')
          

#Job delete
def job_category_delete(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == "POST":
      category = register_user.job_category.get(id=id)
      if category:
        category.delete()
        messages.success(request, f'{category.Jobcategory_name} category deleted successfully')
        return redirect('job_category')
      else:
        messages.error(request, f'Job category not found')
        return redirect('job_category')


@admin_required
def job_category_all(request):
  crn = request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.job_category.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('job_category')






#job export
def job_category_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.no','Job category'])
  i = 0
  for category in register_user.job_category.all():
    i += 1
    writer.writerow([i, category.Jobcategory_name])

  response['Content-Disposition'] = 'attachment; filename="category.csv"'
  return response



#JOb import
def job_category_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=category_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['Category_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 2
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
              messages.error(request, f'File should have {expected_headers} columns')
              return redirect('job_category')
          category_import=row[1]
          if not category_import:
            continue
          if not re.match(r"^[a-zA-Z\s]{3,50}$", category_import):
            continue

          if register_user.job_category.filter(Jobcategory_name=category_import.strip().title()).exists():
           continue
          else:
            Job_Category.objects.create(
              Jobcategory_name=category_import.strip().title(),crn=register_user)
            imported = True
        if imported:
          messages.success(request, f'File imported successfully')      
        else:
          messages.error(request, f'Failed to import file')
        return redirect('job_category')

               
      except Exception as e:
        messages.error(request, f'File Should be only in CSV Format ')
        return redirect('job_category')        
  cat=Job_Category.objects.all()
  context={
      'cat': cat,
  }
  return render(request, 'settings_page/jobcategory.html', context)





def qualification(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  qual=register_user.qualifications.all().order_by('-id')
  if request.method=='POST':
    qualifiy=request.POST.get('qualification')
    if register_user.qualifications.filter(qualification_name=qualifiy.strip().title()).exists():
      messages.error(request, f'{qualifiy.strip().title()} already exists')
      return redirect('qualification')
    else:
      Qualification.objects.create(
        qualification_name=qualifiy.strip().title(),
        crn_number=register_user
        )
      messages.success(request, f" {qualifiy.strip().title()} created successfully.")
      return redirect('qualification')
  context={
    'qual':qual,
  }
  return render(request,'settings_page/qualification.html',context)





def qualification_status(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  qual=register_user.qualifications.get(id=id)
  if qual:
    if qual.status =='Active':
      qual.status = 'Deactive'
    else:
      qual.status = 'Active'
    qual.save()
    return redirect('qualification')
  else:
     messages.error(request,'Qualification not found')
     return redirect('qualification')
     

def qualification_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)

  if request.method=='POST':
    qualify=request.POST.get('editqualification')
    if register_user.qualifications.filter(id=id).exists():
      register_user.qualifications.filter(id=id).update(
        qualification_name=qualify.strip().title()
      )
      messages.success(request, f"{qualify.strip().title()} updated successfully.")
      return redirect('qualification')
    else:
      messages.error(request, f"Qualification not found")
      return redirect('qualification')






def qualification_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    
    qual=register_user.qualifications.get(id=id)
    if qual:
      qual.delete()
      messages.success(request, f"{qual.qualification_name} has been successfully deleted.")
      return redirect('qualification')
    else:
       messages.error(request,"Qualification not found")
       return redirect('qualification')



@admin_required
def qualification_delete_all(request):
  crn = request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.qualifications.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('qualification')






def qualification_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  response = HttpResponse(content_type='text/csv')
  writer = csv.writer(response)
  writer.writerow(['S.no',' Qualification Name'])
  i = 0
  for qual in register_user.qualifications.all():
    i += 1
    writer.writerow([i, qual.qualification_name])

  response['Content-Disposition'] = 'attachment; filename="qualification.csv"'
  return response


def qualification_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method=='POST':
    form=qualification_import_form(request.POST,request.FILES)
    if form.is_valid():
      try:
        csv_file=request.FILES['qualification_file']
        decoded_file=csv_file.read().decode('utf-8')
        reader=csv.reader(decoded_file.splitlines())
        headers=next(reader)
        expected_headers = 2
        imported = False
        for row in reader:
          if len(row)!=expected_headers:
            messages.error(request, f'File should have {expected_headers} columns')
            return redirect('qualification')
          qualification_import=row[1]
          if not qualification_import:
            continue
          if not re.match(r'^[a-zA-Z\s!@#$%^&*()\-_+=\[\]{};:\'",.<>?`~]{3,50}$', qualification_import):
            continue

          if register_user.qualifications.filter(qualification_name=qualification_import.strip().title()).exists():
           continue
          else:
            Qualification.objects.create(
              qualification_name=qualification_import.strip().title(),crn_number=register_user)
        messages.success(request, f'File imported successfully')      
        return redirect('qualification')
      except Exception as e:
        messages.error(request, f'File Should be only in CSV Format ')
        return redirect('qualification')
           
  qual=register_user.qualifications.all()
  context={
      'qual':qual
  }
  return render(request,'settings_page/qualification.html',context)










@admin_required
def jobrole(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  role = register_user.jobrole.all().order_by("-id")  

  if request.method == "POST":
    jobrole = request.POST.get('jobrole_name')
    if register_user.jobrole.filter(jobrole_name=jobrole.strip().title()).exists():
      messages.error(request, f'{jobrole} Job Role already exists for this user')
    else:
      Jobrole.objects.create(
          crn_number=register_user,  
          jobrole_name=jobrole.strip().title(),
      )
      messages.success(request, f'{jobrole.strip().title()} Job Role Created Successfully')
    return redirect('jobrole')

  context = {
    'role': role,
  }
  return render(request, 'settings_page/roles.html', context)


# job role status

@admin_required
def jobrole_status(request, id):
  crn = request.session.get('admin_user').get('crn')
  if crn:
    register_user = Register_model.objects.get(crn=crn)
    try:
        role = register_user.jobrole.get(id=id)
    except Jobrole.DoesNotExist:
        messages.error(request, 'Job Role Not Found')
        return redirect('jobrole')
  else:
    messages.error(request, 'Invalid User Session')
    return redirect('jobrole')
  if role:
    if role.status == "Active":
      role.status = "Deactive"
    else:
      role.status = "Active"
    role.save()
    return redirect('jobrole')
  else:
    messages.error(request, 'Job Role Not Found')
    return redirect('jobrole')  


# Job Edit
@admin_required
def jobrole_edit(request, id):
  crn = request.session.get('admin_user').get('crn')
  if crn:
    register_user = Register_model.objects.get(crn=crn)
    try:
      role = register_user.jobrole.get(id=id)
    except Jobrole.DoesNotExist:
      messages.error(request, 'Job Role Not Found')
      return redirect('jobrole')
  else:
    messages.error(request, 'Invalid User Session')
    return redirect('jobrole')

  if request.method == "POST":
    jobrole_name = request.POST.get('edit_jobrole')
    if register_user.jobrole.exclude(id=id).filter(jobrole_name=jobrole_name).exists():
      messages.error(request, f'{jobrole_name} Job Role already exists')
      return redirect('jobrole')
    else:
      role.jobrole_name = jobrole_name
      role.save()
      messages.success(request, f"{jobrole_name} Job Role updated Successfully")
      return redirect('jobrole')

  return render(request, 'settings_page/roles.html')

# Job Role Delete
@admin_required
def jobrole_delete(request, id):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        try:
          role = register_user.jobrole.get(id=id)
        except Jobrole.DoesNotExist:
          messages.error(request, 'Job Role Not Found')
          return redirect('jobrole')
    else:
      messages.error(request, 'Invalid User Session')
      return redirect('jobrole')

    if request.method == "POST":
      jobrole_name = role.jobrole_name
      role.delete()
      messages.success(request, f'{jobrole_name} Job Role Deleted Successfully')
      return redirect('jobrole')

# job delete all
def jobrole_del_all(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids = request.POST.get('selected_ids')
    selected_ids_list = selected_ids.split(',')
    register_user.jobrole.filter(id__in=selected_ids_list).delete()
    messages.success(request, 'Job Role Deleted Successfully')
    return redirect('jobrole')
  else:
    messages.error(request, 'invalid request')
    return redirect('jobrole')






# Job Role Export
@admin_required
def jobrole_export(request):
  crn = request.session.get('admin_user').get('crn')
  if crn:
    register_user = Register_model.objects.get(crn=crn)
    role = register_user.jobrole.all()
  else:
    messages.error(request, 'Invalid User Session')
    return redirect('jobrole')
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="jobrole.csv"'
  writer = csv.writer(response)
  writer.writerow(['S.No', 'Job Role Name'])
  i = 0
  for d in role:
    i += 1
    writer.writerow([i, d.jobrole_name])

  return response


# Job Role Import
@admin_required
def jobrole_import(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)

  if request.method == 'POST':
      form = jobrole_import_form(request.POST, request.FILES)
      if form.is_valid():
          try:
              csv_file = request.FILES['jobrole_file']
              decoded_file = csv_file.read().decode('utf-8')
              reader = csv.reader(decoded_file.splitlines())
              headers = next(reader)
              expected_headers = 2
              imported = False
              
              for row in reader:
                  if len(row) != expected_headers:
                      messages.error(request, f'File Should Have {expected_headers} Columns')
                      return redirect('jobrole')
                  rolejob = row[1]
                  if not rolejob:
                    continue
                  if not re.match(r"^[a-zA-Z\s\W]{3,50}$", rolejob):
                    continue
                  rolejob.strip().title()
                  if register_user.jobrole.filter(jobrole_name=rolejob.strip().title()).exists():
                      continue
                  else:
                      Jobrole.objects.create(
                          jobrole_name=rolejob,
                          crn_number=register_user
                      )
                      imported = True
              if imported:        
                  messages.success(request, 'File imported successfully')
              else:
                  messages.error(request,'Job Role Already Exists')    
              return redirect('jobrole')
          except Exception as e:
              messages.error(request, 'File Should be only in CSV Format')
              return redirect('jobrole')

  job = register_user.jobrole.all().order_by("-id")
  context = {
      'job': job,
  }
  return render(request, 'settings_page/designations.html', context)








































# Leads start here

def getting_teaching_emp(request,course_id,spec_id):

  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  employee = Employee_model.objects.filter(course_id=course_id,specialization_id = spec_id).all()
  employee_list = [{'id': emp.id, 'first_name': emp.first_name, 'last_name':emp.last_name} for emp in employee]
  
  return JsonResponse(employee_list, safe=False)






@admin_required
def lead_prospects(request):
 
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  # getting prospects lead
  prospects = register_user.leads.filter(lead_position="PROSPECT").all().order_by("-id")
  print(prospects)
  
  # getting branch
  branches = register_user.branches.filter(status='Active')
  # getting courses
  courses = register_user.course_manage.all()
  # getting training types
  training_types = register_user.training_types.filter(status='Active')
  # getting prospect types
  prospect_types = register_user.prospect_types.filter(status='Active')
  # getting faculty
  # faculty = register_user.employee.all()
  prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
  lead_count = register_user.leads.filter(lead_position = "LEAD").count()
  mql_count = register_user.leads.filter(lead_position = 'MQL').count()
  sql_count = register_user.leads.filter(lead_position = 'SQL').count()
  request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
  opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
  admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
  spam_count = register_user.leads.filter(lead_position = 'SPAM').count()
  faculty = register_user.employee.filter(designation_name__designation_name = "Teaching Staff").all()

  
  context={
     'prospects':prospects,
     'Branches':branches,
     'courses':courses,
     'training_types':training_types,
     'prospect_types':prospect_types,
     'faculty':faculty,
     'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
     
  }
  return render(request,'Leads/prospects.html', context)



@admin_required
def get_branches(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    branches = register_user.branches.filter(status='Active').values('id', 'branch_name')
    print("ajex branches",branches)
    return JsonResponse(list(branches), safe=False)

@admin_required
def get_courses(request, branch_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    try:
        branch = register_user.branches.get(id=branch_id, status='Active')
        # Get the CourseManage objects for the specified branch
        courses = register_user.course_manage.filter(branch=branch)

        # Serialize course data manually
        course_data = [{'id': course.id, 'course_name': str(course.course_name), 'specialization': str(course.specialization)} for course in courses]
        
        return JsonResponse(course_data, safe=False)
    except BranchModel.DoesNotExist:
        return JsonResponse([], safe=False)
    except Exception as e:
        print(e)
        return JsonResponse([], safe=False)
 






@admin_required
def lead_leads(request):

  
  return render(request,'Leads/leads.html')


# leads 
@admin_required
def leads(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    leads = register_user.leads.filter(lead_position="LEAD").all()
    lead_stage = register_user.leadstages.filter(status='Active').all()
    faculty = register_user.employee.all()
    demo = register_user.demo.all()
    batches = register_user.regulations.all()
    upi = register_user.upi.filter(status = "Active")
    net_banking = register_user.net_banking.filter(status="Active")
    prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
    lead_count = register_user.leads.filter(lead_position = "LEAD").count()
    mql_count = register_user.leads.filter(lead_position = 'MQL').count()
    sql_count = register_user.leads.filter(lead_position = 'SQL').count()
    request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
    opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
    admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
    spam_count = register_user.leads.filter(lead_position = 'SPAM').count()





    context = {
        'leads': leads,
        'lead_stage':lead_stage,
        'faculty':faculty,
        'demo':demo,
        'batches':batches,
        'upi':upi,
        'net_banking':net_banking,
        'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
    }
    return render(request, 'Leads/lead.html', context)


@admin_required
def get_upi_details(request, upi_id):
    
    try:
        upi_payment = upipayments.objects.get(id=upi_id)        
    
        upi_details = {
            'upipayments_name': upi_payment.upipayments_name,
            'mobilenumber': upi_payment.mobilenumber,
            'upiid': upi_payment.upiid,
            'status': upi_payment.status,
      
        }
        
     
        return JsonResponse(upi_details)
    
    except upipayments.DoesNotExist:
  
        return JsonResponse({'error': 'UPI ID does not exist'}, status=404)



@admin_required
def submit_enquiry_form(request):
    crn = request.session.get('admin_user', {}).get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == "POST":
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        mobile_number = request.POST.get('mobile_number')
        email = request.POST.get('email')
        branch_name_id = request.POST.get('branch_name')
        course_name_id = request.POST.get('course_name')
        training_type_id = request.POST.get('training_type')
        lead_source_id = request.POST.get('lead_source')

        # Validate mobile number format
        mobile_pattern = r'^\d{10}$'
        if not re.match(mobile_pattern, mobile_number):
            return JsonResponse({'otpSent': False, 'error': 'Invalid mobile number format.'})

        # Check if a lead with the same mobile number already exists
        existing_lead = register_user.leads.filter(mobile_number=mobile_number).first()
        if existing_lead:
            print("error")
            return JsonResponse({'otpSent': False, 'error': 'A lead with this mobile number already exists.'})

        print("Branch Name ID:", branch_name_id)
        print("Course Name ID:", course_name_id)
        print("Training Type ID:", training_type_id)
        print("Lead Source ID:", lead_source_id)

        if branch_name_id is None or branch_name_id == '':
            print("Branch Name ID is missing or empty.")
            return JsonResponse({'otpSent': False, 'error': 'Please select a branch.'})

        if course_name_id is None or course_name_id == '':
            print("Course Name ID is missing or empty.")
            return JsonResponse({'otpSent': False, 'error': 'Please select a course.'})

        try:
            branch = register_user.branches.get(id=branch_name_id)
        except BranchModel.DoesNotExist:
            print(f"BranchModel with id {branch_name_id} does not exist.")
            return JsonResponse({'otpSent': False, 'error': 'Invalid branch selected.'})

        try:
            course = register_user.course_manage.get(id=course_name_id)
        except CourseManage.DoesNotExist:
            print(f"CourseManage with course_name__id {course_name_id} does not exist.")
            return JsonResponse({'otpSent': False, 'error': 'Invalid course selected.'})

        try:
            training_type = register_user.training_types.get(id=training_type_id)
        except TrainingType.DoesNotExist:
            print(f"TrainingType with id {training_type_id} does not exist.")
            return JsonResponse({'otpSent': False, 'error': 'Invalid training type selected.'})

        try:
            lead_type = register_user.prospect_types.get(id=lead_source_id)
        except ProspectType_model.DoesNotExist:
            print(f"ProspectType_model with id {lead_source_id} does not exist.")
            return JsonResponse({'otpSent': False, 'error': 'Invalid lead source selected.'})

        print(first_name)
        print(last_name)
        print(mobile_number)
        print(email)
        print(branch.branch_name)
        print(course.course_name.course_name)
        print(training_type.TrainingTypeName)
        print(lead_type.prospect_type)

        otp = random.randint(100000, 999999)
        print("Generated OTP:", otp)

        # Store form data and OTP in the session
        request.session['lead_data'] = {
            'first_name': first_name,
            'last_name': last_name,
            'mobile_number': mobile_number,
            'email': email,
            'course_name': course_name_id,
            'branch_name': branch.id,
            'training_type': training_type.id,
            'lead_source': lead_type.id,
            'crn': crn,
        }
        request.session['otp'] = otp

        return JsonResponse({'otpSent': True})

    else:
        return JsonResponse({'otpSent': False, 'error': 'Invalid request method.'})


@admin_required
def enquiry_verify_otp(request):
    if request.method == "POST":
        otp_entered = request.POST.get('otp')
        otp_generated = request.session.get('otp')
        lead_data = request.session.get('lead_data', {})

        # Retrieve the register_user object
        crn = lead_data.get('crn')
        register_user = Register_model.objects.get(crn=crn)

        print("submitted", otp_entered)
        print("this is session data", lead_data.get('first_name'))
        print("this is session data", lead_data.get('last_name'))
        print("this is session data", lead_data.get('mobile_number'))
        print("this is session data", lead_data.get('email'))
        print("this is session data", lead_data.get('course_name'))
        print("this is session data", lead_data.get('branch_name'))
        print("this is session data", lead_data.get('training_type'))
        print("this is session data", lead_data.get('lead_source'))
        print("this is session data", lead_data.get('crn'))

        if register_user.leads.filter(mobile_number=lead_data.get('mobile_number')).exists():
            print("exists")
            return JsonResponse({'otpVerified': False, 'error': 'A lead with this mobile number already exists.'})
        if register_user.leads.filter(mobile_number=lead_data.get('email')).exists():
            print("email exists")
            return JsonResponse({'otpVerified': False, 'error': 'A lead with this email already exists.'})
        if register_user.leads.filter(Q (mobile_number=lead_data.get('mobile_number')) & Q(email=lead_data.get('email'))).exists():
            print("both exists")
            return JsonResponse({'otpVerified': False, 'error': 'A lead with this mobile number and email already exists.'})  
              
        
        print(otp_entered,otp_generated)  
        if otp_entered:
            if int(otp_entered) == int(otp_generated):
                print("verified")
                register_user = Register_model.objects.get(crn=lead_data.get('crn'))
                course_name = register_user.course_manage.get(pk=lead_data.get('course_name'))
                lead = LeadModel.objects.create(
                    first_name=lead_data.get('first_name'),
                    last_name=lead_data.get('last_name'),
                    mobile_number=lead_data.get('mobile_number'),
                    email=lead_data.get('email'),
                    course_name=register_user.course_manage.get(pk=lead_data.get('course_name')),
                    branch_name=register_user.branches.get(pk=lead_data.get('branch_name')),
                    training_type=register_user.training_types.get(pk=lead_data.get('training_type')),
                    lead_sourse=register_user.prospect_types.get(pk=lead_data.get('lead_source')),
                    crn_number=register_user
                )
                lead.generate_token()
                print("created")

                subject = 'Registration Successful'
                message = (
                f"Hello {lead_data.get('first_name')},\n\n"
                "Thank you for registering with us. We are excited to have you join our community. "
                "Here are your registration details:\n\n"
                f"Registration Number: {lead.token_id}\n"
                f"Course Enrolled: {course_name.course_name}.\n"
                "\nWe look forward to providing you with a quality learning experience. "
                "Should you have any questions or need further information, please do not hesitate to contact us.\n\n"
                "Best Regards,\n"
                f"{request.session.get('admin_user').get('company_name')}\n"
                "Contact Information"
                )
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [lead_data.get('email')]
                send_mail(subject, message, email_from, recipient_list)

                del request.session['otp']
                del request.session['lead_data']

                success_url = reverse('lead_prospects')
                return JsonResponse({'otpverification': True, 'redirectUrl': success_url, 'message': 'OTP verified, and lead created successfully.'})
            else:
                return JsonResponse({'otpverification': False, 'message': 'OTP verification failed.'}) 
            
        else:
            return JsonResponse({'otpverification': False, 'message': 'OTP verification failed.'})



    # Fallback redirect if request method is not POST
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})


@admin_required
def mark_as_lead(request, prospect_id):
    crn = request.session.get('admin_user', {}).get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if register_user.leads.filter(id=prospect_id).exists():
        prospect = register_user.leads.get(id=prospect_id)
        prospect.lead_position = 'LEAD'
        prospect.save(update_fields=['lead_position'])
        messages.success(request, 'Prospect marked as LEAD successfully')
        return redirect('lead_prospects')
    else:
        messages.error(request, 'Prospect not found')
        return redirect('lead_prospects')







# moviing lead data to mql
@admin_required
def lead_move_to_mql(request,id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":

       leadType = request.POST.get('leadType')
       demo_assigned = request.POST.get('demodate')
       Leaddescription = request.POST.get('Leaddescription')
       courseFaculty = request.POST.get('courseFaculty')
       student = register_user.leads.get(id=id)
       register_user.leads.filter(id=id).update(

          lead_type = leadType,
          demo = register_user.demo.get(pk=demo_assigned),
          lead_description = Leaddescription,
          lead_position = 'MQL',
          faculty = register_user.employee.get(pk=courseFaculty)
       )
       demo = register_user.demo.get(pk=demo_assigned)
       message = f""" Hello {student.first_name} {student.last_name},\n\n
       Thank you for your interest in {request.session.get("admin_user").get("company_name")}. We are happy to have you onboard. \n\n
       Your Demo for {demo.demotitle} has been scheduled. \n\n
       Demo Link: {demo.meetinglink }
       Demo Date: {demo.datestartat} \n\n
       """
       subject = 'Demo Scheduled'

       send_mail(subject, message, settings.EMAIL_HOST_USER, [student.email])

       messages.success(request,'Lead moved to MQL')   
       return redirect('leads')
    else:
      messages.success(request,'Invalid request')
      return redirect('leads')   
       

# mql here
@admin_required
def mql(request):
  
  
  crn = request.session.get('admin_user', {}).get('crn')
  register_user = Register_model.objects.get(crn=crn)
  leads = register_user.leads.filter(lead_position='MQL').all().order_by('-id')
  demos = register_user.demo.filter(status='Active').all().order_by('-id')
  batches = register_user.regulations.filter(status = 'Active').all().order_by('-id')
  faculty = register_user.employee.all()
  upi = register_user.upi.filter(status = "Active")
  net_banking = register_user.net_banking.filter(status="Active")
  prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
  lead_count = register_user.leads.filter(lead_position = "LEAD").count()
  mql_count = register_user.leads.filter(lead_position = 'MQL').count()
  sql_count = register_user.leads.filter(lead_position = 'SQL').count()
  request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
  opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
  admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
  spam_count = register_user.leads.filter(lead_position = 'SPAM').count()  
  

  context={
     "leads":leads,
     "demos":demos,
     'batches':batches,
     'faculty':faculty,
     'upi':upi,
     'net_banking':net_banking,
     'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count,
     
  }
  return render(request,'Leads/mql.html', context)



# reschedule the demo here
@admin_required
def reschedule_demo(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
     demo_assigned = request.POST.get('demodate')
     if demo_assigned:
        dem=register_user.leads.filter(id=id).update(
           demo = register_user.demo.get(pk=demo_assigned)
        )
        demo = register_user.demo.get(id=demo_assigned)
        message = f""" Hello {register_user.leads.get(id=id).first_name} {register_user.leads.get(id=id).last_name},\n\n
          Your Demo has been scheduled. \n\n
          Demo Link: {demo.meetinglink }
          Demo Date: {demo.datestartat} \n\n
        """
        subject = 'Demo Scheduled'

        send_mail(subject, message, settings.EMAIL_HOST_USER, [register_user.leads.get(id=id).email])

        messages.success(request,'Demo rescheduled successfully')  
        return redirect('mql')
     else:
       messages.error(request,'Demo not found')
       return redirect('mql')
  else:
    messages.error(request,'Invalid request')
    return redirect('mql')   





# moveing from mql to sql
@admin_required
def move_to_sql(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
     mql_lead = register_user.leads.get(id=id)
     mql_description = request.POST.get('mqldescription')
     courseFaculty = request.POST.get('courseFaculty')
     leadType = request.POST.get('leadType')
     if register_user.leads.filter(id=id).exists():
        register_user.leads.filter(id=id).update(
           lead_position = 'SQL',
           mql_description = mql_description,
           lead_type = leadType,
        )
        messages.success(request,'MQL Lead moved to SQL')
     
        return redirect('mql')
     else:
      messages.error(request,'MQL Lead not found')
      return redirect('mql')
  else:
     messages.error(request,'Invalid request method')
     return redirect('mql')   
          




# sql here
@admin_required
def sql(request):
  
  crn = request.session.get('admin_user', {}).get('crn')
  register_user = Register_model.objects.get(crn=crn)
  leads = register_user.leads.filter(lead_position="SQL").order_by("-id")
  plans = register_user.plans.filter(status="Active").order_by("-id")
  batches = register_user.regulations.filter(status = 'Active').all().order_by('-id')
  faculty = register_user.employee.all()
  upi = register_user.upi.filter(status = "Active")
  net_banking = register_user.net_banking.filter(status="Active")  
  prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
  lead_count = register_user.leads.filter(lead_position = "LEAD").count()
  mql_count = register_user.leads.filter(lead_position = 'MQL').count()
  sql_count = register_user.leads.filter(lead_position = 'SQL').count()
  request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
  opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
  admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
  spam_count = register_user.leads.filter(lead_position = 'SPAM').count()    
  
  context={
     "leads":leads,
     'plans':plans,
     'batches':batches,
     'faculty':faculty,
     'upi':upi,
     'net_banking':net_banking,
     'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
     
  }
  return render(request,'Leads/sql.html', context) 


# move to opportunity
@admin_required
def move_to_opportunity(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
     sql_lead = register_user.leads.get(id=id)
     if register_user.leads.filter(id=id).exists():
        register_user.leads.filter(id=id).update(
          lead_position = 'OPPORTUNITY',
          lead_type = request.POST.get("leadType"),
          sql_description = request.POST.get("sqldescription"),
        )

        messages.success(request,'SQL Lead moved to OPPORTUNITY')
        return redirect('opportunity')
     else:
      messages.error(request,'SQL Lead not found')
      return redirect('opportunity')
  else:
    messages.error(request,"Invalid request")
    return redirect('opportunity')
    




@admin_required
def opportunity(request):
  crn = request.session.get('admin_user', {}).get('crn')
  register_user = Register_model.objects.get(crn=crn)
  leads = register_user.leads.filter(lead_position='OPPORTUNITY').order_by("-id")
  batches = register_user.regulations.filter(status = 'Active').all().order_by('-id')
  faculty = register_user.employee.all()
  upi = register_user.upi.filter(status = "Active")
  net_banking = register_user.net_banking.filter(status="Active")   
  prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
  lead_count = register_user.leads.filter(lead_position = "LEAD").count()
  mql_count = register_user.leads.filter(lead_position = 'MQL').count()
  sql_count = register_user.leads.filter(lead_position = 'SQL').count()
  request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
  opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
  admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
  spam_count = register_user.leads.filter(lead_position = 'SPAM').count() 


  context={
     "leads":leads,
     'batches':batches,
     'faculty':faculty,
     'upi':upi,
     'net_banking':net_banking,
     'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
  }

  return render(request,'Leads/opportunity.html', context) 


@admin_required
def move_to_admission(request, id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == "POST":
        opportunity_lead = register_user.leads.filter(id=id).first()
        
        if opportunity_lead:
            # Capture the existing token_id
            existing_token_id = opportunity_lead.token_id

            if request.POST.get('paymenttype') == 'Cash':
                opportunity_lead.lead_position = 'ADMITTED'
                opportunity_lead.faculty = register_user.employee.get(pk=request.POST.get('courseFaculty'))
                opportunity_lead.batch_number = register_user.regulations.get(pk=request.POST.get("batchno"))
                opportunity_lead.admission_date = timezone.now()
                opportunity_lead.amount_paid = request.POST.get('admissionFee')

                # Exclude token_id from the update
                opportunity_lead.save(update_fields=['lead_position', 'faculty', 'batch_number', 'admission_date','amount_paid'])

                # Restore the existing token_id
                opportunity_lead.token_id = existing_token_id
                
                Student_payment.objects.create(
                    crn_number=register_user,
                    payment_amount=request.POST.get('admissionFee'),
                    student_id=opportunity_lead,
                    mode_of_payment=request.POST.get('paymenttype'),
                    transaction_id=request.POST.get('transactionId'),
                    course_id=opportunity_lead.course_name,
                    date_of_payment=timezone.now()
                )

                

                messages.success(request, 'Lead moved to Admission')
                return redirect('admissions')

            elif request.POST.get('paymenttype') == 'UPI':
                opportunity_lead.lead_position = 'ADMITTED'
                opportunity_lead.faculty = register_user.employee.get(pk=request.POST.get('courseFaculty'))
                opportunity_lead.batch_number = register_user.regulations.get(pk=request.POST.get("batchno"))
                opportunity_lead.admission_date = timezone.now()
                opportunity_lead.amount_paid = request.POST.get('admissionFee')


                # Exclude token_id from the update
                opportunity_lead.save(update_fields=['lead_position', 'faculty', 'batch_number', 'admission_date','amount_paid'])

                # Restore the existing token_id
                opportunity_lead.token_id = existing_token_id
                
                Student_payment.objects.create(
                    crn_number=register_user,
                    payment_amount=request.POST.get('admissionFee'),
                    student_id=opportunity_lead,
                    mode_of_payment=request.POST.get('paymenttype'),
                    transaction_id=request.POST.get('transactionId'),
                    course_id=opportunity_lead.course_name,
                    date_of_payment=timezone.now(),

                    upi_id=register_user.upi.get(pk=request.POST.get('upi_id_id'))
                )

                messages.success(request, 'Lead moved to Admission')
                return redirect('admissions')

            elif request.POST.get('paymenttype') == 'netbanking':
                opportunity_lead.lead_position = 'ADMITTED'
                opportunity_lead.faculty = register_user.employee.get(pk=request.POST.get('courseFaculty'))
                opportunity_lead.batch_number = register_user.regulations.get(pk=request.POST.get("batchno"))
                opportunity_lead.admission_date = timezone.now()
                opportunity_lead.amount_paid = request.POST.get('admissionFee')



                # Exclude token_id from the update
                opportunity_lead.save(update_fields=['lead_position', 'faculty', 'batch_number', 'admission_date','amount_paid'])

                # Restore the existing token_id
                opportunity_lead.token_id = existing_token_id
                
                Student_payment.objects.create(
                    crn_number=register_user,
                    payment_amount=request.POST.get('admissionFee'),
                    student_id=opportunity_lead,
                    mode_of_payment=request.POST.get('paymenttype'),
                    transaction_id=request.POST.get('transactionId'),
                    course_id=opportunity_lead.course_name,
                    date_of_payment=timezone.now(),
                    net_banking=register_user.net_banking.get(pk=request.POST.get('net_banking_id'))
                )

             

                messages.success(request, 'Lead moved to Admission')
                return redirect('admissions')

            else:
                messages.error(request, 'Invalid payment type')
                return redirect('admissions')

        else:
            messages.error(request, 'Lead not found')
            return redirect('admissions')

    else:
        messages.error(request, 'Invalid request')
        return redirect('admissions')          
          
         

@admin_required
def admission_recipt(request, id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    # Fetch the lead based on the provided ID
    leads = get_object_or_404(register_user.leads, id=id)
    total_paid = leads.amount_paid
    remaining_fee = leads.course_name.course_fee - total_paid
    print("total value",total_paid)
    # Render HTML template with lead details
    html_template = render_to_string('Leads/lead_pdf.html', {'leads': leads,'remaining_fee':remaining_fee})
    # Create PDF response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'filename="{leads.first_name}_{leads.last_name}_receipt.pdf"'
    # Convert HTML to PDF and attach to response
    pisa_status = pisa.CreatePDF(html_template, dest=response)
    if pisa_status.err:
        return HttpResponse('We encountered some errors while generating the PDF.')
    return response




@admin_required
def request_dis(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    # sql_lead = register_user.leads.get(id=id)
    if register_user.leads.filter(id=id).exists():
      register_user.leads.filter(id=id).update(
        requested_amount = request.POST.get("requested_amount"),
        request_for_discount = True,
        lead_position  = "REQUEST_DISCOUNT",
        messages_for_discount = request.POST.get('messages_for_discount')
      )
    messages.success(request,'Request sent successfully')
    return redirect('request_discounts')
  else:
    messages.error(request,'Invalid request')
    return redirect('request_discounts')



@admin_required
def request_discounts(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  leads = register_user.leads.filter(lead_position='REQUEST_DISCOUNT').order_by("-id")
  prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
  lead_count = register_user.leads.filter(lead_position = "LEAD").count()
  mql_count = register_user.leads.filter(lead_position = 'MQL').count()
  sql_count = register_user.leads.filter(lead_position = 'SQL').count()
  request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
  opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
  admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
  spam_count = register_user.leads.filter(lead_position = 'SPAM').count()  
  
  
  context={
     "leads":leads,
     'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
  }
  return render(request,'Leads/request_discounts.html', context)







# adminssions
@admin_required
def admissions(request):
  crn = request.session.get('admin_user', {}).get('crn')
  register_user = Register_model.objects.get(crn=crn)
  leads = register_user.leads.filter(lead_position='ADMITTED').order_by("-id")
  prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
  lead_count = register_user.leads.filter(lead_position = "LEAD").count()
  mql_count = register_user.leads.filter(lead_position = 'MQL').count()
  sql_count = register_user.leads.filter(lead_position = 'SQL').count()
  request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
  opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
  admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
  spam_count = register_user.leads.filter(lead_position = 'SPAM').count() 
  


  context={
     "leads":leads,
     'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
  }

  return render(request,'Leads/admission.html', context)

@admin_required
def mark_as_spam(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = get_object_or_404(Register_model, crn=crn)

    if request.method == "POST":
        selected_ids = request.POST.getlist('selected_id')
        leads = LeadModel.objects.filter(crn_number=register_user, id__in=selected_ids)

        if leads:
            leads.update(lead_position="SPAM")

        return redirect('spam')

    return redirect('spam')




















def multiple_mark_as_spam(request):
    if request.method == "POST":
        selected_ids = request.POST.getlist('selected_ids[]')
        for i in selected_ids:
           print(i)
       
        return HttpResponseRedirect(reverse('spam'))





def spam(request):
  try:
    crn = request.session.get('admin_user', {}).get('crn')
    register_user = Register_model.objects.get(crn=crn)
    leads = register_user.leads.filter(lead_position="SPAM").order_by("-id")
    #  leads = Lead_generation.objects.filter(lead_postion="SPAM").order_by('-token_generated_date')
    batches = register_user.regulations.filter(status = 'Active').all().order_by('-id')
    faculty = register_user.employee.all()
    upi = register_user.upi.filter(status = "Active")
    net_banking = register_user.net_banking.filter(status="Active")      
    prospect_count = register_user.leads.filter(lead_position = "PROSPECT").count()
    lead_count = register_user.leads.filter(lead_position = "LEAD").count()
    mql_count = register_user.leads.filter(lead_position = 'MQL').count()
    sql_count = register_user.leads.filter(lead_position = 'SQL').count()
    request_discount_count = register_user.leads.filter(lead_position = 'REQUEST_DISCOUNT').count()
    opportunity_count = register_user.leads.filter(lead_position = 'OPPORTUNITY').count()
    admission_count = register_user.leads.filter(lead_position = 'ADMITTED').count()
    spam_count = register_user.leads.filter(lead_position = 'SPAM').count()     
    
  except Exception as e:
     messages.error(request,'data was not found')

     
  context={
        "leads":leads,
        "batches":batches,
        "faculty":faculty,
        "upi":upi,
        "net_banking":net_banking,

        'prospect_count':prospect_count,
     'lead_count':lead_count,
     'mql_count':mql_count,
     'sql_count':sql_count,
     'request_discount_count':request_discount_count,
     'opportunity_count':opportunity_count,
     'admission_count':admission_count,
     'spam_count':spam_count
        
      }
     
  return render(request,'Leads/spam.html', context) 

      




def lead_stage(request, lead_id):
    crn = request.session.get('admin_user', {}).get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        lead = get_object_or_404(register_user.leads, id=lead_id)
        lead_stage_id = request.POST.get('leadstage')

        try:
            lead_stage = register_user.leadstages.get(id=lead_stage_id)
            lead.lead_stage = lead_stage
            lead.save(update_fields=['lead_stage'])
            messages.success(request, 'Lead stage updated successfully.')
        except Leadstage.DoesNotExist:
            messages.error(request, 'Invalid lead stage selected.')
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
        
        return redirect('leads')
    else:
        messages.error(request, 'Invalid request method.')
        return redirect('leads')



        








# # demo print
# def demo_views(request,id):
#     recipt = Demo.objects.filter(id=id).first()
#     print("recipt", recipt)
#     html_template = render_to_string('demo/demo_pdf.html', {'recipt': recipt})
#     response = HttpResponse(content_type='application/pdf')
#     response['Content-Disposition'] = 'attachment; filename="receipt.pdf"'
#     pisa_status = pisa.CreatePDF(html_template, dest=response)

#     if pisa_status.err:
#       return HttpResponse('We had some errors <pre>' + html_template + '</pre>')

#     return response










# student card
def student_card(request):
    return render(request,'success.html')

  



# finance start here
@admin_required
def student_payment_verification(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  students=register_user.leads.filter(lead_position="ADMITTED").order_by("-id")
  payment=register_user.student_payment.all().order_by("-id") 
  context={
    'payment':payment,
    'students':students
  }
  return render(request,'finance_and_accounts/finance_and_accounts.html',context)

@admin_required
def student_payment_update(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    verify_id=request.POST.get('verify_id')
    payment_verification=request.POST.get('payment_verification')
    remarks=request.POST.get('remarks')
    register_user.student_payment.filter(id=verify_id).update(payment_verification=payment_verification,remarks=remarks)
    if payment_verification =='Received':
      password=random_password()
      register_user.student_payment.filter(id=verify_id).update(student_password=password)
      for obj in register_user.student_payment.filter(id=verify_id):
        subject=f'{request.session.get("admin_user").get("company_name")}'
        message=(
          f'Hi {obj.student_id.first_name} {obj.student_id.last_name},\n\n'
          f'Thank You for joining {request.session.get("admin_user").get("company_name")}. we are happy to have you onboard. \n\n'
          f'Your Token Id is: {obj.student_id.token_id}. You have successfully completed your registration, for course {obj.student_id.course_name}. and specialization {obj.student_id.course_name.specialization}.Your Batch Number is {obj.student_id.batch_number.batch_number}.  \n\n'
          f'Your username is {obj.student_id.email} and password is {password} \n\n'
          f'To Login Click here URL: {settings.URL_DOMAI}\n\n'
          f'In case of any query, please contact us at {request.session.get("admin_user").get("name")}.\n\n'
          f'Thank you for using {request.session.get("admin_user").get("company_name")}.'
        )
        StudentCredentials.objects.create(
          student_id=obj.student_id,
          email=obj.student_id.email,
          password=password,
          crn = register_user
        )

        #send email to the student
        email_form=settings.EMAIL_HOST_USER
        to_email=[obj.student_id.email]
        send_mail(subject,message,email_form,to_email)
      return redirect('payment_verification')
    elif payment_verification =='Not Received':
      for obj in register_user.student_payment.filter(id=verify_id):
        subject=f'{request.session.get("admin_user").get("company_name")}'
        message=(
          f"Dear {obj.student_id.faculty.first_name} {obj.student_id.faculty.last_name},\n\n"
          f'We hope this email finds you well\n\n'
          f'It is with a sense of duty that we inform you of an issue regarding the payment status of {obj.student_id.first_name} {obj.student_id.last_name} ({obj.student_id.token_id}), for the course "{obj.student_id.course_name}" in batch number {obj.student_id.batch_number.batch_number}. We request you to please update the payment status of this student. Student currently has {obj.payment_amount}. Your attention to this matter is greatly appreciated, as it is crucial for maintaining the integrity of our enrollment process.\n\n'
          f'Thank you for your cooperation and support.\n\n'
          f'Your Sincerely,\n{request.session.get("admin_user").get("company_name")}\n'
          )
        #send email to the BD
        email_form=settings.EMAIL_HOST_USER
        to_email=[obj.student_id.faculty.personal_email]
        send_mail(subject,message,email_form,to_email)
      return redirect('payment_verification')
    elif payment_verification =='Pending':
      for obj in register_user.student_payment.filter(id=verify_id):
        subject=f'{request.session.get("admin_user").get("company_name")}'
        message=(
          f"Hi {obj.student_id.first_name} {obj.student_id.last_name},\n\n"
          f'We hope this email finds you well\n\n'
          f'This is gentel reminder that payment for {obj.payment_amount} for the course "{obj.student_id.course_name}" in batch number {obj.student_id.batch_number.batch_number} is {obj.payment_status}.\n\n'
          f'Thank you for your cooperation and support.\n\n'
          f'Your Sincerely,\n{request.session.get("admin_user").get("company_name")}\n'
          
        )
        message2=(
          f'Dear {obj.student_id.faculty.first_name} {obj.student_id.faculty.last_name},\n\n'
          f'We hope this email finds you well\n\n'
          f'This to inform that {obj.student_id.first_name} {obj.student_id.last_name} ({obj.student_id.token_id}) payment is pending  currently has {obj.payment_amount} for the course "{obj.student_id.course_name}" in batch number {obj.student_id.batch_number.batch_number}. \n\n'
          f'Thank you for your cooperation and support.\n\n'
          f'Your Sincerely,\n{request.session.get("admin_user").get("company_name")}\n'
          
        )
        email_form=settings.EMAIL_HOST_USER
        to_email=[obj.student_id.faculty.personal_email]
        to_student=[obj.student_id.email]
        send_mail(subject,message,email_form,to_student)
        send_mail(subject,message2,email_form,to_email)
      return redirect('payment_verification')
    else:
      for obj in register_user.student_payment.filter(id=verify_id):
        subject=f'{request.session.get("admin_user").get("company_name")}'
        message=(
          f'Dear {obj.student_id.faculty.first_name} {obj.student_id.faculty.last_name},\n\n'
          f'We hope this email finds you well\n\n'
          f'It has come to our attention that there is a discrepancy or suspicious activity. The student {obj.student_id.first_name} {obj.student_id.last_name} ({obj.student_id.token_id}) payment status is {obj.payment_status}. We kindly request your immediate attention and further investigation into this matter. Your cooperation in resolving this issue is greatly appreciated.\n\n'
          f'Thank you for your cooperation and support.\n\n'
          f'Your Sincerely,\n{request.session.get("admin_user").get("company_name")}\n'
        )
        email_form=settings.EMAIL_HOST_USER
        to_email=[obj.student_id.faculty.personal_email]
        send_mail(subject,message,email_form,to_email)
     
    messages.success(request,'Payment verification updated successfully')
    return redirect('payment_verification')
@admin_required
def payment_view(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  payment=register_user.student_payment.get(id=id)
  context={
    'payment':payment
  }
  html_template = render_to_string('finance_and_accounts/finance_and_accounts_view.html',context)
  response = HttpResponse(content_type ='application/pdf')
  response['Content-Disposition'] = 'filename="payment.pdf"'
  pisa_status = pisa.CreatePDF(html_template, dest=response)
  if pisa_status.err:
    messages.error(request,f'Error Rendering PDF')
  return response








# expense start here


#Expences Types
@admin_required
def expences_types(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    expences_type=request.POST.get('expences_type')
    if register_user.expences_type.filter(expences_type=expences_type).exists():
      messages.error(request,'Expences type already exists')
      return redirect('expences_types')
    else:
      register_user.expences_type.create(expences_type=expences_type.strip().title(),crn=register_user)
      messages.success(request,'Expences type added successfully')
      return redirect('expences_types')
  expences_type=register_user.expences_type.all().order_by('-id')
  context={
    'expences_type':expences_type
  }

  return render(request,'finance_and_accounts/expences_types.html',context)

@admin_required
def expences_types_status(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  expences_type=register_user.expences_type.get(id=id)
  if expences_type.status=="Active":
    expences_type.status="Deactive"
  else:
    expences_type.status="Active"
  expences_type.save()
  messages.success(request,'Expences type status updated successfully')
  return redirect('expences_types')

@admin_required
def expences_types_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    selected_ids=request.POST.get('selected_ids')
    selected_ids_list=selected_ids.split(',')
    register_user.expences_type.filter(id__in=selected_ids_list).delete()
    messages.success(request,'Expences type deleted successfully')
    return redirect('expences_types')


@admin_required
def expences_types_update(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    expences_type_edit=request.POST.get('expences_type_edit')
    if register_user.expences_type.filter(expences_type=expences_type_edit).exists():
      messages.error(request,'Expences type already exists')
      return redirect('expences_types')
    else:
      register_user.expences_type.filter(id=id).update(
        expences_type=expences_type_edit.strip().title(),
        )
      messages.success(request,'Expences type updated successfully')
      return redirect('expences_types')
@admin_required
def expences_types_delete(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    if register_user.expences_type.filter(id=id).exists():
      expences_type = register_user.expences_type.get(id=id)
      expences_type.delete()
      messages.success(request,'Expences type deleted successfully')
      return redirect('expences_types')
    else:
      messages.error(request,'Expences type does not exists')
      return redirect('expences_types')
  else:
    messages.error(request,'Invalid request')
    return redirect('expences_types')

#company expences and employee expences
@admin_required
def company_expences_and_employee_expences(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    category=request.POST.get('category')
    faculty = register_user.employee.get(pk=request.POST.get('faculty'))
    title=request.POST.get('title')
    expences=register_user.expences_type.get(id=request.POST.get('expences'))
    mode_of_payment=request.POST.get('mode_of_payment')
    upi_type=register_user.upi.get(id=request.POST.get('upi_type'))
    upi_transaction_id=request.POST.get('upi_transaction_id')
    account_number=request.POST.get('account_number')
    account_name=request.POST.get('account_name')
    ifsc_code=request.POST.get('ifsc_code')
    bank_name=request.POST.get('bank_name')
    branch_name=request.POST.get('branch_name')
    amount=request.POST.get('amount')
    payment_date=request.POST.get('payment_date')
    payment_recipt=request.FILES.get('payment_recipt')
    if register_user.company_expences_and_employee_expences.filter(upi_transaction_id=upi_transaction_id,ifsc_code=ifsc_code,bank_name=bank_name,branch_name=branch_name).exists():
      messages.error(request,'Expences already exists')
      return redirect('company_expences_and_employee_expences')
    else:
      register_user.company_and_employee_modal.create(
        category=category.strip().title(),
        faculty=faculty,
        title=title.strip().title(),
        expences=expences,
        mode_of_payment=mode_of_payment.strip().title(),
        upi_type=upi_type,
        upi_transaction_id=upi_transaction_id.strip().title(),
        account_number=account_number,
        account_name=account_name.strip().title(),
        ifsc_code=ifsc_code.strip().title(),
        bank_name=bank_name.strip().title(),
        branch_name=branch_name.strip().title(),
        amount=amount,
        payment_date=payment_date,
        payment_recipt=payment_recipt,
        crn_number=register_user
      )
      return redirect('company_expences_and_employee_expences')
  expence=register_user.company_and_employee_modal.all().order_by("-id")
  faculty=register_user.employee.all().order_by("-id")
  upi=register_user.upi.all().order_by("-id")
  expences_type=register_user.expences_type.all().order_by("-id")
  context = {
        'expence':expence,
        'faculty':faculty,
        'upi':upi,
        'expences_type':expences_type
        
        
    }
    
  return render(request,'finance_and_accounts/company_expences_and_employee_expences.html',context)  




@admin_required
def fetch_employee_details(request, employee_id):
    try:
        employee = Employee_model.objects.get(id=employee_id)
        # Assuming Employee_model has fields: first_name, last_name, department, designation, branch
        data = {
            'employee_name': f"{employee.first_name} {employee.last_name}",
            'designation': employee.designation,
            'department': employee.department,
            'branch': employee.branch
        }
        return JsonResponse(data)
    except Employee_model.DoesNotExist:
        return JsonResponse({'error': 'Employee not found'}, status=404)








# expense end here



























# 
# 
# 
# 
# 
# 
# 
# 
# HR Portal start here
# 
# 
# 
# 
# 
# 
# 

@admin_required
def hr_details(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if register_user.employee.filter(department_name__department_name='Human Resources').exists():
        hr_details = register_user.employee.filter(department_name__department_name='Human Resources')
        hr_details = hr_details.annotate(job_count=Count('job_post'))
        job_postes = register_user.job_post.all()
    else:
        hr_details = None
        job_postes = None
    context = {
        'hr_details': hr_details,
        'job_postes': job_postes
    }
    return render(request, 'hr_portal/HR details/hrdetails.html', context)


@admin_required
def job_detailes(request,id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    # if not register_user.employee.filter(department_name__department_name='Human Resources',id=id).exist():
    #    return redirect('hr_details')
       
    
    if register_user.job_post.filter(post_by=id).exists():
      job_posts = register_user.job_post.filter(post_by=id)
      employee = register_user.employee.get(id=id)


    else:
      job_posts = None
      employee = register_user.employee.get(id=id)
      
    


    context= {
      'job_posts':job_posts,
      'employee':employee,
    }  
    return render(request,'hr_portal/HR details/jobdetails.html',context)




# job details export
@admin_required
def job_details_export(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  job_posts = register_user.job_post.filter(post_by=id)
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = f'attachment; filename="job_details.csv"'
  writer = csv.writer(response)

  writer.writerow(['S.no','Job Title','Company Name','Location','Job Category','HR Name','HR Email','Posted Date','Salary','Last Date To Apply','Job Description'])

  num= 0
  for i in job_posts:
    num+=1
    job_description_plain_text = strip_tags(i.job_description)
    writer.writerow([num, i.job_title, i.companyname.companyname, i.companyname.location, i.companyname.category.Jobcategory_name, i.companyname.hrname, i.companyname.email, i.post_date, i.salary, i.last_date_to_apply, job_description_plain_text])


  return response




# student profile with details the number of jobs he applyed
def student_profile_console(request,std_id):
    crn=request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if register_user.student_job_apply.filter(student_id=std_id).exists():
      student = register_user.leads.get(id=std_id)

    else:
      student = None
    jobs_applyed = register_user.student_job_apply.filter(student_id=std_id)  

    context= {
      'student':student,
      'jobs_applyed':jobs_applyed
    }  
    return render(request,'hr_portal/Profile status/student_profile_console.html',context)






def job_description(request):
    return render(request,'hr_portal/jobdescription.html')

def lokesh(request):
    return render(request,'hr_portal/lokesh.html')



@admin_required
def Student_details(request):
  
    return render(request, 'hr_portal/students/student_Details.html')

def Student_report(request):
    return render(request, 'hr_portal/students/student_Report.html')

def placement_dashboard(request):
    return render(request,'hr_portal/dashboard/placement_dashboard.html')

def students_placed(request):
    return render(request, 'hr_portal/dashboard/placement details/studentsplaced.html')

def students_notplaced(request):
    return render(request,'hr_portal/dashboard/placement details/studentsnotplaced.html')
  
def total_students_applied(request):
    return render(request,'hr_portal/dashboard/placement details/totalstudents.html')

def total_students_eligible(request):
    return render(request,'hr_portal/dashboard/placement details/totaleligible.html')

def total_students_noteligible(request):
    return render(request,'hr_portal/dashboard/placement details/totalnoteligible.html')

def students_underprogress(request):
    return render(request,'hr_portal/dashboard/placement details/underprogress.html')

def students_not_intrested(request):
    return render(request,'hr_portal/dashboard/placement details/totalnotintrested.html')

def profile(request):
    return render(request,'hr_portal/Profile status/profile.html')


def applied_students(request):
    return render(request,'hr_portal/HR details/applied.html')

def placed_students(request):
    return render(request,'hr_portal/HR details/placed.html')

def students_notattended(request):
    return render(request, 'hr_portal/dashboard/placement details/totalnotattended.html')    

def hr_leads(request):
    return render(request, 'hr_portal/dashboard/company leads/hr_leads.html')

def hr_confirmed(request):
    return render(request, 'hr_portal/dashboard/company leads/hr_confirmed.html')

def hr_underprogress(request):
    return render(request,'hr_portal/dashboard/company leads/hrunderprogress.html')

def hr_interviewschedule(request):
    return render(request,'hr_portal/dashboard/company leads/interviewschedule.html')

def profilesent(request):
    return render(request,'hr_portal/dashboard/company leads/profilesent.html')

def not_interested_hr(request):
    return render(request,'hr_portal/dashboard/company leads/not_interested_hr.html')



# job gallery
@admin_required
def job_gallery(request):
    crn= request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    company_vendor = register_user.company_vendor.all()
    job_category = register_user.job_category.filter(status='Active').all()
    qualification = register_user.qualifications.filter(status='Active')
    job_roles = register_user.jobrole.filter(status = 'Active')
    job_postes = register_user.job_post.annotate(apply_count=Count('studetjobapply')).order_by("-id")
    hr_details = register_user.employee.filter(department_name__department_name = 'Human Resources')
    

    if request.method == "POST":
       jobtitle = request.POST.get('jobtitle')
       company = request.POST.get('company')
       experience = request.POST.get('experience')
       qualification = request.POST.get('qualification')
       skills = request.POST.get('skills')
       role = request.POST.get('role')
       salary = request.POST.get('salary')
       last_date_to_apply = request.POST.get('last_date_to_apply')
       hr = request.POST.get('hr')
       requirements = request.POST.get('requirements')

       Job_post.objects.create(
        crn_number = register_user,
        companyname = Company_vendor.objects.get(pk=company),
        job_title = jobtitle,
        experience = experience,
        qualification = Qualification.objects.get(pk=qualification),
        skills = skills,
        role = Jobrole.objects.get(pk=role),
        salary = salary,
        last_date_to_apply = last_date_to_apply,
        post_by = Employee_model.objects.get(pk=hr),
        job_description = requirements
       )
       messages.success(request, 'Job Post created successfully.')

       return redirect('job_gallery.html')


    context={
      'company_vendor':company_vendor,
      'job_category':job_category,
      'qualification':qualification,
      'job_roles':job_roles,
      'job_postes':job_postes,
      'hr_details':hr_details

    }
    return render(request, 'hr_portal/job gallery/job_gallery.html',context)





# job galery edit
def job_gallery_edit(request,id):
   if request.method == "POST":
       jobtitle = request.POST.get('jobtitle')
       company = request.POST.get('company')
       experience = request.POST.get('experience')
       qualification = request.POST.get('qualification')
       skills = request.POST.get('skills')
       role = request.POST.get('role')
       salary = request.POST.get('salary')
       last_date_to_apply = request.POST.get('last_date_to_apply')
       hr = request.POST.get('hr')
       requirements = request.POST.get('requirements')
       if Job_post.objects.filter(id=id).exists():
         print(Job_post.objects.filter(id=id))
         Job_post.objects.filter(id=id).update(
          companyname = Company_vendor.objects.get(pk=company),
          job_title = jobtitle,
          experience = experience,
          qualification = Qualification.objects.get(pk=qualification),
          skills = skills,
          role = Jobrole.objects.get(pk=role),
          salary = salary,
          last_date_to_apply = last_date_to_apply,
          post_by = Employee_model.objects.get(pk=hr),
          job_description = requirements
         )
         messages.success(request, 'Job Post Updated Successfully')
         return redirect('job_gallery.html')
       
   





def export_job_posts_to_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="job_posts.csv"'

    job_posts = Job_post.objects.all()

    writer = csv.writer(response)
    writer.writerow([
        'Company Name', 'Job Title', 'Experience', 'Qualification', 
        'Skills', 'Role', 'Salary', 'Post Date', 'Last Date to Apply', 
        'Job Description', 'CRN Number', 'HR Name', 'Location', 
        'Mobile', 'Alternate Mobile', 'Email', 'Website', 
        'Point of Contact Name', 'Point of Contact Mobile'
    ])

    for job_post in job_posts:
        writer.writerow([
            job_post.companyname.companyname if job_post.companyname else '',
            job_post.job_title,
            job_post.experience,
            job_post.qualification.qualification_name if job_post.qualification else '',
            job_post.skills,
            job_post.role.jobrole_name if job_post.role else '',
            job_post.salary,
            job_post.post_date,
            job_post.last_date_to_apply,
            job_post.job_description,
            job_post.crn_number_id,
            job_post.companyname.hrname if job_post.companyname else '',
            job_post.companyname.location if job_post.companyname else '',
            job_post.companyname.mobile if job_post.companyname else '',
            job_post.companyname.alternatemobile if job_post.companyname else '',
            job_post.companyname.email if job_post.companyname else '',
            job_post.companyname.website if job_post.companyname else '',
            job_post.companyname.pocname if job_post.companyname else '',
            job_post.companyname.pocmobile if job_post.companyname else ''
        ])

    return response







# company dependency

def get_company_vendor(request, id):
    company_id = request.GET.get('company_id')
    if company_id:
        try:
            company = Company_vendor.objects.get(id=company_id)
            data = {
                'email': company.email,
                'location': company.location,
                'mobile': company.mobile,
                'category': company.category.Jobcategory_name 
            }
            return JsonResponse(data)
        except Company_vendor.DoesNotExist:
            pass
    return JsonResponse({})







@admin_required
def job_gallery_applied(request,job_id):
    crn= request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    applyed_job = StudetJobApply.objects.filter(job_id=job_id,crn_number=register_user)
    job_name = Job_post.objects.get(id=job_id)
    context={
      'applyed_job':applyed_job,
      'job_name':job_name
    }
    
    return render(request,'hr_portal/job gallery/jobgalleryapplied.html',context)


@admin_required
def job_applyed_status_change(request, jobid, apply_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == "POST":
        try:
            apply = register_user.student_job_apply.get(pk=apply_id)
            if request.POST.get('status'):
                apply.status = request.POST.get('status')
                status = request.POST.get('status')
                apply.save()
                port = 587
                smtp_server = "smtp.zeptomail.in"
                username = "emailapikey"
                password = "PHtE6r0NRe3ujm4opxUD4vC6QsSiM94t+elhLQJEuYoWC/UAHE1TrtAplmK3qEx/UfhFFvLIzY5vtbzPseyNdz68N2tLXGqyqK3sx/VYSPOZsbq6x00YuVgYcUHUV47te95s1S3Xvd/SNA=="
                user_list = {'student_full_name': apply.student_id.first_name, "status":status}
                if status == "Qualified":
                  html_message = render_to_string('hr_portal/mail_template/qualified_mail.html', context=user_list)
                elif status == "Not Placed":
                  html_message = render_to_string('hr_portal/mail_template/qualified_mail.html', context=user_list)
                elif status == "Not Interested":
                  html_message = render_to_string('hr_portal/mail_template/qualified_mail.html', context=user_list)
                elif status == "Not Attended":
                  html_message = render_to_string('hr_portal/mail_template/not_attended_mail.html', context=user_list)
                elif status == "Not Eligible":
                  html_message = render_to_string('hr_portal/mail_template/not_interested_mail.html', context=user_list)
                elif status == "Placed":
                  html_message = render_to_string('hr_portal/mail_template/placed_mail.html', context=user_list)
                elif status == "Eligible / Profile Sent":
                  html_message = render_to_string('hr_portal/mail_template/eligible_profile_sent_mail.html', context=user_list)  
                elif status == "Under Process / Yet To Receive Feedback":
                  html_message = render_to_string('hr_portal/mail_template/under_process_mail.html', context=user_list)  
                elif status == "Level 1":
                  html_message = render_to_string('hr_portal/mail_template/level_1_mail.html', context=user_list)  
                elif status == "Level 2":
                  html_message = render_to_string('hr_portal/mail_template/level_2_mail.html', context=user_list)  
                elif status == "Level 3":
                  html_message = render_to_string('hr_portal/mail_template/level_3_mail.html', context=user_list)
                elif status == "Delayed Application":
                  html_message = render_to_string('hr_portal/mail_template/delayed_application_mail.html', context=user_list)
                
                plain_message = strip_tags(html_message)
                message = plain_message
                msg = EmailMessage()
                msg['Subject'] = f"Job Application Status for {apply.job_id.job_title}"
                msg['From'] = "noreply@qtnext.com"
                msg['To'] = apply.student_id.email
                msg.set_content(message)
                try:
                    if port == 465:
                        context = ssl.create_default_context()
                        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
                            server.login(username, password)
                            server.send_message(msg)
                    elif port == 587:
                        with smtplib.SMTP(smtp_server, port) as server:
                            server.starttls()
                            server.login(username, password)
                            server.send_message(msg)
                            
                    else:
                        print("use 465 / 587 as port value")
                        exit()
                    print("successfully sent")
                except Exception as e:
                    messages.error(request, "Failed to send email")
                    print(e)

 
                messages.success(request, 'Job Status Changed Successfully')
            else:
                messages.error(request, 'Status Not Found')
            return redirect('jobgalleryapplied', job_id=jobid)  
        except Exception as e:
            messages.error(request, 'Record Not Found')
        return redirect('jobgalleryapplied', job_id=jobid)
    else:
        return redirect('jobgalleryapplied', job_id=jobid)



# export details of applyed jobs
@admin_required
def job_applyed_export(request, job_id):
    try:
        crn = request.session.get('admin_user').get('crn')
        register_user = Register_model.objects.get(crn=crn)
        apply_list = register_user.student_job_apply.filter(job_id=job_id)
        job = register_user.job_post.get(id=job_id)
        response = HttpResponse(content_type='text/csv')
        writer = csv.writer(response)
        writer.writerow(['S.No', 'Company Name', 'City', 'Student Name', 'Job Title', 'Posted Date', 'Last Date To Apply', 'Applied Time', 'Posted By', 'Status', 'Experience Required', 'Qualification', 'Skill','Email', 'Phone Number'])

        i = 0
        for apply in apply_list:
            i += 1
            applied_time_formatted = apply.applyed_date_time.strftime('%Y-%m-%d %H:%M:%S')  # Formatting the datetime
            writer.writerow([
                i,
                apply.job_id.companyname.companyname,
                apply.job_id.companyname.location,
                apply.student_id.first_name + ' ' + apply.student_id.last_name,
                apply.job_id.job_title,
                apply.job_id.post_date,
                apply.job_id.last_date_to_apply,
                applied_time_formatted,  # Using the formatted datetime
                apply.job_id.post_by,
                apply.status,
                apply.job_id.experience,
                apply.job_id.qualification,
                apply.job_id.skills,
                apply.student_id.email,
                apply.student_id.mobile_number
            ])
        
        response['Content-Disposition'] = f'attachment; filename="{job.job_title}.csv"'
        return response

    except Exception as e:
        print(e)
        messages.error(request, 'Record Not Found')
        return redirect('jobgalleryapplied', job_id=job_id)
        






    




def job_gallery_qualified(request):
    return render(request,'hr_portal/job gallery/jobgalleryqualified.html')

def job_gallery_placed(request):
    return render(request,'hr_portal/job gallery/jobgalleryplaced.html')

def job_gallery_elgible(request):
    return render(request,'hr_portal/job gallery/jobgalleryeligible.html')

def job_gallery_inprogress(request):
    return render(request,'hr_portal/job gallery/jobgalleryinprogress.html')


def student_details_json(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    student = register_user.leads.all().order_by('-id')
    student_json = serializers.serialize('json', student)
    return HttpResponse(student_json, content_type='application/json')


def Student_filter(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    student = register_user.leads.all().order_by('-id')
   
    
    
    context = {
       'student':student,
       
    }
    return render(request, 'hr_portal/student filters/student_filter.html',context)    



def placement_status(request):
    return render(request,'hr_portal/placement status/placementstatus.html')

def level1(request):
    return render(request,'hr_portal/dashboard/placement details/level1.html')

def level2(request):
    return render(request,'hr_portal/dashboard/placement details/level2.html')

def level3(request):
    return render(request,'hr_portal/dashboard/placement details/level3.html')



@admin_required
def createvendor(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  job_category = register_user.job_category.filter(status='Active').order_by('-id')
  company_vendors = register_user.company_vendor.all().order_by('-id')

  
  if request.method == "POST":
      companyname = request.POST.get('companyname')
      hrname = request.POST.get('hrname')
      location = request.POST.get('location')
      category = request.POST.get('category')
      mobile = request.POST.get('mobile')
      alternatemobile = request.POST.get('alternatemobile')
      email = request.POST.get('email')
      website = request.POST.get('website')
      pocname = request.POST.get('pocname')
      pocmobile = request.POST.get('pocmobile')

      if register_user.company_vendor.filter(mobile=mobile,email=email).exists():
        messages.error(request,'Company vendor already exists')
        return redirect('createvendor')
      
      if register_user.company_vendor.filter(companyname=companyname,location=location).exists():
        messages.error(request,'Company vendor already exists')
        return redirect('createvendor')

      Company_vendor.objects.create(
        crn_number = register_user,
        companyname = companyname.strip().title(),
        hrname = hrname.strip().title(),
        location = location.strip().title(),
        category = register_user.job_category.get(pk=category),
        mobile = mobile,
        alternatemobile = alternatemobile,
        email = email,
        website = website,
        pocname = pocname.strip().title(),
        pocmobile = pocmobile,
      )
      return redirect('createvendor')
  context={
    'job_category':job_category,
    'company_vendors':company_vendors
    }    

  return render(request,'hr_portal/vendor/createvendor.html',context)   



# company vendor edit
@admin_required
def company_vendor_edit(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  company_vendor = register_user.company_vendor.get(id=id)
  if request.method == "POST":
    companyname = request.POST.get('companyname')
    hrname = request.POST.get('hrname')
    location = request.POST.get('location')
    category = request.POST.get('category')
    mobile = request.POST.get('mobile')
    alternatemobile = request.POST.get('alternatemobile')
    email = request.POST.get('email')
    website = request.POST.get('website')
    pocname = request.POST.get('pocname')
    pocmobile = request.POST.get('pocmobile')

    if register_user.company_vendor.exclude(id=id).filter(mobile=mobile,email=email).exists():
      messages.error(request,'Company vendor already exists')
      return redirect('createvendor')

    if register_user.company_vendor.exclude(id=id).filter(companyname=companyname,location=location).exists():
      messages.error(request,'Company vendor already exists')
      return redirect('createvendor')  
    
    register_user.company_vendor.filter(id=id).update(
       companyname = companyname.strip().title(),
       hrname = hrname.strip().title(),
       location = location.strip().title(),
       category = category,
       mobile = mobile,
       alternatemobile = alternatemobile,
       email = email,
       website = website,
       pocname = pocname.strip().title(),
       pocmobile = pocmobile,

    )
    return redirect('createvendor')


  else:
    messages.error(request,'Invalid request')
    return redirect('createvendor')  




# company delete
@admin_required
def delete_company_vendor(request,id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)

  if request.method == "POST":
    if register_user.company_vendor.filter(id=id).exists():
      register_user.company_vendor.filter(id=id).delete()
      messages.success(request,'Company vendor deleted successfully')
      return redirect('createvendor')
    else:
      messages.error(request,'Company vendor not found')
      return redirect('createvendor')
  else:
    messages.error(request,'Invalid request')
    return redirect('createvendor')  


@admin_required
def company_vendor_mul_delter(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    company_vendor=request.POST.get('selected_ids')
    selected_list=company_vendor.split(",")
    register_user.company_vendor.filter(id__in=selected_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('company_vendor')

  else:
     return redirect('createvendor')   


@admin_required
def company_vendor_export(request):
    crn = request.session.get('admin_user').get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        vendor = register_user.company_vendor.all()
    else:
        messages.error(request, 'Invalid User Session')
        return redirect('company_vendor')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="company_vendor.csv"'
    writer = csv.writer(response)
    writer.writerow(['S.No', 'company Name','HR Name','Location','Category','Mobile','Alternate Mobile','Email','Website','Poc Name','Poc Mobile'])


    num = 0
    for i in vendor:
        num += 1
        writer.writerow([num,i.companyname,i.hrname,i.location,i.category,i.mobile,i.alternatemobile,i.email,i.website,i.pocname,i.pocmobile])

    return response    




     











# moke interview sart here






@admin_required
def getting_employ_slot(request,course_id,spc_id):
  employee_details = Employee_model.objects.filter(course_id = course_id,specialization_id = spc_id)
  employee_list = [{'id': emp.id, 'first_name': emp.first_name, 'last_name':emp.last_name} for emp in employee_details]
  return JsonResponse(employee_list, safe=False)




# faculty login
@admin_required
def faculty_login(request):
    return render(request,'mock_interview/faculty_login.html')


# dashboard

@admin_required
def mock_dashboard(request):
    return render(request,'mock_interview/dashboard.html')

# Student booking slots
@admin_required
def student(request):
    return render(request,'mock_interview/student.html')
# student book an interview view start here
@admin_required
def student_Book_an_interview(request):
    return render(request, 'faculty/student.html')




@admin_required
def get_specializations(request,id):
    if request.is_ajax() and request.method == 'GET':
        course_id = request.GET.get(id)
        if course_id:
            specializations = Specialization.objects.filter(course_name_id=course_id)
            data = [{'id': spec.id, 'name': spec.specilalization_name} for spec in specializations]
            return JsonResponse(data, safe=False)
    return JsonResponse([], safe=False)



@admin_required
def submit_feedback(request, interview_id):
    if request.method == 'POST':
        form = Feedback(request.POST)
        if form.is_valid():
            feedback = form.save(commit=False)
            feedback.interview_id = interview_id
            feedback.save()
            return redirect('interview_list')
    else:
        form = Feedback()
    return render(request, 'feedback_form.html', {'form': form})


# Faculty slot availbility
@admin_required
def faculty_slot(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    scheduling = register_user.schedule.all() 
    employees = register_user.employee.filter(designation_name__designation_name = "Teaching Staff").all()
    if request.method == 'POST':
        Available_Slot = request.POST.get('datetime')
        Mock_Link = request.POST.get('link')
        faculty = request.POST.get('faculty')
        faculty_instance = Employee_model.objects.get(pk=faculty)
        if register_user.schedule.filter(available_slot=Available_Slot).exists():
          messages.error(request,"This slot has already scheduled")
          return redirect('faculty_slot')
        Scheduling_mock_model.objects.create(available_slot = Available_Slot,mock_link = Mock_Link,crn = register_user,faculty = faculty_instance)
        messages.success(request, "Slot rescheduled successfully.")
        return redirect('faculty_slot')
    return render(request,'mock_interview/slot_management.html',{'scheduling':scheduling,'employees':employees})



# edit  faculty slot
@admin_required
def edit_faculty_slot(request, slot_id):  
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == 'POST':
        selected_option = request.POST.get('type_of_change_' + str(slot_id))  
        if selected_option == 'Reschedule Slot':
            Reschedule_Slot = request.POST.get('available_slot')
            Mock_Link = request.POST.get('mock_link')
            Reschedule_Reason = request.POST.get('reschedule_reason')
            if register_user.schedule.filter(available_slot=Reschedule_Slot).exists():
                messages.error(request, "This slot has already been scheduled.")
                return redirect('faculty_slot')
            slot = register_user.schedule.get(id=slot_id)
            slot.rescheduled_slot = Reschedule_Slot
            slot.mock_link = Mock_Link
            slot.reschedule_reason = Reschedule_Reason
            slot.status = 'Reschedule'
            slot.save()
            subject = 'Slot Rescheduled'
            message =  (f"Hello {slot.student_name.first_name},\n\n" 
                "Your mock interview slot has been rescheduled due to "f'{slot.reschedule_reason}'
                ".\n\n"
                "Here are your Rescheduled details:\n\n"
                f" Alotted Time : {slot.rescheduled_slot}\n"
                f"link: {slot.mock_link}.\n"
            
                "If you have any questions or need further information, please do not hesitate to contact us.\n\n"
                "Best Regards,\n"
                f"{request.session.get('admin_user').get('company_name')}\n"
                "Contact Information")
                
            email_from = settings.EMAIL_HOST_USER
            to_email=f'{slot.student_name.email}'
            send_mail(subject, message, email_from, [to_email], fail_silently=False)
            messages.success(request, "Slot rescheduled successfully.")
        elif selected_option == 'Cancel Slot':
            print(selected_option)
            Cancel_Reason = request.POST.get('cancel_reason')
            slot = register_user.schedule.filter(id=slot_id)
            slot.status='Cancel'
            slot.cancel_reason=Cancel_Reason
            slot.save()
            subject = 'Slot Canceled'
            message =  (f"Hello {slot.student_name.first_name},\n\n" 
                "Your mock interview slot has been canceled due to" f'{slot.cancel_reason}'
            
                "Should you have any questions or need further information, please do not hesitate to contact us.\n\n"
                "Best Regards,\n"
                f"{request.session.get('admin_user').get('company_name')}\n"
                "Contact Information")
            to_email=f'{slot.student_name.email}'
            send_mail(subject, message, email_from, [to_email], fail_silently=False)
            messages.success(request, "Slot canceled successfully.")
        return redirect('faculty_slot')

    
# faculty slot import
@admin_required
def faculty_slot_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        form = faculty_slot_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['faculty_slot_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines(), delimiter=',')

                headers = next(reader)
                expected_headers = 3
                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'File should have {expected_headers} columns')
                        return redirect('faculty_slot')

                    slot_import = row[1]
                    mock_import = row[2]

                    if not slot_import or not mock_import:
                        continue

                    if Scheduling_mock_model.objects.filter(available_slot=slot_import).exists():
                        messages.error(request, f'{slot_import} has already scheduled')
                    else:
                        Scheduling_mock_model.objects.create(
                            available_slot=slot_import,
                            mock_link=mock_import,
                            crn=register_user
                        )

                messages.success(request, 'File Imported Successfully')
                return redirect('faculty_slot')
            except Exception as e:
                messages.error(request, 'An error occurred while processing the file')
                return redirect('faculty_slot')

    slots = Scheduling_mock_model.objects.all()
    context = {
        'slots': slots
    }
    return render(request, 'mock_interview/slot_management.html', context)


# faculty slot export
@admin_required
def faculty_slot_export(request):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   response = HttpResponse(content_type='text/csv')
   writer = csv.writer(response)
   writer.writerow(['S.NO','Available Slot','Mock Link'])
   i=0
   for slot in register_user.schedule.all():
     i+=1
     writer.writerow([i,slot.available_slot,slot.mock_link])

   response['Content-Disposition'] = 'attachment; filename="slot.csv"'
   return response



@admin_required
def FeedbackForm(request, id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == 'POST':
        # Get POST data safely
        attendance_status = request.POST.get('attendance_status')
        communication_skills = float(request.POST.get('communication_skills', 0))
        body_language = float(request.POST.get('body_language', 0))
        logical_thinking = float(request.POST.get('logical_thinking', 0))
        technical_skills = float(request.POST.get('technical_skills', 0))
        suggestion = request.POST.get('suggestion')
        send_attachment = request.FILES.get('send_attachment')
        status = request.POST.get('status')

        # Calculate the overall rating
        overall_rating = (communication_skills + body_language +
                          logical_thinking + technical_skills) / 4


        # Set status based on overall_rating
        if overall_rating > 3.5:
          status = 'qualified'
        else:
          status = 'not qualified'
        feedback = Feedback.objects.create(
            crn_number=register_user,
            interview=Scheduling_mock_model.objects.get(pk=id),
            attendance_status=attendance_status,
            communication_skills=communication_skills,
            technical_skills=technical_skills,
            body_language=body_language,
            logical_thinking=logical_thinking,
            suggestion=suggestion,
            send_attachment=send_attachment,
            overall_rating=overall_rating,
            status=status
        )
        feedback.interview.interview_status = 'Completed'
        feedback.interview.save()
        subject = 'Feedback Submitted'
        if attendance_status == 'Present':
            message = f'''
            Feedback Summary:
            Communication Skills:  {communication_skills}
            Technical Skills:      {technical_skills}
            Body Language:         {body_language}
            Logical Thinking:      {logical_thinking}
            Suggestion:            {suggestion}
            Overall Rating:        {overall_rating}
            Status:                {status}
            '''
        else:
            message = f'''
            Unfortunately,  You are absent during the scheduled interview.
            '''
        from_email = settings.EMAIL_HOST_USER
        to_email = [feedback.interview.student_name.email]
        try:
            send_mail(subject, message, from_email, to_email, fail_silently=True)
        except Exception as e:
            # Handle email sending failure gracefully
            pass
        return redirect('total_interviews')
    

@admin_required
def FeedbackForm_2(request, id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == 'POST':
        # Get POST data safely
        attendance_status = request.POST.get('attendance_status')
        communication_skills = float(request.POST.get('communication_skills', 0))
        body_language = float(request.POST.get('body_language', 0))
        logical_thinking = float(request.POST.get('logical_thinking', 0))
        technical_skills = float(request.POST.get('technical_skills', 0))
        suggestion = request.POST.get('suggestion')
        send_attachment = request.FILES.get('send_attachment')
        status = request.POST.get('status')

        # Calculate the overall rating
        overall_rating = (communication_skills + body_language +
                          logical_thinking + technical_skills) / 4


        # Set status based on overall_rating
        if overall_rating > 3.5:
          status = 'qualified'
        else:
          status = 'not qualified'
        feedback = Feedback.objects.create(
            crn_number=register_user,
            interview=Scheduling_mock_model.objects.get(pk=id),
            attendance_status=attendance_status,
            communication_skills=communication_skills,
            technical_skills=technical_skills,
            body_language=body_language,
            logical_thinking=logical_thinking,
            suggestion=suggestion,
            send_attachment=send_attachment,
            overall_rating=overall_rating,
            status=status
        )
        feedback.interview.interview_status = 'Completed'
        feedback.interview.save()
        subject = 'Feedback Submitted'
        if attendance_status == 'Present':
            message = f'''
            Feedback Summary:
            Communication Skills:  {communication_skills}
            Technical Skills:      {technical_skills}
            Body Language:         {body_language}
            Logical Thinking:      {logical_thinking}
            Suggestion:            {suggestion}
            Overall Rating:        {overall_rating}
            Status:                {status}
            '''
        else:
            message = f'''
            Unfortunately,  You are absent during the scheduled interview.
            '''
        from_email = settings.EMAIL_HOST_USER
        to_email = [feedback.interview.student_name.email]
        try:
            send_mail(subject, message, from_email, to_email, fail_silently=True)
        except Exception as e:
            # Handle email sending failure gracefully
            pass
        return render(request, 'mock_interview/admin-facultylist.html')


    

@admin_required
def total_interviews(request, f_id):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    faculty_id = register_user.employee.all().order_by("-id")
    Faculty = Scheduling_mock_model.objects.filter(crn=register_user, faculty=f_id)

    
    today = datetime.now().date()
    print("Today:", today)

    tomorrow = today + timedelta(days=1)
    print("Tomorrow:", tomorrow)

    upcoming=date.today() + timedelta(days=2)
    print("Upcoming:",upcoming)

    # Filter interviews for today, tomorrow, and upcoming days
    today_interviews =Faculty.filter(available_slot__date=today)
    print("Today Interviews:", today_interviews)

    expired_interviews = Faculty.filter(available_slot__date__lt=today).exclude(interview_status__in=['completed', 'pending', 'not_booked'])
    for interview in expired_interviews:
        interview.interview_status = 'pending'
        interview.save()
    
    tomorrow_interviews =Faculty.filter(available_slot__date=tomorrow).exclude(interview_status__in=['completed', 'pending', 'not_booked'])
    print("Tomorrow Interviews:", tomorrow_interviews)
    
    upcoming_interviews =Faculty.filter(available_slot__date__gte=upcoming).exclude(interview_status__in=['completed', 'pending', 'not_booked'])
    print("Upcoming Interviews:", upcoming_interviews)

  
    completed_interviews =Feedback.objects.filter(crn_number=register_user, interview__interview_status='completed', interview__faculty=f_id)
    
    

    context = {
        'faculty_id': faculty_id,
        'today_interviews': today_interviews,
        'tomorrow_interviews': tomorrow_interviews,
        'upcoming_interviews': upcoming_interviews,
        'completed_interviews': completed_interviews,
        
    }
    return render(request, 'mock_interview/interview_list.html', context)



# Student Past Interviews with feedback details
@admin_required
def student_feedback(request, s_id):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  student_id=register_user.leads.filter(lead_position="ADMITTED").order_by("-id")
  feedbacks = Feedback.objects.filter(crn_number=register_user, interview__interview_status='completed', interview__student_name=s_id)
  context = {
    'feedbacks': feedbacks,
    'student_id': student_id,
  }
  return render(request,'mock_interview/student_past_interviews.html', context)

@admin_required
def open_pdf(request, document_id):
    document = Scheduling_mock_model.objects.get(id=document_id)
    pdf_file = document.send_attachment
    response = FileResponse(pdf_file, content_type='application/pdf')
    return response

# Admin mock slot scheduling
@admin_required
def admin_mock(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    courses = Course.objects.all()
    specializations = Specialization.objects.all()
    faculties = Employee_model.objects.all()
    assigning = Scheduling_mock_model.objects.all() 

    if request.method == 'POST':
        Available_Slot = request.POST.get('datetime')
        Mock_Link = request.POST.get('link')
        course =request.POST.get('course')        
        Course_Name = Course.objects.get(id = course)
        specialization = request.POST.get('specialization')
        Specialization_Name = Specialization.objects.get(id = specialization)
        Faculty = Employee_model.objects.get(id=request.POST.get('faculty'))
        
        # Check if the slot has already been scheduled for the faculty
        if register_user.schedule.filter(faculty=Faculty, available_slot=Available_Slot).exists():
            messages.error(request, "This slot has already been scheduled")
            return redirect('admin_mock')
        
        # Create a new slot assignment
        Scheduling_mock_model.objects.create(
            available_slot=Available_Slot, 
            mock_link=Mock_Link, 
            course_name=Course_Name, 
            specialization_name=Specialization_Name,
            faculty=Faculty,
            crn=register_user
        )
        subject='Mock Scheduled successfully'
        message=(f"Hello {Faculty.first_name},\n\n" 
                "Your mock has been scheduled  successfully" 
                  "Here are your Scheduled details:\n\n"
                f" Alotted Time : {Available_Slot}\n"
                f"link: {Mock_Link}.\n"
                "If you have any questions or need further information, please do not hesitate to contact us.\n\n"
                "Best Regards,\n"
                f"{request.session.get('admin_user').get('company_name')}\n"
                "Contact Information")
        email_from=settings.EMAIL_HOST_USER
        to_email=f'{Faculty.personal_email}'
        send_mail(subject,message,email_from,[to_email], fail_silently=False)
        messages.success(request, "Slot has been scheduled successfully")
        return redirect('admin_mock')
  

    context = {
        'courses': courses,  
        'specializations': specializations,
        'faculty': faculties,
        'assigning': assigning,
        # 'faculty_slots_count': faculty_slots_count
    }
    return render(request, 'mock_interview/adminmock_slot.html', context)

@admin_required
def spec_ajax(request, id):
    # Filter specializations based on the selected course
    specializations = Specialization.objects.filter(course_name=id)
    # Prepare a list of dictionaries containing specialization details
    specialization_list = [{"id": spec.id, "name": spec.specilalization_name} for spec in specializations]
    # Return JSON response containing the specialization list
    return JsonResponse({"specialization_list": specialization_list})

@admin_required
def faculty_ajax(request, id):
    # Filter faculty based on the selected specialization name
    faculty = Employee_model.objects.filter(specialization_id_id=id)
    faculty_list = [{"id": f.id, "first_name": f.first_name , "last_name":f.last_name} for f in faculty]
    # Return JSON response containing the faculty list
    return JsonResponse({"faculty_list": faculty_list})



# edit mock slot assiging
@admin_required
def edit_admin_mock(request, slot_id):  
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    if request.method == 'POST':
        selected_option = request.POST.get('type_of_change_' + str(slot_id))  
        if selected_option == 'Reschedule Slot':
            Available_Slot = request.POST.get('available_slot')
            Mock_Link = request.POST.get('mock_link')
            Reschedule_Reason = request.POST.get('reschedule_reason')
            if register_user.schedule.filter(available_slot=Available_Slot).exists():
                messages.error(request, "This slot has already been scheduled.")
                return redirect('admin_mock')
            register_user.schedule.filter(id=slot_id).update(
                available_slot=Available_Slot,
                mock_link=Mock_Link,
                status='Reschedule',
                reschedule_reason=Reschedule_Reason,
                crn=register_user
               )
            messages.success(request, "Slot rescheduled successfully.")
        elif selected_option == 'Cancel Slot':
            print(selected_option)
            Cancel_Reason = request.POST.get('cancel_reason')
            register_user.schedule.filter(id=slot_id).update(status='Cancel', cancel_reason=Cancel_Reason)
            messages.success(request, "Slot canceled successfully.")
        return redirect('admin_mock')




@admin_required
def admin_slot_import(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    if request.method == 'POST':
        form = admin_slot_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['admin_slot_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines(), delimiter=',')

                headers = next(reader)
                expected_headers = 6
                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, f'File should have {expected_headers} columns')
                        return redirect('admin_mock')

                    faculty_import = row[1]
                    course_import = row[2]
                    specialization_import = row[3]
                    slot_import = row[4]
                    mock_link_import = row[5]

                    if not faculty_import or not course_import or not specialization_import or not slot_import or not mock_link_import:
                       continue

                    if Scheduling_mock_model.objects.filter(faculty=faculty_import, available_slot=slot_import).exists():
                        messages.error(request, f'{slot_import} has already been scheduled for {faculty_import}')
                    else:
                        Scheduling_mock_model.objects.create(
                            faculty=faculty_import,
                            course_name=course_import,
                            specialization_name=specialization_import,
                            available_slot=slot_import,
                            mock_link=mock_link_import,
                            crn=register_user
                        )

                messages.success(request, 'File imported successfully')
                return redirect('admin_mock')
            except Exception as e:
                messages.error(request, 'An error occurred while processing the file')
                return redirect('admin_mock')
    slots = Scheduling_mock_model.objects.all()
    context = {
        'slots': slots
    }
    return render(request, 'mock_interview/adminmock_slot.html', context)



@admin_required
def admin_slot_export(request):
   crn = request.session.get('admin_user').get('crn')
   register_user = Register_model.objects.get(crn=crn)
   response = HttpResponse(content_type='text/csv')
   writer = csv.writer(response)
   writer.writerow(['S.NO','Faculty', 'Course', 'Specialization', 'Slot', 'Mock Link'])
   i=0
   for slot in register_user.schedule.all():
     i+=1
     writer.writerow([i,slot.faculty.first_name,slot.course_name,slot.specialization_name ,slot.available_slot,slot.mock_link])

   response['Content-Disposition'] = 'attachment; filename="Admin_slot_assigning.csv"'
   return response

# admin mock rescheduling
@admin_required
def admin_reschedule(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    student = Scheduling_mock_model.objects.all()
    faculty = Employee_model.objects.all()
    scheduling = Scheduling_mock_model.objects.filter(status='Reschedule')
    
    return render(request,'mock_interview/admin_reschedule.html',{'scheduling':scheduling,'student':student,'faculty':faculty})

#  mock slot rescheduling
@admin_required
def faculty_reschedule(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)

    student = Scheduling_mock_model.objects.all()
    scheduling = Scheduling_mock_model.objects.filter(status='Reschedule')
    
    return render(request,'mock_interview/reschedule.html',{'scheduling':scheduling,'student':student})

#  admin interview list
@admin_required
def admin_interview_list(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    today = datetime.now().date()
    print("Today:", today)


    # Filter interviews for today, tomorrow, and upcoming days
    today_interviews = Scheduling_mock_model.objects.filter(crn=register_user, available_slot__date=today).exclude(interview_status__in=['completed', 'pending', 'not_booked'])
    print("Today Interviews:", today_interviews)

    Faculty = Employee_model.objects.filter(designation_name__designation_name='Teaching Staff')
    
    context = {
        'today_interviews': today_interviews,
        'Faculty':Faculty,
    }
    return render(request,'mock_interview/admin_interview_list.html', context)


#  faculty dashboard
@admin_required
def faculty_dashboard(request):
    return render(request,'mock_interview/faculty_dashboard.html')

# admin to watch separate faculty slots by clicking faculty name
@admin_required
def separate_faculty_list(request,faculty_id):
    # Filter students associated with the selected faculty
    students = Scheduling_mock_model.objects.filter(faculty=faculty_id)

    
    today = datetime.now().date()
    print("Today:", today)

    tomorrow = today + timedelta(days=1)
    print("Tomorrow:", tomorrow)

    upcoming=date.today() + timedelta(days=2)
    print("Upcoming:",upcoming)

    # Filter interviews for today, tomorrow, and upcoming days
    today_interviews = students.filter(available_slot__date=today).exclude(interview_status__in=['completed', 'pending', 'not_booked'])
    tomorrow_interviews = students.filter(available_slot__date=tomorrow).exclude(interview_status__in=['completed', 'pending', 'not_booked'])
    upcoming_interviews = students.filter(available_slot__date__gte=upcoming).exclude(interview_status__in=['completed', 'pending', 'not_booked'])


    # Pass the filtered students to the template
    context = {
        'students': students,
        'today_interviews': today_interviews,
        'tomorrow_interviews': tomorrow_interviews,
        'upcoming_interviews': upcoming_interviews,
    }
    return render(request,'mock_interview/admin-facultylist.html',context)



# admin can watch all completed mocks
@admin_required
def admin_completed_mock(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  student_id=LeadModel.objects.filter(lead_position="ADMITTED").order_by("-id")
  feedbacks = Feedback.objects.filter(crn_number=register_user, interview__interview_status='completed')
  context = {
    'feedbacks': feedbacks,
    'student_id': student_id,
  }
  return render(request,'mock_interview/admin_completed_interviews.html', context)

@admin_required
def completed_student_mock(request, student_id):
   students = Feedback.objects.filter(interview__student_name=student_id, interview__interview_status='completed')
   context = {
          'students': students,
       }
    
   return render(request,'mock_interview/adcompleted_student.html', context)





# faculty scheduled  total interviews
@admin_required
def faculty_schedule_list(request):
    return render(request, 'mock_interview/faculty_scheduled_interview.html')

# faculty completed interviews
@admin_required
def faculty_completed_mocklist(request):
    return render(request, 'mock_interview/faculty_completed_mocks.html')

# faculty pending interviews
@admin_required
def faculty_pending_mocks(request):
    return render(request, 'mock_interview/faculty_pending_mocks.html')



















#certification start here


#certification start here
def dashboard_certification(request):
  return render(request,'certifications/certif_dashboard.html')
#Filter
def student_filter_cert(request):
    # crn = request.session.get('admin_user').get('crn')
    # register_user = Register_model.objects.get(crn=crn)
    # if request.method == 'POST':
    #     # Process form data here
    #     course=register_user.courses.get(pk=request.POST.get('course'))
    #     batchno=register_user.regulations.get(pk=request.POST.get('batchno'))
    #     auto_cert = register_user.regulations.get(pk=request.POST.get('auto_certs'))
    #     manual_cert = register_user.regulations.get(pk=request.POST.get('manual_certs'))
    #     start_date = request.POST.get('startdate')
    #     end_date = request.POST.get('enddate')
    #     if register_user.Filters.filter(course=course,batchno=batchno,autocertification=auto_cert,manualcertification=manual_cert,startdate=start_date,enddate=end_date).exists():
           
    #     else:
    #        filter
           
    # coursename=register_user.courses.all()
    # batchno=register_user.regulations.all()
    # auto_certs =register_user.leads.all()
    # manual_certs =register_user.CreateStudent.all()

    # context = {
    #     'coursename': coursename,
    #     'batchno': batchno,
    #     'auto_certs': auto_certs,
    #     'manual_certs': manual_certs,
    # }

    return render(request, 'certifications/sent_emails.html')

def send_email(request):
    crn = request.session.get('admin_user').get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == "POST":
        selected_ids_str = request.POST.get('selected_ids')
        selected_ids = [int(id_str) for id_str in selected_ids_str.split(',') if id_str.strip()]  # Convert to list of integers
        if selected_ids:
            selected_students = register_user.CreateStudent.filter(id__in=selected_ids)
            for student in selected_students:
                subject = 'Course Completion Certificate'
                message = (
                    f"Congratulations {student.fullname},\n\n"
                    "We are happy to share with you the course completion certificate."
                    "You can download the attached PDF Format:\n\n"
                    "\nAll the Best."
                )
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [student.email]
                try:
                    send_mail(subject, message, email_from, recipient_list, fail_silently=False)
                    student.cerficate_sent = True
                    student.save() 
                except Exception as e:
                    messages.error(request, f"Failed to send email to {student.fullname}. Error: {str(e)}")
                    continue
                
            messages.success(request, 'Emails sent successfully')
            return redirect('send_email')
    
    # If request method is GET, render a response
    return render(request, 'certifications/sent_emails.html')


# certification AUTO  of students
def list_student(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  student=register_user.leads.filter(lead_position='ADMITTED')
  context={'student':student}
  print(student)
  for i in student:
     print(i.course_name.specialization.specilalization_name)
  return render(request,'certifications/auto_certification.html',context)
# Auto import
def List_student_import(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  student=register_user.leads.all().order_by('-id')
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="Student.csv"'
  writer = csv.writer(response)
  writer.writerow(['Full Name','Email','Mobile Number','Course Name','Specialization Name','Start Date','End Date','Certifictate Id'])
  i=0
  for s in student:
    i+=1
    writer.writerow([i,s.first_name,s.email,s.mobile_number,s.course_name.course_name,s.course_name.specialization.specilalization_name,s.admissions_date, s.end_date,s.certifictate_id])
  return response
# Auto sent maail all    
def list_student_sent(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids_str = request.POST.get('selected_ids')
    selected_ids = [int(id_str) for id_str in selected_ids_str.split(',') if id_str.strip()]  # Convert to list of integers
    if selected_ids:
      selected_students = register_user.leads.filter(id__in=selected_ids)
      for student in selected_students:
        subject = 'Course Completion Certificate'
        message = (
            f"Congratulations {student.fullname},\n\n"
            "We are happy to share with you the course completion certificate."
            "You can download the attached PDF Format:\n\n"
            "\nAll the Best."
        )
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [student.email]
        try:
          send_mail(subject, message, email_from, recipient_list, fail_silently=False)
          student.cerficate_sent = True
          student.save() 
        except Exception as e:
          messages.error(request, f"Failed to send email to {student.fullname}. Error: {str(e)}")
          continue
        
      messages.success(request, 'Emails sent successfully.')
      return redirect('list_student')

# send_mail('Subject', 'Message', 'from@example.com', ['to@example.com'])



# Manual student
def create_student(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    
    Fullname = request.POST.get('fullname')
    Email = request.POST.get('email')
    Mobilenumber = request.POST.get('mobilenumber')
    Course = request.POST.get('course_name')
    course_instance = register_user.courses.get(pk=Course)
    Specialization = request.POST.get('specialization')
    print(Specialization)
    Specialization_instance = register_user.specializations.get(pk=Specialization)  # Retrieve the Specialization instance
    print(Specialization_instance)
    Startdate = request.POST.get('startdate')
    Enddate = request.POST.get('enddate')
    Certifictateid = request.POST.get('certifictateid')
    if register_user.CreateStudent.filter(fullname=Fullname,certifictateid=Certifictateid).exists():
      messages.error(request, f'{Fullname} ,{Certifictateid} Already Exists')
      return redirect('create_student')
    else:
      creatstudents.objects.create(
        fullname=Fullname,
        email=Email,
        mobilenumber=Mobilenumber,
        course=course_instance,
        specialization=Specialization_instance,
        startdate=Startdate,  
        enddate=Enddate, 
        certifictateid=Certifictateid,
        crn_number= register_user  
      )
      messages.success(request, f'{Fullname.strip().title()} Created Successfully')
      return redirect('create_student')
  student=register_user.CreateStudent.all().order_by('-id')
  coursename=register_user.courses.all()
  specialization=register_user.specializations.all()
  context={
      'student' : student,
      'coursename': coursename,
      'specialization': specialization,    
  }       
  return render(request,'certifications/manual_certification.html',context)
# certification edit 
def create_student_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    Fullname = request.POST.get('editfullname')
    Email = request.POST.get('editemail')
    Mobilenumber = request.POST.get('editmobilenumber')
    Course = request.POST.get('editcourse_name')
    course_instance = register_user.courses.get(pk=Course)  # Retrieve the Specialization instance
    Specialization = request.POST.get('editspecialization')
    Specialization_instance = register_user.specializations.get(pk=Specialization)  # Retrieve the Specialization instance
    Startdate = request.POST.get('editstartdate')
    Enddate = request.POST.get('editenddate')
    Certifictateid = request.POST.get('editcertifictateid')
    if register_user.CreateStudent.filter(fullname=Fullname, certifictateid=Certifictateid).exists():
      messages.error(request, f'{Fullname}) Already Exists')
      return redirect('create_student')
    else:
      register_user.CreateStudent.filter(id=id).update(
        fullname=Fullname,
        email=Email,
        mobilenumber=Mobilenumber,
        course=course_instance,
        specialization=Specialization_instance,
        startdate=Startdate,  
        enddate=Enddate, 
        certifictateid=Certifictateid,
      )
      messages.success(request, f'{Fullname} Manual Updated Successfully')
      return redirect('create_student')
    



# certification export
def create_student_export(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  student=register_user.CreateStudent.all().order_by('-id')
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="Student.csv"'
  writer = csv.writer(response)
  writer.writerow(['Full Name','Email','Mobile Number','Course Name','Specialization Name','Start Date','End Date','Certifictate Id'])
  i=0
  for s in student:
    i+=1
    writer.writerow([i,s.fullname,s.email,s.mobilenumber,s.course,s.specialization,s.startdate, s.enddate,s.certifictateid])
  return response

#certification import
def create_student_import(request):
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    if request.method == 'POST':
        form =createstudent_import_form(request.POST, request.FILES)
        if form.is_valid():
          try:
              csv_file = request.FILES['createstudent_file']
              decoded_file = csv_file.read().decode('utf-8')
              reader = csv.reader(decoded_file.splitlines())
              headers = next(reader)
              expected_headers = 9
              for row in reader:
                  if len(row) != expected_headers:
                      messages.error(request, f'File should have {expected_headers} columns')
                      return redirect('create_student')
                  print(row)
                  fullname = row[1]
                  email = row[2]
                  mobilenumber = row[3]
                  course = row[4]
                  course_instance = register_user.courses.get_or_create(course_name=course)[0]
                  specialization = row[5]
                  specialization_instance=register_user.specializations.get_or_create(specilalization_name=specialization)[0]
                  startdate = row[6]
                  enddate = row[7]
                  certifictateid = row[8]
                  if fullname and email and mobilenumber and course_instance and specialization_instance  and startdate and enddate and certifictateid:
                      if not creatstudents.objects.filter(fullname=fullname,certifictateid=certifictateid).exists():
                          creatstudents.objects.create(
                              fullname=fullname,
                              email=email,
                              mobilenumber=mobilenumber,
                              course=course_instance,
                              specialization=specialization_instance,
                              startdate=startdate,
                              enddate=enddate,
                              certifictateid=certifictateid,
                              crn_number=register_user
                          )
                  else:
                      messages.error(request, 'Some required fields are missing for creating Demo. Skipping this entry.')
              
              messages.success(request, 'File imported successfully')
              return redirect('create_student')
          except Exception as e:
            print(e)
            messages.error(request, f'{e}. File should be in CSV format')
            return redirect('create_student')   
    return render(request,'certifications/manual_certification.html')
# Dependances from Courses to Specialization

@admin_required
def depnd_specilization(request, id_course):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  course = register_user.courses.get(id=id_course)
  display_spec = register_user.specializations.filter(course_name=course,status='Active')
  specialization_list = [{'id': spec.id, 'name': spec.specilalization_name} for spec in display_spec]
  
  return JsonResponse({'specialization_list': specialization_list})

#certification sent maail all
def create_student_sent(request):
  crn = request.session.get('admin_user').get('crn')
  register_user = Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_ids_str = request.POST.get('selected_ids')
    selected_ids = [int(id_str) for id_str in selected_ids_str.split(',') if id_str.strip()]  # Convert to list of integers
    if selected_ids:
      selected_students = register_user.CreateStudent.filter(id__in=selected_ids)
      for student in selected_students:
        subject = 'Course Completion Certificate'
        message = (
            f"Congratulations {student.fullname},\n\n"
            "We are happy to share with you the course completion certificate."
            "You can download the attached PDF Format:\n\n"
            "\nAll the Best."
        )
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [student.email]
        try:
          send_mail(subject, message, email_from, recipient_list, fail_silently=False)
          student.cerficate_sent = True
          student.save() 
        except Exception as e:
          messages.error(request, f"Failed to send email to {student.fullname}. Error: {str(e)}")
          continue
        
      messages.success(request, 'Emails sent successfully.')
      return redirect('create_student')



# bounced mails
def bounced_email(request):
    return render(request,'certifications/bounced_mails.html') 
  #bounced edit
def bounced_edit(request,id):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    Fullname = request.POST.get('editfullname')
    Email = request.POST.get('editemail')
    Mobilenumber = request.POST.get('editmobilenumber')
    Course = request.POST.get('editcourse_name')
    course_instance = register_user.courses.get(pk=Course)  # Retrieve the Specialization instance
    Specialization = request.POST.get('editspecialization')
    Specialization_instance = register_user.specializations.get(pk=Specialization)  # Retrieve the Specialization instance
    Startdate = request.POST.get('editstartdate')
    Enddate = request.POST.get('editenddate')
    Certifictateid = request.POST.get('editcertifictateid')
    if register_user.BouncedStudent.filter(fullname=Fullname, certifictateid=Certifictateid).exists():
      messages.error(request, f'{Fullname}) Already Exists')
      return redirect('bounced_mails')
    else:
      register_user.BouncedStudent.filter(id=id).update(
        fullname=Fullname,
        email=Email,
        mobilenumber=Mobilenumber,
        course=course_instance,
        specialization=Specialization_instance,
        startdate=Startdate,  
        enddate=Enddate, 
        certifictateid=Certifictateid,
      )
      messages.success(request, f'{Fullname} Manual Updated Successfully')
      return redirect('bounced_mails')
# Dependances from Courses to Specialization

@admin_required
def depnd_specilization(request, id_course):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  course = register_user.courses.get(id=id_course)
  display_spec = register_user.specializations.filter(course_name=course,status='Active')
  specialization_list = [{'id': spec.id, 'name': spec.specilalization_name} for spec in display_spec]
  
  return JsonResponse({'specialization_list': specialization_list})

 
def bounced_sent(request):
    crn = request.session.get('admin_user', {}).get('crn')
    if crn:
        register_user = Register_model.objects.get(crn=crn)
        if request.method == "POST":
            selected_ids_str = request.POST.get('selected_ids')
            if selected_ids_str:
                selected_ids = [int(id_str) for id_str in selected_ids_str.split(',') if id_str.strip()]
                if selected_ids:
                    selected_students = register_user.CreateStudent.filter(id__in=selected_ids)
                    for student in selected_students:
                        subject = 'Course Completion Certificate'
                        message = (
                            f"Congratulations {student.fullname},\n\n"
                            "We are happy to share with you the course completion certificate."
                            "You can download the attached PDF Format:\n\n"
                            "\nAll the Best."
                        )
                        email_from = settings.EMAIL_HOST_USER
                        recipient_list = [student.email]
                        try:
                            send_mail(subject, message, email_from, recipient_list, fail_silently=False)
                            student.certificate_sent = True
                            student.save()
                        except Exception as e:
                            messages.error(request, f"Failed to send email to {student.fullname}. Error: {str(e)}")
                            continue
                    messages.success(request, 'Emails sent successfully.')
                    return redirect('bounced_mails')
                else:
                    messages.error(request, 'No selected students found.')
            else:
                messages.error(request, 'No selected IDs provided.')
        else:
            messages.error(request, 'Invalid request method.')
    else:
        messages.error(request, 'CRN not found in session.')
    return redirect('bounced_mails') 

    
    
#cerication name
def create_certification(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == 'POST':
    CertificationName=request.POST.get('certificationname')
    Course = request.POST.get('course_name')
    course_instance = register_user.courses.get(pk=Course)
    print(Course)
    print(course_instance)
    Specialization = request.POST.get('specialization')
    Specialization_instance = register_user.specializations.get(pk=Specialization) 
    print(Specialization_instance)
    Coursetitle = request.POST.get('course_title')
    Image= request.FILES.get('image')
    Description = request.POST.get('description')
    if register_user.certifications.filter(course=course_instance,specialization=Specialization_instance).exists():
      messages.error(request, f'{course_instance} with {Specialization_instance}  already exists')
      return redirect('create_certification')
    else:
      Certification.objects.create(
        course=course_instance, 
        certification=CertificationName,
        specialization=Specialization_instance,
        course_title=Coursetitle,
        image=Image,
        description=Description, 
        crn_number=register_user,
      )
      messages.success(request,f'{course_instance} with {Specialization_instance} details created successfully')
      return redirect('create_certification')
  manage=register_user.courses.all()
  special=register_user.specializations.all() 
  certifi=register_user.certifications.all().order_by('-id')
  context={
    'manage':manage,
    'certifi':certifi,
    'special':special,
  } 
  return render(request,'settings_page/certification_name.html',context)





# Dependances from Courses to Specialization
@admin_required
def depnd_specilization(request, id_course):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  course = register_user.courses.get(id=id_course)
  display_spec = register_user.specializations.filter(course_name=course,status='Active')
  specialization_list = [{'id': spec.id, 'name': spec.specilalization_name} for spec in display_spec]
  
  return JsonResponse({'specialization_list': specialization_list})


@admin_required
def edit_certification(request,id):
  if request.method == 'POST':
    crn=request.session.get('admin_user').get('crn')
    register_user=Register_model.objects.get(crn=crn)
    CertificationName=request.POST.get('editcertificationname')
    Course = request.POST.get('editcourse_name')
    Specialization = request.POST.get('editspecialization')
    Coursetitle = request.POST.get('editcourse_title')
    Image= request.FILES.get('image')
    Description = request.POST.get('editdescription')

    print("crn",crn)
    print("register_user",register_user)
    print("CertificationName",CertificationName)
    print("Course",Course)
    print("Specialization",Specialization)
    print("Coursetitle",Coursetitle)
    print("Image",Image)
    print("Description",Description)

    print("stage one")
    if 'image' in request.FILES:
      print("Stage two")
      if Image:
        certifi = register_user.certifications.get(id=id)
        certifi.Image=Image
        certifi.save()
      if register_user.certifications.filter(course=Course,specialization=Specialization).exclude(id=id).exists():
        messages.error(request, f'{Course} with {Specialization}  already exists')
        return redirect('create_certification')
      else:
        register_user.certifications.filter(id=id).update(
          course=Course,
          specialization=Specialization,
          certification=CertificationName,
          course_title=Coursetitle,
          image=Image,
          description=Description, 
          crn_number=register_user,    
        )
        messages.success(request,f'updated successfully')      
        return redirect('create_certification')
      
    else:
       messages.error(request,'Please select file')  
       return redirect('create_certification')

  else:
    messages.error(request,'Invalid request')     
    return redirect('create_certification')


@admin_required
def delete_certification(request, id):
    if request.method == "POST":
        admin_user = request.session.get('admin_user')
        if admin_user:
            crn = admin_user.get('crn')
            register_user = get_object_or_404(Register_model, crn=crn)
            course = register_user.certifications.filter(id=id).first()
            if course:
                course.delete()
                messages.success(request, 'Certification Deleted Successfully')
            else:
                messages.error(request, 'Certification not found')
        else:
            messages.error(request, 'User not logged in')
    else:
        messages.error(request, 'Invalid request method')

    return redirect('create_certification')


@admin_required
def certification_all(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  if request.method == "POST":
    selected_departments=request.POST.get('selected_departments')
    selected_list=selected_departments.split(",")
    register_user.departments.filter(id__in=selected_list).delete()
    messages.success(request, 'Records deleted successfully')
    return redirect('create_certification')

  else:
     return redirect('create_certification')


  
@admin_required
def export_certification(request):
  crn=request.session.get('admin_user').get('crn')
  register_user=Register_model.objects.get(crn=crn)
  manage = register_user.certifications.all()
  response = HttpResponse(content_type='text/csv')
  response['Content-Disposition'] = 'attachment; filename="course_manage.csv"'
  writer = csv.writer(response)
  writer.writerow(['S.no','Course Name','Specialization','Course Title','Description'])
  i=0
  for d in manage:
    i+=1
    writer.writerow([i,d.course,d.specialization,d.course_title,d.description])
  return response


@admin_required
def import_certification(request):
    crn = request.session.get('admin_user', {}).get('crn')
    register_user = Register_model.objects.get(crn=crn)
    
    if request.method == 'POST':
        form = certification_import_form(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['certification_file']
                decoded_file = csv_file.read().decode('utf-8')
                reader = csv.reader(decoded_file.splitlines())
                headers = next(reader)
                expected_headers = 5

                for row in reader:
                    if len(row) != expected_headers:
                        messages.error(request, "File does not match the expected format")
                        return redirect('create_certification')

                    course_name = row[1]
                    course_instance = register_user.courses.filter(course_name=course_name).first()
                    specialization_name = row[2]
                    specialization_instance = register_user.specializations.filter(specilalization_name=specialization_name).first()
                    course_title = row[3]
                    description = row[4]

                    if course_instance and specialization_instance and course_title and description:
                        if not Certification.objects.filter(course=course_instance, specialization=specialization_instance, course_title=course_title).exists():
                            Certification.objects.create(
                                course=course_instance,
                                specialization=specialization_instance,
                                course_title=course_title,
                                description=description,
                                crn_number=register_user
                            )
                    else:
                        messages.error(request, 'Some required fields are missing for creating certification. Skipping this entry.')

                messages.success(request, 'File imported successfully')
                return redirect('create_certification')
            except Exception as e:
                print(e)
                messages.error(request, f'{e}. File should be in CSV format')
                return redirect('create_certification')
    else:
        form = certification_import_form()

    return render(request, 'settings_page/certification_name.html', {'form': form})
#certi_Templete
def certifi_templete (request,id):
   certificate = Certification.objects.get(id=id)
   context={
      'certificate':certificate
   }
   return render(request,'settings_page/Certifi_templete.html',context)

  
