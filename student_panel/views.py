from django.shortcuts import render,redirect
from .models import *


def student_required(view_func):
    def wrapper(request, *args, **kwargs):
        if 'student' not in request.session:
            # If 'student' is not in session, redirect to login page
            return redirect('student_login')
        # If 'student' is in session, proceed to the view
        return view_func(request, *args, **kwargs)
    return wrapper



def student_login(request):
    if request.method == 'POST':
        email = request.POST.get('email_id')
        password = request.POST.get('password')
        print(email, password)
        if Studen_credentials.objects.filter(email=email, password=password, is_active=True).exists():
            student = Studen_credentials.objects.get(email=email, password=password, is_active=True)
            student_id = student.student_id
            request.session['student'] = {'email': email, 'password': password, 'student_id': student_id}
            print('success')
            return redirect('dash')
        else:
            return redirect('student_login')

    return render(request, 'student_login.html')



def base(request):
    return render(request,'base.html')


@student_required
def dash(request):
    return render(request,'dashbord.html')
def student_profile(request):
    return render(request,'student_profile.html')
def student_id(request):
    return render(request,'id.html')
def my_job(request):
    return render(request,'Myjob.html')
def project(request):
    return render(request,'profile_project.html')
def certification(request):
    return render(request,'profile_certification.html')
def student_login(request):
    return render(request,'student_login.html')
def reset_paasword(request):
    return render(request,'reset_password.html')
def internship(request):
    return render(request, 'internship.html')
def mocks(request):
    return render(request, 'mocks.html')

def mycourse1(request):
    return render(request,"my_course1.html")
def mycourses(request):
    return render(request,"my_courses.html")
def my_course_As1(request):
    return render(request,"my_course_As1.html")
def my_course_As2(request):
    return render(request,"my_course_As2.html")
def my_course_video1(request):
    return render(request,"my_course_video1.html")
def Test_card(request):
    return render(request,"Test_card.html")
def matched_jobs(request):
    return render(request,'matched_jobs.html')

def applied_jobs(request):
    return render(request,'applied_jobs.html')

def qualified_jobs(s):
    return render(s,'qualified_jobs.html')

def job_details(s):
    return render(s,'job_details.html')
# Create your views here.
def student_attendance(request):
    return render(request,'student_attendance.html')

def calendar(request):
    return render(request,'calendar.html')
def CERTIFICATE(request):
    pass
    return render(request, 'certificates.html')
def payments(request):
    return render(request,'payments.html')
def Invoice(request):
    return render(request,'invoice.html')
