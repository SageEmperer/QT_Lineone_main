
from django.http import JsonResponse
from django.shortcuts import render,redirect
from .models import *
from django.contrib import messages

def student_required(view_func):
    def wrapper(request, *args, **kwargs):
        if 'student' not in request.session:
            # If 'student' is not in session, redirect to login page
            return redirect('student_login')
        

        
        # If 'student' is in session, proceed to the view
        return view_func(request, *args, **kwargs)
    return wrapper



        



def student_login(request):
    if request.session.get('student'):
        return redirect('dash')
    
    if request.method == 'POST':
        email = request.POST.get('email_id')
        password = request.POST.get('password')
        
        print("Credentials:")
        print(email, password)
        
        if StudentCredentials.objects.filter(email=email, password=password).exists():
            student = StudentCredentials.objects.get(email=email, password=password)
            print(student.is_active)
            
            if student.is_active:
                
                student_id = LeadModel.objects.get(pk=student.student_id.id)
                request.session['student'] = {'email': email, 'student_id': student_id.id}
                print('Success')
                return redirect('dash')
            else:
                messages.error(request, 'Your account is not active. Please contact admin.')
                return redirect('student_login')
        else:
            messages.error(request, 'Invalid credentials.')
            return redirect('student_login')
    
    return render(request, 'student_login.html')
           

        



@student_required
def student_logout(request):
    if request.method == "POST":
        del request.session['student']
        return redirect('student_login')
    else:
        return redirect('student_login')


@student_required
def student_OTP(request):
    student_id = request.session.get('student').get('student_id')

    student = LeadModel.objects.get(id = student_id)
    crn = student.crn_number
    register_user = Register_model.objects.get(crn=crn)
    qualification = register_user.qualifications.all()
    

    if request.method == "POST":
        gender = request.POST.get('gender')
        stdQualification =  request.POST.get('Qualification')
        linkedin = request.POST.get('linkedin')
        country =  request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        education_data=request.POST.getlist('education_data')
        project_data = request.POST.getlist('project_data')
        certification_data = request.POST.getlist('certification_data')
        qualification_instance = Qualification.objects.get(pk=stdQualification)
        permanent_country = request.POST.get('permanent_country')
        permanent_state = request.POST.get('permanent_state')
        permanent_city = request.POST.get('permanent_city')
        StudentOneTimeProfile.objects.create(

            student = LeadModel.objects.get(pk=student_id),
            gender = gender,
            Qualification = qualification_instance,
            linkedin = linkedin,
            country = country,
            state = state,
            city = city,
            permanent_country = permanent_country,
            permanent_state = permanent_state,
            permanent_city = permanent_city,
            education_data = education_data,
            project_data = project_data,
            certification_data = certification_data,
        )
        
        credential = StudentCredentials.objects.get(student_id= student_id)
        credential.oneTimeProfile = True
        credential.save()
        messages.success(request, 'Profile created successfully')
        return redirect('dash')

    context = {
        'student':student,
        'qualification':qualification
    }

    return render(request, 'student_OTP.html',context)





            
        



def base(request):
    return render(request,'base.html')


@student_required
def dash(request):
    return render(request,'dashbord.html')


@student_required
def student_profile(request):
    return render(request,'student_profile.html')


@student_required
def student_id(request):
    return render(request,'id.html')


@student_required
def my_job(request):
    return render(request,'Myjob.html')

@student_required
def project(request):
    return render(request,'profile_project.html')

@student_required    
def certification(request):
    return render(request,'profile_certification.html')



@student_required
def reset_paasword(request):
    return render(request,'reset_password.html')


@student_required    
def internship(request):
    return render(request, 'internship.html')
 


def faculty_jason(request,spec_id):
    faculty = Employee_model.objects.filter(specialization_id=spec_id)
    faculty_list = [{'first_name': fac.first_name,'last_name': fac.last_name, 'id': fac.id} for fac in faculty] 
    return JsonResponse(faculty_list, safe=False)

def find_slot(request,fac_id):
    slot = Scheduling_mock_model.objects.filter(faculty=fac_id)
    slot_list = [{'available_slot': slot.available_slot, 'id': slot.id} for slot in slot] 
    return JsonResponse(slot_list, safe=False)



@student_required    
def mocks(request):
    student_id = request.session.get('student').get('student_id')
    student = LeadModel.objects.get(id = student_id)
    crn = student.crn_number

    register_user = Register_model.objects.get(crn=crn)
    courses = register_user.courses.all()
    schedules = Scheduling_mock_model.objects.filter(student_name = student_id)
    if request.method == 'POST':
        course_name = request.POST.get('course_name')
        specialization = request.POST.get('specialization')
        faculty = request.POST.get('faculty')
        available_slot = request.POST.get('available_slot')
        attach_Resume = request.FILES.get('attach_Resume')
        schedule = Scheduling_mock_model.objects.filter(id=available_slot)
        if Scheduling_mock_model.objects.filter(id=available_slot, student_name = student_id).exists():
            messages.error(request, 'Already Booked')
            return redirect('mocks')
        
        if schedule.exists():
            Scheduling_mock_model.objects.filter(id=available_slot).update(attach_Resume=attach_Resume, course_name=course_name, specilalization_name=specialization,student_name = student_id)
            
        messages.success(request, 'Slot Booked successfully')
        return redirect('mocks')
    

    



        


    # student= LeadModel.objects.get(id=credentials.studend_id)
    # print(student)
    # crn = LeadModel.objects.get(id=student_id).crn_number
    # print(crn)
    context={
        'courses':courses,
        'schedules':schedules
    }
     
    # coursess= Course.objects.all()
    return render(request, 'mocks.html',context)









@student_required
def mycourse1(request):
    return render(request,"my_course1.html")



@student_required    
def mycourses(request):
    return render(request,"my_courses.html")



@student_required    
def my_course_As1(request):
    return render(request,"my_course_As1.html")



@student_required    
def my_course_As2(request):
    return render(request,"my_course_As2.html")


@student_required    
def my_course_video1(request):
    return render(request,"my_course_video1.html")



@student_required    
def Test_card(request):
    return render(request,"Test_card.html")


@student_required    
def matched_jobs(request):
    student_id = request.session.get('student').get('student_id')
    student = LeadModel.objects.get(id = student_id)
    crn = student.crn_number
    register_user = Register_model.objects.get(crn=crn)
    applied_jobs = StudetJobApply.objects.filter(student_id=student_id).values_list('job_id', flat=True)
    jobs = register_user.job_post.filter(last_date_to_apply__gte=datetime.now()).exclude(id__in=applied_jobs)

    print("studentid",student_id)
    # method for applying for the jobs by the student
    if request.method == "POST":
        job_id = request.POST.get('job_id')
        print("job_id", job_id)
        if register_user.job_post.filter(id=job_id).exists():
            StudetJobApply.objects.create(
                crn_number = register_user,
                job_id = Job_post.objects.get(pk=job_id),
                student_id = LeadModel.objects.get(pk=student.id),
                applyed_date_time = datetime.now()
            )

            messages.success(request,'Job Applyed Successfully')
            return redirect('jobs')
        else:
            messages.error(request,'Job Post not found!')
            return redirect('jobs')
            

    
    context = {

        'jobs':jobs,
        'student':student

    }

    return render(request,'matched_jobs.html',context)



@student_required
def applied_jobs(request):
    return render(request,'applied_jobs.html')



@student_required
def qualified_jobs(s):
    return render(s,'qualified_jobs.html')




@student_required
def job_details(s):
    return render(s,'job_details.html')
# Create your views here.



@student_required
def student_attendance(request):
    return render(request,'student_attendance.html')


@student_required
def calendar(request):
    return render(request,'calendar.html')




@student_required    
def CERTIFICATE(request):
    pass
    return render(request, 'certificates.html')



@student_required    
def payments(request):
    return render(request,'payments.html')


@student_required    
def Invoice(request):
    return render(request,'invoice.html')
