from django.urls import path
from . import views
urlpatterns = [
    path('',views.student_login,name="student_login"),
    path('student_logout/',views.student_logout,name="student_logout"),
    path('dash/',views.dash,name='dash'),
    path('student_profile/',views.student_profile,name='student_profile'),
    path('student_id/',views.student_id,name='student_id'),
    path('my_job/',views.my_job,name='my_job'),
    path('profile_project/',views.project,name='profile_project'),
    path('profile_certification/',views.certification,name='profile_certification'),
    path('reset/',views.reset_paasword,name='reset'),
    path('internship/', views.internship, name='internship'),
    path('mocks/', views.mocks, name='mocks'),
    path('my_course1/', views.mycourse1, name="my_course1"),
    path('my_courses/', views.mycourses, name="my_courses"),
    path('my_course_As1/', views.my_course_As1, name="my_course_As1"),
    path('my_course_As2 /', views.my_course_As2, name="my_course_As2"),
    path('my_course_video1/', views.my_course_video1, name="my_course_video1"),
    path('Test_card/', views.Test_card, name="Test_card"),
    path('jobs',views.matched_jobs,name='jobs'),
    path('applied_jobs',views.applied_jobs,name='applied_jobs'),
    path('qualified_jobs',views.qualified_jobs,name='qualified_jobs'),
    path('job_details',views.job_details,name='job_details'),
    path('student_attendance/', views.student_attendance, name='student_attendance'),
    path('calendar/', views.calendar, name='calendar'),
    path('certificate', views.CERTIFICATE, name='certificate'),
    path('payments/', views.payments, name='payments'),
    path('invoice/',views.Invoice,name='invoice'),
]