from django.urls import path
from .import views
urlpatterns = [
    path('',views.admin_login,name="login"),
    path('logout_page/',views.logout_page,name="logout_page"),
    path('register/',views.register_page,name="register"),
    path('otp_page/<int:user_id>/',views.otp_page,name="otp_page"),
    path('register_resend_otp/',views.register_resend_otp,name="register_resend_otp"),
    path('terms_and_conditions/',views.terms_and_conditions,name="terms_and_conditions"),
    path('departments/',views.departments,name="departments"),
    path('settings/',views.settings_page,name="settings"),
    path('designations/',views.designations,name="designations"),
    path('branches/',views.branches,name="branches"),
    path('batch_type/',views.batch_types,name="batch_type"),
    path('training_type/',views.training_type,name="training_type"),
    path('regulations/',views.regulations,name="regulations"),
    path('upi_payments/',views.upi_payments,name="upi_payments"),
    path('sub_category/',views.sub_category,name='sub_category'),
    path('courses/',views.courses,name="courses"),
    path('specialization/',views.specialization,name="specialization"),
    path('plans/',views.plans,name="plans"),
    path('net_banking/',views.net_banking,name="net_banking"),
    path('register/',views.register_page,name="register"),
    path('otp_page/',views.otp_page,name="otp_page"),
    path('vendor/',views.vendor,name="vendor"),
    path('purpose_of_visit/',views.purposeOfVisit,name="purpose_of_visit"),
    path('prospect_type/',views.prospect_type,name="prospect_type"),
    path('forum_category/',views.forum_category,name="forum_category"),
    path('employee_type/',views.employee_type,name="employee_type"),
    path('dashboard/',views.dashboard,name="dashboard"),
    path('complaints/',views.complaints,name="complaints"),
    path('calender/',views.calender,name="calender"),
    path('demo/',views.demo,name="demo"),
    path('Leads/',views.Leads,name="Leads"),
    path('course_manage/',views.course_manage,name='course_manage'),
    path('employees/',views.employee_list,name="employees"),
    path('Job_type/',views.Job_type,name='Job_type'),  
    path('job_category/',views.job_category,name='job_category'),
    path('qualification/',views.qualification,name='qualification'),
    path('jobrole/',views.jobrole,name="jobrole"),
    path('class_room/',views.classroom,name="class_room"),
     path('chapters/',views.chapters,name='chapters'),
    path('lesson_title/',views.lesson_title,name='lesson_title'),
    path('topics/',views.topics,name='topics'),
    path('video_player',views.video_player,name='video_player'),
    path('language/',views.language,name="language"),
    path('finance/',views.finance,name="finance"),

    #Questoning path
    path('quiz',views.quiz,name='quiz'),
    path('create_quiz',views.create_quiz,name='create_quiz'),
    path('edit_quiz_question',views.edit_quiz,name='edit_quiz'),

    path('worksheet',views.worksheet,name='worksheet'),
    path('create_worksheet',views.create_worksheet,name='create_worksheet'),
    path('edit_worksheet',views.edit_worksheet,name='edit_worksheet'),

    path('assessment',views.assessment,name='assessment'),
    path('create_assessment',views.create_assessment,name='create_assessment'),
    path('edit_assessment',views.edit_assessment,name='edit_assessment'),


   #  student card
   path('student_card/',views.student_card,name="student_card"),


  
  
  
  
  
   #lead portal start here

    path('lead_prospects/',views.lead_prospects,name='lead_prospects'),
    path('lead_leads/',views.lead_leads,name='lead_leads'),
    path('leads/',views.leads,name='leads'),
    path('lead_move_to_mql/<int:id>',views.lead_move_to_mql,name="lead_move_to_mql"),
    path('mql/',views.mql,name='mql'),
    path('reschedule_demo/<int:id>',views.reschedule_demo,name="reschedule_demo"),
    path('move_to_sql/<int:id>',views.move_to_sql,name="move_to_sql"),
    path('move_to_opportunity/<int:id>',views.move_to_opportunity,name="move_to_opportunity"),
    path('get_branches/', views.get_branches, name='get_branches'),
    path('get_courses/<int:branch_id>/', views.get_courses, name='get_courses'),
    path('move_to_admission/<int:id>',views.move_to_admission,name="move_to_admission"),
    path('admissions/',views.admissions,name="admissions"),
    path('mark_as_spam/', views.mark_as_spam, name='mark_as_spam'),
    path('get_upi_details/<int:upi_id>',views.get_upi_details,name="get_upi_details"),



   #  fiance 
   path('finance_and_accounts_update/',views.finance_and_accounts_update,name="finance_and_accounts_update"),
    




    path('sql/',views.sql,name='sql'),
    path('request_discounts/',views.request_discounts,name='request_discounts'),
    path('opportunity/',views.opportunity,name='opportunity'),

    path('spam/',views.spam,name='spam'),


    
    # prosepects to lead actions
    
    path('mark_as_lead/<int:prospect_id>/', views.mark_as_lead, name='mark_as_lead'),
    path('lead_stage/<int:lead_id>/', views.lead_stage, name='lead_stage'),

    path('re_demo/<int:lead_id>/', views.re_demo, name='re_demo'),

    path('submit_to_opportunity/<int:lead_id>/', views.submit_to_opportunity, name='submit_to_opportunity'),


    # udpated operations on leads
    path('submit_enquiry/', views.submit_enquiry_form, name='submit_enquiry'),
    path('submit_to_mql/<int:lead_id>/', views.submit_to_mql, name='submit_to_mql'),
    path('submit_to_sql/<int:lead_id>/', views.submit_to_sql, name='submit_to_sql'),
    path('submit_admission/<int:lead_id>/', views.submit_admission, name='submit_admission'),
    path('request_discount/<int:lead_id>/', views.request_discount, name='request_discount'),
    path('submit_admit/<int:lead_id>/', views.submit_admit, name='submit_admit'),
    path('enquiry_verify_otp/', views.enquiry_verify_otp, name='enquiry_verify_otp'),
    path('multiple_mark_as_spam/', views.multiple_mark_as_spam, name='multiple_mark_as_spam'), 






      # hr portal start here
    path('hr',views.hr_details,name="hr"),
    path('placement_dashboard/',views.placement_dashboard,name='placement_dashboard'),
    path('jobdetails/',views.job_detailes, name='jobdetails'),
    path('applied/',views.applied_students, name='applied'),
    path('placed/',views.placed_students,name='placed'),
    path('jobdescription/',views.job_description, name='jobdescription'),
    path('Studentdetails',views.Student_details,name='student_Details'),
    path('Studentreport',views.Student_report,name="student_Report"),
    path('lokesh/',views.lokesh,name='lokesh'),
    path('studentsplaced/',views.students_placed, name='studentsplaced'),
    path('studentnotplaced/',views.students_notplaced, name='studentsnotplaced'),
    path('totalstudents/',views.total_students_applied, name='totalstudents'),
    path('profile/', views.profile,name='profile'),
    path('studentsreport/', views.studentreport,name='studentsreport'),
    path('hr_leads', views.hr_leads, name='hr_leads'),
    path('hr_confirmed', views.hr_confirmed, name='hr_confirmed'),
    path('not_interested_hr', views.not_interested_hr, name='not_interested_hr'),
    path('hrunderprogress/',views.hr_underprogress, name='hrunderprogress'),
    path('interviewschedule/',views.hr_interviewschedule, name='interviewschedule'),
    path('profilesent/',views.profilesent, name='profilesent'),
    path('job_gallery',views.job_gallery,name='job_gallery.html'),
    path('Studentfilter',views.Student_filter,name="student_filter.html"),
    path('jobgalleryapplied/',views.job_gallery_applied, name='jobgalleryapplied'),
    path('jobgalleryqualified/',views.job_gallery_qualified, name='jobgalleryqualified'),
    path('jobgalleryplaced/',views.job_gallery_placed, name='jobgalleryplaced'),
    path('placementstatus/',views.placement_status, name='placementstatus'),
    path('jobgalleryeligible/',views.job_gallery_elgible, name='jobgalleryeligible'),
    path('jobgalleryinprogress/',views.job_gallery_inprogress, name='jobgalleryinprogress'),
    path('underprogress/',views.students_underprogress, name='underprogress'),
    path('totaleligible/',views.total_students_eligible, name='totaleligible'),
    path('totalnoteligible/',views.total_students_noteligible, name='totalnoteligible'),
    path('totalnotintrested/',views.students_not_intrested, name='totalnotintrested'),
    path('totalnotattended/', views.students_notattended, name='totalnotattended'),
    path('level3/',views.level3, name='level3'),
    path('level2/',views.level2, name='level2'),
    path('level1/',views.level1, name='level1'),
    path('createvendor/',views.createvendor, name='createvendor'),

   #  mock start here
    path('faculty_login/',views.faculty_login,name="faculty_login"),
    path('mock_dashboard/',views.mock_dashboard,name="mock_dashboard"),
    path('student/',views.student,name="student"),
    path('faculty/',views.faculty_slot,name="faculty_slot"),
    path('facultymocks/', views.total_interviews, name="total_interviews"),
    path('past/', views.student_feedback, name="student_feedback"),
    path('admin/', views.admin_mock, name="admin_mock"),
    path('reschedule/', views.reschedule, name="reschedule"),
    path('adinterview/', views.admin_interview_list, name="admin_interview_list"),
    path('facultydashboard/', views.faculty_dashboard, name="faculty_dashboard"),
    path('facultydetails/', views.separate_faculty_list, name="separate_faculty_list"),
    path('adcomplete/', views.completed_mock, name="completed_mock"),
    path('facultyschedule/', views.faculty_schedule_list, name="faculty_schedule_list"),
    path('faculty_completed/', views.faculty_completed_mocklist, name="faculty_completed_mocklist"),
    path('facultypending/', views.faculty_pending_mocks, name="faculty_pending_mocks"),







   # mock end here
   

   # certification start here
     path('certif_dashboard',views.dashboard_certification,name='certif_dashboard'),
    path('send_email',views.send_email,name='send_email'),
    path('create_student',views.create_student,name='create_student'),
   
    path('bounced_email/',views.bounced_email,name='bounced_email'),






    # training type update
    path('training_type_update/<int:id>',views.training_type_update,name="training_type_update"),
    # training type status 
    path('training_type_status/<int:id>',views.training_type_status,name="training_type_status"),
    # training type delete
    path('training_type_delete/<int:id>',views.training_type_delete,name="training_type_delete"),
    #training type all delete
    path('training_type_delete_all/',views.training_type_all,name="training_type_delete_all"),
    # training type export
    path('training_type_export',views.training_type_export,name="training_type_export"),
    # import training type 
    path('training_type_import/',views.training_type_import,name="training_type_import"),
    # regulation status update
    path('regulations_status/<int:id>',views.regulations_status,name="regulations_status"),
    # regulation update
    path('regulation_update/<int:id>',views.regulation_update,name="regulation_update"),
    # regulation delete
    path('regulation_delete/<int:id>',views.regulation_delete,name="regulation_delete"),
    
 # regulations delete all
    path('regulation_delete_all/',views.regulations_all,name="regulation_delete_all"),
    # regulation export
    path('regulation_export',views.regulation_export,name="regulation_export"),
    # regulation import
    path('regulation_import/',views.regulation_import,name="regulation_import"),
    # regulation dropdowm dependency
    path('get_regulations/<int:course_id>/', views.get_regulations, name='get_regulations'),

    # branch status
    path('branches_status/<int:id>',views.branches_status,name="branchstatus"),
    # branch delete
    path('branch_delete/<int:id>',views.branch_delete,name="branchdelete"),
   #  branches delete all
   path('branches_del_all/',views.branches_del_all,name="branches_del_all"),
    # branch update
    path('branch_update/<int:id>',views.branch_update,name="branchupdate"),
    # branch export
    path('branch_export/',views.branch_export,name="branch_export"),
    # branch import
    path('branch_import/',views.branch_import,name="branch_import"),
   #  qrcode form
   path('inquiry_form/<int:id>/<str:crn>',views.inquery_form,name="inquiry_form"),
   path('inquiry_form_default/', views.inquery_form, name='inquiry_form_default'),
   path('opt_page/',views.opt_page,name="opt_page"),
   path('verify_otp/',views.verify_otp,name="verify_otp"),

   path('create_lead/',views.create_lead,name="create_lead"),
   path('receipt/<str:token_num>/<str:crn_number>',views.receipt,name="receipt"),
   path('receipt_pdf/<str:token_id>',views.receipt_pdf,name="receipt_pdf"),
   path('resend-otp/', views.resend_otp, name='resend_otp'),
   path('branch_error/',views.branch_error,name="branch_error"),   

    # complaint status
    path('complaints_status/<int:id>',views.complaints_status,name="complaints_status"),
    # complaints export
    path('complaints_export',views.complaints_export,name="complaints_export"),
    # complaints update
    path('complaints_update/',views.complaints_update,name="complaints_update"),

   # sub category edit
   path('sub_category_edit/<int:id>',views.sub_category_edit,name="sub_category_edit"),
   # sub category delete
   path('sub_category_delete/<int:id>',views.sub_category_delete,name="sub_category_delete"),
   # sub category status
   path('sub_category_status/<int:id>',views.sub_category_status,name="sub_category_status"),



    # course status
    path('courses_status/<int:id>',views.course_status,name="courses_status"),
    # course delete
    path('course_delete/<int:id>',views.course_delete,name="course_delete"),
     #course all delete
   path("course_all/", views.course_all, name="course_all"),
    # course update
    path('course_update/<int:id>',views.course_edit,name="course_update"),
    # course export
    path('course_export/',views.course_export,name="course_export"),
    # course import
    path('course_import/',views.course_import,name='course_import'),



    # department status
    path('department_status/<int:id>',views.department_status,name="department_status"),
    # department delete
    path('department_delete/<int:id>',views.department_delete,name="department_delete"),
    # department all delete
    path("department_all/", views.department_all, name="department_all"),
    # department update
    path('department_update/<int:id>',views.department_edit,name="department_update"),
    # department export
    path('department_export/',views.department_export,name="department_export"),
    # deparmtent impoort
    path('dep_import/',views.dep_import,name='dep_import'),
    # designation status
    path('designation_status/<int:id>',views.designation_status,name="designation_status"),
    # designation delete
    path('designation_delete/<int:id>',views.designation_delete,name="designation_delete"),
    # designation all delete
    path("designation_all/", views.designation_all, name="designation_all"),

    # designation update
    path('designation_update/<int:id>',views.designation_edit,name="designation_update"),
    # designation export
    path('designation_export/',views.designation_export,name="designation_export"),
    # designation import
    path('designation_import/',views.designation_import,name='designation_import'),
    # plans status
    path('plans_status/<int:id>',views.plans_status,name="plans_status"),
    # plans delete
    path('plans_delete/<int:id>',views.plans_delete,name="plans_delete"),
    # plans all delete
    path("plans_all/", views.plans_all, name="plans_all"),
    # plans update
    path('plans_update/<int:id>',views.plans_update,name="plans_update"),
    # plans export
    path('plans_export/',views.plans_export,name="plans_export"),
    # plans import
    path('plans_import/',views.plans_import,name='plans_import'),
    # specialization status
    path('specialization_status/<int:id>',views.specialization_status,name="specialization_status"),
    # specialization delete
    path('specialization_delete/<int:id>',views.specialization_delete,name="specialization_delete"),
     # specialization all delete
    path("specialization_all/", views.specialization_all, name="specialization_all"),
    # specialization update
    path('specialization_update/<int:id>',views.specialization_edit,name="specialization_update"),
    # specialization export
    path('specialization_export/',views.specialization_export,name="specialization_export"),
    # specialization import
    path('specialization_import/',views.specialization_import,name='specialization_import'),

   # chapter status
   path('chapter_status/<int:id>',views.chapter_status,name="chapter_status"),
   # chapter update
   path('chapter_update/<int:id>',views.chapter_update,name="chapter_update"),
   # chapter delete
   path('chapter_delete/<int:id>',views.chapter_delete,name="chapter_delete"),
   # chapters delete all
   path('chapters_all/',views.chapters_all,name="chapters_all"),

   path('get_courses_for_ch/<int:specialization_id>/', views.get_courses_for_ch, name='get_courses_for_ch'),
    path('get_sub_categories/<int:course_id>/', views.get_sub_categories, name='get_sub_categories'),
    path('get_specializations_ch/<int:chapter_id>/', views.get_specializations_ch, name='get_specializations_ch'),
    path('get_chapters/<int:lesson_id>/',views.get_chapters,name="get_chapters"),




   # lesson status
   path('lesson_status/<int:id>',views.lesson_status,name="lesson_status"),
   # lesson edit
   path("lesson_edit/<int:id>",views.lesson_edit,name="lesson_edit"),
   # lesson delete
   path('lesson_delete/<int:id>',views.lesson_delete,name="lesson_delete"),

   
   # topic edit
   path('topics_edit/<int:id>',views.topics_edit,name="topics_edit"),



    # clender status
    path('calender_status/<int:id>',views.calander_status,name="calender_status"),
    # calender delete
    path('calender_delete/<int:id>',views.calander_delete,name="calender_delete"),
     # calender all delete
    path("calender_all/", views.calander_all, name="calender_all"),
    # calender update
    path('calender_update/<int:id>',views.calander_update,name="calender_update"),
    # calender export
    path('calender_export/',views.calander_export,name="calender_export"),
    # calender import
    path('calender_import/',views.calender_import,name="calender_import"),
    # complaints update
    path('complaints_update/<int:id>',views.complaints_update,name="complaints_update"),
    # complaints delete
    path('complaint_delete/<int:id>',views.complaint_delete,name="complaint_delete"),
      #complaints delete all
    path('complaints_delete_all/',views.complaint_all,name="complaints_delete_all"),
    # complaints import
    path('complain_import/',views.complain_import,name="complain_import"),
    # forum update
    path('Forum_update/<int:id>/', views.Forum_update, name='Forum_update'),
    # forum delete
   path('Forum_delete/<int:id>/', views.Forum_delete, name='Forum_delete'),
     #forum all delete
   path('Forum_all/', views.Forum_all, name='Forum_all'),
    #forum status
   path('Forum_status/<int:id>/', views.Forum_status, name='Forum_status'),
    #forum export
   path('Forum_export/', views.Forum_export, name='Forum_export'),
    #forum import
   path('Forum_import/', views.Forum_import, name="Forum_import"),
#    purpose status
   path('purpose_status/<int:id>/', views.purpose_status, name='purpose_status'),
#    purpose delete
   path('purpose_delete/<int:id>/', views.purpose_delete, name='purpose_delete'),
#    purpose update
   path('purpose_update/<int:id>/', views.purpose_update, name='purpose_update'),
   #purpose all delete
   path('purpose_all/', views.purpose_all, name='purpose_all'),

#    purpose export
   path('purpose_export/', views.purpose_export, name='purpose_export'),
#    purpose import
   path('purpose_import/', views.purpose_import, name="purpose_import"),
#    prospect update
   path('Prospect_update/<int:id>/', views.Prospect_update, name='Prospect_update'),
#    prospect delete
   path('prospect_delete/<int:id>/', views.prospect_delete, name='prospect_delete'),
   #prospect all delete
   path('prospect_delete_all/', views.prospect_type_all, name='prospect_delete_all'),
#    prospect status
   path('prospect_status/<int:id>/', views.prospect_status, name='prospect_status'),
#    prospect type
   path('prospect_type_export/', views.prospect_type_export, name='prospect_type_export'),
#    prospect import
   path('prospect_type_import/', views.prospect_type_import, name="prospect_type_import"),
#    vendor update
   path('vendor_update/<int:id>/', views.vendor_update, name='vendor_update'),
#    vendor delete
   path('vendor_delete/<int:id>/', views.vendor_delete, name='vendor_delete'),
    #vendor all delete
   path('vendor_delete_all/', views.vendor_all, name='vendor_delete_all'),
#    vendor status
   path('vendor_status/<int:id>/', views.vendor_status, name='vendor_status'),
#    vendor export
   path('vendor_export/', views.vendor_export, name='vendor_export'),
#    vendor import
   path('vendor_import/', views.vendor_import, name="vendor_import"),
#    employee type update
   path('employeetype_update/<int:id>/', views.employeetype_update, name='employeetype_update'),
#    employee type delete
   path('employee_type_delete/<int:id>/', views.employee_type_delete, name='employee_type_delete'),
   #employee type delete all
   path('employee_type_delete_all/', views.employee_type_all, name='employee_type_delete_all'),

#    empoyee type status
   path('employee_status/<int:id>/', views.employee_status, name='employee_status'),
#    employee type export
   path('emplpoyee_type_export/', views.emplpoyee_type_export, name='emplpoyee_type_export'),
#    employee type import
   path('Employee_import/', views.Employee_import, name="Employee_import"),

   # class room edit
   path('classroomedit/<int:pk>',views.classroomedit,name='classroomedit'),
   # class room delete
   path('classroomdelete/<int:pk>',views.classroomdelete,name='classroomdelete'),
   # class room export
   path('classroom_export/',views.classroom_export,name='classroom_export'),
   # class room import
   path('classroom_import/',views.classroom_import,name='classroom_import'),


    # upi status
    path('upi_status/<int:id>',views.upi_status,name='upi_status'),
    # upi edit
    path('upi_edit/<int:id>',views.upi_edit,name='upi_edit'),
    # upi delete
    path('upi_delete/<int:id>',views.upi_delete,name='upi_delete'),
    #upi delete all
    path('upi_delete_all/',views.upi_payment_all,name='upi_delete_all'),
      
    # upi export
    path('upi_export/',views.upi_export,name='upi_export'),
   #  upi import
    path('upi_import/',views.upi_import,name="upi_import"),
    # net status
    path('net_status/<int:id>',views.net_status,name='net_status'),
    # net edit
    path('net_edit/<int:id>',views.net_edit,name='net_edit'),
    # net delete
    path('net_delete/<int:id>',views.net_delete,name='net_delete'),
    #net delete all
    path('net_delete_all/',views.net_banking_delete_all,name='net_delete_all'),



   # job role status
   path('jobrole_status/<int:id>',views.jobrole_status,name="jobrole_status"),
   # job role edit
   path('jobrole_edit/<int:id>',views.jobrole_edit,name="jobrole_edit"),
   # job role delete
   path('jobrole_delete/<int:id>',views.jobrole_delete,name="jobrole_delete"),
   # job role multi delete
   path('jobrole_del_all/',views.jobrole_del_all,name="jobrole_del_all"),
   # job role export
   path('jobrole_export/',views.jobrole_export,name="jobrole_export"),
   # jobrole import
   path('jobrole_import/',views.jobrole_import,name="jobrole_import"),







    # net export
    path('net_export/',views.net_export,name='net_export'),
   #  net import
    path('net_import/',views.net_import,name="net_import"),
    
    # batch status
    path('batch_status/<int:id>',views.batch_status,name='batch_status'),
    # batch edit
    path('batch_edit/<int:id>',views.batch_edit,name='batch_edit'),
    # batch delete
    path('batch_delete/<int:id>',views.batch_delete,name='batch_delete'),
     #batch delete all
    path('batch_delete_all/',views.batch_all,name='batch_delete_all'),
    # batch export
    path('batch_export/',views.batch_export,name='batch_export'),
    # batch import
    path('batch_import/',views.batch_import,name="batch_import"),
        # demo status
    path('demo_status/<int:id>',views.demo_status,name='demo_status'),
    # demo edit
    path('demo_edit/<int:id>',views.demo_edit,name='demo_edit'),
    # demo delete
    path('demo_delete/<int:id>',views.demo_delete,name='demo_delete'),  
   #  demo delete all
   path('demo_all/',views.demo_all,name="demo_all"),

        #Lead status
    path('Leads_status/<int:id>',views.Leads_status,name='Leads_status'),
    #Lead edit
    path('Leads_edit/<int:id>',views.Leads_edit,name='Leads_edit'),
    #Lead delete
    path('Leads_delete/<int:id>',views.Leads_delete,name='Leads_delete'),
    #Leads delete all
    path('Leads_delete_all/',views.leads_all,name='Leads_delete_all'),
    #Lead export
    path('Leads_export/',views.Leads_export,name='Leads_export'),
    #Leads import
    path('Leads_import/',views.Leads_import,name='Leads_import'),
        # demo status
    path('demo/',views.demo,name='demo'),
    # demo status
    path('demo_status/<int:id>',views.demo_status,name='demo_status'),
    # demo edit
    path('demo_edit/<int:id>',views.demo_edit,name='demo_edit'),
    # demo delete
    path('demo_delete/<int:id>',views.demo_delete,name='demo_delete'),
   #  demo mult delete
   path('demo_delete_all/',views.demo_all,name="demo_delete_all"),
    # demo views
    path('demo_views/<int:id>',views.demo_views,name="demo_views"),
    # demo export
    path('demo_export/',views.demo_export,name='demo_export'),
    # demo import
    path('demo_import/',views.demo_import,name="demo_import"),
    path('load-dependencies/', views.load_dependencies, name='load_dependencies'),
    path('load_specializations_and_batches/',views.load_specializations_and_batches,name="load_specializations_and_batches"),  
    

   path('course_manage_edit/<int:id>',views.course_manage_edit,name='course_manage_edit'),
   path('course_manage_delete/<int:id>',views.course_manage_delete,name='course_manage_delete'),
   path('course_manage_all/',views.course_manage_all,name='course_manage_all'),
   path('course_manage_export/',views.course_manage_export,name='course_manage_export'),
   path('course_manage_import/',views.course_manage_import,name="course_manage_import"),
   path('manage_views/<int:id>',views.manage_views,name="manage_views"),
   path('depnd_specilization/<int:id_course>',views.depnd_specilization,name='depnd_specilization'),

   # employee
       #employee status
        #employee status
    path('employee_status1/<int:id>',views.employee_status1,name="employee_status1"),
    #employee delete
    path('employee_delete/<int:id>',views.employee_delete,name="employee_delete"),
    #employee update
    path('employee_update/<int:id>',views.employee_update,name="employee_update"),
    #employee Pdf
    path('employee_detail/<int:id>',views.employee_detail,name="employee_detail"),
    #employee delete all
    path('employee_delete_all/',views.employee_list_all,name="employee_delete_all"),
    #employee import
    path('employee_import/',views.employee_upload,name="employee_import"),

   #  path('employee_import/',views.employee_import,name="employee_import"),
    #employee export
    path('employee_export/',views.employee_export,name="employee_export"),
     path('get_department/<int:department_id>/', views.get_department, name='get_department'),

     #Job status
   path('Job_status/<int:id>',views.Job_status,name='Job_status'),
   #job edit
   path('Job_edit/<int:id>',views.Job_edit,name='Job_edit'),
   #Job delete
   path('Job_delete/<int:id>',views.Job_delete,name='Job_delete'),
   #    Job delete all
   path('Job_delete_all/',views.job_type_all,name='Job_delete_all'),
   #Job export
   path('Job_export/',views.Job_export,name='Job_export'),
   #JOb import
   path('Job_import/',views.Job_import,name='Job_import'),


   #Job status
path('job_category_status/<int:id>',views.job_category_status,name='job_category_status'),
#job edit
path('job_category_edit/<int:id>',views.job_category_edit,name='job_category_edit'),
#Job delete
path('job_category_delete/<int:id>',views.job_category_delete,name='job_category_delete'),
#Job delete all
path('job_category_delete_all/',views.job_category_all,name='job_category_delete_all'),
#Job export
path('job_category_export/',views.job_category_export,name='job_category_export'),
#Job import
path('job_category_import/',views.job_category_import,name='job_category_import'),


path('qualification_status/<int:id>',views.qualification_status,name='qualification_status'),
   path('qualification_edit/<int:id>',views.qualification_edit,name='qualification_edit'),
   path('qualification_delete/<int:id>',views.qualification_delete,name='qualification_delete'),
   path('qualification_delete_all/',views.qualification_delete_all,name="qualification_delete_all"),
   path('qualification_export/',views.qualification_export,name="qualification_export"),
   path('qualification_import/',views.qualification_import,name="qualification_import"),
  


]
    

    
