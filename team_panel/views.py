from django.shortcuts import render,redirect
from .models import *
# Create your views here.

def team_required(view_func):
    def wrapper(request, *args, **kwargs):
        if 'team' in request.session:
            return view_func(request, *args, **kwargs)
        else:
            return redirect(reverse('team_login'))
    return wrapper



def team_login(request):
  # if request.method == "POST":
    if request.session.get('team'):
      return redirect('team_dashboard')
    if request.POST.get('email_id') and request.POST.get('password'):
      email = request.POST.get('email_id')
      password = request.POST.get('password')
      if Employee_credentials.objects.filter(email = email, password = password).exists():
        emp = Employee_credentials.objects.get(email = email, password = password)
        request.session['team'] = { 'emp_id': emp.id , 'email': email, 'password': password} 
        return redirect('team_dashboard')
         
    return render(request,'account/team_login.html')




@team_required
def team_dashboard(request):
   return render(request,'team_dashboard.html')