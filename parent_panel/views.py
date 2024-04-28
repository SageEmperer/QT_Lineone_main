from django.shortcuts import render ,redirect,reverse

from console.models import LeadModel
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa



def parentLogin(request):  
    if request.method == 'POST':
        try:
            mobileNumber = request.POST.get('mobile')
           
            Moble_Number = LeadModel.objects.filter(mobile_number=mobileNumber).exists()
                       
            if Moble_Number:
                students = LeadModel.objects.get(mobile_number=mobileNumber)
                return redirect(reverse('parentHome', kwargs={"id": students.id}))
            else:
                return redirect('parentLogin')
       
        except ObjectDoesNotExist:            
            return render(request, 'error.html', {'message': 'LeadModel object not found'})
       
        except Exception as e:            
            return render(request, 'error.html', {'message': 'An unexpected error occurred'})
   
    return render(request, 'parentLogin.html')


def parentHome(request,id):    
    student = LeadModel.objects.get(id=id)    
    if student:
        context={
            'student':student            
        }              
        return render(request,'parentHome.html',context)        
    else:
        return redirect('parentLogin')