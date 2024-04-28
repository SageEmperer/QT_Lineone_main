from django.urls import path
from django.conf import settings
from parent_panel import views
from django.conf.urls.static import static
urlpatterns = [
    path('',views.parentLogin, name='parentLogin'),
    path('parentHome/<int:id>', views.parentHome, name='parentHome'),    
   
 
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)