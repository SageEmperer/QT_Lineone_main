from django.urls import path
from .import views
urlpatterns = [
  path('',views.team_login,name="team_login"),
  path('team_dashboard/',views.team_dashboard,name="team_dashboard")

]


