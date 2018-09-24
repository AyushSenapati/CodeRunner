from django.urls import path
from . import views


app_name = 'coderunner'
urlpatterns = [
    path('', views.index, name='index'),
    path('details/<int:qid>/', views.details, name='details'),
    path('program/<int:qid>/', views.program, name='program'),
    path('result/<int:qid>/', views.result, name='result'),
    path('ajax/validate_program/', views.validate_program,
         name='validate_program')
]
