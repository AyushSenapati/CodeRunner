from django.urls import path
from . import views


app_name = 'coderunner'
urlpatterns = [
    path('accounts/signup/account_activation_sent/',
         views.account_activation_sent, name='account_activation_sent'),
    path('activate/<uidb64>/<token>/',
         views.activate, name='activate'),
    path('accounts/signup/', views.signup, name='signup'),

    path('home/', views.home, name='home'),
    path('details/<int:qid>/', views.details, name='details'),
    path('program/<int:qid>/', views.program, name='program'),
    path('ajax/run_code/<int:qid>/', views.run_code, name='run_code'),
    path('result/<int:qid>', views.result, name='result'),
    path('ajax/validate_program/',
         views.validate_program, name='validate_program')
]
