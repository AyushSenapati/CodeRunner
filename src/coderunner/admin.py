from django.contrib import admin
from .models import Questions, Submissions, UserProfile

# Register your models here.
admin.site.register(Questions)
admin.site.register(Submissions)
admin.site.register(UserProfile)
