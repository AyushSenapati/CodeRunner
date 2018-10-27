from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.validators import MinValueValidator


# Create your models here.
class Questions(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    published_on = models.DateTimeField(auto_now_add=True)
    question_text = models.CharField(max_length=200)
    question_desc = models.CharField(max_length=500)
    pre_code_snippet = models.TextField()
    output_format = models.CharField(max_length=500)

    # Set time out for the question
    # [User code must return output by this time]
    # Default is 5 sec (set to 0 for None)
    timeout = models.IntegerField(default=5, validators=[MinValueValidator(0)])

    # one testcase to validate the user code when Run button is pressed
    run_testcase1_input = models.TextField(max_length=50)
    run_testcase1_output = models.TextField()

    # Two testcases to validate user submission
    submit_testcase1_input = models.TextField(max_length=50)
    submit_testcase1_output = models.TextField()
    submit_testcase2_input = models.TextField(max_length=50)
    submit_testcase2_output = models.TextField()
    times_submitted = models.IntegerField(default=0)
    # To track number of times the question answered correctly
    times_correct = models.IntegerField(default=0)
    # To track number of times the question answered wrongly
    times_wrong = models.IntegerField(default=0)
    score = models.IntegerField(default=10,
                                validators=[MinValueValidator(5)])

    class Meta:
        verbose_name = 'Questions'
        verbose_name_plural = 'Questions'

    def __str__(self):
        return self.question_text


class Submissions(models.Model):
    username = models.ForeignKey(User, on_delete=models.CASCADE)
    submitted_on = models.DateTimeField(auto_now_add=True)
    submitted_snippet = models.TextField()
    question = models.ForeignKey(Questions, on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Submissions'
        verbose_name_plural = 'Submissions'

    def __str__(self):
        return (str(self.username) + '@ [' + str(self.question) + ']')


class UserProfile(models.Model):
    username = models.OneToOneField(User, on_delete=models.CASCADE)
    score = models.IntegerField(default=0,
                                validators=[MinValueValidator(0)])

    class Meta:
        verbose_name = "UserProfile"
        verbose_name_plural = "UserProfiles"

    def __str__(self):
        return str(self.username)


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(username=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()
