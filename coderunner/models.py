from django.db import models


# Create your models here.
class QuestionAnswer(models.Model):
    question_text = models.CharField(max_length=200)
    question_desc = models.CharField(max_length=500)
    expected_output = models.CharField(max_length=200)
    # To track number of times the question was appeared
    times_appeared = models.IntegerField(default=0)
    # To track number of times the question answered correctly
    times_correct = models.IntegerField(default=0)
    # To track number of times the question answered wrongly
    times_wrong = models.IntegerField(default=0)

    def __str__(self):
        return self.question_text
