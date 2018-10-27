# Generated by Django 2.1.1 on 2018-09-13 09:12

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='QuestionAnswer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('question_text', models.CharField(max_length=200)),
                ('question_desc', models.CharField(max_length=500)),
                ('expected_output', models.CharField(max_length=200)),
                ('times_appeared', models.IntegerField(default=0)),
                ('times_correct', models.IntegerField(default=0)),
                ('times_wrong', models.IntegerField(default=0)),
            ],
        ),
    ]
