# Generated by Django 2.1.2 on 2018-10-08 16:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coderunner', '0007_auto_20181008_1549'),
    ]

    operations = [
        migrations.AddField(
            model_name='questions',
            name='timeout',
            field=models.IntegerField(default=5),
        ),
    ]