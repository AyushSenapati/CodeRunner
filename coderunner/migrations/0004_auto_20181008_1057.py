# Generated by Django 2.1.2 on 2018-10-08 10:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coderunner', '0003_auto_20181008_1016'),
    ]

    operations = [
        migrations.AlterField(
            model_name='questions',
            name='pre_code_snippet',
            field=models.TextField(),
        ),
    ]
