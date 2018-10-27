# Generated by Django 2.1.2 on 2018-10-10 06:36

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coderunner', '0010_auto_20181009_0657'),
    ]

    operations = [
        migrations.AlterField(
            model_name='questions',
            name='score',
            field=models.IntegerField(default=10, validators=[django.core.validators.MinValueValidator(5)]),
        ),
    ]