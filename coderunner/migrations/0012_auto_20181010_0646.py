# Generated by Django 2.1.2 on 2018-10-10 06:46

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('coderunner', '0011_auto_20181010_0636'),
    ]

    operations = [
        migrations.AlterField(
            model_name='questions',
            name='timeout',
            field=models.IntegerField(default=5, validators=[django.core.validators.MinValueValidator(0)]),
        ),
    ]
