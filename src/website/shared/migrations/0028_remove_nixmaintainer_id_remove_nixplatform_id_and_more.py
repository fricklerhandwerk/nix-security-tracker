# Generated by Django 4.2.7 on 2023-12-13 16:01

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("shared", "0027_alter_nixevaluation_elapsed"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="nixmaintainer",
            name="id",
        ),
        migrations.AlterField(
            model_name="nixmaintainer",
            name="github_id",
            field=models.IntegerField(primary_key=True, serialize=False),
        ),
    ]