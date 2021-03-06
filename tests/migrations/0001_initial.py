# Generated by Django 2.2.6 on 2019-12-19 18:30

from django.db import migrations, models
import webauth.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Customer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', webauth.fields.EmailField(max_length=100)),
                ('hidden_token', models.BinaryField(max_length=8)),
            ],
        ),
    ]
