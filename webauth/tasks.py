from __future__ import absolute_import, unicode_literals
from celery import shared_task

@shared_task
def send_mail(message):
    message.send()


@shared_task
def send_mails(messages):
    for message in messages:
        message.send()
