from __future__ import absolute_import, unicode_literals
from celery import shared_task
from django.core import mail


@shared_task
def send_mail(message):
    message.send()


@shared_task
def send_mails(messages):
    with mail.get_connection() as conn:
        conn.send_messages(messages)
