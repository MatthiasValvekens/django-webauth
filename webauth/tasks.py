from __future__ import absolute_import, unicode_literals
import logging
from celery import shared_task
from django.core import mail

mail_audit_log = logging.getLogger(__name__ + '.send_mail')
LOGGING_SEPARATOR = '\n>>>>>%s<<<<<\n\n' % ('=' * 24)


@shared_task
def send_mail(message):
    message.send()
    mail_audit_log.info('Dispatched message:\n%s' % str(message))


@shared_task
def send_mails(messages):
    with mail.get_connection() as conn:
        conn.send_messages(messages)
    msgs = LOGGING_SEPARATOR.join(str(m) for m in messages)
    mail_audit_log.info('Dispatched messages:\n%s' % msgs)
