from __future__ import absolute_import, unicode_literals
import logging
from celery import shared_task
from django.core import mail

mail_audit_log = logging.getLogger(__name__ + '.send_mail')
LOGGING_SEPARATOR = '\n>>>>>%s<<<<<\n\n' % ('=' * 24)


def msg_to_string(msg):
    # essentially from django internals
    msg = msg.message()
    mbytes = msg.as_bytes()
    charset = msg.get_charset()
    output_charset = charset.get_output_charset() if charset else 'utf-8'
    return mbytes.decode(output_charset)


@shared_task
def send_mail(message):
    message.send()
    mail_audit_log.info('Dispatched message:\n%s' % msg_to_string(message))


@shared_task
def send_mails(messages):
    with mail.get_connection() as conn:
        conn.send_messages(messages)
    msgs = LOGGING_SEPARATOR.join(msg_to_string(m) for m in messages)
    mail_audit_log.info('Dispatched messages:\n%s' % msgs)
