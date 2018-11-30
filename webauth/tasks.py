from __future__ import absolute_import, unicode_literals
import logging
import random
import re
from celery import shared_task
from django.core import mail
from collections import defaultdict

mail_audit_log = logging.getLogger(__name__ + '.send_mail')
LOGGING_SEPARATOR = '\n>>>>>%s<<<<<\n\n' % ('=' * 24)


def msg_to_string(msg):
    # essentially from django internals
    msg = msg.message()
    mbytes = msg.as_bytes()
    charset = msg.get_charset()
    output_charset = charset.get_output_charset() if charset else 'utf-8'
    return mbytes.decode(output_charset)


class LazyMsgLog:
    def __init__(self, msgs):
        self.msgs = msgs

    def __str__(self):
        return LOGGING_SEPARATOR.join(msg_to_string(m) for m in self.msgs)


@shared_task
def send_mail(message):
    message.send()
    mail_audit_log.info('Dispatched message:\n%s', msg_to_string(message))


@shared_task
def send_mails(messages):
    from webauth.utils import chunks
    from django.conf import settings
    batch_size = settings.WEBAUTH_MASS_MAIL_BATCH_SIZE
    batches = chunks(messages, batch_size)
    with mail.get_connection() as conn:
        for ix, batch in enumerate(batches):
            conn.send_messages(batch)
            mail_audit_log.info(
                'Dispatched messages [batch %d, msgs %d through %d].',
                ix + 1, ix * batch_size + 1, ix * batch_size + len(batch)
            )
            mail_audit_log.debug(
                'Dispatched message content:\n%s', LazyMsgLog(batch)
            )


TO_FIELD = re.compile('.*? <(.*)>$')


@shared_task
def send_emails_domain_rled(messages):
    # ensure that every message only has one recipient for optimal
    # queueing
    per_domain_queues = defaultdict(list)
    for msg in messages:
        m = TO_FIELD.match(msg.to[0].strip())
        if m is None:
            domain = 'unknown'
        else:
            hd, domain = m.group(1).strip().rsplit('@', 1)
        per_domain_queues[domain.lower()].append(msg)

    for domain, queue in per_domain_queues.items():
        _email_staggered_delivery.delay(queue, domain)


# apply 15% uniform noise to sending delays
def fuzz(mean_delay):
    fuzz_range = int(mean_delay * 0.15)
    return mean_delay + random.randint(-fuzz_range, fuzz_range)


@shared_task
def _email_staggered_delivery(messages, domain):
    from django.conf import settings
    num = settings.WEBAUTH_CONCURRENT_DOMAIN_BATCH_SIZE
    delay = fuzz(settings.WEBAUTH_CONCURRENT_DOMAIN_MEAN_BATCH_DELAY)
    send_now = messages[:num]
    send_later = messages[num:]
    with mail.get_connection() as conn:
        conn.send_messages(send_now)

    mail_audit_log.info(
        'Dispatched %d messages to domain %s. %d messages '
        'remaining in queue for this domain. ',
        len(send_now), domain, len(send_later)
    )
    mail_audit_log.debug(
        'Content of messages sent to domain %s:\n%s',
        domain, LazyMsgLog(send_now)
    )

    if send_later:
        _email_staggered_delivery.apply_async(
            (send_later, domain), countdown=delay
        )
        mail_audit_log.info(
            'Next batch for domain %s scheduled %d seconds from now. ',
            domain, delay
        )


