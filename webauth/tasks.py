from __future__ import absolute_import, unicode_literals
from celery import shared_task

@shared_task
def send_mail(message):
    message.send()

@shared_task
def send_dynamic_emails(dispatcher, recipient_data, **kwargs):
    extra_context = kwargs.pop('extra_context', {})

    for email, lang, context in recipient_data:
        the_context = dict(extra_context)
        the_context.update(context)
        dispatcher.send_mail(
            email,
            lang=lang,
            extra_context=the_context,
            in_task=False,
            **kwargs
        )
