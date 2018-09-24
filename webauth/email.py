from django.utils.translation import get_language, activate
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.conf import settings
from bs4 import BeautifulSoup
import webauth.tasks

# TODO: make celery dependency optional in standalone webauth

# inspired by code in PasswordResetForm
# TODO: add support for BCC and silent failure toggle
class EmailDispatcher:
    """
    Class for properly sending i18n-able emails, with html and
    plain-text alternatives
    """

    def __init__(self,
                 subject_template_name, email_template_name=None,
                 lang=None, from_email=None,
                 html_email_template_name=None, base_context=None):
        self.subject_template_name = subject_template_name
        self.email_template_name = email_template_name
        self.lang = lang
        self.from_email = from_email
        self.html_email_template_name = html_email_template_name
        self.base_context = {} if base_context is None else base_context

    def make_broadcast_mail(self, to_emails, lang=None, extra_context=None,
                            attachments=None):
        """
        Send the exact same email to multiple recipients, who 
        will all be included in the to-field.
        Note that the message will only be rendered once!
        """

        context = dict(self.base_context)

        if extra_context is not None:
            context.update(extra_context)

        # Add the domain and protocol from the settings to the context.
        # This ensures that mails sent from celery also have a proper 
        # domain and protocol in the template
        # This is set after updating the dict with the extra context, 
        # so django request domain and protocol are ignored.
        context['domain'] = settings.DOMAIN
        context['protocol'] = settings.PROTOCOL

        if lang is None:
            lang = self.lang

        if lang is not None:
            old_lang = get_language()
            activate(lang)
        html_email = None
        if self.html_email_template_name is not None:
            html_email = loader.render_to_string(
                self.html_email_template_name, context
            )
        subject = loader.render_to_string(self.subject_template_name, context)
        # remove newlines
        subject = ''.join(subject.splitlines())

        if self.email_template_name is not None:
            body = loader.render_to_string(self.email_template_name, context)
        else:
            body = BeautifulSoup(
                html_email, features="html.parser"
            ).get_text()

        message = EmailMultiAlternatives(
            subject, body, self.from_email, to_emails
        )
        if html_email is not None:
            message.attach_alternative(html_email, 'text/html')

        if attachments:
            for a in attachments:
                message.attach(a)

        if lang is not None:
            activate(old_lang)
        # TODO: remove this once we have proper outbound logging on the mail server
        print(html_email)
        return message


    def broadcast_mail(self, *args, in_task=True, **kwargs):
        message = self.make_broadcast_mail(*args, **kwargs)
        if in_task:
            webauth.tasks.send_mail.delay(message)
        else:
            message.send(message)

    def send_mail(self, to_email, **kwargs):
        self.broadcast_mail([to_email], **kwargs)

    def send_dynamic_emails(self, recipient_data, in_task=True, **kwargs):
        """
        Send an email to multiple recipients, with context depending on the 
        recipient in question.
        Entries of recipient_data should be a triple (email, lang, context).
        """
        extra_context = kwargs.pop('extra_context', {})

        def message_list():
            for email, lang, context in recipient_data:
                the_context = dict(self.base_context)
                the_context.update(extra_context)
                the_context.update(context)
                yield self.make_broadcast_mail(
                    [email], lang=lang,
                    extra_context=the_context,
                    **kwargs
                )

        if in_task:
            webauth.tasks.send_mails.delay(list(message_list()))
        else:
            webauth.tasks.send_mails(list(message_list()))

def dispatch_email(subject_template_name, email_template_name,
                   to_email, lang=None, from_email=None,
                   html_email_template_name=None, **kwargs):
    dispatcher = EmailDispatcher(
        subject_template_name, email_template_name,
        lang, from_email, html_email_template_name
    )

    context = kwargs.pop('context', {})
    dispatcher.send_mail(to_email, extra_context=context, **kwargs)
