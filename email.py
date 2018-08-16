from django.utils.translation import get_language, activate
from django.core.mail import EmailMultiAlternatives
from django.template import loader
import lukweb.tasks

# inspired by code in PasswordResetForm
# TODO: add support for BCC and silent failure toggle
class EmailDispatcher:
    """
    Class for properly sending i18n-able emails, with html and
    plain-text alternatives
    """

    def __init__(self, 
            subject_template_name, email_template_name,
            lang=None, from_email=None,
            html_email_template_name=None, base_context=None):
        self.subject_template_name = subject_template_name
        self.email_template_name = email_template_name
        self.lang = lang
        self.from_email = from_email
        self.html_email_template_name = html_email_template_name
        self.base_context = {} if base_context is None else base_context
    
    def broadcast_mail(self, to_emails, lang=None, extra_context=None, 
            attachments=None):
        """
        Send the exact same email to multiple recipients, who 
        will all be included in the to-field.
        Note that the message will only be rendered once!
        """

        context = dict(self.base_context)
        if extra_context is not None:
            context.update(extra_context)

        if lang is None:
            lang = self.lang 

        if lang is not None:
            old_lang = get_language()
            activate(lang)

        subject = loader.render_to_string(self.subject_template_name, context)
        # remove newlines
        subject = ''.join(subject.splitlines())
        body = loader.render_to_string(self.email_template_name, context)
        message = EmailMultiAlternatives(
            subject, body, self.from_email, to_emails
        )

        if self.html_email_template_name is not None:
            html_email = loader.render_to_string(
                self.html_email_template_name, context
            )
            message.attach_alternative(html_email, 'text/html')

        if attachments:
            for a in attachments:
                message.attach(a)

        if lang is not None:
            activate(old_lang)
        
        lukweb.tasks.send_mail.delay(message)

    def send_mail(self, to_email, **kwargs):
        self.broadcast_mail([to_email], **kwargs)

    def send_dynamic_emails(self, recipient_data, **kwargs):
        """
        Send an email to multiple recipients, with context depending on the 
        recipient in question.
        Entries of recipient_data should be a triple (email, lang, context).
        """

        extra_context = kwargs.pop('extra_context', {})

        for email, lang, context in recipient_data:
            the_context = dict(extra_context)
            the_context.update(context)
            self.send_mail(
                email, 
                lang=lang,
                extra_context=the_context,
                **kwargs
            )

def dispatch_email(subject_template_name, email_template_name,
        to_email, lang=None, from_email=None,
        html_email_template_name=None, **kwargs):

    dispatcher = EmailDispatcher(
        subject_template_name, email_template_name,
        lang, from_email, html_email_template_name
    )

    context = kwargs.pop('context', {}) 
    dispatcher.send_mail(to_email, extra_context=context, **kwargs)
