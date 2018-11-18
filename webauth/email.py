from django.utils.translation import get_language, activate
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.conf import settings
from bs4 import BeautifulSoup
import webauth.tasks
import html2text


# TODO: make celery dependency optional in standalone webauth
# TODO: add support for BCC and silent failure toggle
class EmailDispatcher:
    """
    Class for properly sending i18n-able emails, with html and
    plain-text alternatives.
    """

    def __init__(self,
                 subject_template_name, email_template_name=None,
                 lang=None, from_email=None, async=True,
                 html_email_template_name=None, base_context=None):
        self.subject_template_name = subject_template_name
        self.email_template_name = email_template_name
        self.lang = lang
        self.from_email = from_email
        self.html_email_template_name = html_email_template_name
        self.base_context = {} if base_context is None else base_context
        self.async = async

    def make_broadcast_mail(self, to_emails, lang=None, extra_context=None,
                            attachments=None, headers=None):
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
            old_lang = None
        else:
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
            # I'm gonna assume that h2t and beautifulsoup are not thread-safe,
            # so let's not reuse these objects
            parsed_message = BeautifulSoup(
                html_email, features="html.parser"
            )
            main_html = str(parsed_message.find(id='main'))
            footer_html = str(parsed_message.find(id='footer'))
            html_renderer = html2text.HTML2Text()
            html_renderer.use_automatic_links = True
            html_renderer.ignore_images = True
            html_renderer.ignore_tables = True
            main = html_renderer.handle(main_html)
            footer = html_renderer.handle(footer_html)
            body = loader.render_to_string(
                'mail/plaintext_generic.txt', context={
                    'content': main,
                    'footer': footer,
                }
            )

        message = EmailMultiAlternatives(
            subject, body, self.from_email, to_emails,
            headers=(headers or {})
        )
        if html_email is not None:
            message.attach_alternative(html_email, 'text/html')

        if attachments:
            for filename, a, mimetype in attachments:
                message.attach(filename, a, mimetype)

        if lang is not None:
            activate(old_lang)
        # TODO: remove this once we have proper outbound logging
        # on the mail server
        print(html_email)
        return message

    def broadcast_mail(self, *args, **kwargs):
        async = kwargs.pop('async', self.async)
        message = self.make_broadcast_mail(*args, **kwargs)
        if async:
            webauth.tasks.send_mail.delay(message)
        else:
            message.send(message)

    def send_mail(self, to_email, **kwargs):
        self.broadcast_mail([to_email], **kwargs)

    def send_dynamic_emails(self, recipient_data, **kwargs):
        """
        Send an email to multiple recipients, with context depending on the 
        recipient in question.
        Entries of recipient_data should be a dict with at least the keys
        'email', 'lang' and 'context'
        """
        extra_context = kwargs.pop('extra_context', {})
        async = kwargs.pop('async', self.async)

        def message_list():
            for options in recipient_data:
                email = options['email']
                lang = options['lang']
                context = options['context']
                headers = options.get('headers')
                attachments = options.get('attachments', [])
                the_context = dict(self.base_context)
                the_context.update(extra_context)
                the_context.update(context)
                yield self.make_broadcast_mail(
                    [email], lang=lang,
                    extra_context=the_context,
                    attachments=attachments,
                    headers=headers
                )

        if async:
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
