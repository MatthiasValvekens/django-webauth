from django.db import models
from django.conf import settings
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _ 
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, PermissionsMixin, Group as BaseGroup
)
from django.contrib.auth.validators import UnicodeUsernameValidator
from webauth.email import dispatch_email, EmailDispatcher
from webauth import utils

# TODO: clearly document which permissions are relevant in the admin!

ACTIVATION_EMAIL_SUBJECT_TEMPLATE = 'mail/activation_email_subject.txt'
ACTIVATION_EMAIL_TEMPLATE = 'mail/activation_email.html'
UNLOCK_EMAIL_SUBJECT_TEMPLATE = 'mail/unlock_email_subject.txt'
UNLOCK_EMAIL_TEMPLATE = 'mail/unlock_email.html'

def no_at_in_uname(name):
    if '@' in name:
        raise ValidationError(
                _('The character \'@\' is not allowed in usernames')
            ) 

def mass_translated_email(users, subject_template_name, 
        context=None, rcpt_context_object_name='user', 
        attachments=None, **kwargs):
    """
    Mass-email users. Context can be a one-argument callable, 
    to which the user will be passed, or a static dict.
    The context dict passed to the email dispatcher will
    always include the user object.
    Other kwargs will be passed to the EmailDispatcher's __init__.

    This method will work with any model with a .lang and .email attribute.
    """

    def dynamic_data():
        for user in users:
            if callable(context):
                the_context = context(user)
            else:
                the_context = {} if context is None else context
            the_context[rcpt_context_object_name] = user
            yield user.email, user.lang, the_context

    # we have to consume the generator, otherwise pickle complains
    EmailDispatcher(
        subject_template_name, **kwargs
    ).send_dynamic_emails(list(dynamic_data()), attachments=attachments)

def send_activation_email(users,
        subject_template_name=ACTIVATION_EMAIL_SUBJECT_TEMPLATE,
        email_template_name=None,
        html_email_template_name=ACTIVATION_EMAIL_TEMPLATE,
        token_generator=None,
        **kwargs):

    if token_generator is None:
        token_generator=utils.ActivationTokenGenerator()

    context = lambda u: u.get_password_reset_context(
        token_generator=token_generator
    )

    mass_translated_email(
        users,
        subject_template_name, 
        email_template_name=email_template_name,
        html_email_template_name=html_email_template_name,
        context=context, **kwargs
    )

class UserQuerySet(models.QuerySet):
    
    # wrappers around the functions defined above
    def mass_email(self, *args, **kwargs):
        mass_translated_email(self, *args, **kwargs)

    def send_activation_email(self, *args, **kwargs):
        send_activation_email(self, *args, **kwargs)



class UserManager(BaseUserManager):
    """
    Replaces django.contrib.auth.models.UserManager.
    Mostly copied from there, we only did away with the username
    requirement, and made email mandatory instead.
    """

    use_in_migrations = True

    def get_queryset(self):
        return UserQuerySet(self.model, using=self._db)

    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError(_('An email address must be set.'))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        if extra_fields.get('is_active') is not True:
            raise ValueError(_('Superuser must have is_active=True.'))

        return self._create_user(email, password, **extra_fields)
    

class User(AbstractBaseUser, PermissionsMixin):
    """
    User class with email authentication.
    Partly based on django.contrib.auth.models.AbstractUser, with a few changes.
    """
    
    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    # Apparently, it is an error to include the USERNAME_FIELD in REQUIRED_FIELDS
    REQUIRED_FIELDS = []

    email = models.EmailField(
        verbose_name = _('email address'),
        unique = True,
        error_messages={
            'unique': _(
                'A user with this email address '
                'already exists'
            )
        }
    )

    default_uname_validator = UnicodeUsernameValidator()

    """ 
    Migration note:
    This field is explicitly marked as non-editable in forms,
    to avoid uniqueness conflicts with empty strings in 
    blankable string fields 
    """
    legacy_username = models.CharField(
        max_length=100,
        verbose_name=_('legacy username'),
        help_text=_(
            'The user\'s username on the '
            'old website, if applicable'
        ),
        validators=[default_uname_validator, no_at_in_uname],
        unique=True,
        editable=False,
        null=True
    )

    migrating = models.BooleanField(
        verbose_name=_('partially migrated'),
        help_text=_(
            'Flag indicating whether account '
            'is currently in the process of being '
            'migrated from the old site.'
        ),
        default=False
    )
    
    is_staff = models.BooleanField(
        verbose_name=_('staff'),
        help_text=_(
            'Marks whether or not a user has access '
            'to the admin console.'
        ),
        default=False
    )

    is_superuser = models.BooleanField(
        verbose_name=_('superuser'),
        help_text=_('Marks whether or not a user has root access.'),
        default=False
    )

    is_active = models.BooleanField(
        verbose_name=_('active'),
        help_text=_(
            'Indicates whether this account is active. '
            'Please use this setting instead of deleting accounts.'
        ),
        # Users start out as inactive, until they click the link
        # in their sign-up email
        default=False
    )

    lang = models.CharField(
        verbose_name=_('communication language'),
        help_text=_(
            'Controls the language of all automatically generated '
            'communication.' 
        ),
        max_length=10,
        choices=settings.LANGUAGES,
        default=settings.LANGUAGES[0][0]
    )

    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    @property
    def username(self):
        """
        Some packages assume that users have a username attribute.
        """
        return self.email

    def get_password_reset_context(self, token_generator=default_token_generator):
        """
        Construct the context necessary to do a password reset for this user.
        """

        return {
            'email': self.email,
            'uid': urlsafe_base64_encode(force_bytes(self.pk)).decode(),
            'user': self,
            'token': token_generator.make_token(self),
        }

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def send_email(self, subject_template_name, email_template_name, **kwargs):
        # add user to context, if applicable
        context = kwargs.pop('context', {})
        context['user'] = self
        kwargs['context'] = context
        dispatch_email(
            subject_template_name, email_template_name,
            self.email, self.lang,
            **kwargs
        )

    def send_activation_email(self, *args, email=None, **kwargs):
        
        send_activation_email([self], *args, **kwargs)

    def send_unlock_email(self, target_email=None,
            subject_template_name=UNLOCK_EMAIL_SUBJECT_TEMPLATE,
            email_template_name=None,
            html_email_template_name=UNLOCK_EMAIL_TEMPLATE,
            token_generator=None,
            **kwargs):

        # the email reset function needs this to be customisable
        if target_email is None:
            target_email = self.email

        if token_generator is None:
            token_generator = utils.UnlockTokenGenerator()

        context = self.get_password_reset_context(
            token_generator=token_generator
        )

        EmailDispatcher(
            subject_template_name, base_context=context, 
            lang=self.lang,
            email_template_name=email_template_name,
            html_email_template_name=html_email_template_name,
            **kwargs
        ).send_mail(target_email)

# for future extensibility and admin consistency
class Group(BaseGroup): 
    class Meta:
        proxy = True
        verbose_name = _('group')
        verbose_name_plural = _('groups')
