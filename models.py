from django.db import models
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _ 
from django.utils import timezone
from django.contrib.auth.models import (
    BaseUserManager, AbstractBaseUser, PermissionsMixin
)
from django.core.mail import send_mail
from django.contrib.auth.validators import UnicodeUsernameValidator

def no_at_in_uname(name):
    if '@' in name:
        raise ValidationError(
                _('The character \'@\' is not allowed in usernames')
            ) 

class UserManager(BaseUserManager):
    """
    Replaces django.contrib.auth.models.UserManager.
    Mostly copied from there, we only did away with the username
    requirement, and made email mandatory instead.
    """

    use_in_migrations = True

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

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

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
        default=True
    )

    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Email this user"""
        send_mail(subject, message, from_email, [self.email], **kwargs)
