from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import ugettext_lazy as _ 

from webauth.models import User
from webauth.forms import (
    UserChangeForm, UserCreationForm, dispatch_activation_email
)

ACTIVATION_EMAIL_SUBJECT_TEMPLATE = 'registration/activation_email_subject.txt'
ACTIVATION_EMAIL_TEMPLATE = 'registration/activation_email.html'

def resend_activation_email(modeladmin, request, qs):
    for user in qs:
        dispatch_activation_email(
            user.email, 
            request, 
            subject_template_name=ACTIVATION_EMAIL_SUBJECT_TEMPLATE,
            email_template_name=ACTIVATION_EMAIL_TEMPLATE
        )

class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    ordering = ('email',) 
    search_fields = ('email',)
    list_display = ('email', 'is_staff', 'is_superuser')
    list_filter = ('is_staff', 'groups')
    actions = [resend_activation_email]

    # Fieldsets for changing a user's data
    fieldsets = (
        (None, {'fields': ('email', 'password', 'lang')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff','is_superuser',
                                        'groups', 'user_permissions')})
    )

    # Fieldsets used when adding a new user
    add_fieldsets = (
        (None, { 
            'classes': ('wide', ), 
            'fields': ('email',),
        }),
    )

    def queryset(self, request):
        qs = super(UserAdmin, self).queryset(request)
        # Only superusers can edit superusers
        if request.user.is_superuser:
            return qs
        else:
            return qs.filter(is_superuser=False)

    def get_readonly_fields(self, request, obj=None):
        # Staff users cannot touch permissions
        if request.user.is_superuser:
            return tuple()
        else:
            return ('is_superuser', 'is_staff', 'groups', 'user_permissions')

    def save_model(self, request, obj, form, change, **kwargs):
        super(UserAdmin, self).save_model(request, obj, form, change)
        kwargs.setdefault('subject_template_name', 
            ACTIVATION_EMAIL_SUBJECT_TEMPLATE)
        kwargs.setdefault('email_template_name',
            ACTIVATION_EMAIL_TEMPLATE)
        if not change:
            # if we are creating a new user, dispatch an activation token.
            dispatch_activation_email(obj.email, request, **kwargs)
