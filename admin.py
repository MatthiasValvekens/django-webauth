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

    # The django.contrib.auth.admin.UserAdmin
    # prohibits adding users without change permission.
    # Since non-superusers can't edit permissions,
    # this is not an issue for us, hence the override.
    def _add_view(self, request, form_url='', extra_context=None):
        if extra_context is None:
            extra_context = {} 
        username_field = self.model._meta.get_field(self.model.USERNAME_FIELD)
        defaults = {
            'auto_populated_fields': (),
            'username_help_text': username_field.help_text,
        }
        extra_context.update(defaults)
        # This is a bit of a hack, but by calling super() with 
        # BaseUserAdmin, we can skip one level in the MRO
        # thus avoiding an infinite loop
        return super(BaseUserAdmin, self).add_view(request, form_url, extra_context)

    def response_add(self, request, obj, post_url_continue=None):
        # again, here we defer to grandpa's defaults
        # this prevents BaseUserAdmin from hijacking the save button
        # and therefore causing PermissionDenied to be thrown when 
        # add_view is called without has_change_permission.
        return super(BaseUserAdmin, self).response_add(
            request, 
            obj, 
            post_url_continue
        )
