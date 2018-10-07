from django.contrib import admin, messages
from django.contrib.auth.admin import (
    UserAdmin as BaseUserAdmin, GroupAdmin as BaseGroupAdmin
)
from django.utils.translation import activate, get_language, ugettext_lazy as _ 

from webauth.models import User
from webauth.forms import (
    UserChangeForm, UserCreationForm
)


def resend_activation_email(modeladmin, request, qs):
    qs.send_activation_email()
    messages.success(
        request, _('Sent')
    )

resend_activation_email.short_description = _('Resend activation email')

class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    ordering = ('email',) 
    search_fields = ('email',)
    list_display = ('email', 'date_joined', 'is_active', 'is_staff',)
    list_filter = ('is_staff', 'is_active', 'groups')
    actions = [resend_activation_email]

    # Fieldsets for changing a user's data
    fieldsets = (
        (None, {'fields': ('email', 'password', 'lang', 'date_joined')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff','is_superuser',
                                        'groups', 'user_permissions')})
    )

    # Fieldsets used when adding a new user
    add_fieldsets = (
        (None, { 
            'classes': ('wide', ), 
            'fields': ('email', 'lang'),
        }),
    )

    readonly_fields = ['date_joined',]

    def has_change_permission(self, request, obj=None):
        # Only superusers can edit superusers, but we allow them
        # to be viewed by all staff users with the appropriate
        # permissions.

        p = super(UserAdmin, self).has_change_permission(request, obj)

        if obj is not None and obj.is_superuser:
            return p and request.user.is_superuser

        return p

    def get_readonly_fields(self, request, obj=None):
        rof = list(super(UserAdmin, self).get_readonly_fields(request, obj))
        # non-superusers cannot touch permissions
        if not request.user.is_superuser:
            rof += ['is_superuser', 'is_staff', 'user_permissions']
        # TODO: if upstream bug 11154 ever gets fixed, this check
        # should probably be rewritten
        if not request.user.has_perm('auth.change_group'):
            rof.append('groups')
        return rof

    def save_model(self, request, obj, form, change, **kwargs):
        super(UserAdmin, self).save_model(request, obj, form, change)
        if not change:
            obj.send_activation_email()

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
        return super(BaseUserAdmin, self).add_view(
            request, form_url, extra_context
        )

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


    def formfield_for_manytomany(self, db_field, request=None, **kwargs):
        # snatched from groupadmin
        # don't know why user admin doesn't include this snippet
        # by default
        if db_field.name == 'user_permissions':
            qs = kwargs.get('queryset', db_field.remote_field.model.objects)
            # Avoid a major performance hit resolving permission names which
            # triggers a content_type load:
            kwargs['queryset'] = qs.select_related('content_type')

        return super().formfield_for_manytomany(
            db_field, request=request, **kwargs
        )


class GroupAdmin(BaseGroupAdmin):
    def get_readonly_fields(self, request, obj=None):
        if request.user.is_superuser:
            return self.readonly_fields
        else:
            return self.readonly_fields + ('permissions',)

    # XXX See Django bug 11154 for the reasoning why this is necessary
    # (the content_type_id points to the base model, which is in 
    # the auth app, and the default lookup code understandably
    # checks in webauth)
    def has_add_permission(self, request, obj=None):
        return request.user.has_perm('auth.add_group')

    def has_delete_permission(self, request, obj=None):
        return request.user.has_perm('auth.delete_group')

    def has_change_permission(self, request, obj=None):
        return request.user.has_perm('auth.change_group')

    def has_view_permission(self, request, obj=None):
        return request.user.has_perm('auth.view_group')
