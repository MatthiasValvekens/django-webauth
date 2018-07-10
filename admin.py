from django.contrib import admin
from django.contrib.auth import forms as auth_forms
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import ugettext_lazy as _ 

from webauth.models import User

"""
We need to reimplement UserCreationForm and UserChangeForm.
""" 

class UserCreationForm(auth_forms.UserCreationForm):
    # The code in django.contrib.auth.forms refers to self._meta,
    # so changing these values should do the trick
    class Meta:
        model = User
        fields = ("email",)
        field_classes = {}


class UserChangeForm(auth_forms.UserChangeForm):
    class Meta:
        model = User
        fields = '__all__'
        field_classes = {}

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    ordering = ('email',) 
    search_fields = ('email',)
    list_display = ('email', 'is_staff', 'is_superuser')
    list_filter = ('is_staff', 'groups')

    # TODO: sort out how permissions to assign permissions work
    # is this automatically set up by inheriting from PermissionsMixin?

    # Fieldsets for changing a user's data
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff','is_superuser',
                                        'groups', 'user_permissions')})
    )

    # Fieldsets used when adding a new user
    add_fieldsets = (
        (None, { 
            'classes': ('wide', ), 
            'fields': ('email', 'password1', 'password2'),
        }),
    )
