from django import forms
from django.contrib.auth import forms as auth_forms
from webauth.models import User

class UserCreationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('email',)
        field_classes = {}

class UserChangeForm(auth_forms.UserChangeForm):
    class Meta:
        model = User
        fields = '__all__'
        field_classes = {}

class ActivateAccountForm(auth_forms.SetPasswordForm):
    """
    Form that lets a user activate their account and set their
    password.
    """
    def save(self, commit=True):
        self.user.is_active = True
        super(ActivateAccountForm, self).save(commit)
