from django import forms
from django.contrib.auth import forms as auth_forms
from django.utils.translation import ugettext_lazy as _ 
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

class EmailResetForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ('email',)
        labels = {
            'email': _('New email address')
        }

    def __init__(self, request, *args, **kwargs):
        self.user = request.user
        super(EmailResetForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        old_email = self.user.email
        self.user.email = User.objects.normalize_email(
            self.cleaned_data['email']
        )
        # TODO kill all sessions
        # otherwise they will simply reactivate as soon as
        # the acct is unlocked
        self.user.is_active = False
        if commit:
            self.user.save() 
            # we cannot do this before saving the user, since 
            # the address change would invalidate the activation token
            self.user.send_unlock_email(target_email=old_email)

        return self.user
