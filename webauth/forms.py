from django import forms
from django.contrib.auth import forms as auth_forms
from django.utils.translation import ugettext_lazy as _ 
from webauth.models import User, send_password_reset_email

# TODO: make this dependency optional
from django_otp import forms as otp_forms

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

class PasswordResetForm(auth_forms.PasswordResetForm):
    def save(self, **kwargs):
        email = self.cleaned_data["email"]
        send_password_reset_email(self.get_users(email), **kwargs)

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

otp_labels = {
    'otp_token': _('OTP token'),
    'otp_device': _('OTP device'),
    'otp_challenge': _('OTP challenge')
}

class OTPAuthenticationForm(otp_forms.OTPAuthenticationForm):
    def __init__(self, *args, **kwargs):
        super(OTPAuthenticationForm, self).__init__(*args, **kwargs)
        for k, v in otp_labels.items():
            self.fields[k].label = v
        self.fields['otp_token'].widget.attrs['autocomplete'] = 'off'

class OTPTokenForm(otp_forms.OTPTokenForm):
    def __init__(self, *args, **kwargs):
        super(OTPTokenForm, self).__init__(*args, **kwargs)
        for k, v in otp_labels.items():
            self.fields[k].label = v
        self.fields['otp_token'].widget.attrs['autocomplete'] = 'off'
