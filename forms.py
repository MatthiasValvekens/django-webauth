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
        # TODO: use a different email template here to make it clear
        # that this is a re-activation email, and have a toggle somewhere
        # that doesn't force the user to reset their password
        old_email = self.user.email
        self.user.email = User.objects.normalize_email(
            self.cleaned_data['email']
        )
        # this should also force a logout, but
        # TODO kill all sessions to make sure
        self.user.is_active = False
        if commit:
            self.user.save() 
            # we cannot do this before saving the user, since 
            # the address change would invalidate the activation token
            self.user.send_activation_email(
                email=old_email
            )

        return self.user
