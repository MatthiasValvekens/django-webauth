from django import forms
from django.contrib.auth import forms as auth_forms
from webauth.models import User

class UserCreationForm(forms.ModelForm):
    """
    A UserCreationForm without password inputs.
    Instead, the users' password is set to something unusable.
    (not suitable for subclassing)
    """
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

class ActivateAccountDispatchForm(auth_forms.PasswordResetForm):
    """
    Subclass PasswordResetForm to reuse Django's password reset
    functionality. We only override get_users to get rid of the 
    restriction on password resets for inactive users and 
    users with unset passwords.
    """
    def get_users(self, email):
        return User.objects.filter(email__iexact=email)

def dispatch_activation_email(email, request, **kwargs):
    """
    A wrapper around Django's native PasswordResetForm
    to dispatch account activation emails.
    Removed a few options for simplicity.
    """
    kwargs.setdefault('use_https', request.is_secure())
    activation_form = ActivateAccountDispatchForm({'email': email})
    # since we need to validate the form before saving,
    # might as well make this an assertion
    assert activation_form.is_valid()
    activation_form.save(request=request, **kwargs)
