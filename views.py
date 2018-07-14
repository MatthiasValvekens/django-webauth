from django.urls import reverse_lazy
from django.contrib.auth.views import (
    PasswordResetConfirmView, PasswordResetCompleteView
)
from django.utils.translation import ugettext_lazy as _ 

from webauth.forms import ActivateAccountForm 

#TODO: for completeness, we should add a url dispatcher

class ActivateAccountView(PasswordResetConfirmView):
    form_class = ActivateAccountForm
    success_url = reverse_lazy('account_activated')
    template_name = 'registration/activate_account.html'
    title = _('Enter password')

class AccountActivatedView(PasswordResetCompleteView):
    template_name = 'registration/account_activated.html'
    title = _('Account activated')
