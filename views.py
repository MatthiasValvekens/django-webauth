from django.urls import reverse_lazy
from django.contrib.auth.views import (
    PasswordResetConfirmView, PasswordResetCompleteView, LoginView
)
from django.utils.translation import ugettext_lazy as _ 
from django.views import i18n
from django.utils import translation

from webauth.forms import ActivateAccountForm 
from webauth.utils import strip_lang

class LoginI18NRedirectView(LoginView):

    def get_redirect_url(self):
        url = super(LoginI18NRedirectView, self).get_redirect_url()
        return strip_lang(url)

class ActivateAccountView(PasswordResetConfirmView):
    form_class = ActivateAccountForm
    success_url = reverse_lazy('account_activated')
    template_name = 'registration/activate_account.html'
    title = _('Enter password')

class AccountActivatedView(PasswordResetCompleteView):
    template_name = 'registration/account_activated.html'
    title = _('Account activated')

def set_language(request):
    response = i18n.set_language(request)
    user = request.user
    if user.is_authenticated:
        # we can now grab the (sanitised/verified) lang code
        # from the session, since the i18n module took care of that
        user.lang = request.session[translation.LANGUAGE_SESSION_KEY]
        user.save()
    return response
