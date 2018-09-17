from django.urls import reverse_lazy
from functools import partial
from django.contrib.auth.views import (
    PasswordResetConfirmView, PasswordResetCompleteView, LoginView
)
from django.contrib.auth import BACKEND_SESSION_KEY
from django.utils.translation import ugettext_lazy as _ 
from django.core.exceptions import SuspiciousOperation
from django.http import JsonResponse, HttpResponse
from django.utils.http import urlsafe_base64_decode
from django.views import i18n
from django.utils import translation
from django.shortcuts import render, redirect

from webauth.forms import ActivateAccountForm, EmailResetForm
from webauth import utils
from webauth.models import User
# TODO: make this dependency optional
#from django_otp.forms import OTPAuthenticationForm, OTPTokenForm
from django_otp import forms as otp_forms
 
class LoginI18NRedirectView(LoginView):

    def get_redirect_url(self):
        url = super(LoginI18NRedirectView, self).get_redirect_url()
        return utils.strip_lang(url)

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

class OTPTokenForm(otp_forms.OTPTokenForm):
    def __init__(self, *args, **kwargs):
        super(OTPTokenForm, self).__init__(*args, **kwargs)
        for k, v in otp_labels.items():
            self.fields[k].label = v

class OTPLoginView(LoginI18NRedirectView):
    """
    Copy of django_otp login to counteract backwards-incompatible
    code moves in Django 2.x's contrib.auth.
    """
    template_name = 'registration/otp_login.html'
    
    def get_form_class(self):
        user = self.request.user
        if user.is_anonymous or user.is_verified():
            return OTPAuthenticationForm
        else:
            # A minor hack to make django.contrib.auth.login happy
            user.backend = self.request.session[BACKEND_SESSION_KEY] 
            return partial(OTPTokenForm, user) 

class ActivateAccountView(PasswordResetConfirmView):
    form_class = ActivateAccountForm
    success_url = reverse_lazy('account_activated')
    template_name = 'registration/activate_account.html'
    title = _('Enter password')
    token_generator = utils.ActivationTokenGenerator()

class AccountActivatedView(PasswordResetCompleteView):
    template_name = 'registration/account_activated.html'
    title = _('Account activated')

def unlock_account_view(request, uidb64, token):
    validlink = False
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, 
            User.DoesNotExist, ValidationError):
        raise SuspiciousOperation()

    tg = utils.UnlockTokenGenerator()
    if tg.check_token(user, token):
        user.is_active = True
        user.save()
        validlink = True
    return render(request, 
        'registration/unlock_account.html', 
        context={ 'validlink': validlink }
    )


def email_reset_view(request):
    if request.method == 'POST':
        if not request.user.is_authenticated:
            raise SuspiciousOperation()
        form = EmailResetForm(request, request.POST)
        if form.is_valid():
            form.save()
            return HttpResponse()
        else: 
            return JsonResponse(form.errors, status=400)
    else:
        # this page should never be accessed by a non-anon user
        if request.user.is_authenticated:
            return redirect(reverse_lazy('index'))
        return render(request, 'registration/email_reset_done.html')
        
def set_language(request):
    response = i18n.set_language(request)
    user = request.user
    if user.is_authenticated:
        # we can now grab the (sanitised/verified) lang code
        # from the session, since the i18n module took care of that
        user.lang = request.session[translation.LANGUAGE_SESSION_KEY]
        user.save()
    return response
