from django.urls import reverse_lazy
from django.contrib.auth.views import (
    PasswordResetConfirmView, PasswordResetCompleteView, LoginView
)
from django.utils.translation import ugettext_lazy as _ 
from django.core.exceptions import SuspiciousOperation
from django.http import JsonResponse, HttpResponse
from django.views import i18n
from django.utils import translation
from django.shortcuts import render, redirect

from webauth.forms import ActivateAccountForm, EmailResetForm
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
