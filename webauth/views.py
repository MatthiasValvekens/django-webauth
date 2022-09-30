from django.contrib import messages
from django.urls import reverse_lazy
from functools import partial
from django.contrib.auth import BACKEND_SESSION_KEY, views as auth_views
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import SuspiciousOperation, ValidationError
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.utils.http import urlsafe_base64_decode
from django.views import i18n, View
from django.views.generic.edit import FormView
from django.utils import translation
from django.shortcuts import render, redirect
from django.contrib.auth.mixins import UserPassesTestMixin

from webauth import utils, tokens, forms, decorators
from webauth.models import User

LogoutView = auth_views.LogoutView
PasswordChangeView = auth_views.PasswordChangeView
PasswordChangeDoneView = auth_views.PasswordChangeDoneView
PasswordResetDoneView = auth_views.PasswordResetDoneView
PasswordResetCompleteView = auth_views.PasswordResetCompleteView


class OTPRequiredMixin(View):
    def dispatch(self, request, *args, **kwargs):
        if not self.request.user.is_verified():
            return redirect(
                utils.login_redirect_url(request.get_full_path(), otp=True)
            )
        return super(OTPRequiredMixin, self).dispatch(request, *args, **kwargs)


class LoginI18NRedirectView(auth_views.LoginView):

    def get_redirect_url(self):
        url = super(LoginI18NRedirectView, self).get_redirect_url()
        return utils.strip_lang(url)


class OTPLoginView(LoginI18NRedirectView):
    """
    Copy of django_otp login to counteract backwards-incompatible
    code moves in Django 2.x's contrib.auth.
    """
    template_name = 'registration/otp_login.html'
    
    def get_form_class(self):
        user = self.request.user
        if user.is_anonymous or user.is_verified():
            return forms.OTPAuthenticationForm
        else:
            # A minor hack to make django.contrib.auth.login happy
            user.backend = self.request.session[BACKEND_SESSION_KEY] 
            return partial(forms.OTPTokenForm, user) 

# TODO subclass PasswordResetView and PasswordResetConfirmView!!!!!


class PasswordResetView(FormView):
    success_url = reverse_lazy('password_reset_done')
    template_name = 'registration/password_reset_form.html'
    form_class = forms.PasswordResetForm
    email_opts = {}

    def form_valid(self, form):
        form.save(**self.email_opts)
        return super().form_valid(form)


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    token_generator = tokens.PasswordResetTokenGenerator.validator


class ActivateAccountView(PasswordResetConfirmView):
    form_class = forms.ActivateAccountForm
    success_url = reverse_lazy('account_activated')
    template_name = 'registration/activate_account.html'
    title = _('Enter password')
    token_generator = tokens.ActivationTokenGenerator.validator


class AccountActivatedView(auth_views.PasswordResetCompleteView):
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

    tg = tokens.UnlockTokenGenerator.validator(user)
    if tg.validate_token(token):
        user.is_active = True
        user.save()
        validlink = True
    return render(
        request,
        'registration/unlock_account.html', 
        context={'validlink': validlink}
    )


def email_reset_view(request):
    if request.method == 'POST':
        if not request.user.is_authenticated:
            raise SuspiciousOperation()
        form = forms.EmailResetForm(request, request.POST)
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


@decorators.require_password_confirmation
def email_update_view(request):
    if request.method == 'POST':
        form = forms.EmailUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(
                request, _(
                    'Your email address has been updated successfully. '
                    'Please log in with your new credentials.'
                )
            )
            return redirect(reverse_lazy('login'))
    else:
        form = forms.EmailUpdateForm(instance=request.user)
    return render(
        request,
        'registration/email_reset.html',
        context={
            'form': form
        }
    )


def set_language(request):
    response = i18n.set_language(request)
    user = request.user
    if user.is_authenticated:
        # we can now grab the (sanitised/verified) lang code
        # from the session, since the i18n module took care of that
        user.lang = translation.get_language_from_request(request)
        user.save()
    return response


class PasswordConfirmView(UserPassesTestMixin, LoginI18NRedirectView):
    template_name = 'registration/confirm_password.html'

    def test_func(self):
        return self.request.user.is_authenticated

    def form_valid(self, form):
        """
        Instead of logging the user in, we generate a 'password confirmed'
        token and stick it somewhere in the current session.
        """
        req = self.request
        # even from an attacker's point of view, this doesn't make much sense
        # but checking costs us next to nothing.
        if form.get_user() != req.user:
            raise SuspiciousOperation(
                'PasswordConfirmView POST data does not match '
                'currently authenticated user.'
            )
        tokens.PasswordConfirmationTokenGenerator(req).embed_token()
        return HttpResponseRedirect(self.get_success_url())
