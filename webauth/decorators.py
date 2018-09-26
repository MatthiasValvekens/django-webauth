from functools import wraps
from urllib.parse import urlparse
from django.core.exceptions import PermissionDenied
from django.urls import reverse_lazy

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import resolve_url

from django.contrib.auth.views import redirect_to_login
from webauth.utils import build_login_redirect

from webauth.tokens import PasswordConfirmationTokenGenerator as PCTG

def request_passes_test(test_func, login_url=None, 
        redirect_field_name=REDIRECT_FIELD_NAME, raise_exception=True):
    """
    More general version of django.contrib.auth.decorators.user_passes_test. 
    Largely copied from there.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request):
                return view_func(request, *args, **kwargs)
            if raise_exception:
                raise PermissionDenied()
            return build_login_redirect(
                request, login_url=login_url, 
                redirect_field_name=redirect_field_name
            )
        return _wrapped_view
    return decorator

def user_passes_test(test, *args, **kwargs):
    """
    Version of user_passes_test decorator that raises 403
    """
    def test_wrap(request):
        return test(request.user)
    return request_passes_test(test_wrap)

# decorator that forces password confirmation
# (token is consumed by default)

def confirm_password_redir_url(request, *args, **kwargs):
    return build_login_redirect(
        request, login_url=reverse_lazy('confirm_password')
    )

require_password_confirmation = PCTG.validator.enforce_token(
    redirect_url=confirm_password_redir_url
)
