from functools import wraps
from urllib.parse import urlparse
from django.core.exceptions import PermissionDenied
from django.urls import reverse_lazy

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import resolve_url

from django.contrib.auth.views import redirect_to_login

from webauth.utils import PasswordConfirmationTokenGenerator

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
            path = request.build_absolute_uri()
            resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
            login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
            current_scheme, current_netloc = urlparse(path)[:2]
            if ((not login_scheme or login_scheme == current_scheme) and
                    (not login_netloc or login_netloc == current_netloc)):
                path = request.get_full_path()
            return redirect_to_login(
                path, resolved_login_url, redirect_field_name)
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
require_password_confirmation = request_passes_test(
    PasswordConfirmationTokenGenerator.validate_request, 
    login_url=reverse_lazy('confirm_password'),
    raise_exception=False
)
