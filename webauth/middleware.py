from dateutil.parser import parse as parse_datetime
from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone
# TODO: make this dependency optional
from django_otp import DEVICE_ID_SESSION_KEY

LAST_REQUEST_SESSION_KEY = 'last_request'

try:
    timeout = settings.WEBAUTH_INACTIVE_TIMEOUT
    otp_timeout = settings.WEBAUTH_OTP_INACTIVE_TIMEOUT
except AttributeError:
    raise ImproperlyConfigured(
        "WEBAUTH_INACTIVE_TIMEOUT and/or WEBAUTH_OTP_INACTIVE_TIMEOUT are "
        "undefined. This is probably not what you want. To disable "
        "(part of) the InactiveTimeoutMiddleware functionality, please set "
        "the relevant settings to None."
    )


class InactiveTimeoutMiddleware:
    """
    Middleware for enforcing session and 2FA timeouts.
    Needs to run after django.contrib.auth.middleware.AuthenticationMiddleware.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated and timeout is not None:
            now = timezone.now()
            try:
                # TODO: when we upgrade to python 3.7, use native fromisoformat
                last_req = parse_datetime(
                    request.session[LAST_REQUEST_SESSION_KEY]
                )
                delta = (now - last_req).seconds // 60
                if otp_timeout is not None and delta >= otp_timeout:
                    try:
                        del request.session[DEVICE_ID_SESSION_KEY]
                    except KeyError:
                        pass
                    request.user.otp_device = None
                # if both timeouts have passed, we need to process both
                if delta >= timeout:
                    logout(request)
            except (KeyError, ValueError):
                pass
            finally:
                # when the user is no longer logged in, we don't want to
                # update the timestamp, as it might cause the timeout to
                # be triggered right after the next login attempt
                if request.user.is_authenticated:
                    request.session[LAST_REQUEST_SESSION_KEY] = now.isoformat()
                else:
                    del request.session[LAST_REQUEST_SESSION_KEY]
        return self.get_response(request)
