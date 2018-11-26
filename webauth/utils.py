import re
from urllib.parse import urlparse, urlunparse
from django.shortcuts import resolve_url
from django.http import QueryDict

from django.conf import settings
from django.utils.translation import get_language
from django.contrib.auth import REDIRECT_FIELD_NAME

# inspired by https://stackoverflow.com/questions/19080211/
LANG_REGEXES = {
    lang[0]: re.compile('^(/%s)/' % lang[0])
    for lang in settings.LANGUAGES
}


def strip_lang(path):
    lang = get_language()
    try:
        match = LANG_REGEXES[lang].search(path)
    except KeyError:
        return path

    if match is None:
        return path
    else:
        return path[match.end(1):]


# adapted from Django's own redirect_to_login and user_passes_test code
def login_redirect_url(target, login_url=None, otp=False, **kwargs):
    if login_url is None:
        login_url = settings.OTP_LOGIN_URL if otp else settings.LOGIN_URL
    resolved_url = resolve_url(login_url) 
    login_url_parts = list(urlparse(resolved_url))
    return _login_redirect_url(target, login_url_parts, **kwargs)


def build_login_redirect(request, login_url=None, otp=False, **kwargs):
    if login_url is None:
        login_url = settings.OTP_LOGIN_URL if otp else settings.LOGIN_URL

    path = request.build_absolute_uri()
    login_url_parts = list(urlparse(resolve_url(login_url)))
    login_scheme, login_netloc = login_url_parts[:2]
    current_scheme, current_netloc = urlparse(path)[:2]
    if ((not login_scheme or login_scheme == current_scheme) and
            (not login_netloc or login_netloc == current_netloc)):
        path = request.get_full_path()
    return _login_redirect_url(path, login_url_parts, **kwargs)


def _login_redirect_url(target, login_url_parts, 
                        redirect_field_name=REDIRECT_FIELD_NAME):
    querystring = QueryDict(login_url_parts[4], mutable=True)
    querystring[redirect_field_name] = target
    login_url_parts[4] = querystring.urlencode(safe='/')
    return urlunparse(login_url_parts)


def named_email(name, email):
    return '%s <%s>' % (
        name.replace('\n', ''),
        email
    )


# slice a list into chunks of even size
# https://stackoverflow.com/q/312443/4355619
def chunks(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]
