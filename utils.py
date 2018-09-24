import re, datetime
from urllib.parse import urlparse, urlunparse
from django.shortcuts import resolve_url
from django.http import QueryDict

from django.conf import settings
from django.utils.translation import get_language

# inspired by https://stackoverflow.com/questions/19080211/internalization-set-language-redirect-view-how-to-redirect-to-the-same-page
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

def login_redirect_url(target, otp=False):
    # stolen from Django's own redirect_to_login code
    resolved_url = resolve_url(
        settings.OTP_LOGIN_URL if otp else settings.LOGIN_URL
    ) 
    login_url_parts = list(urlparse(resolved_url))
    querystring = QueryDict(login_url_parts[4], mutable=True)
    querystring['next'] = target
    login_url_parts[4] = querystring.urlencode(safe='/')
    return urlunparse(login_url_parts)
