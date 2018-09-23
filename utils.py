import re, datetime
from urllib.parse import urlparse, urlunparse
from django.shortcuts import resolve_url
from django.http import QueryDict
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36

from django.conf import settings
from django.utils.translation import get_language
from django.contrib.auth.tokens import PasswordResetTokenGenerator

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

class TimeBasedTokenGenerator:
    """
    Inspired by PasswordResetTokenGenerator.
    Subclasses must provide lifespan
    in whatever unit time_elapsed uses (default hours)
    """
    secret = settings.SECRET_KEY
    origin = datetime.datetime.combine(
        datetime.date(2001, 1, 1), datetime.datetime.min.time()
    )

    VALID_TOKEN = 1
    MALFORMED_TOKEN = 2
    EXPIRED_TOKEN = 3
    

    def make_token(self):
        """
        Returns a token and the timestamp when it expires.
        """
        return self._make_token_with_timestamp(
            self.time_elapsed(self.current_time()), self.get_lifespan()
        ) 

    def bare_token(self):
        """
        Returns a token without the timestamp when it expires.
        """
        return self.make_token()[0]
    
    def extra_hash_data(self):
        return ''

    def _make_token_with_timestamp(self, timestamp, lifespan):
        ts_b36 = int_to_base36(timestamp)
        hash = salted_hmac(
            self.get_key_salt(),
            str(lifespan) + str(timestamp) + str(self.extra_hash_data()),
            secret=self.secret,
        ).hexdigest()[::2]
        token = "%s-%s-%s" % (lifespan, ts_b36, hash)
        if lifespan:
            expiry_ts = lifespan + timestamp
            valid_until = self.timestamp_to_datetime(expiry_ts)
            return (token, valid_until)
        else:
            return (token, None)
    

    def parse_token(self, token):
        if not token:
            return self.MALFORMED_TOKEN, None

        # Parse the token
        try:
            lifespan_str, ts_b36, hash = token.split("-")
            lifespan = int(lifespan_str)
        except ValueError:
            return self.MALFORMED_TOKEN, None

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return self.MALFORMED_TOKEN, None

        token_intact = constant_time_compare(
            self._make_token_with_timestamp(ts, lifespan)[0], token
        )
        if not token_intact:
            return self.MALFORMED_TOKEN, None

        # lifespan = 0 => always valid
        if lifespan:
            cur_ts = self.time_elapsed(self.current_time())
            expiry_ts = lifespan + ts
            valid_until = self.timestamp_to_datetime(expiry_ts)
            if cur_ts < ts or cur_ts > expiry_ts:
                return self.EXPIRED_TOKEN, valid_until 
            return self.VALID_TOKEN, valid_until
        else:
            return self.VALID_TOKEN, None

    def check_token(self, token):
        response, _ = self.parse_token(token)
        return response == self.VALID_TOKEN

    def timestamp_to_datetime(self, ts):
        """
        Convert a timestamp in hours to a datetime object.
        Can be overridden by subclasses (e.g. to support other units).
        """
        return self.origin + datetime.timedelta(seconds=ts * 3600)
        
    def time_elapsed(self, dt):
        delta = dt - self.origin
        return delta.days * 24 + delta.seconds // 3600

    def current_time(self): 
        return datetime.datetime.now().replace(
            minute=0, second=0, microsecond=0
        )

    def get_lifespan(self):
        return self.lifespan

    def get_key_salt(self):
        cls = self.__class__
        return '%s.%s' % (cls.__module__, cls.__qualname__)

# change the salt and account for active status
class ActivationTokenGenerator(PasswordResetTokenGenerator):
    key_salt = "webauth.utils.ActivationTokenGenerator"

    def _make_hash_value(self, user, timestamp):
        v = super(ActivationTokenGenerator, self)\
                ._make_hash_value(user, timestamp)
        return v + str(user.is_active)

class UnlockTokenGenerator(ActivationTokenGenerator):
    key_salt = "webauth.utils.UnlockTokenGenerator"

class PasswordConfirmationTokenGenerator(TimeBasedTokenGenerator):

    PASSWORD_CONFIRMED_SESSION_KEY = 'pwconfirmationtoken'

    def __init__(self, request):
        self.request = request

    def extra_hash_data(self):
        user = self.request.user
        return ''.join([
            # explicitly include the session key
            # to mitigate the possibility of replay attacks
            # TODO: does this actually do anything, and
            # does it depend on the session engine used?
            # Probably fairly useless with cookie-backed sessions,
            # unless they are on a timer.
            str(self.request.session.session_key),
            str(user.last_login),
            str(user.pk),
            str(user.password),
        ])

    def get_lifespan(self):
        # TODO: something like 15 minutes would be more reasonable,
        # but then we need to override more methods in TBT.
        # Regardless, the token is session-bound, so it will expire
        # along with the session.
        return 1

    def embed_token(self):    
        # The token is session-bound, so this makes sense.
        # also, this avoids leaking the token through the URL
        req = self.request
        req.session[self.PASSWORD_CONFIRMED_SESSION_KEY] = self.bare_token()

    @classmethod
    def validate_request(cls, request, consume_token=True):
        if not request.user.is_authenticated:
            return False

        try:
            token = request.session[cls.PASSWORD_CONFIRMED_SESSION_KEY]
        except KeyError:
            return False

        if consume_token:
            del request.session[cls.PASSWORD_CONFIRMED_SESSION_KEY]

        return cls(request).check_token(token)

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
