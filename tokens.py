import datetime
from functools import wraps
from django.utils.crypto import constant_time_compare, salted_hmac
from django.http import HttpResponseGone, Http404
from django.utils.http import base36_to_int, int_to_base36
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import render
from django.conf import settings
from django.views.generic.detail import SingleObjectMixin

class TokenValidator:
    VALID_TOKEN = 1
    MALFORMED_TOKEN = 2
    EXPIRED_TOKEN = 3
    
    def parse_token(self, token):
        # TODO: document this interface, see DBTokenValidator
        # and TimeBasedTokenGenerator
        raise NotImplementedError(
            'TokenValidator subclasses must implement `parse_token`'
        )

    def check_token(self, token):
        response, v = self.parse_token(token)
        return response == self.VALID_TOKEN

class ObjectTokenValidator(TokenValidator):
    token_attribute_name = 'token'
    is_binary_field = True
    
    def get_object(self):
        raise NotImplementedError(
            'Subclasses of ObjectTokenValidator should implement get_object'
        )

    def object_expired(self):
        """
        If this function returns True, the token will be considered stale.
        """
        return False

    def parse_token(self, token):
        real_token = getattr(self.get_object(), self.token_attribute_name)
        if self.is_binary_field:
            real_token = real_token.hex()
        if token != real_token:
            return self.MALFORMED_TOKEN, None
        elif self.object_expired():
            return self.EXPIRED_TOKEN, None
        else:
            return self.VALID_TOKEN, None

class TimeBasedTokenGenerator:
    """
    Inspired by PasswordResetTokenGenerator.
    Subclasses must provide lifespan
    in whatever unit time_elapsed uses (default hours)
    """
    origin = datetime.datetime.combine(
        datetime.date(2001, 1, 1), datetime.datetime.min.time()
    )

    secret = settings.SECRET_KEY

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
        return self.__class__.__name__

class TimeBasedTokenValidator(TokenValidator):
     
    def get_generator(self):
        return self.generator 

    def parse_token(self, token):
        if not token:
            return self.MALFORMED_TOKEN, None

        generator = self.get_generator()

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
            generator._make_token_with_timestamp(ts, lifespan)[0], token
        )
        if not token_intact:
            return self.MALFORMED_TOKEN, None

        # lifespan = 0 => always valid
        if lifespan:
            cur_ts = generator.time_elapsed(generator.current_time())
            expiry_ts = lifespan + ts
            valid_until = generator.timestamp_to_datetime(expiry_ts)
            if cur_ts < ts or cur_ts > expiry_ts:
                return self.EXPIRED_TOKEN, valid_until 
            return self.VALID_TOKEN, valid_until
        else:
            return self.VALID_TOKEN, None

class UrlTokenValidator(TokenValidator):

    pass_token = True
    pass_valid_until = False

    @classmethod
    def enforce_token(cls, view_func=None, gone_template_name=None, 
            malformed_token_name=None,
            pass_valid_until=False, pass_token=False, view_instance=None):
        """
        Decorator that validates the `token` URL parameter.
        If the token is malformed, the wrapped view raises 404.
        If the token has expired, a 410 response is returned.
        If the token is valid, the view is executed normally.
        You can control what extra information is passed to the view via kwargs.
        """
        def decorator(view_func):
            @wraps(view_func)
            def _wrapped_view(request, *args, **kwargs):
                token = kwargs.get('token')
                # construct the validator instance
                gen = cls(
                    request=request, view_args=args, view_kwargs=kwargs,
                    view_instance=view_instance
                )
                # validate the token
                parse_res, valid_until = gen.parse_token(token)
                if parse_res == cls.VALID_TOKEN:
                    if pass_valid_until or cls.pass_valid_until:
                        kwargs['valid_until'] = valid_until
                    if pass_token or cls.pass_token:
                        kwargs['token'] = token
                    return view_func(request, *args, **kwargs)
                elif parse_res == cls.EXPIRED_TOKEN:
                    # Return a 410 response
                    if gone_template_name is None:
                        if valid_until is not None:
                            response_str = _(
                                'The token %(token)s expired at '
                                '%(valid_until)s.'
                            ) % {
                                'token': token,
                                'valid_until': valid_until
                            }
                        else:
                            response_str = _(
                                'The token %(token)s has expired.'
                            ) % { 'token': token }
                           
                        return HttpResponseGone(response_str)
                    else:
                        return render(
                            request, gone_template_name, status=410
                        )
                else:
                    raise Http404('Malformed token')
            return _wrapped_view

        if view_func is None:
            # called with arguments, so we should return a decorator
            return decorator
        elif callable(view_func):
            # called without arguments, so we *are* the decorator
            return decorator(view_func)
        else:
            raise ValueError('Invalid arguments for enforce_token')
    
    @classmethod
    def as_mixin(cls, *args, **kwargs):
        """
        Returns a view mixin that takes care of token enforcement.
        All kwargs are passed to the enforce_token decorator, and we 
        use some voodoo to pass the view instance as well.
        Unless forced otherwise, this also sets the valid_until and 
        token attributes on the view class.
        """
        # since we control the class here, we can safely
        # default these to yes
        decorator_kwargs = {
            'pass_valid_until': True,
            'pass_token': True,
        }
        decorator_kwargs.update(kwargs)
        class Mixin:
            def dispatch(self, *args, **kwargs):
                def _dispatch(*args, valid_until=None, token=None, **kwargs):
                    self.valid_until = valid_until
                    self.token = token
                    # python MRO magic takes care of the rest
                    return super(Mixin, self).dispatch(*args, **kwargs)
                # pass the view instance too
                wrapped_view = cls.enforce_token(
                    _dispatch, *args, view_instance=self, **decorator_kwargs
                )
                return wrapped_view(*args, **kwargs)

        return Mixin
    
    def __init__(self, request, view_args=None, view_kwargs=None,
            view_instance=None, **kwargs):
        self.request = request
        self.view_args = view_args
        self.view_kwargs = view_kwargs
        # only relevant for class-based views
        self.view_instance = view_instance
        super().__init__(**kwargs)

class DBUrlTokenValidator(UrlTokenValidator):
    """
    Validate tokens on views that render single objects.
    """

    def get_object(self):
        try:
            return self.object
        except AttributeError:
            if not isinstance(self.view_instance, SingleObjectMixin):
                raise ValueError(
                    'DBUrlTokenValidator requires SingleObjectMixin views'
                )
            # retrieve object from view and cache it
            obj = self.view_instance.get_object()
            def get_cached_object(queryset=None):
                return obj
            self.view_instance.get_object = get_cached_object
            self.object = obj
            return self.object

class TimeBasedUrlTokenValidator(UrlTokenValidator, TimeBasedTokenValidator):

    def get_generator(self):
        gen_class = self.__class__.generator_class
        # attempt to call from_view_data, else no-args constructor
        try:
            return gen_class.from_view_data(
                self.request, self.view_args, self.view_kwargs, 
                self.view_instance
            )
        except AttributeError:
            return gen_class()

class TimeBasedDBUrlTokenValidator(DBUrlTokenValidator, TimeBasedTokenValidator):
    def get_generator(self):
        # instantiate a generator using the object we have
        return self.__class__.generator_class(self.get_object())

class ObjectDBUrlTokenValidator(DBUrlTokenValidator, ObjectTokenValidator):
    pass

def with_url_validator(validator_base):
    def decorator(cls):
        validator = type(
            'ValidatorFrom' + cls.__name__,
            (validator_base,),
            { 'generator_class': cls }
        )
        cls.validator = validator
        return cls
    return decorator 

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
    validator = TimeBasedTokenValidator

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

        # instantiate a validator
        validator = cls.validator()
        validator.generator = cls(request)
        return validator.check_token(token)
