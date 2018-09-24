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
    """Base class for all token validators."""

    VALID_TOKEN = 1
    MALFORMED_TOKEN = 2
    EXPIRED_TOKEN = 3
    
    def parse_token(self, token):
        """Parse a token.

        This method should return a tuple containing one of 
        :const:`TokenValidator.VALID_TOKEN`, 
        :const:`TokenValidator.MALFORMED_TOKEN` or 
        :const:`TokenValidator.EXPIRED_TOKEN` and a :class:`datetime.datetime`
        object specifying the token's expiration timestamp.
        The expiration time may be ``None`` in all cases.

        :param str token: a token string
        :returns: the parse result and the token's expiration time.
        :rtype: int, datetime.datetime
        """
        raise NotImplementedError(
            'TokenValidator subclasses must implement `parse_token`'
        )

    def check_token(self, token):
        """Check a token.

        This is a thin wrapper around :meth:`parse_token`.  
        Returns ``True`` if and only if the parse result is 
        :const:`TokenValidator.VALID_TOKEN`.

        :param str token: a token string
        :rtype: bool
        """
        response, _ = self.parse_token(token)
        return response == TokenValidator.VALID_TOKEN

class ObjectTokenValidator(TokenValidator):
    """Token validator that looks up a token as an attribute on an object."""

    token_attribute_name = 'token'
    """
    Name of the token attribute.
    """

    is_binary_field = True
    """
    Controls whether or not the token field is binary.
    If so, :meth:`str.hex` is called first.
    """
    
    def get_object(self):
        """
        Function called to retrieve the object on which the token lives.
        Must be implemented by subclasses.
        """
        raise NotImplementedError(
            'Subclasses of ObjectTokenValidator should implement get_object'
        )

    def object_expired(self):
        """
        If this function returns ``True``, the token will be considered stale.
        """
        return False

    def parse_token(self, token):
        """
        Returns :const:`TokenValidator.MALFORMED_TOKEN` if ``token`` does not
        match the token stored on the object.
        Otherwise, if :meth:`object_expired` returns ``True``, 
        :const:`TokenValidator.EXPIRED_TOKEN` is returned.
        Barring either of these, the method returns 
        :const:`TokenValidator.VALID_TOKEN`.
        """

        real_token = getattr(self.get_object(), self.token_attribute_name)
        if self.is_binary_field:
            real_token = real_token.hex()
        if token != real_token:
            return TokenValidator.MALFORMED_TOKEN, None
        elif self.object_expired():
            return TokenValidator.EXPIRED_TOKEN, None
        else:
            return TokenValidator.VALID_TOKEN, None

class TimeBasedTokenGenerator:
    """
    Inspired by :class:`django.contrib.auth.tokens.PasswordResetTokenGenerator`.
    Instances of this class generate tokens that expire after a given time.
    Ultimately relies on :func:`django.utils.crypto.salted_hmac`.

    The default implementation uses a timespan in hours.
    This can be changed by overriding :meth:`ts_from_delta` and 
    :meth:`ts_to_delta`. The default datetime epoch is set to January 1st 2001,
    which is reasonable for tokens with a lifespan expressed in hours.

    :ivar datetime.datetime origin: the datetime epoch used
    :ivar str secret: the secret passed to :func:`salted_hmac`.
    :ivar int lifespan: the token's lifespan (see :meth:`get_lifespan`)
    """

    origin = datetime.datetime.combine(
        datetime.date(2001, 1, 1), datetime.datetime.min.time()
    )

    secret = settings.SECRET_KEY

    lifespan = 0

    def make_token(self):
        """
        :returns: a token and the timestamp when it expires.
        :rtype: str, datetime.datetime
        """
        return self._make_token_with_timestamp(
            self.time_elapsed(self.current_time()), self.get_lifespan()
        ) 

    def bare_token(self):
        """
        :returns: a token without the timestamp when it expires.
        :rtype: str
        """
        return self.make_token()[0]
    
    def extra_hash_data(self):
        """
        Generate extra hash data to pass to :func:`salted_hmac`.
        Default is the empty string.

        :rtype: str
        """
        return ''

    def get_lifespan(self):
        """
        :returns: ``self.lifespan`` by default
        :rtype: int
        """
        return self.lifespan

    def get_key_salt(self):
        """Returns the salt salt passed to :func:`salted_hmac`.
        The default is ``self.__class__.__name__``.
        :rtype: str
        """
        return self.__class__.__name__

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
    
    def ts_to_delta(self, ts):
        """
        Convert an integer timespan indication to a :class:`datetime.timedelta`
        object.
        The default implementation assumes the timespan is in hours.

        :param int ts: the timespan indication
        :rtype: datetime.timedelta
        """
        return datetime.timedelta(seconds=ts * 3600)

    def ts_from_delta(self, delta):
        """
        Convert a :class:`datetime.timedelta` object to an integer timespan.
        The default implementation assumes the timespan is in hours.

        :param datetime.timedelta delta: the time delta to convert
        :rtype: int
        """
        return delta.days * 24 + delta.seconds // 3600

    def timestamp_to_datetime(self, ts):
        """
        Convert an integer timespan indication to a :class:`datetime.datetime`
        object by adding the result of :meth:`ts_to_delta` to ``self.origin``.

        :param int ts: the timespan indication
        :rtype: datetime.datetime
        """
        return self.origin + self.ts_to_delta(ts)
        
    def time_elapsed(self, dt):
        """
        Convert a :class:`datetime.datetime` object to an integer timespan
        by applying :meth:`ts_from_delta` to the difference of ``dt`` and 
        ``self.origin``.

        :param datetime.datetime delta: the datetime to convert
        :rtype: int
        """
        return self.ts_from_delta(dt - self.origin)

    def current_time(self): 
        return datetime.datetime.now().replace(
            minute=0, second=0, microsecond=0
        )

class TimeBasedTokenValidator(TokenValidator):
    """
    Validate tokens from a :class:`TimeBasedTokenGenerator`.
    """
     
    def get_generator(self):
        """
        Fetch the generator to obtain tokens from.

        :returns: ``self.generator`` by default
        :rtype: TimeBasedTokenGenerator
        """
        return self.generator 

    def parse_token(self, token):
        """
        Parse a token according to the semantics of 
        :meth:`TokenValidator.parse_token`.
        """
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
    """
    Implement URL token validation boilerplate.
    """

    pass_token = True
    pass_valid_until = False

    @classmethod
    def enforce_token(cls, view_func=None, gone_template_name=None, 
            malformed_token_name=None,
            pass_valid_until=False, pass_token=False, view_instance=None):
        """
        Decorator that validates the ``token`` URL parameter.
        If the token is malformed, the wrapped view raises ``404``.
        If the token has expired, a ``410`` response is returned.
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
    
    # TODO: put examples from lukweb in docs
    @classmethod
    def as_mixin(cls, *args, **kwargs):
        """
        Returns a view mixin that takes care of token enforcement.
        All kwargs are passed to the :dec:`enforce_token` decorator, and we 
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
