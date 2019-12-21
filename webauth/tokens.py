import datetime
import inspect
import abc
import re
from functools import wraps
from typing import Type, Tuple, Iterable, Optional

import pytz
from django.utils.crypto import constant_time_compare, salted_hmac
from django.http import HttpResponseGone, HttpResponseNotFound
from django.utils.http import base36_to_int, int_to_base36
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import render, redirect
from django.conf import settings
from django.views import View
from django.views.generic.detail import SingleObjectMixin

# FIXME: naming inconsistency: XXX.validator is a class, while XXX.generator
#  is an instance
# FIXME: outdated docstrings

LIFESPAN_MAX = 1000000

class TokenValidator(abc.ABC):
    """Base class for all token validators."""

    VALID_TOKEN = 1
    MALFORMED_TOKEN = 2

    @abc.abstractmethod
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
        raise NotImplementedError  # pragma: nocover

    def validate_token(self, token):
        """Validate a token.

        This is a thin wrapper around :meth:`parse_token`.  
        Returns ``True`` if and only if the parse result is 
        :const:`TokenValidator.VALID_TOKEN`.

        :param str token: a token string
        :rtype: bool
        """
        response, _ = self.parse_token(token)
        return response == TokenValidator.VALID_TOKEN


class ObjectTokenValidator(TokenValidator, abc.ABC):
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

    @abc.abstractmethod
    def get_object(self):
        """
        Function called to retrieve the object on which the token lives.
        Must be implemented by subclasses.
        """
        raise NotImplementedError  # pragma: nocover

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
        else:
            return TokenValidator.VALID_TOKEN, None


class TokenGenerator(abc.ABC):

    secret = settings.SECRET_KEY
    validator: Type['TokenValidator'] = None

    # TODO: add validator_base kwarg example
    def __init_subclass__(cls, validator_base=None):
        # As opposed to hasattr(), this ensures that a subclass can only
        # override our inheritance magic by explicitly declaring
        # the relevant attribute
        if 'key_salt' not in cls.__dict__:
            cls.key_salt = cls.__name__

        if 'validator' not in cls.__dict__:
            if validator_base is None:
                if issubclass(cls, TokenValidator):
                    # in this scenario, the generator and validator
                    # are one and the same, so this makes sense
                    # as a default.
                    # We don't even attempt to subclass
                    cls.validator = cls
                    return
                # see if we can find a validator somewhere
                # in the superclasses because __init_subclass__
                # kwargs are not inherited
                for ancestor in cls.__mro__[1:]:
                    try:
                        # noinspection PyUnresolvedReferences
                        validator_base = ancestor.validator
                        break
                    except AttributeError:
                        continue
            # if validator_base is still None, we take
            # the most basic one available
            validator_base = validator_base or BoundTokenValidator
            if inspect.isabstract(cls):
                validator = validator_base
            else:
                validator = type(
                    'ValidatorFrom' + cls.__name__,
                    (validator_base,),
                    {'generator_class': cls}
                )
            assert issubclass(validator, BoundTokenValidator)
            cls.validator = validator

    @abc.abstractmethod
    def get_token_data(self) -> Iterable:
        """
        Get data that is to be incorporated in the token hash, and in the
        token itself. Typically a tuple.
        :return: Iterable
        """
        raise NotImplementedError  # pragma: nocover

    def extra_hash_data(self):
        """
        Generate extra hash data to pass to :func:`salted_hmac`.
        Default is the empty string.
        This data is not passed to `format_token`, so cannot be recovered
        from the token emitted.

        :rtype: str
        """
        return ''

    @abc.abstractmethod
    def format_token(self, data, token_hash) -> Tuple[str, object]:
        raise NotImplementedError  # pragma: nocover

    def _compute_token_hash(self, data) -> str:
        hash_data = ''.join(str(d) for d in data) + self.extra_hash_data()
        token_hash = salted_hmac(
            self.key_salt, hash_data, secret=self.secret,
        ).hexdigest()[::2]
        assert len(token_hash) == 20
        return token_hash

    def make_token(self):
        data = self.get_token_data()
        token_hash = self._compute_token_hash(data)
        return self.format_token(data, token_hash)

    def bare_token(self):
        """
        :returns: a token without validity info.
        :rtype: str
        """
        return self.make_token()[0]


class BoundTokenValidator(TokenValidator, abc.ABC):
    """
    Validate tokens from a :class:`TokenGenerator`.
    """

    generator: TokenGenerator = None
    generator_class: Type[TokenGenerator] = TokenGenerator

    def __init__(self, generator_kwargs=None, **kwargs):
        self.generator_kwargs = generator_kwargs or {}
        super().__init__(**kwargs)

    def get_generator(self) -> TokenGenerator:
        """
        Fetch the generator to obtain tokens from.
        The default implementation requires that either
        ``self.generator`` be defined.

        If this object is itself an instance of `self.generator_class`,
        this method will return `self` unless `self.generator` is specified.
        If ``self.generator`` is specified, the value of this
        instance attribute is used.
        If not, this method looks for ``self.generator_class``
        and attempts to instantiate it through
        the :meth:`instantiate_generator` method.

        By default, subclasses of :class:`TokenGenerator`
        make sure that their respective `validator` class attributes
        come with the right fields to make this work out of the box.

        :rtype: TimeBasedTokenGenerator
        """

        gen = self.generator
        if gen is None:
            if isinstance(self, self.generator_class):
                return self
            gen = self.generator = self.instantiate_generator()
            if gen is None or not isinstance(gen, self.generator_class):
                raise TypeError('Could not get hold of a generator instance.')

        return gen


    def instantiate_generator(self):
        """
        Attempt to instantiate a generator.
        Only called if ``self.generator`` is None.
        The default implementation attempts to call ``self.generator_class``
        with ``self.generator_kwargs``, but subclasses are free to change that.
        """

        try:
            # noinspection PyArgumentList
            return self.generator_class(**self.generator_kwargs)
        except (KeyError, TypeError) as e:
            raise TypeError(
                'Could not instantiate generator from kwargs %s' % (
                    self.generator_kwargs
                ), e
            )


class TimeBasedTokenValidator(BoundTokenValidator):

    EXPIRED_TOKEN = 3
    NOT_YET_VALID_TOKEN = 4

    def parse_token(self, token):
        """
        Parse a token according to the semantics of
        :meth:`TokenValidator.parse_token`.
        """
        if not token:
            return self.MALFORMED_TOKEN, None

        generator = self.get_generator()
        assert isinstance(generator, TimeBasedTokenGenerator)

        # Parse the token
        try:
            lifespan_str, ts_b36, token_hash = token.split("-")
            lifespan = int(lifespan_str)
            if lifespan > LIFESPAN_MAX:
                raise ValueError(
                    'Token lifespan %d larger than %d' % (
                        lifespan, LIFESPAN_MAX
                    )
                )
        except ValueError:
            return self.MALFORMED_TOKEN, None

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return self.MALFORMED_TOKEN, None

        data = generator._token_data_for_ts(ts, lifespan=lifespan)
        token_intact = constant_time_compare(
            generator._compute_token_hash(data), token_hash
        )
        if not token_intact:
            return self.MALFORMED_TOKEN, None

        # Token is real. Now let's check the timestamps
        cur_time = generator.current_time(strip=False)
        valid_from = generator.timestamp_to_datetime(ts)
        # lifespan = 0 => only check valid_from
        if lifespan:
            valid_until = generator.timestamp_to_datetime(lifespan + ts)
        else:
            valid_until = None
        valid_range = (valid_from, valid_until)
        if cur_time < valid_from:
            return self.NOT_YET_VALID_TOKEN, valid_range
        if valid_until is not None and cur_time > valid_until:
            return self.EXPIRED_TOKEN, valid_range
        return self.VALID_TOKEN, valid_range


KWARG_PARAM_KINDS = (
    inspect.Parameter.KEYWORD_ONLY,
    inspect.Parameter.POSITIONAL_OR_KEYWORD
)

def init_kwargs(cls, mro=None):
    if mro is None:
        mro = cls.__mro__
    mro = mro[1:]
    try:
        kwargs_to_pass = cls.kwargs_to_pass
        if kwargs_to_pass is None:
            set_on_class = True
        else:
            return kwargs_to_pass
    except AttributeError:
        set_on_class = False

    # pick off kwargs that may not be recognised
    init_sign = inspect.signature(cls.__init__)
    has_varkwargs = any(
        p.kind == inspect.Parameter.VAR_KEYWORD
        for p in init_sign.parameters.values()
    )

    kwargs_to_pass = {
        name for name, param in init_sign.parameters.items()
        if param.kind in KWARG_PARAM_KINDS and name != 'self'
    }

    if has_varkwargs and mro:
        for p in mro:
            kwargs_to_pass |= init_kwargs(p, mro=mro)

    if set_on_class:
        cls.kwargs_to_pass = kwargs_to_pass

    return kwargs_to_pass


class TokenGeneratorRequestMixin:

    pass_anything = False
    kwargs_to_pass = None

    @classmethod
    def get_constructor_kwargs(cls, request, *, view_kwargs, view_instance=None):
        if not cls.pass_anything:
            return {
                k: v for k, v in view_kwargs.items() if k in init_kwargs(cls)
            }
        return view_kwargs


class TimeBasedTokenGenerator(TokenGenerator, abc.ABC,
                              validator_base=TimeBasedTokenValidator):
    """
    Inspired by :class:`django.contrib.auth.tokens.PasswordResetTokenGenerator`.
    Instances of this class generate tokens that expire after a given time.
    Ultimately relies on :func:`django.utils.crypto.salted_hmac`.

    The default implementation uses a timespan in hours.
    This can be changed by overriding :meth:`ts_from_delta` and 
    :meth:`ts_to_delta`. The default datetime epoch is set to January 1st 2001,
    which is reasonable for tokens with a lifespan expressed in hours.

    Subclasses of this class automatically get a ``validator`` class attribute 
    that derives a compatible subclass of TimeBasedTokenValidator.

    Instantiating this class without subclassing it is discouraged, since 
    the salt is derived from the subclass name, so tokens generated by the
    same class for different purposes would be interchangeable.
    This is usually not what you want.

    :ivar datetime.datetime origin: the datetime epoch used
    :ivar str secret: the secret passed to :func:`salted_hmac`.
    :ivar int lifespan: the token's lifespan (see :meth:`get_lifespan`)
    """

    origin = datetime.datetime.combine(
        datetime.date(2001, 1, 1), datetime.datetime.min.time(), tzinfo=pytz.utc
    )

    lifespan = 0

    TBTG_TOKEN_REGEX = r'(\d+)-([a-z0-9]+)-[a-f0-9]{20}'
    TBTG_TOKEN_PATTERN = re.compile(TBTG_TOKEN_REGEX)

    def __init__(self, *, valid_from: Optional[datetime.datetime]=None,
                 **kwargs):
        self.valid_from = valid_from
        super().__init__(**kwargs)

    def get_lifespan(self):
        """
        :returns: ``self.lifespan`` by default
        :rtype: int
        """
        return self.lifespan

    def _token_data_for_ts(self, ts, lifespan=None) -> Tuple:
        lifespan = lifespan if lifespan is not None else self.get_lifespan()
        if lifespan > LIFESPAN_MAX or lifespan < 0:
            raise ValueError(
                'Token lifespan %d larger than %d' % (
                    lifespan, LIFESPAN_MAX
                )
            )
        return lifespan, ts

    def get_token_data(self) -> Tuple:
        valid_from = getattr(self, 'valid_from',  None) or self.current_time()
        if valid_from and valid_from < self.origin:
            raise ValueError(
                'valid_from timestamp should occur after origin'
            )
        valid_from_ts = self.time_elapsed(valid_from)
        return self._token_data_for_ts(valid_from_ts)

    def format_token(self, data, token_hash) \
            -> Tuple[str, Tuple[datetime.datetime,Optional[datetime.datetime]]]:
        lifespan, timestamp = data
        ts_b36 = int_to_base36(timestamp)
        token = "%s-%s-%s" % (lifespan, ts_b36, token_hash)
        valid_from = self.timestamp_to_datetime(timestamp)
        if lifespan:
            expiry_ts = lifespan + timestamp
            valid_until = self.timestamp_to_datetime(expiry_ts)
        else:
            valid_until = None
        return token, (valid_from, valid_until)

    @classmethod
    def ts_to_delta(cls, ts: int) -> datetime.timedelta:
        """
        Convert an integer timespan indication to a :class:`datetime.timedelta`
        object.
        The default implementation assumes the timespan is in hours.

        :param int ts: the timespan indication
        :rtype: datetime.timedelta
        """
        return datetime.timedelta(seconds=ts * 3600)

    @classmethod
    def ts_from_delta(cls, delta: datetime.timedelta) -> int:
        """
        Convert a :class:`datetime.timedelta` object to an integer timespan.
        The default implementation assumes the timespan is in hours.

        :param datetime.timedelta delta: the time delta to convert
        :rtype: int
        """
        return delta.days * 24 + delta.seconds // 3600

    def timestamp_to_datetime(self, ts: int) -> datetime.datetime:
        """
        Convert an integer timespan indication to a :class:`datetime.datetime`
        object by adding the result of :meth:`ts_to_delta` to ``self.origin``.

        :param int ts: the timespan indication
        :rtype: datetime.datetime
        """
        return self.origin + self.ts_to_delta(ts)
        
    def time_elapsed(self, dt: datetime.datetime) -> int:
        """
        Convert a :class:`datetime.datetime` object to an integer timespan
        by applying :meth:`ts_from_delta` to the difference of ``dt`` and 
        ``self.origin``.

        :param datetime.datetime dt: the datetime to convert
        :rtype: int
        """
        return self.ts_from_delta(dt - self.origin)

    @classmethod
    def current_time(cls, strip=True) -> datetime.datetime:
        base = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
        if not strip:
            return base
        return base.replace(minute=0, second=0, microsecond=0)


def _maybe_pass_kwarg(name, pass_kwarg, value, kwargs):
    if pass_kwarg:
        kwargs[name] = value
    else:
        try:
            del kwargs[name]
        except KeyError:
            pass


class RequestTokenValidator(BoundTokenValidator, abc.ABC):
    """
    Eliminate boilerplate for token validation in views.
    """

    pass_token = True
    pass_validity_info = False
    redirect_url = None

    def __init__(self, *, request, view_kwargs=None, view_instance=None, **kwargs):
        self.request = request
        self.view_kwargs = view_kwargs
        # only relevant for class-based views
        self.view_instance = view_instance
        super().__init__(**kwargs)

    @abc.abstractmethod
    def get_token(self):
        """
        Retrieve the token from request data.
        """
        raise NotImplementedError  # pragma: nocover

    def instantiate_generator(self):
        gen_class = self.generator_class
        assert issubclass(gen_class, TokenGeneratorRequestMixin)
        view_kwargs = dict(self.view_kwargs)
        try:
            kwargs = gen_class.get_constructor_kwargs(
                request=self.request, view_kwargs=view_kwargs,
                view_instance=self.view_instance
            )
            return gen_class(**kwargs)
        except (KeyError, TypeError) as e:
            raise TypeError(
                'Could not instantiate generator from view data.', e
            )

    def handle_token(self, view_func, pass_token=None, redirect_url=None,
                     pass_validity_info=None):
        """
        Return a response based on the token value and view parameters.
        If a valid token is found, the view is executed with the correct
        parameters.
        If either ``redirect_url`` or ``self.redirect_url`` 
        is not ``None``, the response will be a redirect
        no matter where the validation fails.
        These fields may be callables. In this case, they will be called with
        the view parameters.
        Otherwise, we return an appropriate error response.
        """
        redirect_url = redirect_url or self.redirect_url
        if pass_validity_info is None:
            pass_validity_info = self.pass_validity_info
        if pass_token is None:
            pass_token = self.pass_token
        # validate the token
        try:
            token = self.get_token()
            parse_res, validity_info = self.parse_token(token)
        except (KeyError, AttributeError):
            token = validity_info = None
            parse_res = self.MALFORMED_TOKEN

        view_kwargs = dict(self.view_kwargs)
        if parse_res == self.VALID_TOKEN:
            # decide which arguments to pass through or remove
            _maybe_pass_kwarg(
                'validity_info', pass_validity_info, validity_info, view_kwargs
            )
            _maybe_pass_kwarg('token', pass_token, token, view_kwargs)
            return view_func(self.request, **view_kwargs)
        else:
            return self.handle_invalid(
                token=token, parse_res=parse_res, validity_info=validity_info,
                redirect_url=redirect_url
            )

    def handle_invalid(self, *, token, parse_res, validity_info,
                       redirect_url=None):
        if redirect_url is not None:
            if callable(redirect_url):
                redirect_url = redirect_url(self.request)
            return redirect(redirect_url)
        else:
            return HttpResponseNotFound('Invalid token')

    @classmethod
    def enforce_token(cls, view_func=None, view_instance=None, **kwargs):
        """
        Decorator that validates the ``token`` URL parameter.
        If the token is malformed, the wrapped view raises ``404``.
        If the token is valid, the view is executed normally.
        You can control what extra information is passed to the view via kwargs.
        """
        def decorator(_view_func):
            @wraps(_view_func)
            def _wrapped_view(request, **view_kwargs):
                # construct the validator instance
                validator = cls(
                    request=request, view_kwargs=view_kwargs,
                    view_instance=view_instance
                )
                return validator.handle_token(_view_func, **kwargs)
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
    def as_mixin(cls, pass_token=True, pass_validity_info=False, **mixin_kwargs):
        """
        Returns a view mixin that takes care of token enforcement.
        All kwargs are passed to the :dec:`enforce_token` decorator, and we 
        use some voodoo to pass the view instance as well.
        Unless forced otherwise, this also sets the validity_info and
        token attributes on the view class.
        """
        decorator_kwargs = mixin_kwargs.copy()
        # we force these to be true, our mixin handles these kwargs anyway
        # the true handler for these conditions is in our CBV-specific
        # dispatch wrapper
        decorator_kwargs['pass_validity_info'] = True
        decorator_kwargs['pass_token'] = True

        class Mixin(View):
            def dispatch(self, request, **view_kwargs):
                def _dispatch(_request, validity_info=None, token=None, **kwargs):
                    self.validity_info = validity_info
                    self.token = token
                    if pass_token:
                        kwargs['token'] = token
                    if pass_validity_info:
                        kwargs['validity_info'] = validity_info
                    # update kwargs on view object
                    self.kwargs = kwargs
                    # python MRO magic takes care of the rest
                    return super(Mixin, self).dispatch(_request, **kwargs)
                # pass the view instance too
                wrapped_view = cls.enforce_token(
                    _dispatch, view_instance=self, **decorator_kwargs
                )
                return wrapped_view(request, **view_kwargs)

        return Mixin


class TimeBasedRequestTokenValidator(
        RequestTokenValidator,
        TimeBasedTokenValidator,
        abc.ABC):

    gone_template_name = None
    early_template_name = None

    def handle_invalid(self, *, token, parse_res, validity_info,
                       redirect_url=None):
        gone_tpl = self.gone_template_name or self.__class__.gone_template_name
        early_tpl = self.early_template_name or self.__class__.early_template_name
        try:
            valid_from, valid_until = validity_info
        except (TypeError, ValueError):
            valid_from = valid_until = None
        if parse_res == self.EXPIRED_TOKEN:
            # Return a 410 response
            if gone_tpl is None:
                if valid_until is not None:
                    response_str = _(
                        'The token %(token)s expired at '
                        '%(valid_until)s.'
                    ) % { 'token': token, 'valid_until': valid_until}
                else:  # pragma: nocover
                    response_str = _(
                        'The token %(token)s has expired.'
                    ) % {'token': token}

                return HttpResponseGone(response_str)
            else:
                return render(
                    self.request, gone_tpl, status=410
                )
        elif parse_res == self.NOT_YET_VALID_TOKEN:
            # 404 seems to be the most appropriate
            # (425 Too Early is specific to another HTTP feature)
            if early_tpl is None:
                if valid_from is not None:
                    response_str = _(
                        'The token %(token)s is only valid from '
                        '%(valid_from)s.'
                    ) % { 'token': token, 'valid_from': valid_from}
                else:  # pragma: nocover
                    response_str = _(
                        'The token %(token)s is not valid yet.'
                    ) % {'token': token}

                return HttpResponseNotFound(response_str)
            else:
                return render(
                    self.request, early_tpl, status=404
                )
        else:
            return super().handle_invalid(
                token=token, parse_res=parse_res,
                validity_info=validity_info, redirect_url=redirect_url
            )


class UrlTokenValidator(RequestTokenValidator, abc.ABC):

    def get_token(self):
        return self.view_kwargs['token']


class SessionTokenValidator(RequestTokenValidator, abc.ABC):

    def get_token(self):
        assert issubclass(self.generator_class, SessionTokenGenerator)
        session_key = self.generator_class.get_session_key()
        token = self.request.session[session_key]
        # consume the token if necessary
        # only POST requests should trigger this
        try:
            if self.generator_class.consume_token \
                    and self.request.method == 'POST':
                del self.request.session[session_key]
        except AttributeError:  # pragma: nocover
            pass
        return token


class DBUrlTokenValidator(UrlTokenValidator, abc.ABC):
    """
    Validate tokens on views that render single objects.
    """

    def get_object(self):
        try:
            return self.object
        except AttributeError:
            if not isinstance(self.view_instance, SingleObjectMixin):
                raise TypeError(
                    'DBUrlTokenValidator requires SingleObjectMixin views'
                )

            # retrieve object from view and cache it
            obj = self.view_instance.get_object()

            def get_cached_object(**_kwargs):
                return obj

            self.view_instance.get_object = get_cached_object
            self.object = obj
            return self.object


class TimeBasedUrlTokenValidator(
        UrlTokenValidator,
        TimeBasedRequestTokenValidator):
    pass


class TimeBasedSessionTokenValidator(
        SessionTokenValidator,
        TimeBasedRequestTokenValidator):
    pass_token = False


class TimeBasedUrlTokenGenerator(
        TimeBasedTokenGenerator, TokenGeneratorRequestMixin,
        validator_base=TimeBasedUrlTokenValidator):
    validator: Type[TimeBasedUrlTokenValidator]


class SessionTokenGenerator(TokenGenerator, TokenGeneratorRequestMixin, abc.ABC,
                           validator_base=TimeBasedSessionTokenValidator):
    consume_token = True
    validator: Type[TimeBasedSessionTokenValidator]

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    @classmethod
    def get_session_key(cls):
        try:
            return cls.session_key
        except AttributeError:  # pragma: nocover
            raise NotImplementedError

    def embed_token(self):
        # The token is session-bound, so this makes sense.
        # also, this avoids leaking the token through the URL
        req = self.request
        req.session[self.get_session_key()] = self.bare_token()

    @classmethod
    def get_constructor_kwargs(cls, request, *, view_kwargs,
                               view_instance=None):
        return {'request': request}


class TimeBasedSessionTokenGenerator(
        TimeBasedTokenGenerator, SessionTokenGenerator, abc.ABC,
        validator_base=TimeBasedSessionTokenValidator):
    pass


class TimeBasedDBUrlTokenValidator(
        DBUrlTokenValidator, TimeBasedTokenValidator):

    def instantiate_generator(self):
        # instantiate a generator using the object we have
        return self.generator_class(self.get_object())


class ObjectDBUrlTokenValidator(DBUrlTokenValidator, ObjectTokenValidator):
    pass


class TimeBasedDBUrlTokenGenerator(
        TimeBasedTokenGenerator,
        validator_base=TimeBasedDBUrlTokenValidator):
    validator: Type[TimeBasedDBUrlTokenValidator]


class AccountTokenHandler(TimeBasedTokenGenerator, TimeBasedTokenValidator):
    """
    Essentially reimplements the functionality of 
    :class:`django.contrib.auth.tokens.PasswordResetTokenGenerator` in
    our framework.
    """

    def __init__(self, user, lifespan=None):
        super().__init__()
        self.user = user
        self.lifespan = lifespan

    # for compatibility with Django's pw reset interface
    @classmethod
    def check_token(cls, user, token):
        return cls(user).validate_token(token)

    def extra_hash_data(self):
        user = self.user
        login_timestamp = '' if user.last_login is None else (
            user.last_login.replace(microsecond=0, tzinfo=None)
        )
        return ''.join([
            str(user.pk), user.password, str(login_timestamp), 
            str(user.is_active)
        ])

    def get_lifespan(self):
        if self.lifespan is None:
            return settings.PASSWORD_RESET_TIMEOUT_DAYS * 24
        else:
            return self.lifespan


class PasswordResetTokenGenerator(AccountTokenHandler):
    pass


class UnlockTokenGenerator(AccountTokenHandler):
    pass


class ActivationTokenGenerator(AccountTokenHandler):
    pass


class PasswordConfirmationTokenGenerator(TimeBasedSessionTokenGenerator):

    session_key = 'pwconfirmationtoken'
    consume_token = False

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
            str(user.email),
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

class SignedSerialTokenGenerator(TokenGenerator, BoundTokenValidator, abc.ABC):
    """
    Generate tokens that do not depend on any timestamps.
    Intended to tie primary keys (or any serial number) to a specific
    server/model. The result should be reproducible and independent of
    environmental factors.
    """

    secret = settings.SECRET_KEY

    def parse_token(self, token):
        try:
            serial, token_hash = token.split("-")
            serial = int(serial)
        except ValueError:
            return self.MALFORMED_TOKEN, None

        if serial != self.serial:
            return self.MALFORMED_TOKEN, None

        if constant_time_compare(self.bare_token(), token):
            return self.VALID_TOKEN, None
        else:
            return self.MALFORMED_TOKEN, None

    def __init__(self, serial: int):
        super().__init__()
        self.serial = serial

    def get_token_data(self) -> Iterable:
        return self.serial,

    def format_token(self, data, token_hash) -> Tuple[str, object]:
        return "%s-%s" % (self.serial, token_hash), None
