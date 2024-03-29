import abc
import datetime
import decimal
import inspect
import json
import logging
import uuid
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Optional, Type, List, Dict, Tuple, Set, Iterable, Union

import pytz
from django.conf import settings
from django.core.exceptions import PermissionDenied

from django.http import JsonResponse
from django.shortcuts import render
from django.urls import reverse, path
from django.utils import translation
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _, gettext_noop
from django.views import View
from django.views.decorators.csrf import csrf_protect, csrf_exempt

from webauth.tokens import (
    TimeBasedTokenGenerator, TimeBasedTokenValidator,
    TokenValidator,
)

class APIError(ValueError):
    status: int
    raw_message: str = ''

    def __init__(self, msg, params=None, *args, status=400):
        self.status = status
        if isinstance(msg, str):
            self.raw_message = (msg % params) if params is not None else msg
        super().__init__(
            (_(msg) % params) if params is not None else _(msg),
            *args
        )


def _attempt_parse_json(request, logger):

    data_posted = None
    try:
        data_posted = json.loads(
            request.body.decode('utf8').strip(), parse_float=decimal.Decimal
        )
    except ValueError:
        # probably the request is not JSON/badly encoded
        logger.debug(
            'Could not decode %s as JSON, hopefully it\'s form-encoded',
            repr(request.body)
        )
    request._json_data = data_posted


def _get_raw_param(request, name):
    raw_value = None
    if request._json_data:
        raw_value = request._json_data.get(name)

    # in principle these branches should be exclusive,
    #  but let's code defensively
    #  we're generous in what we allow: querystrings and form-encoded
    #  body are both OK
    if raw_value is None:
        raw_value = request.POST.get(name, request.GET.get(name))
    return raw_value


def parse_dn(dn):
    pairs = [part.split('=', 1) for part in dn.split(',')]
    return {k.upper(): v for k, v in pairs}


class APIAccessStatusCode(IntEnum):
    API_ACCESS_DUNNO = 0
    API_ACCESS_GRANTED = 1
    API_ACCESS_DENIED = 2


class APIAuthMechanism(abc.ABC):
    csrf_exempt = False
    json_name = None

    def __call__(self, request, *args, endpoint: 'APIEndpoint', **kwargs) \
            -> 'APIAccessStatus':
        raise NotImplementedError


@dataclass
class APIAccessStatus:
    code: APIAccessStatusCode
    msg: str = ''
    term_display_name: str = ''
    term_uid: str = ''
    issuer: Optional[APIAuthMechanism] = None
    issuer_name: str=''


class DummyAuthMechanism(APIAuthMechanism):
    csrf_exempt = True

    def __call__(self, request, *args, **kwargs) -> 'APIAccessStatus':
        return APIAccessStatus(
            code=APIAccessStatusCode.API_ACCESS_GRANTED,
            term_uid=uuid.uuid4().hex,
            term_display_name='dummy'
        )


class X509AuthMechanism(APIAuthMechanism):
    """
    Attempt to authenticate a ticketing terminal via SSL.
    The actual authentication happens at the level of the webserver,
    who also decides which CAs to trust
    Configure nginx/uwsgi to pass the relevant headers to Django if you want
    to use this feature.
    """
    json_name = 'x509'

    def __init__(self, cert_dn_requirements: dict):
        self.cert_dn_requirements = cert_dn_requirements

    def __call__(self, request, *_args, **_kwargs) -> APIAccessStatus:

        # it's the front web server's responsibility to make sure that
        # invalid/untrusted SSL certs get nixed, so we only care about enforcing
        # organisational units etc. here
        try:
            dn = request.META['HTTP_X_SSL_USER_DN']
        except KeyError:
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DUNNO,
                msg='No SSL header found'
            )
        try:
            dn_parts = parse_dn(dn)
            ident = dn_parts['CN']
            uid = dn_parts['UID']
            # enforce cert restrictions
            for k, v in self.cert_dn_requirements.items():
                if dn_parts[k.upper()] != v:
                    return APIAccessStatus(
                        code=APIAccessStatusCode.API_ACCESS_DENIED,
                        msg='Unauthorised X509 DN spec'
                    )
        except (KeyError, ValueError):
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DENIED,
                msg='X509 spec is not properly formatted'
            )
        return APIAccessStatus(
            code=APIAccessStatusCode.API_ACCESS_GRANTED,
            term_uid=uid, term_display_name=ident
        )


class APITokenGenerator(TimeBasedTokenGenerator, TimeBasedTokenValidator):

    def __init__(self, *, uid: str, display_name: str, lifespan=None):
        self.uid = uid
        self.display_name = display_name[:20]
        self.lifespan = lifespan or 12
        super().__init__()

    def extra_hash_data(self):
        return self.uid + self.display_name

    def make_base64_token(self):
        token, (valid_from, expiry_date) = self.make_token()
        extd_token = ':'.join(
            (self.display_name, self.uid, token)
        )
        return urlsafe_base64_encode(extd_token.encode('ascii')), expiry_date


class TokenAuthMechanism(APIAuthMechanism):
    json_name = 'token'
    csrf_exempt = True

    def __init__(self, generator_class: Type['APITokenGenerator']):
        self.generator_class = generator_class

    def __call__(self, request, *_args, api_token=None, **_kwargs) \
            -> APIAccessStatus:
        """
        Attempt to authenticate a ticketing terminal via access token.
        The token should be base64 encoded and consist of three segments:
        `display_name:uuid:bare_token`, where `bare_token` is generated by
        the TicketApiTokenGenerator class.
        In principle clients don't need to know this, they can simply pass around
        the result of `TicketApiTokenGenerator.make_base64_token()`.
        """

        api_token = api_token or _get_raw_param(request, 'api_token')
        if api_token is None:
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DUNNO,
                msg='No auth token supplied'
            )

        try:
            token_string = urlsafe_base64_decode(api_token).decode('utf-8')
        except (ValueError, AttributeError, TypeError):
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DENIED,
                msg='Could not decode base64 token'
            )

        try:
            ident, uid, bare_token = token_string.split(':')
        except ValueError:
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DENIED,
                msg='Improperly formatted token string'
            )

        result, _ = self.generator_class(
            uid=uid, display_name=ident
        ).parse_token(bare_token)

        if result == TokenValidator.VALID_TOKEN:
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_GRANTED,
                term_uid=uid, term_display_name=ident
            )
        elif result == TimeBasedTokenValidator.EXPIRED_TOKEN:
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DENIED,
                msg='Access token expired'
            )
        else:
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_DUNNO,
                msg='Invalid access token'
            )


SESSION_UID_KEY = 'ticketing_term_uid'

API_REQUIRE_OTP = object()

class UserStatus(IntFlag):
    anonymous = 0
    authenticated = 1
    otp_verified = 3  # user can't be verified without being authenticated
    staff = 4

    @staticmethod
    def user_status(user):
        if not user.is_authenticated:
            return UserStatus.anonymous

        result = UserStatus.authenticated
        try:
            if user.is_verified():
                result = UserStatus.otp_verified
        except AttributeError:
            # django-otp not installed, or middleware not running
            pass

        if user.is_staff:
            return result | UserStatus.staff
        else:
            return result

    def verify(self, user):
        user_privs = UserStatus.user_status(user)
        return self & user_privs == self

@dataclass(frozen=True)
class PermissionSpec:
    permissions: frozenset
    auth_requirement: UserStatus

    @staticmethod
    def declare(auth_requirement: UserStatus, *args):
        return PermissionSpec(
            permissions=frozenset(args), auth_requirement=auth_requirement
        )

# an (endpoint, method) pair
EndpointAccessSpec = Tuple[str, Optional[str]]
FlexPermissionSpec = Union[Iterable[str], PermissionSpec]

# Example of an auth map access dict:
# {
#    ('submit_intlpayments', None): {'lukweb.add_internalpayment'},
#    ('submit_intldebts', None): {'lukweb.add_internaldebtitem'},
#    ('submit_transfers', 'GET'): {
#        'lukweb.view_internalpayment', 'lukweb.view_reservationpayment'
#    }
#    ('submit_transfers', 'POST'): {
#        'lukweb.add_internalpayment', 'lukweb.add_reservationpayment'
#    }
#}

# TODO add unit tests for UserAuthMap edge cases
class UserAuthMap:

    default_perm_set: Set[str] = None
    default_auth_req: UserStatus = UserStatus.authenticated
    _access_dict: Dict[EndpointAccessSpec, PermissionSpec] = None

    def __init__(self, access_dict: Dict[EndpointAccessSpec, FlexPermissionSpec],
                 default_perm_set: Union[Set[str], str]=None):

        def unflex(perm_spec: FlexPermissionSpec) -> PermissionSpec:
            if isinstance(perm_spec, PermissionSpec):
                return perm_spec
            else:
                return PermissionSpec(
                    permissions=frozenset(perm_spec),
                    auth_requirement=self.default_auth_req
                )

        self._access_dict = {
            (endpoint_name, method.casefold() if method is not None else None):
                unflex(perm_set)
            for ((endpoint_name, method), perm_set) in access_dict.items()
        }
        if isinstance(default_perm_set, str):
            self.default_perm_set = {default_perm_set}
        else:
            self.default_perm_set = default_perm_set

    def can_access(self, user, endpoint: str, method: str):
        perm_spec = self._access_dict.get((endpoint, method.casefold()))
        if perm_spec is None:
            # try with method = None as a default
            perm_spec = self._access_dict.get((endpoint, None))
        if perm_spec is None:
            perms = self.default_perm_set
            auth_req = self.default_auth_req
        else:
            perms = perm_spec.permissions
            auth_req = perm_spec.auth_requirement

        # set default_perm_set to the empty set to allow access by default
        #  None means "always deny on fallthrough"
        if perms is None:
            return False
        # type checker doesn't know about django-otp's monkeypatching
        # noinspection PyTypeChecker
        user_status_ok = auth_req.verify(user)
        return user_status_ok and (not perms or user.has_perms(perms))


class UserAuthMechanism(APIAuthMechanism):
    json_name = 'user'

    def __init__(self, auth_map: UserAuthMap):
        self.auth_map = auth_map

    def __call__(self, request, *_args, endpoint, **_kwargs):
        user = request.user
        can_access = self.auth_map.can_access(
            request.user, endpoint.endpoint_name, request.method
        )
        if can_access:
            try:
                uid = request.session[SESSION_UID_KEY]
            except KeyError:
                uid = request.session[SESSION_UID_KEY] = uuid.uuid4().hex
            name = user.username if user.is_authenticated else 'anonymous'
            return APIAccessStatus(
                code=APIAccessStatusCode.API_ACCESS_GRANTED,
                term_uid=uid, term_display_name=name
            )
        else:
            # the auth map may decide to allow anonymous access for some things
            if request.user.is_authenticated:
                return APIAccessStatus(
                    code=APIAccessStatusCode.API_ACCESS_DENIED,
                    msg='User does not have the appropriate permissions'
                )
            else:
                return APIAccessStatus(
                    code=APIAccessStatusCode.API_ACCESS_DUNNO,
                    msg='User not logged in'
                )


API_ERROR_FIELD = 'api_error'
SERVER_ERROR_RESPONSE = JsonResponse(
    {API_ERROR_FIELD: 'Server error'}, status=500
)

class API:
    def __init__(self, *, name: str, auth_workflow: List[APIAuthMechanism],
                 endpoint_url_base='', logger=None):
        self.api_name = name
        self.auth_workflow = auth_workflow
        self.endpoint_registry = {}
        self.endpoint_url_base = endpoint_url_base
        self._logger = logger or logging.getLogger(__name__)

    def endpoint_url_name(self, endpoint_name):
        return '%s_%s_endpoint' % (self.api_name, endpoint_name)

    @property
    def endpoint_urls(self):
        return [
            path(self.endpoint_url_base + name, csrf_exempt(cls.as_view()),
                 name=self.endpoint_url_name(name))
            for name, cls in self.endpoint_registry.items()
        ]

    def register(self, endpoint_class: Type['APIEndpoint']):
        if endpoint_class.api is not None and endpoint_class.api is not self:
            raise TypeError(
                'Endpoint %s is already registered to an api' % endpoint_class
            )
        endpoint_class.api = self
        self.endpoint_registry[endpoint_class.endpoint_name] = endpoint_class

    def log(self, level, msg, *args, term_uid, term_display_name,
            auth_basis=None, endpoint: 'APIEndpoint'=None, **kwargs):
        if endpoint is None:
            formatted_msg = '[%s, UID:%s, auth:%s] %s' % (
                term_display_name, term_uid, auth_basis or 'unknown', msg
            )
        else:
            auth_basis = auth_basis or getattr(
                endpoint.auth_result, 'issuer_name', 'unknown'
            )
            formatted_msg = '<%s>[%s, UID:%s, auth:%s] %s' % (
                endpoint.endpoint_name, term_display_name, term_uid,
                auth_basis, msg
            )
        self._logger.log(level, formatted_msg, *args, **kwargs)


class APIEndpoint(View):
    api: API = None
    endpoint_name = None
    gui_view = False
    auth_fail_on_deny = True

    def __init_subclass__(cls, *args, abstract=False, **kwargs):
        if not abstract:
            if cls.endpoint_name is None:
                raise TypeError('API endpoint must set endpoint_name attr')
            if cls.api is not None:
                cls.api.register(cls)
        super().__init_subclass__(*args, **kwargs)

    def __init__(self):
        if self.__class__.api is None:
            raise TypeError('Endpoint not registered to an API')
        self.auth_errors = {}
        self.auth_result: Optional[APIAccessStatus] = None
        super().__init__()

    def http_method_not_allowed(self, request, *args, **kwargs):
        # failure response for Method Not Allowed
        method_str = ' or '.join(self._allowed_methods())
        return JsonResponse(
            {
                API_ERROR_FIELD: 'This endpoint requires %s.' % method_str
            },
            status=405
        )

    @property
    def auth_workflow(self):
        """
        Optionally override API auth workflow on a per-endpoint basis
        """
        return self.api.auth_workflow

    def auth(self, request, *args, **kwargs) -> bool:
        for auth_method in self.auth_workflow:
            result = auth_method(request, *args, endpoint=self, **kwargs)
            json_name = auth_method.json_name or auth_method.__class__.__name__
            result.issuer = auth_method
            result.issuer_name = json_name
            if result.code != APIAccessStatusCode.API_ACCESS_GRANTED:
                self.auth_errors[json_name] = result.msg
            if result.code == APIAccessStatusCode.API_ACCESS_DENIED \
                    and self.auth_fail_on_deny:
                if self.gui_view:
                    raise PermissionDenied()
                else:
                    return False
            if result.code == APIAccessStatusCode.API_ACCESS_GRANTED:
                self.auth_result = result
                return True
        return False

    def pre_call_log(self, request, kwargs):
        # debug log: pre-call entry
        debug_msg = (
            'API endpoint %(endp)s called with %(meth)s and '
            'params %(kwargs)s'
        ) % {
            'endp': self.endpoint_name, 'kwargs': kwargs,
            'meth': request.method
        }
        self.log(logging.DEBUG, msg=debug_msg)

    def post_call_log(self, response):
        # info log: post-call response
        log_msg = (
            'API response from endpoint %(endp)s: '
            'status %(status)d'
        ) % {
            'status': response.status_code,
            'endp': self.endpoint_name,
        }
        self.log(logging.INFO, msg=log_msg)

    def extract_handler_kwargs(self, request):
        """
        Attempt to extract kwargs from a request to pass to an API endpoint.
        The philosophy is that URL kwargs should never be handled by individual
        endpoints, but handled uniformly for every endpoint in a given API.
        One way to accomplish this is by overriding dispatch(...) in an abstract
        subclass of APIEndpoint (see e.g. TicketingAPIEndpoint).
        URL kwargs will therefore never reach the endpoints, and all data
        to be consumed by an API endpoint should be included in the request body.
        This helps keeping the endpoint URLs clean and consistent.
        """
        # TODO: handle dataclasses, List args, etc. recursively

        if request.method.lower() in self.http_method_names:
            handler = getattr(
                self, request.method.lower(), self.http_method_not_allowed
            )
        else:
            handler = self.http_method_not_allowed

        endpoint_signature = inspect.signature(handler)
        endpoint_kwargs = {
            param_name: p
            for param_name, p in endpoint_signature.parameters.items()
            if p.kind == inspect.Parameter.KEYWORD_ONLY
        }

        def param_list():
            for name, param_obj in endpoint_kwargs.items():
                argument_type = param_obj.annotation
                raw_value = _get_raw_param(request, name)
                if raw_value is not None:
                    if argument_type is not inspect.Parameter.empty:
                        if argument_type is datetime.datetime:
                            ts = datetime.datetime.fromisoformat(
                                str(raw_value)
                            )
                            if ts.tzinfo is None:
                                # naive datetime - treat as UTC
                                ts = pytz.utc.localize(ts)
                            else:
                                # replace timezone by UTC
                                ts = ts.astimezone(pytz.utc)
                            yield name, ts
                        elif isinstance(argument_type, type) and \
                                issubclass(argument_type, decimal.Decimal):
                            dec_val = (
                                argument_type(raw_value)
                                if raw_value else argument_type()
                            )
                            yield name, dec_val
                        else:
                            yield name, argument_type(raw_value)
                    else:
                        yield name, raw_value

        try:
            kwargs_to_pass = dict(param_list())
            for param, parobj in endpoint_kwargs.items():
                has_default = parobj.default is not inspect.Parameter.empty
                if not param in kwargs_to_pass and not has_default:
                    raise APIError(
                        gettext_noop("The parameter '%s' is required"), param
                    )
        except APIError:
            raise
        except (ValueError, TypeError):
            self.log(
                logging.INFO, 'Error processing request params', exc_info=1,
            )
            raise APIError(gettext_noop('Could not parse arguments'))

        return handler, kwargs_to_pass

    def log(self, level, msg, **kwargs):
        self.api.log(
            level, msg=msg, endpoint=self,
            term_uid=self.auth_result.term_uid,
            term_display_name=self.auth_result.term_display_name,
            auth_basis=self.auth_result.issuer_name, **kwargs
        )

    def dispatch(self, request, *args, **kwargs):
        # parse JSON and populate the request._json_data parameter
        # so that auth workflow can already access it
        _attempt_parse_json(request, self.api._logger)
        if not self.auth(request, *args, **kwargs):
            return JsonResponse(
                {'auth_error_info': self.auth_errors}, status=403
            )

        try:
            # attempt to set language, with the user's
            # language as the default whenever available
            lang = _get_raw_param(request, 'lang')
            if not lang and request.user.is_authenticated:
                lang = request.user.lang
            translation.activate(lang or settings.LANGUAGE_CODE)
            handler, kwargs_to_pass = self.extract_handler_kwargs(request)
            self.pre_call_log(request, kwargs_to_pass)
            if self.auth_result.issuer.csrf_exempt:
                response = handler(request, *args, **kwargs_to_pass)
            else:
                response = csrf_protect(handler)(
                    request, *args, **kwargs_to_pass
                )
            return response
        except APIError as e:
            self.log(
                logging.INFO,
                msg='API error response: %(msg)s, status %(status)d' % {
                    'msg': e.raw_message, 'status': e.status
                },
            )
            if self.gui_view:
                # GUI views should handle error conditions
                # themselves. Failing to do so => an automatic 500
                #  (details will appear in the logs anyway)
                return render(request, '500.html', status=500)
            else:
                return JsonResponse(
                    {API_ERROR_FIELD: str(e)}, status=e.status
                )
        except Exception as e:
            self.log(
                logging.CRITICAL, 'Server error during API call: %s' % str(e),
                exc_info=1
            )
            if self.gui_view:
                return render(request, '500.html', status=500)
            else:
                return SERVER_ERROR_RESPONSE

    @classmethod
    def url(cls, *args, **kwargs) -> str:
        endpoint_url_name = cls.api.endpoint_url_name(cls.endpoint_name)
        return reverse(endpoint_url_name, args=args, kwargs=kwargs)
