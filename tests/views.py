import datetime
import logging
from django.http import HttpResponse, JsonResponse
from django.views.generic.detail import SingleObjectMixin

from webauth import tokens, decorators, api_utils
from webauth.tokens import SessionTokenValidator
from . import models

class SimpleTBUrlTokenGenerator(tokens.TimeBasedUrlTokenGenerator):

    def __init__(self, *, stuff: int, **kwargs):
        self.stuff = stuff
        super().__init__(**kwargs)

class SimpleUnsafeTBUrlTokenGenerator(SimpleTBUrlTokenGenerator):
    pass_anything = True


@SimpleTBUrlTokenGenerator.validator.enforce_token(pass_token=False)
def simple_view(request, stuff: int):
    return HttpResponse(str(stuff))

@SimpleTBUrlTokenGenerator.validator.enforce_token(pass_token=False, pass_validity_info=True)
def simple_view_with_more_args(request, stuff: int, foo: str, bar: str, validity_info):
    assert validity_info is not None
    return HttpResponse(str(stuff) + str(foo))

SimpleTokenMixin = SimpleTBUrlTokenGenerator.validator.as_mixin(pass_validity_info=True)
class SimpleCBV(SimpleTokenMixin):
    def get(self, request, *args, stuff, foo, validity_info, **kwargs):
        assert validity_info is not None
        return HttpResponse(str(stuff) + str(foo))


CustomerEmailMixin = models.CustomerDbEmailCompareTokenValidator.as_mixin()
class SimpleCustomerCBV(CustomerEmailMixin, SingleObjectMixin):
    queryset = models.Customer.objects.all()

    def get(self, request, *args, **kwargs):
        return HttpResponse(self.get_object().name)



CustomerDbTokenMixin = models.CustomerDbTokenCompareTokenValidator.as_mixin()
class SimpleCustomerCBV2(CustomerDbTokenMixin, SingleObjectMixin):
    queryset = models.Customer.objects.all()

    def get(self, request, *args, **kwargs):
        return HttpResponse(self.get_object().name)

    def put(self, request, *args, **kwargs):
        self.validator.instantiate_generator()
        return HttpResponse('this should error')  # pragma: nocover


class BadDbTokenMixin(CustomerDbTokenMixin):
    pass

@models.CustomerTokenGenerator.validator.enforce_token(pass_token=False)
def simple_customer_view(request, pk):
    return HttpResponse(str(pk))

@models.CustomerSessionTokenGenerator.validator.enforce_token(pass_token=False)
def simple_customer_session_view(request, pk):
    return HttpResponse(str(pk))

CustomerTBDbTokenMixin = models.MixinBasedCustomerTokenGenerator.validator.as_mixin()
class SimpleCustomerCBV3(CustomerTBDbTokenMixin, SingleObjectMixin):
    queryset = models.Customer.objects.all()

    def get(self, request, *args, **kwargs):
        return HttpResponse(self.get_object().name)

class SillySessionTokenValidator(SessionTokenValidator):
    generator_class = models.CustomerTokenGenerator

    def parse_token(self, token):  # pragma: nocover
        pass

@SillySessionTokenValidator.enforce_token(pass_token=False)
def bad_session_view(request):
    pass  # pragma: nocover


@decorators.require_password_confirmation
def is_password_confirmed(request):
    return HttpResponse('confirmed')


@models.CustomerTokenGenerator.validator.enforce_token
def bad_customer_view(request, token):
    return HttpResponse(token)  # pragma: nocover


class TestAPITokenGenerator(api_utils.APITokenGenerator):
    pass


api_logger = logging.getLogger('api_test')


dummy = api_utils.API(
    name='dummy_api', auth_workflow=[api_utils.DummyAuthMechanism()],
    logger=api_logger
)
class DummyAPIEndpoint(api_utils.APIEndpoint):
    api = dummy
    endpoint_name = 'dummy'

    def get(self, request, *, blah: str):
        return JsonResponse({ 'blah': blah})

    def post(self, request, *, blah: str):
        return JsonResponse({ 'blah': blah})

# TODO: figure out how to test x509 stuff properly (docker?)
advanced_auth_map = api_utils.UserAuthMechanism(
    api_utils.UserAuthMap(
        {
            ('customer', 'GET'): api_utils.PermissionSpec.declare(
                api_utils.UserStatus.anonymous
            ),
            # I know view_permission looks bizarre, but I want the strictness
            #  to increase strictly for easy testing purposes
            ('customer', None): {'tests.view_customer'},
            ('customer_shielded', 'GET'): {'tests.view_customer'},
            ('customer_shielded', 'POST'): {'tests.change_customer'},
            ('customer_shielded', 'PUT'): {'tests.change_customer'},
            ('customer_knox', 'GET'): api_utils.PermissionSpec.declare(
                api_utils.UserStatus.staff,
                'tests.view_customer',
            ),
            ('customer_knox', 'POST'): api_utils.PermissionSpec.declare(
                api_utils.UserStatus.otp_verified, 'tests.change_customer',
            ),
            ('customer_knox', 'PUT'): api_utils.PermissionSpec.declare(
                api_utils.UserStatus.otp_verified | api_utils.UserStatus.staff,
                'tests.change_customer'
            ),
        }
    )
)
API_AUTH = [
    api_utils.TokenAuthMechanism(TestAPITokenGenerator), advanced_auth_map
]
testing_api = api_utils.API(
    name='testing_api', auth_workflow=API_AUTH, logger=api_logger
)

class CustomerEndpoint(api_utils.APIEndpoint):
    api = testing_api
    endpoint_name = 'customer'

    def get(self, request, *, customer_id: int=None, date_param: datetime.datetime=None):

        qs = models.Customer.objects.filter( )
        if customer_id is not None:
            qs = qs.filter(pk=customer_id)
        res = { 'names': [ c.name for c in qs ] }
        if date_param is not None:
            res['date'] = date_param.isoformat()
        return JsonResponse(res)

    def post(self, request, *, name:str, email: str, lang: str=None, error=False):
        if error:
            raise api_utils.APIError('This is an error')
        c = models.Customer(name=name, email=email)
        if lang is not None:
            c.lang = lang
        c.save()
        return JsonResponse({}, status=201)

    def put(self, request, *, name:str, email: str, lang: str=None):
        try:
            c = models.Customer.objects.get(email=email)
        except (models.Customer.DoesNotExist, models.Customer.MultipleObjectsReturned) as e:
            raise api_utils.APIError(e)
        c.name = name
        if lang is not None:
            c.lang = lang
        c.save()
        return JsonResponse({}, status=200)

class ShieldedCustomerEndpoint(CustomerEndpoint):
    api = testing_api
    endpoint_name = 'customer_shielded'

class SuperShieldedCustomerEndpoint(CustomerEndpoint):
    api = testing_api
    endpoint_name = 'customer_knox'
