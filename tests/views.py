from django.http import HttpResponse
from django.views.generic.detail import SingleObjectMixin

from webauth import tokens, decorators
from webauth.tokens import SessionTokenValidator
from . import models

class SimpleTBUrlTokenGenerator(tokens.TimeBasedUrlTokenGenerator):

    def __init__(self, *, stuff: int, **kwargs):
        self.stuff = stuff
        super().__init__(**kwargs)


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


class BadDbTokenMixin(CustomerDbTokenMixin):
    pass

@models.CustomerTokenGenerator.validator.enforce_token(pass_token=False)
def simple_customer_view(request, pk):
    return HttpResponse(str(pk))

@models.CustomerSessionTokenGenerator.validator.enforce_token(pass_token=False)
def simple_customer_session_view(request, pk):
    return HttpResponse(str(pk))


class SillySessionTokenValidator(SessionTokenValidator):
    generator_class = models.CustomerTokenGenerator

    def parse_token(self, token):  # pragma: nocover
        pass

@SillySessionTokenValidator.enforce_token(pass_token=False)
def bad_session_view(request):
    pass


@decorators.require_password_confirmation
def is_password_confirmed(request):
    return HttpResponse('confirmed')
