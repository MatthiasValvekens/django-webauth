from django.http import HttpResponse
from django.views.generic.detail import SingleObjectMixin

from webauth import tokens
from . import models

class SimpleTBUrlTokenGenerator(tokens.TimeBasedUrlTokenGenerator):

    def __init__(self, *, stuff: int, **kwargs):
        self.stuff = stuff
        super().__init__(**kwargs)


@SimpleTBUrlTokenGenerator.validator.enforce_token(pass_token=False)
def simple_view(request, stuff: int):
    return HttpResponse(str(stuff))

@SimpleTBUrlTokenGenerator.validator.enforce_token(pass_token=False)
def simple_view_with_more_args(request, stuff: int, foo: str, bar: str):
    return HttpResponse(str(stuff) + str(foo))

SimpleTokenMixin = SimpleTBUrlTokenGenerator.validator.as_mixin()
class SimpleCBV(SimpleTokenMixin):
    def get(self, request, *args, stuff, foo, bar, **kwargs): 
        return HttpResponse(str(stuff) + str(foo))

CustomerEmailMixin = models.CustomerDbEmailCompareTokenValidator.as_mixin()
class SimpleCustomerCBV(CustomerEmailMixin, SingleObjectMixin):
    queryset = models.Customer.objects.all()

    def get(self, request, *args, **kwargs):
        return HttpResponse(self.get_object().name)



CustomerEmailMixin = models.CustomerDbTokenCompareTokenValidator.as_mixin()
class SimpleCustomerCBV2(CustomerEmailMixin, SingleObjectMixin):
    queryset = models.Customer.objects.all()

    def get(self, request, *args, **kwargs):
        return HttpResponse(self.get_object().name)


@models.CustomerTokenGenerator.validator.enforce_token(pass_token=False)
def simple_customer_view(request, pk):
    return HttpResponse(str(pk))

@models.CustomerSessionTokenGenerator.validator.enforce_token(pass_token=False)
def simple_customer_session_view(request, pk):
    return HttpResponse(str(pk))
