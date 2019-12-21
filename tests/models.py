from django.db import models
from django.http import Http404

from webauth import fields as webauth_fields
from webauth.tokens import (
    ObjectDBUrlTokenValidator, TimeBasedUrlTokenGenerator,
    TimeBasedUrlTokenValidator,
    TimeBasedSessionTokenGenerator, SignedSerialTokenGenerator
)


class Customer(models.Model):

    name = models.CharField(
        max_length=100,
    )

    email = webauth_fields.EmailField(
        max_length=100,
    )

    hidden_token = models.BinaryField(
        max_length=8,
        editable=False,
    )

class CustomerTokenValidator(TimeBasedUrlTokenValidator):
    gone_template_name = 'expired.html'
    early_template_name = 'early.html'


class CustomerTokenGenerator(TimeBasedUrlTokenGenerator,
                             validator_base=CustomerTokenValidator):

    def __init__(self, customer, **kwargs):
        assert issubclass(self.validator, CustomerTokenValidator)
        self.customer = customer
        super().__init__(**kwargs)

    def extra_hash_data(self):
        return str(self.customer.pk) + self.customer.hidden_token.hex()

    @classmethod
    def get_constructor_kwargs(cls, request, *, view_kwargs, view_instance=None):
        notfound = Http404('No customer record found.')
        try:
            customer = Customer.objects.get(pk=view_kwargs['pk'])
            return {'customer': customer}
        except Customer.DoesNotExist:
            raise notfound


class CustomerSessionTokenGenerator(TimeBasedSessionTokenGenerator):
    session_key = 'customer_session_token'

    def __init__(self, customer, **kwargs):
        self.customer = customer
        super().__init__(**kwargs)

    def extra_hash_data(self):
        return str(self.customer.pk) + self.customer.hidden_token.hex()

    @classmethod
    def get_constructor_kwargs(cls, request, *, view_kwargs, view_instance=None):
        kwargs = super().get_constructor_kwargs(
            request, view_kwargs=view_kwargs, view_instance=None
        )
        notfound = Http404('No customer record found.')
        try:
             kwargs['customer'] = Customer.objects.get(pk=view_kwargs['pk'])
             return kwargs
        except Customer.DoesNotExist:
            raise notfound


class CustomerDbEmailCompareTokenValidator(ObjectDBUrlTokenValidator):
    token_attribute_name = 'email'
    is_binary_field = False

class CustomerDbTokenCompareTokenValidator(ObjectDBUrlTokenValidator):
    token_attribute_name = 'hidden_token'
    is_binary_field = True


class CustomerSignedSerialGenerator(SignedSerialTokenGenerator):
    pass
