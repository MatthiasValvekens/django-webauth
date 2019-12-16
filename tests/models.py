from django.db import models
from webauth import fields as webauth_fields
from webauth.tokens import TimeBasedTokenGenerator

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

class CustomerTokenGenerator(TimeBasedTokenGenerator):
    def __init__(self, customer, **kwargs):
        self.customer = customer
        super().__init__(**kwargs)

    def extra_hash_data(self):
        return str(self.customer.pk) + self.customer.hidden_token.hex()
