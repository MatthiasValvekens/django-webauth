import json
from datetime import datetime

import pytz
from django.contrib.auth.models import Permission
from django.test import TestCase
from webauth import models as webauth_models
from . import views as test_views
from . import models


class DummyAuthTest(TestCase):

    def testDummyAuth(self):
        response = self.client.get(
            test_views.DummyAPIEndpoint.url(), data={
                'blah': 'hi there'
            }, content_type='application/json'
        )
        payload = json.loads(response.content)
        self.assertTrue(payload['blah'] == 'hi there')

# noinspection DuplicatedCode
class CustomerTestingAPI(TestCase):
    fixtures = ['users.json']

    # TODO: further API token tests (expiry/malformed/...)

    @classmethod
    def setUpTestData(cls):
        perm = Permission.objects.get(codename='change_customer')
        u = webauth_models.User.objects.get(pk=1)
        u.user_permissions.add(perm)
        cls.api_token = test_views.TestAPITokenGenerator(
            uid='testtesttesttesttest',
            display_name='test', lifespan=0
        ).make_base64_token()[0]
        cls.endpoint = test_views.CustomerEndpoint.url()

    def test_create_customer(self):
        email = 'aaaaaaaaa@example.com'
        response = self.client.post(
            self.endpoint, data={
                'api_token': self.api_token,
                'name': 'Test', 'email': email
            }, content_type='application/json'
        )
        self.assertEquals(response.status_code, 201)
        self.assertTrue(models.Customer.objects.filter(email=email).exists())

    def test_create_customer_put(self):
        email = 'aaaaaaaaa@example.com'
        response = self.client.post(
            self.endpoint, data={
                'api_token': self.api_token,
                'name': 'Test', 'email': email
            }, content_type='application/json'
        )
        self.assertEquals(response.status_code, 201)
        self.assertTrue(models.Customer.objects.filter(email=email).exists())
        response = self.client.put(
            self.endpoint, data={
                'api_token': self.api_token,
                'name': 'Twest', 'email': email
            }, content_type='application/json'
        )
        self.assertEquals(response.status_code, 200)

    def test_trigger_error(self):
        email = 'aaaaaaaaa@example.com'
        response = self.client.post(
            self.endpoint, data={
                'api_token': self.api_token,
                'name': 'Test', 'email': email, 'error': True
            }, content_type='application/json'
        )
        self.assertEquals(response.status_code, 400)

    def test_wrong_api_token(self):
        response = self.client.get(
            self.endpoint, data={'api_token': 'nonsense'}
        )
        self.assertEquals(response.status_code, 403)

    def test_user_auth_get(self):
        self.client.login(username='john.doe@example.com', password='password')
        response = self.client.get(self.endpoint, data={})
        self.assertEquals(response.status_code, 200)

    def test_user_auth_forbidden(self):
        self.client.login(username='jane.smith@example.com', password='letmein')
        response = self.client.get(self.endpoint, data={})
        self.assertEquals(response.status_code, 403)

    def test_unauth_user_plus_token(self):
        self.client.login(username='jane.smith@example.com', password='letmein')
        response = self.client.get(
            self.endpoint, data={'api_token': self.api_token}
        )
        self.assertEquals(response.status_code, 200)

    def test_noauth(self):
        response = self.client.get(self.endpoint, data={})
        self.assertEquals(response.status_code, 403)

    def test_nonexistent_param(self):
        # should be ignored
        response = self.client.get(
            self.endpoint, data={
                'blaha': True, 'api_token': self.api_token
            }
        )
        self.assertEquals(response.status_code, 200)

    def test_datetime_param(self):
        dt = datetime(2019, 10, 10, 2, 1, 1).astimezone(pytz.utc)
        response = self.client.get(
            self.endpoint, data={
                'date_param': dt.isoformat(), 'api_token': self.api_token
            }
        )
        response_payload = json.loads(response.content)
        self.assertEqual(
            response_payload['date'], dt.isoformat()
        )
