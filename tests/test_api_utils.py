import json
from datetime import datetime

import pytz
from django.contrib.auth.models import Permission
from django.test import TestCase
from webauth import models as webauth_models
from . import views as test_views
from . import models


class DummyAuthTest(TestCase):

    def setUp(self):
        self.client.handler.enforce_csrf_checks = True

    def test_dummy_auth_get(self):
        response = self.client.get(
            test_views.DummyAPIEndpoint.url(), data={
                'blah': 'hi there'
            }, content_type='application/json'
        )
        payload = json.loads(response.content)
        self.assertTrue(payload['blah'] == 'hi there')

    def test_dummy_auth_post(self):
        response = self.client.post(
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
    def setUp(self):
        self.client.handler.enforce_csrf_checks = True

    @classmethod
    def setUpTestData(cls):
        jd = webauth_models.User.objects.get(email='john.doe@example.com')
        jd_permissions = Permission.objects.filter(
            codename__in={'view_customer', 'change_customer'}
        )
        jd.user_permissions.set(jd_permissions)
        jd.is_staff = True
        jd.save()
        js = webauth_models.User.objects.get(email='jane.smith@example.com')
        js_permission = Permission.objects.get(codename='view_customer')
        js.user_permissions.add(js_permission)
        cls.api_token = test_views.TestAPITokenGenerator(
            uid='testtesttesttesttest',
            display_name='test', lifespan=0
        ).make_base64_token()[0]
        cls.endpoint = test_views.CustomerEndpoint.url()
        cls.endpoint_shielded = test_views.ShieldedCustomerEndpoint.url()
        cls.endpoint_knox = test_views.SuperShieldedCustomerEndpoint.url()
        cls.model_post_request = {
            'api_token': cls.api_token,
            'name': 'Test', 'email': 'aaaaaaaaa@example.com'
        }

    def test_create_customer(self):
        email = 'aaaaaaaaa@example.com'
        response = self.client.post(
            self.endpoint, data=self.model_post_request,
            content_type='application/json'
        )
        self.assertEquals(response.status_code, 201)
        self.assertTrue(models.Customer.objects.filter(email=email).exists())

    def test_create_customer_put(self):
        email = 'aaaaaaaaa@example.com'
        response = self.client.post(
            self.endpoint, data=self.model_post_request,
            content_type='application/json'
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

    def user_auth_tests(self, fail_at, fail_otponly=True):
        self.client.handler.enforce_csrf_checks = False
        response = self.client.get(self.endpoint, data={})
        # this should always succeed
        post_request = {
            'name': 'Test', 'email': 'aaaaaaaaa@example.com'
        }
        put_request = json.dumps(post_request)
        self.assertEquals(response.status_code, 200)
        response = self.client.post(self.endpoint, data=post_request)
        self.assertEquals(response.status_code, 403 if fail_at <= 1 else 201)
        response = self.client.put(self.endpoint, data=put_request)
        self.assertEquals(response.status_code, 403 if fail_at <= 2 else 200)
        models.Customer.objects.filter(email='aaaaaaaaa@example.com').delete()

        response = self.client.get(self.endpoint_shielded, data={})
        self.assertEquals(response.status_code, 403 if fail_at <= 3 else 200)
        response = self.client.post(
            self.endpoint_shielded, data=post_request
        )
        self.assertEquals(response.status_code, 403 if fail_at <= 4 else 201)
        response = self.client.put(
            self.endpoint_shielded, data=put_request
        )
        self.assertEquals(response.status_code, 403 if fail_at <= 5 else 200)
        models.Customer.objects.filter(email='aaaaaaaaa@example.com').delete()

        response = self.client.get(self.endpoint_knox, data={})
        self.assertEquals(response.status_code, 403 if fail_at <= 6 else 200)
        # this one isn't strictly stricter than the previous check, so
        # it's controlled by a different flag
        response = self.client.post(
            self.endpoint_knox, data=post_request
        )
        self.assertEquals(response.status_code, 403 if fail_otponly else 201)
        response = self.client.put(
            self.endpoint_knox, data=put_request
        )
        self.assertEquals(response.status_code, 403 if fail_at <= 7 else 200)
        models.Customer.objects.filter(email='aaaaaaaaa@example.com').delete()

    def test_anonymous(self):
        self.user_auth_tests(1)

    def test_user_auth_viewonly(self):
        self.client.login(username='jane.smith@example.com', password='letmein')
        self.user_auth_tests(4)

    def test_user_auth_privileged(self):
        self.client.login(username='john.doe@example.com', password='password')
        self.user_auth_tests(7)

    # TODO OTP tests

    def test_unauth_user_plus_token(self):
        self.client.login(username='jane.smith@example.com', password='letmein')
        response = self.client.get(
            self.endpoint, data={'api_token': self.api_token}
        )
        self.assertEquals(response.status_code, 200)

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
