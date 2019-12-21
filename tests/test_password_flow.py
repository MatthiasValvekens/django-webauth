import pytz
import datetime
from django.test import TestCase
from django.urls import reverse
from webauth import tokens, models as webauth_models

class TestPasswordConfirm(TestCase):

    @classmethod
    def setUpTestData(cls):
        u = webauth_models.User(
            pk=1, email='john.doe@example.com', lang='en-gb',
            last_login=datetime.datetime(2010, 1,1,1,1,1, tzinfo=pytz.utc),
            is_active=True
        )
        u.set_password('password')
        u.save()

    def test_password_confirm(self):
        u = webauth_models.User.objects.get(pk=1)
        self.client.login(username=u.email, password='password')
        pwc = tokens.PasswordConfirmationTokenGenerator(user=u)
        u.refresh_from_db()
        session = self.client.session
        session[pwc.session_key] = pwc.bare_token()
        session.save()
        response = self.client.get(reverse('password_confirm_required'))
        self.assertContains(response, 'confirmed', status_code=200)
