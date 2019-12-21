import pytz
import datetime
from django.test import TestCase
from django.urls import reverse
from webauth import tokens, models as webauth_models

# noinspection DuplicatedCode
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
        u = webauth_models.User(
            pk=2, email='jane.smith@example.com', lang='en-gb',
            last_login=datetime.datetime(2014,1,1,1,1,1, tzinfo=pytz.utc),
            is_active=True
        )
        u.set_password('letmein')
        u.save()

    def test_password_confirm(self):
        self.client.login(username='john.doe@example.com', password='password')
        u = webauth_models.User.objects.get(pk=1)
        pwc = tokens.PasswordConfirmationTokenGenerator(user=u)
        session = self.client.session
        session[pwc.session_key] = pwc.bare_token()
        session.save()
        response = self.client.get(reverse('password_confirm_required'))
        self.assertContains(response, 'confirmed')

    def test_password_confirm_from_login_state(self):
        self.client.login(username='john.doe@example.com', password='password')
        url = reverse('password_confirm_required')
        response = self.client.get(url, follow=False)
        self.assertRedirects(
            response, '%s?next=%s' % (reverse('confirm_password'), url)
        )
        response = self.client.post(
            reverse('confirm_password'), data={
                'password': 'password', 'next': url,
                'username': 'john.doe@example.com'
            }, follow=False
        )
        self.assertRedirects(response, url)
        response = self.client.get(url)
        self.assertContains(response, 'confirmed')

    def test_wrong_then_right_password(self):
        self.client.login(username='john.doe@example.com', password='password')
        url = reverse('password_confirm_required')
        response = self.client.post(
            reverse('confirm_password'), data={
                'password': 'wrongpassword', 'next': url,
                'username': 'john.doe@example.com'
            }
        )
        # we should get the same form back
        self.assertContains(response, 'Password confirmation', html=True)
        self.assertContains(response, 'Errors:', html=True)
        # ... and still shouldn't allowed to access the page we want
        response = self.client.get(url, follow=False)
        self.assertRedirects(
            response, '%s?next=%s' % (reverse('confirm_password'), url)
        )
        # let's try again
        response = self.client.post(
            reverse('confirm_password'), data={
                'password': 'password', 'next': url,
                'username': 'john.doe@example.com'
            }, follow=False
        )
        self.assertRedirects(response, url)
        response = self.client.get(url)
        self.assertContains(response, 'confirmed')


    def test_user_mismatch(self):
        self.client.login(username='john.doe@example.com', password='password')
        url = reverse('password_confirm_required')
        response = self.client.post(
            reverse('confirm_password'), data={
                'password': 'letmein', 'next': url,
                'username': 'jane.smith@example.com'
            }
        )
        self.assertEquals(response.status_code, 400)
        response = self.client.get(url, follow=False)
        self.assertRedirects(
            response, '%s?next=%s' % (reverse('confirm_password'), url)
        )

    def test_password_confirm_then_change(self):
        self.client.login(username='john.doe@example.com', password='password')
        u = webauth_models.User.objects.get(pk=1)
        pwc = tokens.PasswordConfirmationTokenGenerator(user=u)
        session = self.client.session
        session[pwc.session_key] = pwc.bare_token()
        session.save()
        url = reverse('password_confirm_required')
        response = self.client.get(url)
        self.assertContains(response, 'confirmed')
        u.set_password('ablalalala')
        u.save()
        # this should invalidate the confirmation token, and log the user out
        #  --> double redirect to a login form
        response = self.client.get(url, follow=False)
        self.assertRedirects(
            response, '%s?next=%s' % (reverse('confirm_password'), url),
            target_status_code=302
        )


    def test_password_confirm_then_login(self):
        self.client.login(username='john.doe@example.com', password='password')
        u = webauth_models.User.objects.get(pk=1)
        pwc = tokens.PasswordConfirmationTokenGenerator(user=u)
        session = self.client.session
        session[pwc.session_key] = pwc.bare_token()
        session.save()
        url = reverse('password_confirm_required')
        response = self.client.get(url)
        self.assertContains(response, 'confirmed')
        self.client.login(username='john.doe@example.com', password='password')
        response = self.client.get(url, follow=False)
        self.assertRedirects(
            response, '%s?next=%s' % (reverse('confirm_password'), url)
        )

