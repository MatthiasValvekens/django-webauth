from django.test import TestCase
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from webauth import tokens, models as webauth_models

# noinspection DuplicatedCode
class TestPasswordConfirm(TestCase):
    fixtures = ['users.json']

    # TODO: test expiry

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


# TODO: test full workflow, expiry, etc.
class TestPasswordReset(TestCase):
    fixtures = ['users.json']

    def test_reset_password(self):
        u = webauth_models.User.objects.get(pk=1)
        uid = urlsafe_base64_encode(force_bytes(u.pk))
        tok = tokens.PasswordResetTokenGenerator(u).bare_token()
        reset_url = reverse(
            'password_reset_confirm', kwargs={
                'uidb64': uid, 'token': tok
            }
        )
        # django does this in two steps
        response = self.client.get(reset_url)
        reset_intl_url = reverse(
            'password_reset_confirm', kwargs={
                'uidb64': uid, 'token': 'set-password'
            }
        )
        self.assertRedirects(
            response, reset_intl_url, fetch_redirect_response=False
        )
        response = self.client.post(
            reset_intl_url, data = {
                'new_password1': 'letmein', 'new_password2': 'letmein',
            }
        )
        self.assertRedirects(
            response, reverse('password_reset_complete'),
            fetch_redirect_response=False
        )
