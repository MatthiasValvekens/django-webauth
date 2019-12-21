import pytz
import datetime
from django.test import TestCase
from django.urls import reverse
# This is in test-requirements.txt, but PyCharm doesn't know that
# noinspection PyPackageRequirements
from testfixtures import Replace, test_datetime
from webauth import tokens, models as webauth_models
from . import views as test_views
from . import models


token_datetime = 'webauth.tokens.datetime.datetime'

class SimpleTBTGenerator(tokens.TimeBasedTokenGenerator):
    EXAMPLE_TOKEN = '12-3iyp-dcb63c6bc16c93c2b130'
    lifespan = 12

class FakeSimpleTBTGenerator(SimpleTBTGenerator):
    pass

class ExtraTBTGenerator(SimpleTBTGenerator):
    def __init__(self, stuff: int):
        self.stuff = stuff
        super().__init__()

    def extra_hash_data(self):
        return str(self.stuff)

simple_validator = SimpleTBTGenerator.validator()

MALFORMED_RESPONSE = (
    tokens.TimeBasedTokenValidator.MALFORMED_TOKEN, None
)


# noinspection DuplicatedCode
class BasicTokenTest(TestCase):

    def test_token(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok = SimpleTBTGenerator().bare_token()
            self.assertEqual(tok, SimpleTBTGenerator.EXAMPLE_TOKEN)

    
    def test_expiry_base(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok, (valid_from, valid_until) = SimpleTBTGenerator().make_token()
            self.assertEqual(
                valid_from, 
                datetime.datetime(2019,10,10,1,0,0, tzinfo=pytz.utc)
            )
            self.assertEqual(
                valid_until, 
                datetime.datetime(2019,10,10,13,0,0, tzinfo=pytz.utc)
            )
            d.set(2019,10,10,0,59,59)
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(simple_validator.validate_token(tok))
            d.set(2019,10,10,13,0,1)
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,13,0,0)
            self.assertTrue(simple_validator.validate_token(tok))
    
    def test_validity_from(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,0,59,59)
            tok = SimpleTBTGenerator.EXAMPLE_TOKEN
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(simple_validator.validate_token(tok))

    def test_validity_until(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,13,0,1)
            tok = SimpleTBTGenerator.EXAMPLE_TOKEN
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,13,0,0)
            self.assertTrue(simple_validator.validate_token(tok))

    def test_malformed_none(self):
        # noinspection PyTypeChecker
        self.assertEqual(
            simple_validator.parse_token(None), MALFORMED_RESPONSE
        )

    def test_malformed_part_count(self):
        # too many sections
        self.assertEqual(
            simple_validator.parse_token('12-3iyp-dcb63c6bc16c93c2b130-zzz'),
            MALFORMED_RESPONSE
        )
        self.assertEqual(
            simple_validator.parse_token('3iyp-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_malformed_huge_lifespan(self):
        # too many sections
        self.assertEqual(
            simple_validator.parse_token('2193891283912839218391823-3iyp-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )
        gen = SimpleTBTGenerator()
        gen.lifespan = 2193891283912839218391823
        with self.assertRaises(ValueError):
            gen.make_token()

    def test_malformed_bad_lifespan(self):
        self.assertEqual(
            simple_validator.parse_token('XX-3iyp-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_malformed_date(self):
        # malformed date part
        self.assertEqual(
            simple_validator.parse_token('12-3***-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_malformed_hash(self):
        # bad hash
        self.assertEqual(
            simple_validator.parse_token('12-3iyp-dcb63c6bc16c93c2aaaa'),
            MALFORMED_RESPONSE
        )
        

    def test_lifespan_zero(self): 
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            gen = SimpleTBTGenerator()
            gen.lifespan = 0
            tok, (valid_from, valid_until) = gen.make_token()
            self.assertEqual(valid_until, None)
            self.assertTrue(tok.startswith('0-'))
            d.set(2019,10,10,0,59,59)
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(simple_validator.validate_token(tok))
            d.set(2019,10,10,13,0,0)
            self.assertTrue(simple_validator.validate_token(tok))
            d.set(2019,10,10,17,0,0)
            self.assertTrue(simple_validator.validate_token(tok))

    def test_lifespan_custom(self): 
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            gen = SimpleTBTGenerator()
            gen.lifespan = 20
            tok, (valid_from, valid_until) = gen.make_token()
            self.assertEqual(
                valid_until, 
                datetime.datetime(2019,10,10,21,0,0,tzinfo=pytz.utc)
            )
            self.assertTrue(tok.startswith('20-'))
            d.set(2019,10,10,0,59,59)
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(simple_validator.validate_token(tok))
            d.set(2019,10,10,21,0,1)
            self.assertEqual(
                simple_validator.parse_token(tok)[0],
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,21,0,0)
            self.assertTrue(simple_validator.validate_token(tok))

    def test_valid_from_custom(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            gen = SimpleTBTGenerator()
            gen.lifespan = 2
            gen.valid_from = datetime.datetime(
                2019, 12, 10, 1, 1, 1, tzinfo=pytz.utc
            )
            val = gen.validator()
            tok = gen.bare_token()
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,12,10,0,59,59)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,12,10,1,0,0)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,12,10,1,1,1)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,12,10,3,0,0)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,12,10,3,0,1)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )

    
    def test_negative_lifespan(self): 
        gen = SimpleTBTGenerator()
        gen.lifespan = -100
        with self.assertRaises(ValueError):
            gen.make_token()

    def test_time_before_origin(self): 
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(1919,10,10,1,1,1)
            gen = SimpleTBTGenerator()
            with self.assertRaises(ValueError):
                gen.make_token()

            d.set(2019,10,10,1,1,1)
            gen.valid_from = datetime.datetime(
                1919,10,10,1,1,1, tzinfo=pytz.utc
            )
            with self.assertRaises(ValueError):
                gen.make_token()
    
    def test_naive_valid_from(self):
        gen = SimpleTBTGenerator()
        gen.valid_from = datetime.datetime(1919,10,10,1,1,1)
        with self.assertRaises(TypeError):
            gen.make_token()
        
    def test_class_salt(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            fake_gen = FakeSimpleTBTGenerator()
            fake_tok = fake_gen.bare_token()
            gen = SimpleTBTGenerator()
            real_tok = gen.bare_token()
            self.assertEqual(real_tok, gen.EXAMPLE_TOKEN)
            self.assertNotEqual(fake_tok, real_tok)
            self.assertTrue(fake_gen.validator().validate_token(fake_tok))
            self.assertFalse(gen.validator().validate_token(fake_tok))

    def test_extra_hash_data(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            gen = ExtraTBTGenerator(stuff=4)
            tok1 = gen.bare_token()
            gen.stuff = 5
            d.set(2019,10,10,1,1,1)
            tok2 = gen.bare_token()
            self.assertNotEqual(tok1, tok2)
            evaluator = gen.validator(
                generator_kwargs={'stuff': 5}
            )
            self.assertTrue(evaluator.validate_token(tok2))
            self.assertFalse(
                evaluator.validate_token(tok1)
            )


# noinspection DuplicatedCode
class TestRequestTokens(TestCase):

    def test_filter_kwargs(self):
        gen_cls = test_views.SimpleTBUrlTokenGenerator
        view_kwargs = {'stuff': 5, 'irrelevant': 1239}
        gen_kwargs = gen_cls.get_constructor_kwargs(
            request=None, view_kwargs=dict(view_kwargs)
        )
        self.assertFalse('irrelevant' in gen_kwargs)
        gen = gen_cls(**gen_kwargs)
        self.assertEquals(gen.stuff, 5)

        val = gen_cls.validator(request=None)
        val.view_kwargs = dict(view_kwargs)
        gen = val.instantiate_generator()
        self.assertEquals(gen.stuff, 5)

    def test_simple_view(self):
        tok = test_views.SimpleTBUrlTokenGenerator(stuff=5).bare_token()
        url = reverse('simple_view', kwargs={'stuff': 5, 'token': tok})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'5')

    def test_simple_view_no_token(self):
        url = reverse('simple_view_notoken', kwargs={'stuff': 5})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'Invalid token')

    def test_simple_view_wrong_token(self):
        tok = SimpleTBTGenerator().bare_token()
        url = reverse('simple_view', kwargs={'stuff': 5, 'token': tok})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'Invalid token')

    def test_simple_view_expired_token(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            gen = test_views.SimpleTBUrlTokenGenerator(stuff=5)
            gen.lifespan = 3
            tok = gen.bare_token()
            url = reverse('simple_view', kwargs={'stuff': 5, 'token': tok})

            d.set(2019,10,10,2,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'5')

            d.set(2019,10,10,4,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'5')

            d.set(2019,10,10,4,0,1)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 410)
            self.assertTrue(b'expired' in response.content)

            d.set(2019,10,10,0,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 404)
            self.assertTrue(b'only valid from' in response.content)

    def test_simple_view_with_more_args(self):
        tok = test_views.SimpleTBUrlTokenGenerator(stuff=5).bare_token()
        url = reverse(
            'simple_view_with_more_args', kwargs={
                'stuff': 5, 'token': tok,
                'foo': 'abcd', 'bar': 'baz'
            }
        )
        response = self.client.get(url)
        self.assertEqual(response.content, b'5abcd')

    def test_simple_cbv(self):
        tok = test_views.SimpleTBUrlTokenGenerator(stuff=5).bare_token()
        url = reverse(
            'simple_cbv', kwargs={
                'stuff': 5, 'token': tok, 'foo': 'abcd', 'bar': 'baz'
            }
        )
        response = self.client.get(url)
        self.assertEqual(response.content, b'5abcd')

    def test_simple_cbv_expired_token(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            gen = test_views.SimpleTBUrlTokenGenerator(stuff=5)
            gen.lifespan = 3
            tok = gen.bare_token()
            url = reverse(
                'simple_cbv', kwargs={
                    'stuff': 5, 'token': tok, 'foo': 'abcd', 'bar': 'baz'
                }
            )

            d.set(2019,10,10,2,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'5abcd')

            d.set(2019,10,10,4,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'5abcd')

            d.set(2019,10,10,4,0,1)
            response = self.client.get(url)
            self.assertContains(response, 'expired', status_code=410)

            d.set(2019,10,10,0,0,0)
            response = self.client.get(url)
            self.assertContains(response, 'only valid from', status_code=404)

# noinspection DuplicatedCode
class TestDBDrivenTokens(TestCase):

    @classmethod
    def setUpTestData(cls):
        models.Customer(
            pk=1, name='Foo Bar', email='a@b.com',
            hidden_token=bytes.fromhex('deadbeefcafebabe')
        ).save()
        models.Customer(
            pk=2, name='Baz Quux', email='boss@example.com',
            hidden_token=bytes.fromhex('cafebabedeadbeef')
        ).save()

    def test_object_based_token(self):
        url1 = reverse(
            'objtok_email', kwargs={
                'pk': 1, 'token': 'a@b.com'
            }
        )
        url2 = reverse(
            'objtok_hidden', kwargs={
                'pk': 1, 'token': 'deadbeefcafebabe'
            }
        )

        for url in (url1, url2):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.content, b'Foo Bar')

    def test_object_based_token_mismatch(self):
        url1 = reverse(
            'objtok_email', kwargs={
                'pk': 2, 'token': 'a@b.com'
            }
        )
        url2 = reverse(
            'objtok_hidden', kwargs={
                'pk': 2, 'token': 'deadbeefcafebabe'
            }
        )

        for url in (url1, url2):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.content, b'Invalid token')

    def test_object_based_token_notfound(self):
        url1 = reverse(
            'objtok_email', kwargs={
                'pk': 100, 'token': 'a@b.com'
            }
        )
        url2 = reverse(
            'objtok_hidden', kwargs={
                'pk': 100, 'token': 'deadbeefcafebabe'
            }
        )

        for url in (url1, url2):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertContains(
                    response, 'No customer found matching the query',
                    status_code=404
                )

    def test_timebased_token(self):
        cust = models.Customer.objects.get(pk=1)
        gen = models.CustomerTokenGenerator(customer=cust)
        url = reverse(
            'simple_cust_view', kwargs={
                'pk': cust.pk, 'token': gen.bare_token()
            }
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'1')

    def test_timebased_token_expired(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            cust = models.Customer.objects.get(pk=1)
            gen = models.CustomerTokenGenerator(customer=cust)
            gen.lifespan = 3
            d.set(2019,10,10,1,1,1)
            url = reverse(
                'simple_cust_view', kwargs={
                    'pk': cust.pk, 'token': gen.bare_token()
                }
            )
            d.set(2019,10,10,2,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'1')

            d.set(2019,10,10,4,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'1')

            d.set(2019,10,10,4,0,1)
            response = self.client.get(url)
            self.assertContains(
                response,
                'This is a template stating that your token has expired.',
                status_code=410
            )

            d.set(2019,10,10,0,0,0)
            response = self.client.get(url)
            self.assertContains(
                response,
                "This is a template stating that your token isn't valid yet.",
                status_code=404
            )

    def test_timebased_token_notfound(self):
        cust = models.Customer.objects.get(pk=1)
        tok = models.CustomerTokenGenerator(customer=cust).bare_token()
        url = reverse(
            'simple_cust_view', kwargs={ 'pk': 100, 'token': tok }
        )
        response = self.client.get(url)
        self.assertContains(
            response, 'No customer record found', status_code=404
        )

    def test_timebased_token_mismatch(self):
        cust = models.Customer.objects.get(pk=1)
        tok = models.CustomerTokenGenerator(customer=cust).bare_token()
        url = reverse(
            'simple_cust_view', kwargs={ 'pk': 2, 'token': tok }
        )
        response = self.client.get(url)
        self.assertContains(
            response, 'Invalid', status_code=404
        )

    def test_session_token(self):
        cust = models.Customer.objects.get(pk=1)
        gen = models.CustomerSessionTokenGenerator(request=None, customer=cust)
        tok = gen.bare_token()
        session = self.client.session
        session[gen.session_key] = tok
        session.save()
        url = reverse(
            'simple_cust_session_view', kwargs={ 'pk': 1 }
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'1')

    def test_session_token_mismatch(self):
        cust = models.Customer.objects.get(pk=1)
        gen = models.CustomerSessionTokenGenerator(request=None, customer=cust)
        tok = gen.bare_token()
        session = self.client.session
        session[gen.session_key] = tok
        session.save()
        url = reverse(
            'simple_cust_session_view', kwargs={ 'pk': 2 }
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'Invalid token')

    def test_session_token_notoken(self):
        url = reverse(
            'simple_cust_session_view', kwargs={ 'pk': 2 }
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content, b'Invalid token')

    def test_session_token_expired(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            cust = models.Customer.objects.get(pk=1)
            gen = models.CustomerSessionTokenGenerator(
                request=None, customer=cust
            )
            gen.lifespan = 3
            tok = gen.bare_token()

            session = self.client.session
            session[gen.session_key] = tok
            session.save()

            url = reverse('simple_cust_session_view', kwargs={'pk': 1})
            d.set(2019,10,10,2,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'1')
            d.set(2019,10,10,4,0,0)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, b'1')

            d.set(2019,10,10,4,0,1)
            response = self.client.get(url)
            self.assertContains(response, 'expired', status_code=410)

            d.set(2019,10,10,0,0,0)
            response = self.client.get(url)
            self.assertContains(response, 'only valid from', status_code=404)

    def test_session_token_consumption(self):
        cust = models.Customer.objects.get(pk=1)
        gen = models.CustomerSessionTokenGenerator(request=None, customer=cust)
        tok = gen.bare_token()
        session = self.client.session
        session[gen.session_key] = tok
        session.save()
        url = reverse(
            'simple_cust_session_view', kwargs={ 'pk': 1 }
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'1')
        self.assertTrue(gen.session_key in self.client.session)
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'1')
        self.assertFalse(gen.session_key in self.client.session)

    def test_bad_view(self):
        url = reverse('bad_db_token_view', kwargs={'token': 'quux'})
        with self.assertRaises(TypeError):
            self.client.get(url)

    def test_bad_view_2(self):
        url = reverse('bad_session_token_view')
        with self.assertRaises(AssertionError):
            self.client.get(url)

    def test_bad_enforce_call(self):
        from tests import views
        with self.assertRaises(ValueError):
            views.SimpleTBUrlTokenGenerator.validator.enforce_token('bleh')


class TestSignedSerial(TestCase):

    def test_signed_serial(self):
        tok = models.CustomerSignedSerialGenerator(serial=5).bare_token()
        self.assertTrue(
            models.CustomerSignedSerialGenerator(serial=5).validate_token(tok)
        )

    def test_time_invariance(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok1 = models.CustomerSignedSerialGenerator(serial=5).bare_token()
            d.set(2013,9,7,1,1,1)
            tok2 = models.CustomerSignedSerialGenerator(serial=5).bare_token()
            self.assertEqual(tok1, tok2)

    def test_serial_mismatch(self):
        tok = models.CustomerSignedSerialGenerator(serial=5).bare_token()
        self.assertEqual(
            models.CustomerSignedSerialGenerator(serial=6).parse_token(tok),
            MALFORMED_RESPONSE
        )

    def test_malformed_part_count(self):
        val = models.CustomerSignedSerialGenerator(serial=5)
        self.assertEqual(
            val.parse_token('5-3iyp-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )
        self.assertEqual(
            val.parse_token('dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_malformed_serial(self):
        val = models.CustomerSignedSerialGenerator(serial=5)
        self.assertEqual(
            val.parse_token('***-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_bad_hash(self):
        val = models.CustomerSignedSerialGenerator(serial=5)
        self.assertEqual(
            val.parse_token('5-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )


class TestUserTokens(TestCase):

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