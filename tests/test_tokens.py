import pytz
import datetime
from django.test import TestCase
from testfixtures import Replace, test_datetime
from webauth import tokens


token_datetime = 'webauth.tokens.datetime.datetime'

class SimpleTBTGenerator(tokens.TimeBasedTokenGenerator):
    EXAMPLE_TOKEN = '12-3iyp-dcb63c6bc16c93c2b130'
    lifespan = 12

val = SimpleTBTGenerator.validator()

MALFORMED_RESPONSE = (
    tokens.TimeBasedTokenValidator.MALFORMED_TOKEN, None
)

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
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,10,10,13,0,1)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,13,0,0)
            self.assertTrue(val.validate_token(tok))
    
    def test_validity_from(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,0,59,59)
            tok = SimpleTBTGenerator.EXAMPLE_TOKEN
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(val.validate_token(tok))

    def test_validity_until(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,13,0,1)
            tok = SimpleTBTGenerator.EXAMPLE_TOKEN
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,13,0,0)
            self.assertTrue(val.validate_token(tok))

    def test_malformed_none(self):
        self.assertEqual(
            val.parse_token(None), MALFORMED_RESPONSE
        )

    def test_malformed_too_many_parts(self):
        # too many sections
        self.assertEqual(
            val.parse_token('12-3iyp-dcb63c6bc16c93c2b130-zzz'),
            MALFORMED_RESPONSE
        )

    def test_malformed_bad_lifespan(self):
        self.assertEqual(
            val.parse_token('XX-3iyp-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_malformed_date(self):
        # malformed date part
        self.assertEqual(
            val.parse_token('12-3AAA-dcb63c6bc16c93c2b130'),
            MALFORMED_RESPONSE
        )

    def test_malformed_hash(self):
        # bad hash
        self.assertEqual(
            val.parse_token('12-3iyp-dcb63c6bc16c93c2aaaa'),
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
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,10,10,13,0,0)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,10,10,17,0,0)
            self.assertTrue(val.validate_token(tok))

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
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertTrue(val.validate_token(tok))
            d.set(2019,10,10,21,0,1)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,21,0,0)
            self.assertTrue(val.validate_token(tok))
