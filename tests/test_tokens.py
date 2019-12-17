import pytz
import datetime
from django.test import TestCase
from testfixtures import Replace, test_datetime
from webauth import tokens


token_datetime = 'webauth.tokens.datetime.datetime'

class SimpleTBTGenerator(tokens.TimeBasedTokenGenerator):
    def get_lifespan(self):
        return 12

MALFORMED_RESPONSE = (
    tokens.TimeBasedTokenValidator.MALFORMED_TOKEN, None
)

class BasicTokenTest(TestCase):

    def test_token(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok = SimpleTBTGenerator().bare_token()
            self.assertEqual(tok, '12-3iyp-dcb63c6bc16c93c2b130')

    
    def test_expiry(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok, (valid_from, valid_until) = SimpleTBTGenerator().make_token()
            self.assertEqual(
                valid_from, 
                datetime.datetime(2019,10,10,1,0,0)
            )
            self.assertEqual(
                valid_until, 
                datetime.datetime(2019,10,10,13,0,0)
            )
    
            val = SimpleTBTGenerator.validator()
            d.set(2019,10,10,0,59,59)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.NOT_YET_VALID_TOKEN
            )
            d.set(2019,10,10,1,0,0)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.VALID_TOKEN
            )
            d.set(2019,10,10,13,0,1)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.EXPIRED_TOKEN
            )
            d.set(2019,10,10,13,0,0)
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.VALID_TOKEN
            )

    def test_malformed(self):
        with Replace(token_datetime, test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok, validity_info = SimpleTBTGenerator().make_token()
            val = SimpleTBTGenerator.validator()
            self.assertEqual(
                val.parse_token(None), MALFORMED_RESPONSE
            )
            self.assertEqual(
                val.parse_token(tok)[0], 
                tokens.TimeBasedTokenValidator.VALID_TOKEN
            )
            # too many sections
            self.assertEqual(
                val.parse_token('12-3iyp-dcb63c6bc16c93c2b130-zzz'),
                MALFORMED_RESPONSE
            )
            # bad lifespan string
            self.assertEqual(
                val.parse_token('XX-3iyp-dcb63c6bc16c93c2b130'),
                MALFORMED_RESPONSE
            )
            # malformed date part
            self.assertEqual(
                val.parse_token('12-3AAA-dcb63c6bc16c93c2b130'),
                MALFORMED_RESPONSE
            )
            # bad hash
            self.assertEqual(
                val.parse_token('12-3iyp-dcb63c6bc16c93c2aaaa'),
                MALFORMED_RESPONSE
            )
