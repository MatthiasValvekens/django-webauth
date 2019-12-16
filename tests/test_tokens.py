from django.test import TestCase
from testfixtures import Replace, test_datetime
from webauth import tokens


class SimpleTBTGenerator(tokens.TimeBasedTokenGenerator):
    pass

class BasicTokenTest(TestCase):

    def test_token(self):
        with Replace('datetime.datetime', test_datetime(None)) as d:
            d.set(2019,10,10,1,1,1)
            tok = SimpleTBTGenerator().bare_token()
            self.assertEqual(tok, '0-3iyp-bca579d94a3a0acd48d0')
