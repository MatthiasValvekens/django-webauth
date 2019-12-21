import pytz
from contextlib import contextmanager
# This is in test-requirements.txt, but PyCharm doesn't know that
# noinspection PyPackageRequirements
from testfixtures import Replace, test_datetime
from django.test import TestCase

token_datetime = 'webauth.tokens.datetime'

def utc_dateseq(d):
    d.set(2019, 10, 10, 1, 1, 1)
    yield
    d.set(2019, 10, 10, 2, 0, 0)
    yield
    d.set(2019, 10, 10, 4, 0, 0)
    yield
    d.set(2019, 10, 10, 4, 0, 1)
    yield
    d.set(2019, 10, 10, 0, 0, 0)
    yield

def cest_dateseq(d):
    d.set(2019, 10, 10, 3, 1, 1)
    yield
    d.set(2019, 10, 10, 4, 0, 0)
    yield
    d.set(2019, 10, 10, 6, 0, 0)
    yield
    d.set(2019, 10, 10, 6, 0, 1)
    yield
    d.set(2019, 10, 10, 2, 0, 0)
    yield

def jst_dateseq(d):
    d.set(2019, 10, 10, 10, 1, 1)
    yield
    d.set(2019, 10, 10, 11, 0, 0)
    yield
    d.set(2019, 10, 10, 13, 0, 0)
    yield
    d.set(2019, 10, 10, 13, 0, 1)
    yield
    d.set(2019, 10, 10, 9, 0, 0)
    yield

def edt_dateseq(d):
    d.set(2019, 10, 9, 21, 1, 1)
    yield
    d.set(2019, 10, 9, 22, 0, 0)
    yield
    d.set(2019, 10, 10, 0, 0, 0)
    yield
    d.set(2019, 10, 10, 0, 0, 1)
    yield
    d.set(2019, 10, 9, 20, 0, 0)
    yield

@contextmanager
def dateseq_test(testcase: TestCase, timezone, seq_factory, strict):
    mocked_dt = Replace(token_datetime, test_datetime(tzinfo=timezone, strict=strict, delta=0))
    with mocked_dt as d, testcase.subTest(tz=timezone):
        yield seq_factory(d)

# cross-timezone testing: generate first date in timezone A,
#  and then switch to timezone B for consistency checks
@contextmanager
def cross_timezone(testcase: TestCase, gen_timezone, gen_seq_factory,
                   poll_timezone, poll_seq_factory, strict):
    mocked_gen_dt = Replace(token_datetime, test_datetime(tzinfo=gen_timezone, strict=strict, delta=0))
    mocked_poll_dt = Replace(token_datetime, test_datetime(tzinfo=poll_timezone, strict=strict, delta=0))
    def mixed_seq():
        with mocked_gen_dt as d:
            next(gen_seq_factory(d))
            yield
        with mocked_poll_dt as d:
            poll_seq = poll_seq_factory(d)
            next(poll_seq)  # skip first entry
            yield from poll_seq

    with testcase.subTest(tz1=gen_timezone, tz2=poll_timezone):
        yield mixed_seq()


def timezone_seqs(testcase: TestCase, strict=False):
    utc = pytz.utc
    cest = pytz.timezone('Europe/Brussels')
    jst = pytz.timezone('Asia/Tokyo')
    edt = pytz.timezone('America/New_York')
    return [
        dateseq_test(testcase, utc, utc_dateseq, strict=strict),
        dateseq_test(testcase, cest, cest_dateseq, strict=strict),
        dateseq_test(testcase, jst, jst_dateseq, strict=strict),
        dateseq_test(testcase, edt, edt_dateseq, strict=strict),
        cross_timezone(testcase, cest, cest_dateseq, utc, utc_dateseq, strict=strict),
        cross_timezone(testcase, cest, cest_dateseq, jst, jst_dateseq, strict=strict),
        cross_timezone(testcase, cest, cest_dateseq, edt, edt_dateseq, strict=strict),
    ]
