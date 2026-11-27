"""Shared deterministic test helpers."""

import datetime
import hashlib

from pycookiecage import CookieCageError


def derived_test_key(label):
    return hashlib.sha256(b"pycookiecage-test-key-" + label).digest()


STRONG_KEY = derived_test_key(b"one")
STRONG_KEY_2 = derived_test_key(b"two")
STRONG_KEY_3 = derived_test_key(b"three")
WEAK_KEY = b"x"
NOW_MS = 1700000000000
UTC = datetime.timezone.utc


def assert_error_code(testcase, code, func, *args, **kwargs):
    with testcase.assertRaises(CookieCageError) as caught:
        func(*args, **kwargs)
    testcase.assertEqual(code, caught.exception.code)
    return caught.exception


def matrix_method(check):
    def method(self):
        check(self)
    return method
