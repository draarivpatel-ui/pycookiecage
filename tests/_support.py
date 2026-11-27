"""Shared deterministic test helpers."""

import datetime

from pycookiecage import CookieCageError

STRONG_KEY = bytes(range(32))
STRONG_KEY_2 = bytes(range(32, 64))
STRONG_KEY_3 = bytes((index * 7 + 11) % 256 for index in range(32))
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
