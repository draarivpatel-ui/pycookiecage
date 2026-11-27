"""pycookiecage: zero-dependency hardened cookie serialization, parsing, and signing.

Typical use::

    from pycookiecage import serialize_cookie, parse_cookie_header

    header = serialize_cookie("__Host-session", token, same_site="Strict")
    cookies = parse_cookie_header("sid=abc")
"""

from __future__ import annotations

from .errors import ERROR_CODES, CookieCageError
from .guard import CookieJarGuard
from .parsing import parse_cookie_header
from .serialization import delete_cookie, serialize_cookie
from .signing import VerifiedCookie, sign_cookie_value, verify_cookie_value

__version__ = "1.0.0"

__all__ = [
    "CookieCageError",
    "CookieJarGuard",
    "ERROR_CODES",
    "VerifiedCookie",
    "__version__",
    "delete_cookie",
    "parse_cookie_header",
    "serialize_cookie",
    "sign_cookie_value",
    "verify_cookie_value",
]
