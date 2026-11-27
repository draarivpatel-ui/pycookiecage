"""Typed error surface for pycookiecage.

Every expected failure raised by the library is a :class:`CookieCageError`
with a stable machine-readable ``code``. Callers should branch on the code,
not on the human-readable message. Error messages deliberately omit cookie
values and secret material.
"""

from __future__ import annotations

from typing import Optional, Tuple

INVALID_INPUT = "INVALID_INPUT"
INVALID_OPTIONS = "INVALID_OPTIONS"
INVALID_NAME = "INVALID_NAME"
INVALID_VALUE = "INVALID_VALUE"
CRLF = "CRLF"
CONTROL_CHARACTER = "CONTROL_CHARACTER"
NON_ASCII = "NON_ASCII"
PREFIX_INVARIANT = "PREFIX_INVARIANT"
SAMESITE_INVARIANT = "SAMESITE_INVARIANT"
PARTITIONED_INVARIANT = "PARTITIONED_INVARIANT"
INVALID_DOMAIN = "INVALID_DOMAIN"
INVALID_PATH = "INVALID_PATH"
INVALID_MAX_AGE = "INVALID_MAX_AGE"
INVALID_EXPIRES = "INVALID_EXPIRES"
LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
PARSE_ERROR = "PARSE_ERROR"
DUPLICATE_COOKIE = "DUPLICATE_COOKIE"
ENCODING_ERROR = "ENCODING_ERROR"
WEAK_KEY = "WEAK_KEY"
INVALID_KEYRING = "INVALID_KEYRING"
INVALID_SIGNATURE = "INVALID_SIGNATURE"
COOKIE_EXPIRED = "COOKIE_EXPIRED"
CONFIG_INVALID = "CONFIG_INVALID"

ERROR_CODES: Tuple[str, ...] = (
    INVALID_INPUT,
    INVALID_OPTIONS,
    INVALID_NAME,
    INVALID_VALUE,
    CRLF,
    CONTROL_CHARACTER,
    NON_ASCII,
    PREFIX_INVARIANT,
    SAMESITE_INVARIANT,
    PARTITIONED_INVARIANT,
    INVALID_DOMAIN,
    INVALID_PATH,
    INVALID_MAX_AGE,
    INVALID_EXPIRES,
    LIMIT_EXCEEDED,
    PARSE_ERROR,
    DUPLICATE_COOKIE,
    ENCODING_ERROR,
    WEAK_KEY,
    INVALID_KEYRING,
    INVALID_SIGNATURE,
    COOKIE_EXPIRED,
    CONFIG_INVALID,
)


class CookieCageError(Exception):
    """Raised for every rejected cookie, keyring, or configuration.

    Attributes:
        code: stable uppercase identifier from :data:`ERROR_CODES`.
        message: short explanation that never contains secret or cookie value material.
        field: optional structural field name, never the field's contents.
    """

    __slots__ = ("code", "message", "field")

    def __init__(self, code: str, message: str, *, field: Optional[str] = None) -> None:
        self.code = code
        self.message = message
        self.field = field
        super().__init__("{}: {}".format(code, message))

    def __str__(self) -> str:
        return "{}: {}".format(self.code, self.message)


__all__ = [
    "CONFIG_INVALID",
    "CONTROL_CHARACTER",
    "COOKIE_EXPIRED",
    "CRLF",
    "DUPLICATE_COOKIE",
    "ENCODING_ERROR",
    "ERROR_CODES",
    "INVALID_DOMAIN",
    "INVALID_EXPIRES",
    "INVALID_INPUT",
    "INVALID_KEYRING",
    "INVALID_MAX_AGE",
    "INVALID_NAME",
    "INVALID_OPTIONS",
    "INVALID_PATH",
    "INVALID_SIGNATURE",
    "INVALID_VALUE",
    "LIMIT_EXCEEDED",
    "NON_ASCII",
    "PARSE_ERROR",
    "PARTITIONED_INVARIANT",
    "PREFIX_INVARIANT",
    "SAMESITE_INVARIANT",
    "WEAK_KEY",
    "CookieCageError",
]
