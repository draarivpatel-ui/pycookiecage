"""Shared RFC 6265 validation helpers.

The validators are deliberately small, deterministic, and ASCII-only. They are
private implementation details; public functions document the stable behavior.
"""

from __future__ import annotations

import datetime as _datetime
import re
from typing import Optional

from .errors import (
    CONTROL_CHARACTER,
    CRLF,
    INVALID_DOMAIN,
    INVALID_EXPIRES,
    INVALID_INPUT,
    INVALID_MAX_AGE,
    INVALID_NAME,
    INVALID_PATH,
    INVALID_VALUE,
    LIMIT_EXCEEDED,
    NON_ASCII,
    CookieCageError,
)

MAX_VALUE_BYTES = 4096
MAX_NAME_BYTES = 4096
MAX_SERIALIZED_BYTES = 4096
MAX_MAX_AGE_SECONDS = 34560000
MAX_CONFIG_LIMIT = 1048576

TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
COOKIE_OCTET_RE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*\Z")
ASCII_PRINTABLE_RE = re.compile(r"^[\x20-\x7E]*\Z")
CRLF_RE = re.compile(r"[\r\n]")
CONTROL_RE = re.compile(r"[\x00-\x1F\x7F-\x9F]")
NON_ASCII_RE = re.compile(r"[^\x00-\x7F]")
IPV4_SHAPE_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\Z")
DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")

COMMON_PUBLIC_SUFFIXES = frozenset(
    (
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "com.br", "net.br", "org.br",
        "com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn",
        "com.hk", "net.hk", "org.hk",
        "co.in", "firm.in", "net.in", "org.in", "gen.in",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "ne.kr", "ac.kr",
        "com.mx", "net.mx", "org.mx",
        "co.nz", "net.nz", "org.nz",
        "com.sg", "net.sg", "org.sg",
        "com.tr", "net.tr", "org.tr",
        "com.tw", "net.tw", "org.tw",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
        "co.za", "org.za", "net.za",
    )
)

DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def fail(code: str, message: str, field: Optional[str] = None) -> None:
    raise CookieCageError(code, message, field=field) from None


def byte_length(text: str) -> int:
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        return len(text.encode("utf-8", "surrogatepass"))


def validate_header_text(text: str, field: str) -> None:
    if not isinstance(text, str):
        fail(INVALID_INPUT, field + " must be a string", field)
    if ASCII_PRINTABLE_RE.fullmatch(text):
        return
    if CRLF_RE.search(text):
        fail(CRLF, field + " contains a CR or LF character", field)
    if CONTROL_RE.search(text):
        fail(CONTROL_CHARACTER, field + " contains a control character", field)
    if NON_ASCII_RE.search(text):
        fail(NON_ASCII, field + " contains a non-ASCII character", field)
    fail(INVALID_INPUT, field + " is not printable ASCII", field)


def validate_cookie_name(name: str, field: str = "name") -> str:
    validate_header_text(name, field)
    if len(name) == 0:
        fail(INVALID_NAME, "cookie name must not be empty", field)
    if byte_length(name) > MAX_NAME_BYTES:
        fail(LIMIT_EXCEEDED, "cookie name exceeds the 4096 byte limit", field)
    if not TOKEN_RE.fullmatch(name):
        fail(INVALID_NAME, "cookie name is not an RFC 6265 token", field)
    return name


def validate_cookie_value(value: str, field: str = "value", *, max_bytes: int = MAX_VALUE_BYTES) -> str:
    if not isinstance(value, str):
        fail(INVALID_INPUT, field + " must be a string", field)
    size = byte_length(value)
    if size > max_bytes:
        fail(LIMIT_EXCEEDED, field + " exceeds the configured byte limit", field)
    if COOKIE_OCTET_RE.fullmatch(value):
        return value
    if CRLF_RE.search(value):
        fail(CRLF, field + " contains a CR or LF character", field)
    if CONTROL_RE.search(value):
        fail(CONTROL_CHARACTER, field + " contains a control character", field)
    if NON_ASCII_RE.search(value):
        fail(NON_ASCII, field + " contains a non-ASCII character", field)
    fail(INVALID_VALUE, field + " is not valid RFC 6265 cookie-octet data", field)
    return value


def ascii_startswith_ignore_case(value: str, prefix: str) -> bool:
    if len(value) < len(prefix):
        return False
    return value[: len(prefix)].lower() == prefix


def validate_domain(domain: str) -> str:
    if not isinstance(domain, str):
        fail(INVALID_INPUT, "domain must be a string", "domain")
    validate_header_text(domain, "domain")
    if len(domain) == 0:
        fail(INVALID_DOMAIN, "domain must not be empty", "domain")
    if domain.strip(" ") != domain:
        fail(INVALID_DOMAIN, "domain must not have leading or trailing whitespace", "domain")

    normalized = domain.lower()
    if normalized.startswith("."):
        normalized = normalized[1:]
    if len(normalized) == 0 or normalized.endswith("."):
        fail(INVALID_DOMAIN, "domain must not be empty or end in a root dot", "domain")
    if len(normalized) > 253:
        fail(INVALID_DOMAIN, "domain exceeds the DNS name length limit", "domain")

    if IPV4_SHAPE_RE.fullmatch(normalized):
        parts = normalized.split(".")
        canonical = all(
            len(part) <= 3
            and (part == "0" or not part.startswith("0"))
            and 0 <= int(part) <= 255
            for part in parts
        )
        if canonical:
            fail(INVALID_DOMAIN, "domain IP literals are not allowed", "domain")
        fail(INVALID_DOMAIN, "domain is a malformed IPv4 literal", "domain")
    if ":" in normalized or "[" in normalized or "]" in normalized:
        fail(INVALID_DOMAIN, "IPv6 literals are not valid cookie Domain values", "domain")

    labels = normalized.split(".")
    if any(len(label) == 0 or len(label) > 63 or not DNS_LABEL_RE.fullmatch(label) for label in labels):
        fail(INVALID_DOMAIN, "domain contains an invalid DNS label", "domain")
    if len(labels) < 2:
        fail(INVALID_DOMAIN, "domain must not be a bare top-level or single-label name", "domain")
    if normalized in COMMON_PUBLIC_SUFFIXES:
        fail(INVALID_DOMAIN, "domain is a common public suffix and cannot receive cookies safely", "domain")
    return normalized


def validate_path(path: str) -> str:
    if not isinstance(path, str):
        fail(INVALID_INPUT, "path must be a string", "path")
    validate_header_text(path, "path")
    if not path.startswith("/"):
        fail(INVALID_PATH, "path must start with /", "path")
    if ";" in path:
        fail(INVALID_PATH, "path must not contain a semicolon", "path")
    if not COOKIE_OCTET_RE.fullmatch(path):
        fail(INVALID_PATH, "path is not valid RFC 6265 cookie-octet data", "path")
    return path


def validate_max_age(max_age: int, field: str = "max_age") -> int:
    if type(max_age) is not int or max_age < 0 or max_age > MAX_MAX_AGE_SECONDS:
        fail(INVALID_MAX_AGE, field + " must be an integer from 0 to 34560000 seconds", field)
    return max_age


def format_imf_fixdate(value: _datetime.datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        fail(INVALID_EXPIRES, "expires must be a timezone-aware datetime", "expires")
    if value.microsecond != 0:
        fail(INVALID_EXPIRES, "expires must not contain microseconds because IMF-fixdate has second precision", "expires")
    try:
        utc_value = value.astimezone(_datetime.timezone.utc)
    except (OverflowError, ValueError):
        fail(INVALID_EXPIRES, "expires cannot be represented as an IMF-fixdate in UTC", "expires")
    return "{}, {} {} {} {}:{}:{} GMT".format(
        DAY_NAMES[utc_value.weekday()],
        "{:02d}".format(utc_value.day),
        MONTH_NAMES[utc_value.month - 1],
        "{:04d}".format(utc_value.year),
        "{:02d}".format(utc_value.hour),
        "{:02d}".format(utc_value.minute),
        "{:02d}".format(utc_value.second),
    )


def validate_expires(value: _datetime.datetime) -> str:
    if not isinstance(value, _datetime.datetime):
        fail(INVALID_EXPIRES, "expires must be a datetime object", "expires")
    return format_imf_fixdate(value)


def validate_strict_bool(value: bool, field: str) -> bool:
    if type(value) is not bool:
        fail(INVALID_INPUT, field + " must be a boolean", field)
    return value


def validate_positive_limit(value: int, field: str, maximum: int) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        fail(INVALID_INPUT, field + " must be a positive integer within the supported range", field)
    return value
