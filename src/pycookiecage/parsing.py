"""Strict parser for incoming Cookie header values."""

from __future__ import annotations

from typing import Dict

from .errors import (
    DUPLICATE_COOKIE,
    INVALID_INPUT,
    INVALID_OPTIONS,
    INVALID_VALUE,
    LIMIT_EXCEEDED,
    PARSE_ERROR,
)
from .validation import (
    MAX_CONFIG_LIMIT,
    fail,
    validate_cookie_name,
    validate_cookie_value,
    utf8_byte_length_exceeds,
    validate_header_text,
    validate_positive_limit,
)

DEFAULT_MAX_HEADER_BYTES = 16384
DEFAULT_MAX_COOKIES = 100
DEFAULT_MAX_COOKIE_BYTES = 4096
MAX_COOKIE_SEGMENT_BYTES = 65536


def _validate_duplicate_policy(value: str) -> str:
    if value not in ("reject", "first", "last"):
        fail(INVALID_OPTIONS, "duplicate_policy must be reject, first or last", "duplicate_policy")
    return value


def _parse_cookie_value(raw_value: str, max_cookie_bytes: int) -> str:
    quoted = False
    inner = raw_value
    if raw_value.startswith('"') or raw_value.endswith('"'):
        if len(raw_value) < 2 or not raw_value.startswith('"') or not raw_value.endswith('"'):
            fail(INVALID_VALUE, "cookie value has mismatched quotes", "value")
        quoted = True
        inner = raw_value[1:-1]
    checked = validate_cookie_value(inner, "value", max_bytes=max_cookie_bytes)
    if quoted:
        return '"' + checked + '"'
    return checked


def parse_cookie_header(
    header: str,
    *,
    duplicate_policy: str = "reject",
    max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
    max_cookies: int = DEFAULT_MAX_COOKIES,
    max_cookie_bytes: int = DEFAULT_MAX_COOKIE_BYTES,
) -> Dict[str, str]:
    """Parse one incoming ``Cookie`` header into a name-to-value mapping.

    Parsing is strict and bounded. Exact duplicate names reject by default to
    make cookie-tossing visible. Quoted values keep their outer quotes because
    RFC 6265bis treats those quotes as part of the value.
    """

    _validate_duplicate_policy(duplicate_policy)
    validate_positive_limit(max_header_bytes, "max_header_bytes", MAX_CONFIG_LIMIT)
    validate_positive_limit(max_cookies, "max_cookies", 1000)
    validate_positive_limit(max_cookie_bytes, "max_cookie_bytes", MAX_COOKIE_SEGMENT_BYTES)

    if not isinstance(header, str):
        fail(INVALID_INPUT, "header must be a string", "header")
    if len(header) > max_header_bytes or utf8_byte_length_exceeds(header, max_header_bytes):
        fail(LIMIT_EXCEEDED, "Cookie header exceeds the configured byte limit", "header")
    validate_header_text(header, "header")
    if len(header) == 0:
        fail(PARSE_ERROR, "Cookie header must contain at least one cookie pair", "header")

    output = {}  # type: Dict[str, str]
    segment_index = 0
    start = 0
    while True:
        separator = header.find(";", start)
        if separator == -1:
            raw_segment = header[start:]
            final = True
        else:
            raw_segment = header[start:separator]
            final = False

        content_start = 0
        while content_start < len(raw_segment) and raw_segment[content_start] == " ":
            content_start += 1
        segment = raw_segment[content_start:]
        if len(segment) == 0:
            fail(PARSE_ERROR, "Cookie header contains an empty cookie segment", "header")
        if len(segment) > max_cookie_bytes:
            fail(LIMIT_EXCEEDED, "cookie segment exceeds the configured byte limit", "cookie")

        equals = segment.find("=")
        if equals <= 0:
            fail(PARSE_ERROR, "cookie segment must contain a non-empty name followed by =", "cookie")
        name = validate_cookie_name(segment[:equals])
        value = _parse_cookie_value(segment[equals + 1 :], max_cookie_bytes)

        if name in output:
            if duplicate_policy == "reject":
                fail(DUPLICATE_COOKIE, "Cookie header contains a duplicate cookie name", "cookie")
            if duplicate_policy == "last":
                output[name] = value
        else:
            output[name] = value

        if final:
            break
        segment_index += 1
        if segment_index >= max_cookies:
            fail(LIMIT_EXCEEDED, "Cookie header exceeds the configured cookie count", "header")
        start = separator + 1

    return output


__all__ = [
    "DEFAULT_MAX_COOKIES",
    "DEFAULT_MAX_COOKIE_BYTES",
    "DEFAULT_MAX_HEADER_BYTES",
    "parse_cookie_header",
]
