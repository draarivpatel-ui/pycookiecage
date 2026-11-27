"""Hardened RFC 6265 Set-Cookie serialization."""

from __future__ import annotations

import datetime as _datetime
from typing import Optional

from .errors import (
    INVALID_INPUT,
    LIMIT_EXCEEDED,
    PARTITIONED_INVARIANT,
    PREFIX_INVARIANT,
    SAMESITE_INVARIANT,
)
from .validation import (
    MAX_SERIALIZED_BYTES,
    MAX_VALUE_BYTES,
    ascii_startswith_ignore_case,
    fail,
    validate_cookie_name,
    validate_cookie_value,
    validate_domain,
    validate_expires,
    validate_max_age,
    validate_path,
    validate_strict_bool,
)

_DELETE_EXPIRES = _datetime.datetime(1970, 1, 1, tzinfo=_datetime.timezone.utc)


def _normalize_same_site(value: str) -> str:
    if not isinstance(value, str):
        fail(SAMESITE_INVARIANT, "same_site must be Strict, Lax or None", "same_site")
    lowered = value.lower()
    if lowered == "strict":
        return "Strict"
    if lowered == "lax":
        return "Lax"
    if lowered == "none":
        return "None"
    fail(SAMESITE_INVARIANT, "same_site must be Strict, Lax or None", "same_site")
    return "Lax"


def serialize_cookie(
    name: str,
    value: str,
    *,
    http_only: bool = True,
    secure: bool = True,
    same_site: str = "Lax",
    path: str = "/",
    domain: Optional[str] = None,
    max_age: Optional[int] = None,
    expires: Optional[_datetime.datetime] = None,
    partitioned: bool = False,
) -> str:
    """Serialize one hardened ``Set-Cookie`` header value.

    The function is intentionally strict. Names must be RFC 6265 tokens,
    unquoted values must already be valid cookie-octet data, and output is
    limited to 4096 bytes. ``__Host-`` and ``__Secure-`` prefixes are matched
    ASCII case-insensitively as required by RFC 6265bis.
    """

    validate_strict_bool(http_only, "http_only")
    validate_strict_bool(secure, "secure")
    validate_strict_bool(partitioned, "partitioned")
    canonical_same_site = _normalize_same_site(same_site)

    checked_name = validate_cookie_name(name)
    checked_value = validate_cookie_value(value, max_bytes=MAX_VALUE_BYTES)

    normalized_domain = None
    if domain is not None:
        normalized_domain = validate_domain(domain)
    checked_path = validate_path(path)

    checked_max_age = None
    if max_age is not None:
        checked_max_age = validate_max_age(max_age)
    formatted_expires = None
    if expires is not None:
        formatted_expires = validate_expires(expires)

    if ascii_startswith_ignore_case(checked_name, "__host-"):
        if secure is not True or checked_path != "/" or normalized_domain is not None:
            fail(
                PREFIX_INVARIANT,
                "__Host- cookies require Secure, Path=/ and no Domain attribute",
                "name",
            )
    if ascii_startswith_ignore_case(checked_name, "__secure-") and secure is not True:
        fail(PREFIX_INVARIANT, "__Secure- cookies require the Secure attribute", "name")
    if canonical_same_site == "None" and secure is not True:
        fail(SAMESITE_INVARIANT, "SameSite=None cookies require the Secure attribute", "same_site")
    if partitioned and secure is not True:
        fail(PARTITIONED_INVARIANT, "Partitioned cookies require the Secure attribute", "partitioned")

    output = checked_name + "=" + checked_value
    if normalized_domain is not None:
        output += "; Domain=" + normalized_domain
    output += "; Path=" + checked_path
    if checked_max_age is not None:
        output += "; Max-Age=" + str(checked_max_age)
    if formatted_expires is not None:
        output += "; Expires=" + formatted_expires
    if http_only:
        output += "; HttpOnly"
    if secure:
        output += "; Secure"
    output += "; SameSite=" + canonical_same_site
    if partitioned:
        output += "; Partitioned"

    if len(output) > MAX_SERIALIZED_BYTES:
        fail(LIMIT_EXCEEDED, "serialized cookie exceeds the 4096 byte limit")
    return output


def delete_cookie(
    name: str,
    *,
    http_only: bool = True,
    secure: bool = True,
    same_site: str = "Lax",
    path: str = "/",
    domain: Optional[str] = None,
    partitioned: bool = False,
) -> str:
    """Serialize an immediate-expiry deletion cookie.

    Prefix, SameSite and Partitioned invariants are enforced exactly as they
    are for :func:`serialize_cookie`. The value is empty, ``Max-Age`` is zero,
    and ``Expires`` is the Unix epoch in IMF-fixdate form.
    """

    return serialize_cookie(
        name,
        "",
        http_only=http_only,
        secure=secure,
        same_site=same_site,
        path=path,
        domain=domain,
        max_age=0,
        expires=_DELETE_EXPIRES,
        partitioned=partitioned,
    )


__all__ = ["delete_cookie", "serialize_cookie"]
