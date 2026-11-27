"""Reusable policy-bound cookie jar guard."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .errors import INVALID_KEYRING, INVALID_OPTIONS
from .parsing import parse_cookie_header
from .serialization import delete_cookie, serialize_cookie
from .signing import VerifiedCookie, sign_cookie_value, verify_cookie_value
from .validation import fail

_SERIALIZE_KEYS = frozenset(
    ("http_only", "secure", "same_site", "path", "domain", "max_age", "expires", "partitioned")
)
_DELETE_KEYS = frozenset(("http_only", "secure", "same_site", "path", "domain", "partitioned"))
_PARSE_KEYS = frozenset(("duplicate_policy", "max_header_bytes", "max_cookies", "max_cookie_bytes"))
_SIGN_KEYS = frozenset(("max_age", "now", "allow_weak_keys", "key_or_keyring"))
_VERIFY_KEYS = frozenset(("now", "allow_weak_keys", "key_or_keyring"))
_POLICY_KEYS = frozenset(("serialize", "delete", "parse", "sign", "verify", "key_or_keyring"))


def _validate_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        fail(INVALID_OPTIONS, label + " must be a mapping")
    return value


def _validate_keys(options: Mapping[str, Any], allowed: frozenset, label: str) -> Dict[str, Any]:
    output = dict(options)
    for key in output:
        if key not in allowed:
            fail(INVALID_OPTIONS, label + " contains an unknown option", str(key))
    return output


def _merge_options(base: Mapping[str, Any], overrides: Mapping[str, Any], allowed: frozenset, label: str) -> Dict[str, Any]:
    merged = _validate_keys(base, allowed, label)
    checked_overrides = _validate_keys(overrides, allowed, label)
    merged.update(checked_overrides)
    return merged


class CookieJarGuard:
    """Reusable guard that applies one cookie policy consistently.

    ``policy`` is a mapping with optional ``serialize``, ``delete``, ``parse``,
    ``sign`` and ``verify`` nested mappings plus optional top-level
    ``key_or_keyring``. Method keyword arguments override policy defaults for
    that call. The guard repr never includes key material.
    """

    __slots__ = ("_serialize_defaults", "_delete_defaults", "_parse_defaults", "_sign_defaults", "_verify_defaults", "_key_or_keyring")

    def __init__(self, policy: Optional[Mapping[str, Any]] = None) -> None:
        if policy is None:
            policy_mapping = {}  # type: Mapping[str, Any]
        else:
            policy_mapping = _validate_mapping(policy, "CookieJarGuard policy")
        unknown = [key for key in policy_mapping if key not in _POLICY_KEYS]
        if unknown:
            fail(INVALID_OPTIONS, "CookieJarGuard policy contains an unknown option", str(unknown[0]))

        self._serialize_defaults = _validate_keys(
            _validate_mapping(policy_mapping.get("serialize", {}), "guard serialize policy"),
            _SERIALIZE_KEYS,
            "guard serialize policy",
        )
        self._delete_defaults = _validate_keys(
            _validate_mapping(policy_mapping.get("delete", {}), "guard delete policy"),
            _DELETE_KEYS,
            "guard delete policy",
        )
        self._parse_defaults = _validate_keys(
            _validate_mapping(policy_mapping.get("parse", {}), "guard parse policy"),
            _PARSE_KEYS,
            "guard parse policy",
        )
        self._sign_defaults = _validate_keys(
            _validate_mapping(policy_mapping.get("sign", {}), "guard sign policy"),
            _SIGN_KEYS,
            "guard sign policy",
        )
        self._verify_defaults = _validate_keys(
            _validate_mapping(policy_mapping.get("verify", {}), "guard verify policy"),
            _VERIFY_KEYS,
            "guard verify policy",
        )
        self._key_or_keyring = policy_mapping.get("key_or_keyring")

    def __repr__(self) -> str:
        return "CookieJarGuard(policy_keys_configured={}, keyring_configured={})".format(
            sorted(key for key, value in (
                ("serialize", self._serialize_defaults),
                ("delete", self._delete_defaults),
                ("parse", self._parse_defaults),
                ("sign", self._sign_defaults),
                ("verify", self._verify_defaults),
            ) if value),
            self._key_or_keyring is not None,
        )

    def serialize(self, name: str, value: str, **overrides: Any) -> str:
        options = _merge_options(self._serialize_defaults, overrides, _SERIALIZE_KEYS, "guard serialize options")
        return serialize_cookie(name, value, **options)

    def delete(self, name: str, **overrides: Any) -> str:
        options = _merge_options(self._delete_defaults, overrides, _DELETE_KEYS, "guard delete options")
        return delete_cookie(name, **options)

    def parse(self, header: str, **overrides: Any) -> Dict[str, str]:
        options = _merge_options(self._parse_defaults, overrides, _PARSE_KEYS, "guard parse options")
        return parse_cookie_header(header, **options)

    def _resolve_keyring(self, options: Dict[str, Any]) -> Any:
        key_or_keyring = options.pop("key_or_keyring", self._key_or_keyring)
        if key_or_keyring is None:
            fail(INVALID_KEYRING, "cookie jar guard has no key_or_keyring configured")
        return key_or_keyring

    def sign(self, name: str, value: str, **overrides: Any) -> str:
        options = _merge_options(self._sign_defaults, overrides, _SIGN_KEYS, "guard sign options")
        key_or_keyring = self._resolve_keyring(options)
        return sign_cookie_value(name, value, key_or_keyring, **options)

    def verify(self, name: str, signed_value: str, **overrides: Any) -> VerifiedCookie:
        options = _merge_options(self._verify_defaults, overrides, _VERIFY_KEYS, "guard verify options")
        key_or_keyring = self._resolve_keyring(options)
        return verify_cookie_value(name, signed_value, key_or_keyring, **options)


__all__ = ["CookieJarGuard"]
