"""HMAC-SHA256 signed cookie values.

The signed envelope is ``v1.<kid>.<exp>.<payload>.<mac>``. It provides
integrity and expiry, not confidentiality. The MAC input uses explicit length
prefixes and binds the cookie name, key id, expiration, and raw value bytes.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import hashlib
import hmac
import math
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Mapping, Optional, Tuple, Union

from .errors import (
    COOKIE_EXPIRED,
    ENCODING_ERROR,
    INVALID_INPUT,
    INVALID_KEYRING,
    INVALID_OPTIONS,
    INVALID_SIGNATURE,
    LIMIT_EXCEEDED,
    WEAK_KEY,
)
from .validation import (
    fail,
    utf8_byte_length_exceeds,
    validate_cookie_name,
    validate_header_text,
    validate_max_age,
    validate_strict_bool,
)

MIN_SECRET_BYTES = 32
MIN_SECRET_ENTROPY_BITS = 128
MAX_KEYRING_KEYS = 32
MAX_SIGN_VALUE_BYTES = 4096
MAX_SIGNED_BYTES = 4096
MAX_EXPIRY_MS = 9999999999999999
_UNIX_EPOCH = _datetime.datetime(1970, 1, 1, tzinfo=_datetime.timezone.utc)

KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EXPIRY_RE = re.compile(r"^[0-9]{1,16}\Z")
PEM_MARKER_RE = re.compile(rb"-----BEGIN [A-Z0-9][A-Z0-9 -]{0,79}-----", re.IGNORECASE)
OPENSSH_KEY_TYPES = frozenset(
    (
        b"ssh-rsa",
        b"ssh-dss",
        b"rsa-sha2-256",
        b"rsa-sha2-512",
        b"ssh-ed25519",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
        b"sk-ssh-ed25519@openssh.com",
        b"sk-ecdsa-sha2-nistp256@openssh.com",
    )
)
OPENSSH_TOKEN_EDGE_CHARS = b"'\"`;,[](){}"
BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*\Z")
PLACEHOLDER_SECRET_PREFIXES = (
    b"change-me",
    b"change_me",
    b"change me",
    b"changeme",
    b"password",
    b"secret",
    b"test-secret",
    b"test_secret",
    b"test secret",
    b"example-secret",
    b"example_secret",
    b"example secret",
    b"placeholder",
    b"replace-me",
    b"replace_me",
    b"replace me",
    b"your-secret",
    b"your_secret",
    b"your secret",
)

SecretInput = Union[str, bytes, bytearray, memoryview]
KeyringInput = Union[SecretInput, Mapping[str, SecretInput]]


@dataclass(frozen=True)
class VerifiedCookie:
    """Result of successful signed-cookie verification.

    ``expires_at`` is a Unix epoch timestamp in milliseconds, or ``None`` for
    a non-expiring signed value. The dataclass repr intentionally omits the
    cookie value.
    """

    value: str = field(repr=False)
    key_id: str
    rotated: bool
    expires_at: Optional[int]


@dataclass(frozen=True)
class _Key:
    key_id: str
    secret: bytes = field(repr=False)


@dataclass(frozen=True)
class _ParsedSignedValue:
    key_id: str
    expires_at: int
    payload: str
    payload_bytes: bytes
    mac: bytes


def _validate_key_id(key_id: object) -> str:
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        fail(INVALID_KEYRING, "key id must be a URL-safe token of 1 to 64 characters")
    return key_id


def _shannon_entropy_bits(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = float(len(data))
    bits_per_byte = 0.0
    for count in counts:
        if count:
            probability = count / length
            bits_per_byte -= probability * math.log2(probability)
    return bits_per_byte * length


def _has_obvious_period(data: bytes) -> bool:
    sample = data[:512]
    size = len(sample)
    if size < 16:
        return False
    max_period = min(256, size // 2)
    for period in range(1, max_period + 1):
        if sample[period:] == sample[:-period]:
            return True
    return False


def _has_dominant_arithmetic_difference(data: bytes) -> bool:
    sample = data[:512]
    size = len(sample)
    if size < 24:
        return False
    counts = [0] * 256
    for index in range(1, size):
        counts[(sample[index] - sample[index - 1]) % 256] += 1
    return max(counts) * 5 >= (size - 1) * 4


def _looks_like_labeled_asymmetric_key(data: bytes) -> bool:
    sample = data[:4096]
    if PEM_MARKER_RE.search(sample) is not None:
        return True
    lowered = sample.lower()
    for token in lowered.split():
        if token.strip(OPENSSH_TOKEN_EDGE_CHARS) in OPENSSH_KEY_TYPES:
            return True
    return False


def _normalize_secret(secret: SecretInput, *, allow_weak_keys: bool) -> bytes:
    if isinstance(secret, str):
        if len(secret) == 0:
            fail(WEAK_KEY, "secret must not be empty")
        if secret.strip() != secret:
            fail(WEAK_KEY, "secret must not have leading or trailing whitespace")
        try:
            data = secret.encode("utf-8")
        except UnicodeEncodeError:
            fail(INVALID_KEYRING, "key secret must be valid UTF-8 when provided as a string")
    elif isinstance(secret, (bytes, bytearray, memoryview)):
        data = bytes(secret)
        if len(data) == 0:
            fail(WEAK_KEY, "secret must not be empty")
    else:
        fail(INVALID_KEYRING, "key secret must be a string or bytes-like object")

    if _looks_like_labeled_asymmetric_key(data):
        fail(WEAK_KEY, "labeled asymmetric key material must not be used as an HMAC secret")
    if allow_weak_keys:
        return data
    if len(data) < MIN_SECRET_BYTES:
        fail(WEAK_KEY, "secret is shorter than the required minimum length")
    if len(set(data)) < 8:
        fail(WEAK_KEY, "secret does not contain enough byte diversity")
    if _shannon_entropy_bits(data) < MIN_SECRET_ENTROPY_BITS:
        fail(WEAK_KEY, "secret does not meet the minimum estimated entropy floor")
    if _has_obvious_period(data) or _has_dominant_arithmetic_difference(data):
        fail(WEAK_KEY, "secret has an obvious repeating or sequential byte pattern")
    lowered = data.lower()
    for prefix in PLACEHOLDER_SECRET_PREFIXES:
        if lowered.startswith(prefix):
            fail(WEAK_KEY, "secret appears to be a placeholder or weak well-known value")
    return data


def _normalize_keyring(key_or_keyring: KeyringInput, *, allow_weak_keys: bool) -> Tuple[_Key, ...]:
    if isinstance(key_or_keyring, (str, bytes, bytearray, memoryview)):
        entries = [("k1", key_or_keyring)]
    elif isinstance(key_or_keyring, Mapping):
        if len(key_or_keyring) == 0:
            fail(INVALID_KEYRING, "keyring must contain at least one key")
        if len(key_or_keyring) > MAX_KEYRING_KEYS:
            fail(INVALID_KEYRING, "keyring exceeds the maximum active key count")
        entries = list(key_or_keyring.items())
    else:
        fail(INVALID_KEYRING, "key_or_keyring must be a secret or a mapping of key ids to secrets")

    seen = set()
    keys = []
    for key_id, secret in entries:
        checked_id = _validate_key_id(key_id)
        if checked_id in seen:
            fail(INVALID_KEYRING, "keyring contains a duplicate key id")
        seen.add(checked_id)
        keys.append(_Key(checked_id, _normalize_secret(secret, allow_weak_keys=allow_weak_keys)))
    return tuple(keys)


def _read_now(value: Optional[Union[int, _datetime.datetime]]) -> int:
    if value is None:
        return int(time.time() * 1000)
    if isinstance(value, _datetime.datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            fail(INVALID_OPTIONS, "now datetime must be timezone-aware", "now")
        try:
            utc_value = value.astimezone(_datetime.timezone.utc)
            delta = utc_value - _UNIX_EPOCH
        except (OverflowError, ValueError):
            fail(INVALID_OPTIONS, "now datetime is outside the supported timestamp range", "now")
        timestamp = (delta.days * 86400 + delta.seconds) * 1000 + delta.microseconds // 1000
        if timestamp < 0 or timestamp > MAX_EXPIRY_MS:
            fail(INVALID_OPTIONS, "now is outside the supported timestamp range", "now")
        return timestamp
    if type(value) is not int or value < 0 or value > MAX_EXPIRY_MS:
        fail(INVALID_OPTIONS, "now must be a nonnegative integer millisecond timestamp or timezone-aware datetime", "now")
    return value


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _is_canonical_base64url(text: str) -> bool:
    if not BASE64URL_RE.fullmatch(text):
        return False
    remainder = len(text) % 4
    if remainder == 1:
        return False
    if remainder == 0 or len(text) == 0:
        return True
    try:
        last_bits = BASE64URL_ALPHABET.index(text[-1])
    except ValueError:
        return False
    if remainder == 2:
        return (last_bits & 0x0F) == 0
    return (last_bits & 0x03) == 0


def _b64url_decode(text: str, field_name: str) -> bytes:
    if not _is_canonical_base64url(text):
        fail(ENCODING_ERROR, field_name + " is not valid canonical unpadded base64url", field_name)
    padding = "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.b64decode((text + padding).encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        fail(ENCODING_ERROR, field_name + " is not valid canonical unpadded base64url", field_name)
    return b""


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _mac_input(name: str, key_id: str, expires_at: int, value_bytes: bytes) -> bytes:
    return (
        b"pycookiecage signed cookie v1\x00"
        + _length_prefixed(name.encode("utf-8"))
        + _length_prefixed(key_id.encode("ascii"))
        + struct.pack(">Q", expires_at)
        + _length_prefixed(value_bytes)
    )


def _mac_for(secret: bytes, name: str, key_id: str, expires_at: int, value_bytes: bytes) -> bytes:
    return hmac.new(secret, _mac_input(name, key_id, expires_at, value_bytes), hashlib.sha256).digest()


def sign_cookie_value(
    name: str,
    value: str,
    key_or_keyring: KeyringInput,
    *,
    max_age: Optional[int] = None,
    now: Optional[Union[int, _datetime.datetime]] = None,
    allow_weak_keys: bool = False,
) -> str:
    """Sign a cookie value with HMAC-SHA256.

    ``now`` is a Unix epoch timestamp in milliseconds. A timezone-aware
    datetime is also accepted. ``max_age`` is expressed in seconds. The first
    key in a mapping is the primary signing key.
    """

    validate_strict_bool(allow_weak_keys, "allow_weak_keys")
    checked_name = validate_cookie_name(name)
    if not isinstance(value, str):
        fail(INVALID_INPUT, "value must be a string", "value")
    if len(value) > MAX_SIGN_VALUE_BYTES:
        fail(LIMIT_EXCEEDED, "value exceeds the 4096 byte signing limit", "value")
    try:
        value_bytes = value.encode("utf-8")
    except UnicodeEncodeError:
        fail(ENCODING_ERROR, "value must be valid UTF-8", "value")
    if len(value_bytes) > MAX_SIGN_VALUE_BYTES:
        fail(LIMIT_EXCEEDED, "value exceeds the 4096 byte signing limit", "value")

    checked_max_age = None
    if max_age is not None:
        checked_max_age = validate_max_age(max_age)
    now_ms = _read_now(now)
    expires_at = 0
    if checked_max_age is not None:
        expires_at = now_ms + checked_max_age * 1000
        if expires_at > MAX_EXPIRY_MS:
            fail(INVALID_OPTIONS, "signing expiration exceeds the supported timestamp range", "max_age")

    keys = _normalize_keyring(key_or_keyring, allow_weak_keys=allow_weak_keys)
    key = keys[0]
    payload = _b64url_encode(value_bytes)
    mac = _b64url_encode(_mac_for(key.secret, checked_name, key.key_id, expires_at, value_bytes))
    signed = "v1.{}.{}.{}.{}".format(key.key_id, expires_at, payload, mac)
    if len(signed.encode("ascii")) > MAX_SIGNED_BYTES:
        fail(LIMIT_EXCEEDED, "signed value exceeds the 4096 byte limit", "signed_value")
    return signed


def _parse_signed_value(signed_value: str, *, max_signed_bytes: int = MAX_SIGNED_BYTES) -> _ParsedSignedValue:
    if not isinstance(signed_value, str):
        fail(INVALID_INPUT, "signed_value must be a string", "signed_value")
    if len(signed_value) > max_signed_bytes or utf8_byte_length_exceeds(signed_value, max_signed_bytes):
        fail(LIMIT_EXCEEDED, "signed value exceeds the configured byte limit", "signed_value")
    validate_header_text(signed_value, "signed_value")
    parts = signed_value.split(".")
    if len(parts) != 5 or parts[0] != "v1":
        fail(INVALID_SIGNATURE, "signed value does not use the pycookiecage v1 format", "signed_value")

    key_id = parts[1]
    if not KEY_ID_RE.fullmatch(key_id):
        fail(INVALID_SIGNATURE, "signed value contains an invalid key id", "signed_value")
    expiry_text = parts[2]
    if not EXPIRY_RE.fullmatch(expiry_text):
        fail(INVALID_SIGNATURE, "signed value contains an invalid expiration field", "signed_value")
    expires_at = int(expiry_text)
    if str(expires_at) != expiry_text or expires_at > MAX_EXPIRY_MS:
        fail(INVALID_SIGNATURE, "signed value expiration is outside the supported range or is not canonical", "signed_value")

    payload = parts[3]
    mac_text = parts[4]
    if not _is_canonical_base64url(payload) or not _is_canonical_base64url(mac_text):
        fail(INVALID_SIGNATURE, "signed value contains malformed or noncanonical base64url data", "signed_value")
    payload_bytes = _b64url_decode(payload, "payload")
    mac = _b64url_decode(mac_text, "signature")
    if len(mac) != 32:
        fail(INVALID_SIGNATURE, "signed value contains a wrong-length HMAC-SHA256 tag", "signed_value")
    return _ParsedSignedValue(key_id, expires_at, payload, payload_bytes, mac)


def verify_cookie_value(
    name: str,
    signed_value: str,
    key_or_keyring: KeyringInput,
    *,
    now: Optional[Union[int, _datetime.datetime]] = None,
    allow_weak_keys: bool = False,
) -> VerifiedCookie:
    """Verify a signed cookie value and return its authenticated contents.

    Every active keyring entry is processed without an early exit. Expiry is
    evaluated only after the MAC has been authenticated. A result with
    ``rotated=True`` was verified by a non-primary key.
    """

    validate_strict_bool(allow_weak_keys, "allow_weak_keys")
    checked_name = validate_cookie_name(name)
    keys = _normalize_keyring(key_or_keyring, allow_weak_keys=allow_weak_keys)
    parsed = _parse_signed_value(signed_value)

    matched_index = -1
    for index, key in enumerate(keys):
        expected = _mac_for(key.secret, checked_name, parsed.key_id, parsed.expires_at, parsed.payload_bytes)
        equal = hmac.compare_digest(expected, parsed.mac)
        if equal and key.key_id == parsed.key_id and matched_index == -1:
            matched_index = index
    if matched_index == -1:
        fail(INVALID_SIGNATURE, "signed value failed HMAC-SHA256 verification", "signed_value")

    now_ms = _read_now(now)
    if parsed.expires_at != 0 and now_ms >= parsed.expires_at:
        fail(COOKIE_EXPIRED, "signed cookie value is expired", "signed_value")

    if len(parsed.payload_bytes) > MAX_SIGN_VALUE_BYTES:
        fail(LIMIT_EXCEEDED, "signed payload exceeds the configured value byte limit", "payload")
    try:
        value = parsed.payload_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail(ENCODING_ERROR, "signed payload is not valid UTF-8", "payload")
    return VerifiedCookie(
        value=value,
        key_id=parsed.key_id,
        rotated=matched_index != 0,
        expires_at=None if parsed.expires_at == 0 else parsed.expires_at,
    )


__all__ = [
    "MAX_EXPIRY_MS",
    "MAX_KEYRING_KEYS",
    "MAX_SIGNED_BYTES",
    "MAX_SIGN_VALUE_BYTES",
    "MIN_SECRET_BYTES",
    "MIN_SECRET_ENTROPY_BITS",
    "KeyringInput",
    "SecretInput",
    "VerifiedCookie",
    "sign_cookie_value",
    "verify_cookie_value",
]
