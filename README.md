# pycookiecage

Zero-dependency Python library for strict RFC 6265 cookie serialization, strict incoming Cookie header parsing, case-insensitive `__Host-` and `__Secure-` prefix enforcement, cookie-tossing duplicate rejection, and constant-time HMAC-SHA256 signed cookie values.

pycookiecage is the Python stdlib companion to the JavaScript `cookiecage` package. It is defensive only. It performs no network access, filesystem access, subprocess execution, browser interaction, or framework integration.

## Installation

```bash
python3 -m pip install pycookiecage
```

For local development from a source checkout:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Hardened serialization

```python
from pycookiecage import serialize_cookie

header = serialize_cookie(
    "__Host-session",
    "opaque-token-value",
    http_only=True,
    secure=True,
    same_site="Strict",
    path="/",
    max_age=3600,
)
```

Output uses canonical attribute capitalization:

```text
__Host-session=opaque-token-value; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict
```

Validation is strict by design:

- Cookie names must be RFC 6265 tokens and are bounded to 4096 bytes. Empty names, spaces, semicolons, equals signs, commas, quotes, backslashes, CRLF, control characters, and non-ASCII characters reject.
- Values must already be valid RFC 6265 cookie-octet data. CRLF, control characters, semicolon smuggling, non-ASCII characters, and values over 4096 bytes reject.
- Complete serialized output is also limited to 4096 bytes.
- `__Host-` and `__Secure-` prefixes are enforced ASCII case-insensitively. Mixed-case spellings such as `__host-` and `__SECURE-` cannot bypass the invariant.
- `__Host-` cookies require `secure=True`, `path="/"`, and no domain.
- `__Secure-` cookies require `secure=True`.
- `SameSite=None` requires `secure=True` across ASCII case variants.
- `Partitioned` requires `secure=True`.
- `max_age` must be an integer from 0 to 34560000 seconds. Booleans, floats, NaN, and infinity reject.
- `expires` must be a timezone-aware `datetime` with zero microseconds and is emitted as an RFC 7231 IMF-fixdate.

`delete_cookie` emits an empty value, `Max-Age=0`, and `Expires=Thu, 01 Jan 1970 00:00:00 GMT` while preserving every prefix, SameSite, and Partitioned invariant.

```python
from pycookiecage import delete_cookie

expiry_header = delete_cookie("__Host-session", secure=True, path="/")
```

## Strict Cookie header parsing

```python
from pycookiecage import parse_cookie_header

cookies = parse_cookie_header('sid=abc; theme="light"')
assert cookies["sid"] == "abc"
assert cookies["theme"] == '"light"'
```

The parser is for one complete incoming `Cookie` header value. It does not split or join HTTP/2 or HTTP/3 cookie fragments. Applications must follow their server framework's safe header reconstruction rules before calling it.

Security behavior:

- Exact duplicate names reject by default, making cookie-tossing visible instead of silently resolving it.
- `duplicate_policy="first"` and `duplicate_policy="last"` exist only as explicit compatibility modes.
- Cookie names remain case-sensitive, as they are in RFC 6265bis.
- Balanced quoted values are accepted, but the outer quotes are preserved. `"abc"` and `abc` remain distinct wire values.
- Mismatched quotes, empty segments, missing equals signs, invalid names, invalid cookie octets, control characters, non-ASCII input, and CRLF reject.
- Header size is checked before scanning. Header bytes, cookie count, and per-cookie bytes are bounded. Defaults are 16384 bytes, 100 cookies, and 4096 bytes per cookie segment.
- ASCII spaces before cookie pairs are tolerated as transport whitespace. Tabs reject as control characters.

## Signed cookie values

Signing provides integrity, key rotation, and expiry. It does not encrypt or hide the value. Anyone who receives the cookie can decode the payload.

```python
from pycookiecage import sign_cookie_value, verify_cookie_value

import os

current = os.urandom(32)
previous = os.urandom(32)
keyring = {
    "2026-02": current,
    "2026-01": previous,
}

signed = sign_cookie_value(
    "session",
    "user-123",
    keyring,
    max_age=300,
    now=1700000000000,
)
result = verify_cookie_value("session", signed, keyring, now=1700000000100)
assert result.value == "user-123"
assert result.rotated is False
```

The signed envelope is `v1.<kid>.<exp>.<payload>.<mac>`. The HMAC input is not simple concatenation. It uses a versioned domain separator, explicit length prefixes for variable fields, and a fixed-width expiration field. This binds cookie name, key id, expiration, and raw value bytes into one non-ambiguous MAC input and prevents cross-cookie substitution.

Verification behavior:

- Uses only stdlib `hmac`, `hashlib.sha256`, and `hmac.compare_digest`.
- Evaluates every active key in the keyring without an early exit.
- The first mapping entry is the primary signing key. A non-primary successful verification returns `rotated=True`.
- Expiration is checked only after MAC verification.
- Payloads and tags must be canonical unpadded base64url. Padding, standard base64 alphabet characters, impossible lengths, and nonzero trailing padding bits reject.
- Expiration fields must be canonical decimal milliseconds since the Unix epoch, with no leading zeros.
- Wrong key ids, cross-cookie substitution, expiration tampering, payload tampering, truncated tags, malformed UTF-8 payloads, and noncanonical encodings fail closed.
- Errors never echo the raw secret or cookie value.

Keys must be at least 32 bytes, contain at least 8 distinct byte values, pass a 128 bit Shannon entropy screening estimate, and must not look like placeholders or obvious repeating or arithmetic byte patterns. Screening cannot prove how a key was generated. Labeled PEM or OpenSSH asymmetric key material always rejects because it must not be confused with an HMAC secret. `allow_weak_keys=True` bypasses only the length, diversity, entropy, pattern, and placeholder checks for deterministic tests and local fixtures. Do not enable it in production.

`now` is an integer Unix epoch timestamp in milliseconds or a timezone-aware `datetime`. `max_age` is in seconds.

## CookieJarGuard

`CookieJarGuard` binds reusable policy defaults in one object.

```python
import os

from pycookiecage import CookieJarGuard

guard = CookieJarGuard(
    {
        "serialize": {"secure": True, "same_site": "Strict", "path": "/"},
        "parse": {"duplicate_policy": "reject"},
        "key_or_keyring": {"2026-02": os.urandom(32)},
    }
)

header = guard.serialize("__Host-session", "value")
cookies = guard.parse("sid=abc")
```

Per-call keyword arguments override policy defaults after strict key validation. The guard's repr does not expose key material.

## Command line inspection

The CLI is structural inspection only. It never accepts key material and never verifies a MAC.

```bash
python3 -m pycookiecage inspect 'sid=abc; theme=light'
python3 -m pycookiecage inspect-cookie 'sid=abc' --show-values
python3 -m pycookiecage inspect-signed "$SIGNED_COOKIE"
```

Cookie values are redacted unless `--show-values` is passed. Output JSON always includes `verified: false` for incoming cookie inspection. Signed inspection reports envelope structure and payload length only.

## Error handling

```python
from pycookiecage import CookieCageError, parse_cookie_header

try:
    parse_cookie_header("sid=1; sid=2")
except CookieCageError as exc:
    assert exc.code == "DUPLICATE_COOKIE"
```

Branch on `exc.code`, not the human-readable message. The stable exported list is `ERROR_CODES`.

## Scope and limitations

- HMAC-SHA256 is the only built-in cryptographic primitive. There is no encryption, no confidentiality, no asymmetric cryptography, no key fetching, no KMS integration, and no framework middleware.
- Signed cookies are integrity-protected but still readable by the client.
- The library does not vendor the full Public Suffix List. Domain validation is conservative and rejects single-label names, bare TLDs, IPv4 and IPv6 literals, ambiguous all-numeric IPv4 spellings, malformed DNS labels, and a built-in set of common multi-part public suffixes. Applications with strict domain requirements should validate their own exact allowed domains.
- The parser handles one already reconstructed Cookie header value. It does not combine multiple header fields.
- The parser does not percent-decode values. Percent decoding is application-specific and can create parser differentials when applied implicitly.
- The serializer emits unquoted cookie-octet values. It does not automatically quote or percent-encode values.
- Python cannot guarantee perfect physical constant time at the interpreter level. The implementation uses `hmac.compare_digest`, fixed-length tags, and no keyring early exit.
- The library does not decide cookie ownership, session rotation, CSRF policy, or which domains and keys an application trusts.

## Test evidence and development

The offline unittest suite currently contains 585 real deterministic tests covering RFC 6265 validation, case-insensitive prefixes, attribute invariants, CRLF and smuggling rejection, cookie-tossing defenses, parser bounds, HMAC framing, rotation, canonical base64url, expiry, weak-key rejection, the guard, the CLI, typing exports, packaging, and repository hygiene. All 585 tests passed in the local verification run for this commit.

Run the suite with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

The project has no runtime dependencies and no third-party test dependencies.
