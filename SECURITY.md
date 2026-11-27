# Security Policy

## Supported versions

Version 1.x receives security fixes.

## Reporting a vulnerability

Please use GitHub's private security advisory form on the repository. Do not open a public issue for an undisclosed vulnerability.

Include the affected version, a minimal input or code reproduction, the expected behavior, and the observed behavior. Do not include real secrets, session cookies, production signed values, or personal data. Reports are acknowledged within seven days. Fixes are released as patch versions with a changelog entry.

## In scope

- `__Host-` or `__Secure-` prefix enforcement bypasses, including ASCII case variants
- `SameSite=None` or `Partitioned` emitted without `Secure`
- CRLF, control character, semicolon, or cookie-octet validation bypasses
- Cookie-tossing duplicate handling bypasses
- Parser behavior that exceeds documented byte or count bounds
- HMAC comparison, key-strength policy, or keyring evaluation bypasses
- Cross-cookie or cross-key substitution caused by ambiguous MAC framing
- Non-canonical base64url acceptance in signed values
- Expiration checked before authentication or otherwise bypassed
- Error output that discloses secret or raw cookie value material
- CLI behavior that implies unverified data is verified

## Out of scope

- Vulnerabilities in applications using this library
- Application decisions about trusted domains, session ownership, CSRF defenses, or key storage
- Denial of service from inputs above documented parser limits
- Use of `allow_weak_keys=True` outside tests or local fixtures
- Physical access, social engineering, or compromised Python runtimes
- The incomplete built-in public suffix defense when exact domain allowlisting is required by the application

## Design notes

pycookiecage is defensive only. It performs no network access, filesystem access, subprocess execution, browser interaction, key fetching, or remote validation. Built-in cryptography is limited to HMAC-SHA256 using Python `hmac` and `hashlib`.

Signed-cookie expiration is evaluated only after MAC authentication. Structural command line inspection is explicitly unverified. Exceptions are designed not to contain cookie values or secret material.
