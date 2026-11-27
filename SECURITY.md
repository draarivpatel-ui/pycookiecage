# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

Security fixes land on the latest 1.x release. Upgrade before reporting an issue that only reproduces on an older release.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/pycookiecage/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

- The affected pycookiecage version or commit.
- The Python version and operating system.
- A minimal proof of concept or input that demonstrates the problem.
- The expected behavior and the observed behavior.
- A short assessment of impact and any preconditions.

Do not include real credentials, tokens, cookies, private keys, customer data or personal data in a report. Redact secrets before attaching logs.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix or documented mitigation within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed state and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

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
