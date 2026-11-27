# Contributing

Thanks for helping improve pycookiecage. The project has zero runtime dependencies and targets Python 3.9 through 3.13.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Running tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Every change must keep the suite green using Python 3.9 syntax. No third-party test packages are required.

## Security invariants

- Keep `dependencies = []` in `pyproject.toml`.
- Keep `__Host-` and `__Secure-` enforcement ASCII case-insensitive.
- Preserve the distinction between quoted and unquoted parsed values.
- Reject duplicate cookie names unless the caller explicitly selects `first` or `last`.
- Keep input bounds enforced before scanning or allocation-heavy work.
- Keep HMAC verification constant time through `hmac.compare_digest`.
- Evaluate every active key in a keyring without an early exit.
- Keep expiration checks after MAC verification.
- Keep base64url decoding canonical and reject nonzero trailing pad bits.
- Keep key material and raw cookie values out of exceptions, logs, repr output, tests, and documentation.
- Add regression tests for every validation rule or bug fix.
- Prefer explicit opt-in for unsafe compatibility behavior.
- Do not add em dashes or en dashes to source, docs, tests, or workflow files.

## Code guidelines

- Use only the Python standard library at runtime.
- Use type annotations on public functions.
- Preserve Python 3.9 compatibility.
- Raise `CookieCageError` with a stable machine-readable code for every expected failure.
- Keep error messages free of secrets and attacker-controlled values.
- Keep structural validation deterministic and bounded.

## Pull requests

1. Fork the repository and create a focused branch.
2. Describe the security impact of the change.
3. Add or update regression tests.
4. Run the full suite and paste the result.
5. Keep commits small and self-contained.

## Good first issues

See [docs/good-first-issues.md](docs/good-first-issues.md) for ten modular starter tasks.
