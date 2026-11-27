# Good first issues

Ten modular starter tasks for new contributors. Each is scoped to one file or one focused behavior. Every task must preserve the zero runtime dependency rule and Python 3.9 compatibility.

1. **Add RFC 6265 token matrix tests** in `tests/test_serialization.py` covering every allowed punctuation character in cookie names and one rejected position for every forbidden separator.
2. **Add a cookie-octet boundary matrix** in `tests/test_serialization.py` that exhaustively checks byte values 0x00 through 0x7F as one-character cookie values.
3. **Add domain regression fixtures** in `tests/test_serialization.py` for additional malformed IPv4 spellings, long labels, repeated dots, and mixed uppercase DNS names.
4. **Add cookie-tossing order tests** in `tests/test_parsing.py` proving that `first` and `last` differ when three or more duplicate names appear in different positions.
5. **Add a parser decision record** in `docs/parser-decisions.md` documenting whether repeated ASCII spaces before cookie pairs should remain accepted, with compatibility and security tradeoffs.
6. **Add HTTP/2 reconstruction guidance** in `README.md` explaining that safe Cookie header combination is the server framework's responsibility before this strict single-header parser is called.
7. **Add a base64url trailing-bit matrix** in `tests/test_signing.py` covering every noncanonical final-character variant for payload lengths modulo 2 and modulo 3.
8. **Add keyring mutation regression tests** in `tests/test_signing.py` proving that changing a mapping after signing does not alter already produced signed strings and that verification uses the caller's current explicit keyring.
9. **Add CLI golden-file tests** in `tests/test_cli.py` using small JSON fixtures stored under `tests/fixtures/`, while keeping cookie values redacted by default.
10. **Write `docs/threat-model.md`** describing attacker capabilities, trust boundaries, key ownership, parser responsibilities, and application responsibilities.

Before starting one, open an issue or comment on the existing issue so work is not duplicated. Add tests with every code change.
