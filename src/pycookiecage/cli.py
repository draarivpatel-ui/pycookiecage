"""Command line inspection interface.

The CLI never accepts key material and never verifies a signature. It reports
structural information only. Cookie values are redacted unless the operator
explicitly passes ``--show-values``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .errors import CookieCageError
from .parsing import (
    DEFAULT_MAX_COOKIES,
    DEFAULT_MAX_COOKIE_BYTES,
    DEFAULT_MAX_HEADER_BYTES,
    parse_cookie_header,
)
from .signing import _parse_signed_value


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _add_cookie_inspect_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("header", help="incoming Cookie header value")
    parser.add_argument(
        "--duplicate-policy",
        choices=("reject", "first", "last"),
        default="reject",
        help="duplicate cookie name policy (default: %(default)s)",
    )
    parser.add_argument("--max-header-bytes", type=_positive_int, default=DEFAULT_MAX_HEADER_BYTES)
    parser.add_argument("--max-cookies", type=_positive_int, default=DEFAULT_MAX_COOKIES)
    parser.add_argument("--max-cookie-bytes", type=_positive_int, default=DEFAULT_MAX_COOKIE_BYTES)
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="include exact unverified cookie values in the report",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the command line argument parser."""
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="pycookiecage",
        description="Inspect Cookie headers and signed cookie envelopes without verifying them.",
    )
    parser.add_argument("--version", action="version", version="pycookiecage {}".format(__version__))
    subparsers = parser.add_subparsers(dest="command")

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="inspect an incoming Cookie header using strict structural checks",
    )
    _add_cookie_inspect_arguments(inspect_parser)

    cookie_parser = subparsers.add_parser(
        "inspect-cookie",
        help="inspect an incoming Cookie header using strict structural checks",
    )
    _add_cookie_inspect_arguments(cookie_parser)

    signed_parser = subparsers.add_parser(
        "inspect-signed",
        help="inspect a signed cookie envelope without verifying its MAC",
    )
    signed_parser.add_argument("signed_value", help="signed cookie envelope")
    return parser


def _inspect_cookie(args: argparse.Namespace) -> int:
    try:
        parsed = parse_cookie_header(
            args.header,
            duplicate_policy=args.duplicate_policy,
            max_header_bytes=args.max_header_bytes,
            max_cookies=args.max_cookies,
            max_cookie_bytes=args.max_cookie_bytes,
        )
    except CookieCageError as exc:
        print("pycookiecage: error: {}".format(exc), file=sys.stderr)
        return 3

    cookies = []
    for name, value in parsed.items():
        item = {
            "name": name,
            "quoted": len(value) >= 2 and value.startswith('"') and value.endswith('"'),
            "value_bytes": len(value.encode("utf-8")),
        }
        if args.show_values:
            item["value"] = value
        cookies.append(item)
    report = {
        "count": len(cookies),
        "cookies": cookies,
        "verified": False,
        "note": "Cookie values are unverified input. Do not trust them without application authentication.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _inspect_signed(args: argparse.Namespace) -> int:
    try:
        parsed = _parse_signed_value(args.signed_value)
    except CookieCageError as exc:
        print("pycookiecage: error: {}".format(exc), file=sys.stderr)
        return 3
    report = {
        "version": "v1",
        "key_id": parsed.key_id,
        "expires_at": None if parsed.expires_at == 0 else parsed.expires_at,
        "payload_bytes": len(parsed.payload_bytes),
        "payload_base64url_bytes": len(parsed.payload.encode("ascii")),
        "mac_bytes": len(parsed.mac),
        "verified": False,
        "note": "The MAC and expiry are not verified by this command. Structure only.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CLI and return the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in ("inspect", "inspect-cookie"):
        return _inspect_cookie(args)
    if args.command == "inspect-signed":
        return _inspect_signed(args)
    parser.print_help(sys.stderr)
    return 2


__all__ = ["build_parser", "main"]
