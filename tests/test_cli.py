"""Command line inspection tests."""

import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pycookiecage import sign_cookie_value
from pycookiecage.cli import build_parser, main

from _support import NOW_MS, STRONG_KEY


def run_cli(args):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(args)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def test_no_command_returns_usage_error(self):
        code, stdout, stderr = run_cli([])
        self.assertEqual(2, code)
        self.assertEqual("", stdout)
        self.assertIn("usage:", stderr)

    def test_parser_program_name(self):
        self.assertEqual("pycookiecage", build_parser().prog)

    def test_inspect_cookie_success(self):
        code, stdout, stderr = run_cli(["inspect", "sid=abc"])
        self.assertEqual(0, code)
        self.assertEqual("", stderr)
        report = json.loads(stdout)
        self.assertEqual(1, report["count"])
        self.assertEqual("sid", report["cookies"][0]["name"])
        self.assertFalse(report["verified"])

    def test_inspect_cookie_alias_success(self):
        code, stdout, stderr = run_cli(["inspect-cookie", "sid=abc"])
        self.assertEqual(0, code)
        self.assertEqual("", stderr)
        self.assertEqual(1, json.loads(stdout)["count"])

    def test_values_redacted_by_default(self):
        code, stdout, stderr = run_cli(["inspect", "sid=secret-value"])
        report = json.loads(stdout)
        self.assertNotIn("value", report["cookies"][0])
        self.assertNotIn("secret-value", stdout)

    def test_show_values_includes_exact_value(self):
        code, stdout, stderr = run_cli(["inspect", "sid=abc", "--show-values"])
        report = json.loads(stdout)
        self.assertEqual("abc", report["cookies"][0]["value"])

    def test_quoted_flag_true(self):
        code, stdout, stderr = run_cli(["inspect", 'sid="abc"'])
        report = json.loads(stdout)
        self.assertTrue(report["cookies"][0]["quoted"])

    def test_unquoted_flag_false(self):
        code, stdout, stderr = run_cli(["inspect", "sid=abc"])
        report = json.loads(stdout)
        self.assertFalse(report["cookies"][0]["quoted"])

    def test_value_byte_count_is_reported(self):
        code, stdout, stderr = run_cli(["inspect", "sid=abcd"])
        report = json.loads(stdout)
        self.assertEqual(4, report["cookies"][0]["value_bytes"])

    def test_multiple_cookie_count_is_reported(self):
        code, stdout, stderr = run_cli(["inspect", "a=1; b=2"])
        report = json.loads(stdout)
        self.assertEqual(2, report["count"])

    def test_duplicate_default_returns_error_code_3(self):
        code, stdout, stderr = run_cli(["inspect", "sid=1; sid=2"])
        self.assertEqual(3, code)
        self.assertEqual("", stdout)
        self.assertIn("DUPLICATE_COOKIE", stderr)

    def test_duplicate_policy_last_is_accepted(self):
        code, stdout, stderr = run_cli(["inspect", "sid=1; sid=2", "--duplicate-policy", "last"])
        self.assertEqual(0, code)
        report = json.loads(stdout)
        self.assertEqual(1, report["count"])

    def test_invalid_input_returns_error_code_3(self):
        code, stdout, stderr = run_cli(["inspect", "not-a-pair"])
        self.assertEqual(3, code)
        self.assertIn("PARSE_ERROR", stderr)

    def test_error_output_does_not_call_input_verified(self):
        code, stdout, stderr = run_cli(["inspect", "not-a-pair"])
        self.assertNotIn("verified: true", stderr.lower())

    def test_max_header_option_is_honored(self):
        code, stdout, stderr = run_cli(["inspect", "sid=abcdef", "--max-header-bytes", "3"])
        self.assertEqual(3, code)
        self.assertIn("LIMIT_EXCEEDED", stderr)

    def test_max_cookies_option_is_honored(self):
        code, stdout, stderr = run_cli(["inspect", "a=1; b=2", "--max-cookies", "1"])
        self.assertEqual(3, code)
        self.assertIn("LIMIT_EXCEEDED", stderr)

    def test_max_cookie_bytes_option_is_honored(self):
        code, stdout, stderr = run_cli(["inspect", "a=123456", "--max-cookie-bytes", "4"])
        self.assertEqual(3, code)
        self.assertIn("LIMIT_EXCEEDED", stderr)

    def test_inspect_signed_success(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS, max_age=60)
        code, stdout, stderr = run_cli(["inspect-signed", signed])
        self.assertEqual(0, code)
        report = json.loads(stdout)
        self.assertEqual("v1", report["version"])
        self.assertEqual("k1", report["key_id"])
        self.assertEqual(NOW_MS + 60000, report["expires_at"])
        self.assertEqual(3, report["payload_bytes"])
        self.assertEqual(32, report["mac_bytes"])
        self.assertFalse(report["verified"])

    def test_inspect_signed_non_expiring_reports_null_expiry(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS)
        code, stdout, stderr = run_cli(["inspect-signed", signed])
        self.assertIsNone(json.loads(stdout)["expires_at"])

    def test_inspect_signed_does_not_print_payload(self):
        signed = sign_cookie_value("sid", "sensitive-payload", STRONG_KEY, now=NOW_MS)
        code, stdout, stderr = run_cli(["inspect-signed", signed])
        self.assertEqual(0, code)
        self.assertNotIn("sensitive-payload", stdout)

    def test_inspect_signed_invalid_structure_returns_3(self):
        code, stdout, stderr = run_cli(["inspect-signed", "not-valid"])
        self.assertEqual(3, code)
        self.assertIn("INVALID_SIGNATURE", stderr)

    def test_inspect_signed_never_verifies_even_with_valid_mac(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS)
        code, stdout, stderr = run_cli(["inspect-signed", signed])
        report = json.loads(stdout)
        self.assertFalse(report["verified"])
        self.assertIn("not verified", report["note"])

    def test_module_invocation_works(self):
        completed = subprocess.run(
            [sys.executable, "-m", "pycookiecage", "inspect", "sid=abc"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        self.assertEqual(0, completed.returncode)
        self.assertEqual(1, json.loads(completed.stdout)["count"])

    def test_module_invocation_error_exit(self):
        completed = subprocess.run(
            [sys.executable, "-m", "pycookiecage", "inspect", "bad"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        self.assertEqual(3, completed.returncode)
        self.assertIn("PARSE_ERROR", completed.stderr)


if __name__ == "__main__":
    unittest.main()
