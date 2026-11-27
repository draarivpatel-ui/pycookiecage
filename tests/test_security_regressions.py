"""Focused regression tests for red-team lessons and integration behavior."""

import datetime
import re
import unittest

from pycookiecage import parse_cookie_header, serialize_cookie, sign_cookie_value, verify_cookie_value

from _support import NOW_MS, STRONG_KEY, STRONG_KEY_2, assert_error_code


class SerializationRegressionTests(unittest.TestCase):
    def test_nan_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=float("nan"))

    def test_positive_infinity_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=float("inf"))

    def test_negative_infinity_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=float("-inf"))

    def test_non_string_path_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, "sid", "abc", path=1)

    def test_non_string_domain_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, "sid", "abc", domain=1)

    def test_domain_slash_rejects(self):
        assert_error_code(self, "INVALID_DOMAIN", serialize_cookie, "sid", "abc", domain="example.com/path")

    def test_domain_port_rejects(self):
        assert_error_code(self, "INVALID_DOMAIN", serialize_cookie, "sid", "abc", domain="example.com:443")

    def test_domain_semicolon_smuggling_rejects(self):
        assert_error_code(self, "INVALID_DOMAIN", serialize_cookie, "sid", "abc", domain="example.com;Secure")



    def test_expires_utc_conversion_overflow_rejects_typed_error(self):
        zone = datetime.timezone(datetime.timedelta(hours=-23, minutes=59))
        moment = datetime.datetime(9999, 12, 31, 23, 59, tzinfo=zone)
        assert_error_code(self, "INVALID_EXPIRES", serialize_cookie, "sid", "abc", expires=moment)

    def test_lone_surrogate_value_rejects_with_typed_error(self):
        assert_error_code(self, "NON_ASCII", serialize_cookie, "sid", "a\ud800b")

    def test_lone_surrogate_domain_rejects_with_typed_error(self):
        assert_error_code(self, "NON_ASCII", serialize_cookie, "sid", "abc", domain="exa\ud800mple.com")

    def test_serialized_output_never_contains_crlf_for_hostile_inputs(self):
        hostile_inputs = [
            ("bad\rname", "abc", {}),
            ("bad\nname", "abc", {}),
            ("sid", "abc\rdef", {}),
            ("sid", "abc", {"path": "/\r\n"}),
            ("sid", "abc", {"domain": "example.com\r\n"}),
        ]
        for name, value, options in hostile_inputs:
            with self.assertRaises(Exception):
                serialize_cookie(name, value, **options)


class ParserRegressionTests(unittest.TestCase):
    def test_duplicate_error_does_not_expose_cookie_values(self):
        first = "first-sensitive-value"
        second = "second-sensitive-value"
        try:
            parse_cookie_header("sid=" + first + "; sid=" + second)
        except Exception as exc:
            self.assertNotIn(first, str(exc))
            self.assertNotIn(second, str(exc))
        else:
            self.fail("duplicate cookie unexpectedly accepted")


    def test_lone_surrogate_header_rejects_with_typed_error(self):
        assert_error_code(self, "NON_ASCII", parse_cookie_header, "sid=a\ud800b")

    def test_repeated_calls_return_independent_dicts(self):
        first = parse_cookie_header("sid=one")
        first["sid"] = "mutated"
        second = parse_cookie_header("sid=one")
        self.assertEqual("one", second["sid"])

    def test_default_count_bound_rejects_101_cookies(self):
        header = ";".join("k{}=v".format(index) for index in range(101))
        assert_error_code(self, "LIMIT_EXCEEDED", parse_cookie_header, header)

    def test_default_count_bound_accepts_100_cookies(self):
        header = ";".join("k{}=v".format(index) for index in range(100))
        self.assertEqual(100, len(parse_cookie_header(header)))

    def test_header_bound_rejects_one_byte_over(self):
        assert_error_code(self, "LIMIT_EXCEEDED", parse_cookie_header, "a=1", max_header_bytes=2)

    def test_single_cookie_at_default_segment_bound_accepts(self):
        value_length = 4096 - len("sid=")
        header = "sid=" + "x" * value_length
        self.assertEqual({"sid": "x" * value_length}, parse_cookie_header(header))

    def test_single_cookie_over_default_segment_bound_rejects(self):
        value_length = 4096 - len("sid=") + 1
        assert_error_code(self, "LIMIT_EXCEEDED", parse_cookie_header, "sid=" + "x" * value_length)


class SigningRegressionTests(unittest.TestCase):

    def test_oversize_cookie_name_rejects_before_signing(self):
        assert_error_code(self, "LIMIT_EXCEEDED", sign_cookie_value, "n" * 4097, "abc", STRONG_KEY, now=NOW_MS)

    def test_signed_output_uses_cookie_safe_ascii(self):
        signed = sign_cookie_value("sid", "payload", STRONG_KEY, now=NOW_MS)
        self.assertRegex(signed, r"^[A-Za-z0-9_.\-]+\Z")

    def test_signed_output_can_be_serialized_as_cookie_value(self):
        signed = sign_cookie_value("sid", "payload", STRONG_KEY, now=NOW_MS)
        output = serialize_cookie("sid", signed)
        self.assertIn("sid=" + signed + ";", output)

    def test_signed_output_can_roundtrip_through_parser_and_verify(self):
        signed = sign_cookie_value("sid", "payload", STRONG_KEY, now=NOW_MS)
        parsed = parse_cookie_header("sid=" + signed)
        result = verify_cookie_value("sid", parsed["sid"], STRONG_KEY, now=NOW_MS)
        self.assertEqual("payload", result.value)

    def test_mac_high_bit_tampering_rejects(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        last = signed[-1]
        mutated_last = alphabet[alphabet.index(last) ^ 32]
        mutated = signed[:-1] + mutated_last
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", mutated, STRONG_KEY, now=NOW_MS)

    def test_key_id_embedded_in_mac_even_for_same_secret(self):
        keyring = {"one": STRONG_KEY, "two": STRONG_KEY}
        signed = sign_cookie_value("sid", "abc", {"one": STRONG_KEY}, now=NOW_MS)
        parts = signed.split(".")
        parts[1] = "two"
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), keyring, now=NOW_MS)

    def test_unknown_key_id_cannot_verify_with_other_active_keys(self):
        keyring = {"active": STRONG_KEY, "other": STRONG_KEY_2}
        signed = sign_cookie_value("sid", "abc", {"missing": STRONG_KEY}, now=NOW_MS)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", signed, keyring, now=NOW_MS)

    def test_removed_rotation_key_can_no_longer_verify(self):
        old_ring = {"new": STRONG_KEY, "old": STRONG_KEY_2}
        signed = sign_cookie_value("sid", "abc", {"old": STRONG_KEY_2}, now=NOW_MS)
        self.assertTrue(verify_cookie_value("sid", signed, old_ring, now=NOW_MS).rotated)
        new_ring = {"new": STRONG_KEY}
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", signed, new_ring, now=NOW_MS)

    def test_key_id_may_contain_hyphen_and_underscore(self):
        keyring = {"a-b_c": STRONG_KEY}
        signed = sign_cookie_value("sid", "abc", keyring, now=NOW_MS)
        self.assertEqual("a-b_c", verify_cookie_value("sid", signed, keyring, now=NOW_MS).key_id)

    def test_signing_value_limit_counts_utf8_bytes(self):
        value = "\U0001f600" * 1100
        assert_error_code(self, "LIMIT_EXCEEDED", sign_cookie_value, "sid", value, STRONG_KEY, now=NOW_MS)

    def test_payload_plus_character_rejects_even_when_length_valid(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS)
        parts = signed.split(".")
        parts[3] = "+" + parts[3][1:]
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_oversized_signed_value_rejects_before_parsing(self):
        signed = "v1.k1.0." + "A" * 4100 + "." + "A" * 43
        assert_error_code(self, "LIMIT_EXCEEDED", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS)

    def test_expiration_overflow_rejects(self):
        assert_error_code(
            self,
            "INVALID_OPTIONS",
            sign_cookie_value,
            "sid",
            "abc",
            STRONG_KEY,
            now=9999999999999999,
            max_age=1,
        )



    def test_pre_epoch_datetime_now_rejects(self):
        zone = datetime.timezone(datetime.timedelta(hours=23, minutes=59))
        moment = datetime.datetime(1, 1, 1, 0, 0, tzinfo=zone)
        assert_error_code(self, "INVALID_OPTIONS", sign_cookie_value, "sid", "abc", STRONG_KEY, now=moment)

    def test_lone_surrogate_signing_value_rejects_with_typed_error(self):
        assert_error_code(self, "ENCODING_ERROR", sign_cookie_value, "sid", "a\ud800b", STRONG_KEY, now=NOW_MS)

    def test_lone_surrogate_secret_rejects_with_typed_error(self):
        secret = "a\ud800b" + "x" * 40
        assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", secret, now=NOW_MS)

    def test_error_context_is_suppressed_for_utf8_payload_failure(self):
        payload_bytes = b"\xff"
        import base64
        import pycookiecage.signing as signing_module
        payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        mac = signing_module._b64url_encode(signing_module._mac_for(STRONG_KEY, "sid", "k1", 0, payload_bytes))
        signed = "v1.k1.0.{}.{}".format(payload, mac)
        try:
            verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS)
        except Exception as exc:
            self.assertTrue(getattr(exc, "__suppress_context__", False))
        else:
            self.fail("invalid UTF-8 payload unexpectedly accepted")

    def test_non_boolean_allow_weak_keys_sign_rejects(self):
        assert_error_code(self, "INVALID_INPUT", sign_cookie_value, "sid", "abc", STRONG_KEY, now=NOW_MS, allow_weak_keys=1)

    def test_non_boolean_allow_weak_keys_verify_rejects(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS)
        assert_error_code(self, "INVALID_INPUT", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS, allow_weak_keys=1)


if __name__ == "__main__":
    unittest.main()
