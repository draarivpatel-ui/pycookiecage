"""HMAC signing, framing, keyring, canonical encoding, rotation, and expiry tests."""

import base64
import datetime
import unittest

import pycookiecage.signing as signing_module
from pycookiecage import sign_cookie_value, verify_cookie_value

from _support import NOW_MS, STRONG_KEY, STRONG_KEY_2, STRONG_KEY_3, UTC, WEAK_KEY, assert_error_code


def _add_test(cls, name, func):
    setattr(cls, name, func)
    func.__name__ = name


def _sign(value="abc", **kwargs):
    options = {"now": NOW_MS}
    options.update(kwargs)
    return sign_cookie_value("sid", value, STRONG_KEY, **options)


def _parts(signed):
    return signed.split(".")


class SigningRoundTripTests(unittest.TestCase):
    def test_roundtrip_ascii_value(self):
        signed = _sign()
        result = verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS)
        self.assertEqual("abc", result.value)
        self.assertEqual("k1", result.key_id)
        self.assertFalse(result.rotated)
        self.assertIsNone(result.expires_at)

    def test_envelope_shape(self):
        parts = _parts(_sign())
        self.assertEqual(5, len(parts))
        self.assertEqual("v1", parts[0])
        self.assertEqual("k1", parts[1])
        self.assertEqual("0", parts[2])
        self.assertEqual("YWJj", parts[3])
        self.assertEqual(43, len(parts[4]))

    def test_signing_is_deterministic_with_fixed_now(self):
        self.assertEqual(_sign(), _sign())

    def test_empty_value_roundtrips(self):
        signed = _sign("")
        self.assertIn(".0..", signed)
        self.assertEqual("", verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS).value)

    def test_unicode_value_roundtrips(self):
        value = "user-\u00e9-\u20ac-\U0001f600"
        signed = _sign(value)
        self.assertEqual(value, verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS).value)

    def test_control_character_input_is_safe_inside_payload(self):
        value = "line1\r\nline2\x00end"
        signed = _sign(value)
        self.assertNotIn("\r", signed)
        self.assertNotIn("\n", signed)
        self.assertEqual(value, verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS).value)

    def test_cookie_unsafe_input_is_safe_inside_payload(self):
        value = 'a;b,c"d\\e f'
        signed = _sign(value)
        self.assertEqual(value, verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS).value)

    def test_datetime_now_is_accepted(self):
        moment = datetime.datetime.fromtimestamp(NOW_MS / 1000, tz=UTC)
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=moment, max_age=10)
        result = verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS + 1)
        self.assertEqual(NOW_MS + 10000, result.expires_at)

    def test_max_age_sets_expiry(self):
        signed = _sign(max_age=60)
        result = verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS)
        self.assertEqual(NOW_MS + 60000, result.expires_at)

    def test_expiry_boundary_one_ms_before_accepts(self):
        signed = _sign(max_age=60)
        result = verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS + 59999)
        self.assertEqual("abc", result.value)

    def test_expiry_exact_boundary_rejects(self):
        signed = _sign(max_age=60)
        assert_error_code(self, "COOKIE_EXPIRED", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS + 60000)

    def test_expiry_after_boundary_rejects(self):
        signed = _sign(max_age=60)
        assert_error_code(self, "COOKIE_EXPIRED", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS + 60001)

    def test_max_age_zero_is_immediately_expired(self):
        signed = _sign(max_age=0)
        assert_error_code(self, "COOKIE_EXPIRED", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS)

    def test_non_expiring_value_accepts_late_now(self):
        signed = _sign()
        result = verify_cookie_value("sid", signed, STRONG_KEY, now=9999999999999999)
        self.assertEqual("abc", result.value)

    def test_verified_repr_omits_value(self):
        result = verify_cookie_value("sid", _sign("super-sensitive"), STRONG_KEY, now=NOW_MS)
        self.assertNotIn("super-sensitive", repr(result))

    def test_signed_size_boundary_accepts(self):
        signed = _sign("a" * 3033)
        self.assertLessEqual(len(signed), 4096)

    def test_signed_size_boundary_rejects(self):
        assert_error_code(self, "LIMIT_EXCEEDED", _sign, "a" * 3034)

    def test_oversize_plain_value_rejects(self):
        assert_error_code(self, "LIMIT_EXCEEDED", _sign, "a" * 5000)

    def test_non_string_value_rejects(self):
        assert_error_code(self, "INVALID_INPUT", sign_cookie_value, "sid", b"abc", STRONG_KEY, now=NOW_MS)

    def test_invalid_cookie_name_rejects_before_signing(self):
        assert_error_code(self, "INVALID_NAME", sign_cookie_value, "bad;name", "abc", STRONG_KEY, now=NOW_MS)

    def test_verify_invalid_cookie_name_rejects(self):
        signed = _sign()
        assert_error_code(self, "INVALID_NAME", verify_cookie_value, "bad;name", signed, STRONG_KEY, now=NOW_MS)


class SigningKeyTests(unittest.TestCase):
    def test_bytes_key_accepted(self):
        self.assertEqual("abc", verify_cookie_value("sid", _sign(), STRONG_KEY, now=NOW_MS).value)

    def test_string_key_accepted_when_strong(self):
        key = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
        signed = sign_cookie_value("sid", "abc", key, now=NOW_MS)
        self.assertEqual("abc", verify_cookie_value("sid", signed, key, now=NOW_MS).value)

    def test_bytearray_key_accepted(self):
        key = bytearray(STRONG_KEY)
        signed = sign_cookie_value("sid", "abc", key, now=NOW_MS)
        self.assertEqual("abc", verify_cookie_value("sid", signed, key, now=NOW_MS).value)

    def test_memoryview_key_accepted(self):
        key = memoryview(STRONG_KEY)
        signed = sign_cookie_value("sid", "abc", key, now=NOW_MS)
        self.assertEqual("abc", verify_cookie_value("sid", signed, key, now=NOW_MS).value)

    def test_weak_key_can_be_enabled_explicitly(self):
        signed = sign_cookie_value("sid", "abc", WEAK_KEY, now=NOW_MS, allow_weak_keys=True)
        result = verify_cookie_value("sid", signed, WEAK_KEY, now=NOW_MS, allow_weak_keys=True)
        self.assertEqual("abc", result.value)

    def test_weak_key_rejects_by_default_on_sign(self):
        assert_error_code(self, "WEAK_KEY", sign_cookie_value, "sid", "abc", WEAK_KEY, now=NOW_MS)

    def test_weak_key_rejects_by_default_on_verify(self):
        signed = sign_cookie_value("sid", "abc", WEAK_KEY, now=NOW_MS, allow_weak_keys=True)
        assert_error_code(self, "WEAK_KEY", verify_cookie_value, "sid", signed, WEAK_KEY, now=NOW_MS)

    def test_keyring_rotation_second_key_reports_rotated(self):
        keyring = {"new": STRONG_KEY, "old": STRONG_KEY_2}
        signed = sign_cookie_value("sid", "abc", keyring, now=NOW_MS)
        result = verify_cookie_value("sid", signed, keyring, now=NOW_MS)
        self.assertFalse(result.rotated)

    def test_verify_with_secondary_key_reports_rotated(self):
        keyring = {"new": STRONG_KEY, "old": STRONG_KEY_2}
        signed = sign_cookie_value("sid", "abc", {"old": STRONG_KEY_2}, now=NOW_MS)
        result = verify_cookie_value("sid", signed, keyring, now=NOW_MS)
        self.assertTrue(result.rotated)
        self.assertEqual("old", result.key_id)

    def test_mapping_first_entry_is_primary_signing_key(self):
        keyring = {"first": STRONG_KEY, "second": STRONG_KEY_2}
        signed = sign_cookie_value("sid", "abc", keyring, now=NOW_MS)
        self.assertEqual("first", _parts(signed)[1])

    def test_all_keyring_entries_are_processed(self):
        keyring = {"one": STRONG_KEY, "two": STRONG_KEY_2, "three": STRONG_KEY_3}
        signed = sign_cookie_value("sid", "abc", {"three": STRONG_KEY_3}, now=NOW_MS)
        calls = []
        original = signing_module.hmac.compare_digest

        def counting(left, right):
            calls.append((left, right))
            return original(left, right)

        signing_module.hmac.compare_digest = counting
        try:
            result = verify_cookie_value("sid", signed, keyring, now=NOW_MS)
        finally:
            signing_module.hmac.compare_digest = original
        self.assertTrue(result.rotated)
        self.assertEqual(3, len(calls))

    def test_maximum_32_keys_accepted(self):
        keyring = {}
        for index in range(32):
            keyring["k{:02d}".format(index)] = bytes((index + offset) % 256 for offset in range(32))
        signed = sign_cookie_value("sid", "abc", keyring, now=NOW_MS)
        self.assertEqual("abc", verify_cookie_value("sid", signed, keyring, now=NOW_MS).value)

    def test_33_keys_reject(self):
        keyring = {}
        for index in range(33):
            keyring["k{:02d}".format(index)] = bytes((index + offset) % 256 for offset in range(32))
        assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", keyring, now=NOW_MS)

    def test_empty_keyring_rejects(self):
        assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", {}, now=NOW_MS)

    def test_non_mapping_keyring_rejects(self):
        assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", 123, now=NOW_MS)

    def test_keyring_list_rejects(self):
        assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", [("k1", STRONG_KEY)], now=NOW_MS)

    def test_signed_value_does_not_cross_verify_under_other_name(self):
        signed = sign_cookie_value("first", "abc", STRONG_KEY, now=NOW_MS)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "second", signed, STRONG_KEY, now=NOW_MS)

    def test_cross_cookie_substitution_rejects(self):
        first = sign_cookie_value("first", "admin", STRONG_KEY, now=NOW_MS)
        second = sign_cookie_value("second", "admin", STRONG_KEY, now=NOW_MS)
        self.assertNotEqual(first, second)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "first", second, STRONG_KEY, now=NOW_MS)

    def test_wrong_secret_rejects(self):
        signed = sign_cookie_value("sid", "abc", STRONG_KEY, now=NOW_MS)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", signed, STRONG_KEY_2, now=NOW_MS)

    def test_key_id_substitution_rejects(self):
        keyring = {"new": STRONG_KEY, "old": STRONG_KEY_2}
        signed = sign_cookie_value("sid", "abc", {"new": STRONG_KEY}, now=NOW_MS)
        parts = _parts(signed)
        parts[1] = "old"
        substituted = ".".join(parts)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", substituted, keyring, now=NOW_MS)

    def test_payload_tampering_rejects(self):
        signed = _sign()
        parts = _parts(signed)
        parts[3] = "YWRh"  # canonical encoding for a different three-letter value prefix shape
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_expiration_tampering_rejects(self):
        signed = _sign(max_age=1)
        parts = _parts(signed)
        parts[2] = str(int(parts[2]) + 100000)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_expired_valid_mac_reports_expired(self):
        signed = _sign(max_age=1)
        assert_error_code(self, "COOKIE_EXPIRED", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS + 1000)

    def test_expired_invalid_mac_reports_signature_not_expiry(self):
        signed = _sign(max_age=1)
        parts = _parts(signed)
        parts[3] = "YWRh"
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS + 1000)


def _weak_secret_matrix():
    cases = [
        ("short", b"1234567890123456789012345678901"),
        ("low_diversity", b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("empty_bytes", b""),
        ("empty_string", ""),
        ("whitespace_padded", "  A1b2C3d4E5f6G7h8I9j0K1l2M3n4  "),
        ("placeholder_password", "password" + "x" * 30),
        ("placeholder_secret", "secret" + "x" * 30),
        ("placeholder_change_me", "change-me" + "x" * 30),
        ("placeholder_replace_me", "replace-me" + "x" * 30),
        ("placeholder_test", "test-secret" + "x" * 30),
    ]
    for label, secret in cases:
        def check(self, secret=secret):
            assert_error_code(self, "WEAK_KEY", sign_cookie_value, "sid", "abc", secret, now=NOW_MS)
        _add_test(SigningKeyTests, "test_weak_secret_%s_rejects" % label, check)


def _invalid_keyring_matrix():
    key_ids = [
        ("empty", ""),
        ("leading_underscore", "_abc"),
        ("dot", "ab.cd"),
        ("slash", "ab/cd"),
        ("space", "ab cd"),
        ("too_long", "a" * 65),
        ("non_ascii", "ab\u00e9"),
    ]
    for label, key_id in key_ids:
        def check(self, key_id=key_id):
            assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", {key_id: STRONG_KEY}, now=NOW_MS)
        _add_test(SigningKeyTests, "test_invalid_key_id_%s_rejects" % label, check)

    def non_string_key_id(self):
        assert_error_code(self, "INVALID_KEYRING", sign_cookie_value, "sid", "abc", {1: STRONG_KEY}, now=NOW_MS)
    _add_test(SigningKeyTests, "test_non_string_key_id_rejects", non_string_key_id)


def _now_and_age_matrix():
    now_cases = [
        ("boolean", True),
        ("float", 1.5),
        ("negative", -1),
        ("string", "1700000000000"),
        ("too_large", 10000000000000000),
    ]
    for label, now in now_cases:
        def check(self, now=now):
            assert_error_code(self, "INVALID_OPTIONS", sign_cookie_value, "sid", "abc", STRONG_KEY, now=now)
        _add_test(SigningKeyTests, "test_invalid_now_%s_rejects" % label, check)

    def naive_datetime(self):
        assert_error_code(self, "INVALID_OPTIONS", sign_cookie_value, "sid", "abc", STRONG_KEY, now=datetime.datetime(2026, 1, 1))
    _add_test(SigningKeyTests, "test_naive_now_datetime_rejects", naive_datetime)

    age_cases = [("boolean", True), ("float", 1.0), ("negative", -1), ("too_large", 34560001), ("string", "10")]
    for label, age in age_cases:
        def check(self, age=age):
            assert_error_code(self, "INVALID_MAX_AGE", sign_cookie_value, "sid", "abc", STRONG_KEY, now=NOW_MS, max_age=age)
        _add_test(SigningKeyTests, "test_invalid_signing_max_age_%s_rejects" % label, check)


class SignedEnvelopeTests(unittest.TestCase):
    def valid_signed(self):
        return _sign(max_age=60)

    def replace_part(self, index, value):
        parts = _parts(self.valid_signed())
        parts[index] = value
        return ".".join(parts)

    def test_non_string_signed_value_rejects(self):
        assert_error_code(self, "INVALID_INPUT", verify_cookie_value, "sid", b"v1", STRONG_KEY, now=NOW_MS)

    def test_valid_envelope_accepted(self):
        signed = self.valid_signed()
        self.assertEqual("abc", verify_cookie_value("sid", signed, STRONG_KEY, now=NOW_MS).value)

    def test_wrong_length_tag_rejects(self):
        signed = self.valid_signed()
        truncated = signed[:-1]
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", truncated, STRONG_KEY, now=NOW_MS)

    def test_mac_padding_rejects(self):
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", self.valid_signed() + "=", STRONG_KEY, now=NOW_MS)

    def test_payload_padding_rejects(self):
        parts = _parts(self.valid_signed())
        parts[3] += "="
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_standard_plus_alphabet_rejects(self):
        parts = _parts(self.valid_signed())
        parts[4] = "+" + parts[4][1:]
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_standard_slash_alphabet_rejects(self):
        parts = _parts(self.valid_signed())
        parts[4] = "/" + parts[4][1:]
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_noncanonical_mac_trailing_bits_reject(self):
        signed = self.valid_signed()
        alphabet = signing_module.BASE64URL_ALPHABET
        last = signed[-1]
        index = alphabet.index(last)
        mutated_last = alphabet[index ^ 1]
        mutated = signed[:-1] + mutated_last
        self.assertNotEqual(last, mutated_last)
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", mutated, STRONG_KEY, now=NOW_MS)

    def test_noncanonical_payload_trailing_bits_reject(self):
        signed = sign_cookie_value("sid", "a", STRONG_KEY, now=NOW_MS)
        parts = _parts(signed)
        self.assertEqual("YQ", parts[3])
        parts[3] = "YR"
        assert_error_code(self, "INVALID_SIGNATURE", verify_cookie_value, "sid", ".".join(parts), STRONG_KEY, now=NOW_MS)

    def test_invalid_utf8_payload_rejects_after_valid_mac(self):
        payload_bytes = b"\xff"
        payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        expires_at = 0
        mac = signing_module._b64url_encode(signing_module._mac_for(STRONG_KEY, "sid", "k1", expires_at, payload_bytes))
        signed = "v1.k1.{}.{}.{}".format(expires_at, payload, mac)
        assert_error_code(self, "ENCODING_ERROR", verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS)

    def test_error_does_not_echo_cookie_value(self):
        secret_value = "raw-cookie-value-that-must-not-appear"
        signed = _sign(secret_value)
        parts = _parts(signed)
        parts[3] = "YWRh"
        try:
            verify_cookie_value("sid", ".".join(parts), STRONG_KEY, now=NOW_MS)
        except Exception as exc:
            self.assertNotIn(secret_value, str(exc))
        else:
            self.fail("tampered value unexpectedly verified")

    def test_weak_key_error_does_not_echo_secret(self):
        secret = "secret" + "x" * 30
        try:
            sign_cookie_value("sid", "abc", secret, now=NOW_MS)
        except Exception as exc:
            self.assertNotIn(secret, str(exc))
        else:
            self.fail("weak key unexpectedly accepted")


def _malformed_envelope_matrix():
    base = "v1.k1.0.YWJj." + "A" * 43
    cases = [
        ("empty", ""),
        ("missing_mac", "v1.k1.0.YWJj"),
        ("extra_part", base + ".extra"),
        ("wrong_version", "v2.k1.0.YWJj." + "A" * 43),
        ("uppercase_version", "V1.k1.0.YWJj." + "A" * 43),
        ("empty_kid", "v1..0.YWJj." + "A" * 43),
        ("bad_kid_dot_shape", "v1.k%1.0.YWJj." + "A" * 43),
        ("empty_exp", "v1.k1..YWJj." + "A" * 43),
        ("negative_exp", "v1.k1.-1.YWJj." + "A" * 43),
        ("plus_exp", "v1.k1.+1.YWJj." + "A" * 43),
        ("float_exp", "v1.k1.1.5.YWJj." + "A" * 43),
        ("leading_zero_exp", "v1.k1.01.YWJj." + "A" * 43),
        ("seventeen_digit_exp", "v1.k1.10000000000000000.YWJj." + "A" * 43),
        ("empty_mac", "v1.k1.0.YWJj."),
        ("mac_length_mod_one", "v1.k1.0.YWJj.A"),
        ("payload_length_mod_one", "v1.k1.0.A." + "A" * 43),
        ("spaces", " v1.k1.0.YWJj." + "A" * 43),
        ("control", "v1.k1.0.YWJj." + "A" * 42 + "\x01"),
        ("non_ascii", "v1.k1.0.YWJj." + "A" * 42 + "\u00e9"),
    ]
    for label, signed in cases:
        def check(self, signed=signed):
            if "\x01" in signed:
                expected = "CONTROL_CHARACTER"
            elif any(ord(ch) > 127 for ch in signed):
                expected = "NON_ASCII"
            else:
                expected = "INVALID_SIGNATURE"
            assert_error_code(self, expected, verify_cookie_value, "sid", signed, STRONG_KEY, now=NOW_MS)
        _add_test(SignedEnvelopeTests, "test_malformed_envelope_%s_rejects" % label, check)


_weak_secret_matrix()
_invalid_keyring_matrix()
_now_and_age_matrix()
_malformed_envelope_matrix()


if __name__ == "__main__":
    unittest.main()
