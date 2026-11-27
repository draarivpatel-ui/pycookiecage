"""CookieJarGuard policy merging and keyring behavior tests."""

import unittest

from pycookiecage import CookieJarGuard

from _support import NOW_MS, STRONG_KEY, STRONG_KEY_2, assert_error_code


class CookieJarGuardTests(unittest.TestCase):
    def test_empty_guard_serializes_with_library_defaults(self):
        guard = CookieJarGuard()
        self.assertEqual(
            "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
            guard.serialize("sid", "abc"),
        )

    def test_none_policy_is_accepted(self):
        self.assertEqual({"a": "1"}, CookieJarGuard(None).parse("a=1"))

    def test_serialize_policy_defaults_apply(self):
        guard = CookieJarGuard({"serialize": {"same_site": "Strict", "http_only": False}})
        output = guard.serialize("sid", "abc")
        self.assertIn("SameSite=Strict", output)
        self.assertNotIn("HttpOnly", output)

    def test_serialize_call_overrides_policy(self):
        guard = CookieJarGuard({"serialize": {"same_site": "Strict"}})
        output = guard.serialize("sid", "abc", same_site="Lax")
        self.assertIn("SameSite=Lax", output)

    def test_delete_policy_defaults_apply(self):
        guard = CookieJarGuard({"delete": {"same_site": "Strict", "partitioned": True}})
        output = guard.delete("sid")
        self.assertIn("Max-Age=0", output)
        self.assertIn("SameSite=Strict", output)
        self.assertTrue(output.endswith("; Partitioned"))

    def test_parse_policy_defaults_apply(self):
        guard = CookieJarGuard({"parse": {"duplicate_policy": "last"}})
        self.assertEqual({"sid": "2"}, guard.parse("sid=1; sid=2"))

    def test_parse_call_overrides_policy(self):
        guard = CookieJarGuard({"parse": {"duplicate_policy": "last"}})
        assert_error_code(self, "DUPLICATE_COOKIE", guard.parse, "sid=1; sid=2", duplicate_policy="reject")

    def test_sign_uses_top_level_keyring(self):
        guard = CookieJarGuard({"key_or_keyring": STRONG_KEY})
        signed = guard.sign("sid", "abc", now=NOW_MS)
        result = guard.verify("sid", signed, now=NOW_MS)
        self.assertEqual("abc", result.value)

    def test_sign_policy_keyring(self):
        guard = CookieJarGuard({"sign": {"key_or_keyring": STRONG_KEY}, "verify": {"key_or_keyring": STRONG_KEY}})
        signed = guard.sign("sid", "abc", now=NOW_MS)
        self.assertEqual("abc", guard.verify("sid", signed, now=NOW_MS).value)

    def test_call_keyring_overrides_top_level(self):
        guard = CookieJarGuard({"key_or_keyring": STRONG_KEY})
        signed = guard.sign("sid", "abc", key_or_keyring=STRONG_KEY_2, now=NOW_MS)
        result = guard.verify("sid", signed, key_or_keyring=STRONG_KEY_2, now=NOW_MS)
        self.assertEqual("abc", result.value)

    def test_sign_without_keyring_rejects(self):
        assert_error_code(self, "INVALID_KEYRING", CookieJarGuard().sign, "sid", "abc", now=NOW_MS)

    def test_verify_without_keyring_rejects(self):
        assert_error_code(self, "INVALID_KEYRING", CookieJarGuard().verify, "sid", "v1.k1.0..x", now=NOW_MS)

    def test_sign_policy_max_age_applies(self):
        guard = CookieJarGuard({"key_or_keyring": STRONG_KEY, "sign": {"max_age": 60}})
        signed = guard.sign("sid", "abc", now=NOW_MS)
        result = guard.verify("sid", signed, now=NOW_MS)
        self.assertEqual(NOW_MS + 60000, result.expires_at)

    def test_rotation_reports_rotated_through_guard(self):
        keyring = {"new": STRONG_KEY, "old": STRONG_KEY_2}
        creator = CookieJarGuard({"key_or_keyring": {"old": STRONG_KEY_2}})
        signed = creator.sign("sid", "abc", now=NOW_MS)
        guard = CookieJarGuard({"key_or_keyring": keyring})
        self.assertTrue(guard.verify("sid", signed, now=NOW_MS).rotated)

    def test_repr_omits_key_material(self):
        guard = CookieJarGuard({"key_or_keyring": STRONG_KEY})
        representation = repr(guard)
        self.assertIn("keyring_configured=True", representation)
        self.assertNotIn(str(STRONG_KEY), representation)

    def test_unknown_policy_key_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"unknown": {}})

    def test_non_mapping_policy_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, [])

    def test_non_mapping_nested_policy_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"serialize": []})

    def test_unknown_serialize_policy_key_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"serialize": {"unknown": True}})

    def test_unknown_delete_policy_key_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"delete": {"max_age": 0}})

    def test_unknown_parse_policy_key_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"parse": {"unknown": True}})

    def test_unknown_sign_policy_key_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"sign": {"unknown": True}})

    def test_unknown_verify_policy_key_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", CookieJarGuard, {"verify": {"max_age": 1}})

    def test_unknown_serialize_override_rejects(self):
        guard = CookieJarGuard()
        assert_error_code(self, "INVALID_OPTIONS", guard.serialize, "sid", "abc", unknown=True)

    def test_unknown_parse_override_rejects(self):
        guard = CookieJarGuard()
        assert_error_code(self, "INVALID_OPTIONS", guard.parse, "a=1", unknown=True)

    def test_unknown_sign_override_rejects(self):
        guard = CookieJarGuard({"key_or_keyring": STRONG_KEY})
        assert_error_code(self, "INVALID_OPTIONS", guard.sign, "sid", "abc", unknown=True)

    def test_unknown_verify_override_rejects(self):
        guard = CookieJarGuard({"key_or_keyring": STRONG_KEY})
        assert_error_code(self, "INVALID_OPTIONS", guard.verify, "sid", "x", unknown=True)

    def test_prefix_policy_still_enforced(self):
        guard = CookieJarGuard({"serialize": {"secure": False}})
        assert_error_code(self, "PREFIX_INVARIANT", guard.serialize, "__host-sid", "abc")

    def test_policy_original_mapping_mutation_does_not_rewrite_options(self):
        serialize_policy = {"same_site": "Strict"}
        guard = CookieJarGuard({"serialize": serialize_policy})
        serialize_policy["same_site"] = "Lax"
        self.assertIn("SameSite=Strict", guard.serialize("sid", "abc"))


if __name__ == "__main__":
    unittest.main()
