"""Serialization, attribute invariant, prefix, domain, and deletion tests."""

import datetime
import unittest

from pycookiecage import delete_cookie, serialize_cookie

from _support import UTC, assert_error_code


class SerializeCookieTests(unittest.TestCase):
    def test_default_output_is_hardened_and_canonical(self):
        self.assertEqual(
            "sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax",
            serialize_cookie("sid", "abc"),
        )

    def test_empty_value_is_valid(self):
        self.assertEqual(
            "sid=; Path=/; HttpOnly; Secure; SameSite=Lax",
            serialize_cookie("sid", ""),
        )

    def test_all_attributes_emit_in_stable_order(self):
        expires = datetime.datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
        self.assertEqual(
            "sid=abc; Domain=example.com; Path=/app; Max-Age=60; Expires=Wed, 02 Jan 2030 03:04:05 GMT; HttpOnly; Secure; SameSite=Strict; Partitioned",
            serialize_cookie(
                "sid",
                "abc",
                domain="example.com",
                path="/app",
                max_age=60,
                expires=expires,
                same_site="Strict",
                partitioned=True,
            ),
        )

    def test_http_only_false_omits_attribute(self):
        self.assertNotIn("HttpOnly", serialize_cookie("sid", "abc", http_only=False))

    def test_secure_false_omits_attribute_for_plain_cookie(self):
        output = serialize_cookie("sid", "abc", secure=False, same_site="Lax")
        self.assertNotIn("; Secure", output)

    def test_partitioned_true_emits_attribute(self):
        output = serialize_cookie("sid", "abc", partitioned=True)
        self.assertTrue(output.endswith("; Partitioned"))

    def test_domain_is_lowercased(self):
        output = serialize_cookie("sid", "abc", domain="ExAmPle.COM")
        self.assertIn("Domain=example.com", output)

    def test_domain_single_leading_dot_is_normalized(self):
        output = serialize_cookie("sid", "abc", domain=".example.com")
        self.assertIn("Domain=example.com", output)

    def test_expires_converts_offset_to_gmt(self):
        zone = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        output = serialize_cookie("sid", "abc", expires=datetime.datetime(2030, 1, 2, 8, 34, 5, tzinfo=zone))
        self.assertIn("Expires=Wed, 02 Jan 2030 03:04:05 GMT", output)

    def test_expires_year_one_formats_four_digits(self):
        output = serialize_cookie("sid", "abc", expires=datetime.datetime(1, 1, 1, 0, 0, 0, tzinfo=UTC))
        self.assertIn("Expires=Mon, 01 Jan 0001 00:00:00 GMT", output)

    def test_max_age_zero_is_emitted(self):
        self.assertIn("Max-Age=0", serialize_cookie("sid", "abc", max_age=0))

    def test_max_age_upper_bound_is_accepted(self):
        self.assertIn("Max-Age=34560000", serialize_cookie("sid", "abc", max_age=34560000))

    def test_expires_naive_datetime_rejects(self):
        assert_error_code(
            self,
            "INVALID_EXPIRES",
            serialize_cookie,
            "sid",
            "abc",
            expires=datetime.datetime(2030, 1, 1),
        )

    def test_expires_microseconds_reject(self):
        assert_error_code(
            self,
            "INVALID_EXPIRES",
            serialize_cookie,
            "sid",
            "abc",
            expires=datetime.datetime(2030, 1, 1, tzinfo=UTC, microsecond=1),
        )

    def test_expires_date_object_rejects(self):
        assert_error_code(self, "INVALID_EXPIRES", serialize_cookie, "sid", "abc", expires=datetime.date(2030, 1, 1))

    def test_boolean_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=True)

    def test_float_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=1.0)

    def test_negative_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=-1)

    def test_oversize_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age=34560001)

    def test_string_max_age_rejects(self):
        assert_error_code(self, "INVALID_MAX_AGE", serialize_cookie, "sid", "abc", max_age="60")

    def test_serialized_output_limit_enforced(self):
        assert_error_code(self, "LIMIT_EXCEEDED", serialize_cookie, "sid", "a" * 4096)

    def test_non_string_value_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, "sid", b"abc")

    def test_non_string_name_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, b"sid", "abc")

    def test_non_boolean_secure_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, "sid", "abc", secure=1)

    def test_non_boolean_http_only_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, "sid", "abc", http_only=0)

    def test_non_boolean_partitioned_rejects(self):
        assert_error_code(self, "INVALID_INPUT", serialize_cookie, "sid", "abc", partitioned="yes")


class DeleteCookieTests(unittest.TestCase):
    def test_delete_exact_output(self):
        self.assertEqual(
            "sid=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax",
            delete_cookie("sid"),
        )

    def test_delete_preserves_domain_and_path(self):
        output = delete_cookie("sid", domain="example.com", path="/app")
        self.assertIn("Domain=example.com", output)
        self.assertIn("Path=/app", output)

    def test_delete_host_prefix_valid(self):
        output = delete_cookie("__Host-sid")
        self.assertIn("__Host-sid=; Path=/; Max-Age=0", output)

    def test_delete_host_prefix_rejects_insecure(self):
        assert_error_code(self, "PREFIX_INVARIANT", delete_cookie, "__host-sid", secure=False)

    def test_delete_host_prefix_rejects_domain(self):
        assert_error_code(self, "PREFIX_INVARIANT", delete_cookie, "__HOST-sid", domain="example.com")

    def test_delete_host_prefix_rejects_non_root_path(self):
        assert_error_code(self, "PREFIX_INVARIANT", delete_cookie, "__HoSt-sid", path="/app")

    def test_delete_secure_prefix_rejects_insecure(self):
        assert_error_code(self, "PREFIX_INVARIANT", delete_cookie, "__secure-sid", secure=False)

    def test_delete_samesite_none_rejects_insecure(self):
        assert_error_code(self, "SAMESITE_INVARIANT", delete_cookie, "sid", secure=False, same_site="None")

    def test_delete_partitioned_rejects_insecure(self):
        assert_error_code(self, "PARTITIONED_INVARIANT", delete_cookie, "sid", secure=False, partitioned=True)

    def test_delete_partitioned_valid(self):
        self.assertTrue(delete_cookie("sid", partitioned=True).endswith("; Partitioned"))


# Generated matrix tests are deterministic unittest methods. They make byte and
# character coverage explicit without copy-pasting large blocks.

def _add_test(cls, name, func):
    setattr(cls, name, func)
    func.__name__ = name


def _valid_name_matrix():
    chars = list("!#$%&'*+-.^_`|~") + ["A", "z", "0", "9"]
    for index, char in enumerate(chars):
        def check(self, char=char):
            output = serialize_cookie("pre" + char + "post", "v")
            self.assertTrue(output.startswith("pre" + char + "post=v;"))
        _add_test(SerializeCookieTests, "test_valid_token_character_%02d" % index, check)


def _invalid_name_matrix():
    cases = [
        ("empty", ""),
        ("space", "bad name"),
        ("semicolon", "bad;name"),
        ("equals", "bad=name"),
        ("comma", "bad,name"),
        ("quote", 'bad"name'),
        ("backslash", "bad\\name"),
        ("carriage_return", "bad\rname"),
        ("line_feed", "bad\nname"),
        ("tab", "bad\tname"),
        ("nul", "bad\x00name"),
        ("delete", "bad\x7fname"),
        ("c1_control", "bad\x80name"),
        ("non_ascii", "bad\u00e9name"),
        ("left_bracket", "bad[name"),
        ("right_bracket", "bad]name"),
        ("colon", "bad:name"),
        ("slash", "bad/name"),
        ("question", "bad?name"),
    ]
    for label, value in cases:
        def check(self, value=value):
            if "\r" in value or "\n" in value:
                expected = "CRLF"
            elif any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in value):
                expected = "CONTROL_CHARACTER"
            elif any(ord(ch) > 127 for ch in value):
                expected = "NON_ASCII"
            else:
                expected = "INVALID_NAME"
            assert_error_code(self, expected, serialize_cookie, value, "abc")
        _add_test(SerializeCookieTests, "test_invalid_name_%s" % label, check)


def _valid_value_matrix():
    chars = ["!", "#", "$", "%", "&", "'", "*", "+", "-", ".", "/", "0", ":", "=", "?", "@", "[", "]", "^", "_", "`", "{", "|", "}", "~"]
    for index, char in enumerate(chars):
        def check(self, char=char):
            output = serialize_cookie("sid", "a" + char + "b")
            self.assertIn("sid=a" + char + "b;", output)
        _add_test(SerializeCookieTests, "test_valid_cookie_octet_%02d" % index, check)


def _invalid_value_matrix():
    cases = [
        ("space", "bad value", "INVALID_VALUE"),
        ("semicolon", "bad;value", "INVALID_VALUE"),
        ("comma", "bad,value", "INVALID_VALUE"),
        ("quote", 'bad"value', "INVALID_VALUE"),
        ("backslash", "bad\\value", "INVALID_VALUE"),
        ("carriage_return", "bad\rvalue", "CRLF"),
        ("line_feed", "bad\nvalue", "CRLF"),
        ("tab", "bad\tvalue", "CONTROL_CHARACTER"),
        ("nul", "bad\x00value", "CONTROL_CHARACTER"),
        ("delete", "bad\x7fvalue", "CONTROL_CHARACTER"),
        ("c1_control", "bad\x80value", "CONTROL_CHARACTER"),
        ("non_ascii", "bad\u00e9value", "NON_ASCII"),
    ]
    for label, value, code in cases:
        def check(self, value=value, code=code):
            assert_error_code(self, code, serialize_cookie, "sid", value)
        _add_test(SerializeCookieTests, "test_invalid_value_%s" % label, check)


def _same_site_matrix():
    valid = [
        ("strict_lower", "strict", "Strict"),
        ("strict_upper", "STRICT", "Strict"),
        ("strict_mixed", "sTrIcT", "Strict"),
        ("lax_lower", "lax", "Lax"),
        ("lax_upper", "LAX", "Lax"),
        ("lax_mixed", "lAx", "Lax"),
        ("none_lower", "none", "None"),
        ("none_upper", "NONE", "None"),
        ("none_mixed", "nOnE", "None"),
    ]
    for label, value, canonical in valid:
        def check(self, value=value, canonical=canonical):
            output = serialize_cookie("sid", "abc", same_site=value)
            self.assertIn("SameSite=" + canonical, output)
        _add_test(SerializeCookieTests, "test_samesite_valid_%s" % label, check)

    invalid = ["", "sometimes", "nonee", " strict", "strict ", "0"]
    for index, value in enumerate(invalid):
        def check(self, value=value):
            assert_error_code(self, "SAMESITE_INVARIANT", serialize_cookie, "sid", "abc", same_site=value)
        _add_test(SerializeCookieTests, "test_samesite_invalid_%02d" % index, check)


def _host_prefix_matrix():
    variants = ["__Host-sid", "__host-sid", "__HOST-sid", "__HoSt-sid", "__hOsT-sid"]
    for index, name in enumerate(variants):
        def insecure(self, name=name):
            assert_error_code(self, "PREFIX_INVARIANT", serialize_cookie, name, "abc", secure=False)
        def domain(self, name=name):
            assert_error_code(self, "PREFIX_INVARIANT", serialize_cookie, name, "abc", domain="example.com")
        def path(self, name=name):
            assert_error_code(self, "PREFIX_INVARIANT", serialize_cookie, name, "abc", path="/app")
        def valid(self, name=name):
            output = serialize_cookie(name, "abc")
            self.assertIn("; Secure", output)
            self.assertIn("; Path=/", output)
            self.assertNotIn("; Domain=", output)
        _add_test(SerializeCookieTests, "test_host_prefix_%02d_rejects_insecure" % index, insecure)
        _add_test(SerializeCookieTests, "test_host_prefix_%02d_rejects_domain" % index, domain)
        _add_test(SerializeCookieTests, "test_host_prefix_%02d_rejects_non_root_path" % index, path)
        _add_test(SerializeCookieTests, "test_host_prefix_%02d_valid" % index, valid)


def _secure_prefix_matrix():
    variants = ["__Secure-sid", "__secure-sid", "__SECURE-sid", "__SeCuRe-sid"]
    for index, name in enumerate(variants):
        def insecure(self, name=name):
            assert_error_code(self, "PREFIX_INVARIANT", serialize_cookie, name, "abc", secure=False)
        def valid(self, name=name):
            self.assertIn("; Secure", serialize_cookie(name, "abc"))
        _add_test(SerializeCookieTests, "test_secure_prefix_%02d_rejects_insecure" % index, insecure)
        _add_test(SerializeCookieTests, "test_secure_prefix_%02d_valid" % index, valid)


def _attribute_invariant_matrix():
    none_variants = ["None", "none", "NONE", "nOnE"]
    for index, value in enumerate(none_variants):
        def reject(self, value=value):
            assert_error_code(self, "SAMESITE_INVARIANT", serialize_cookie, "sid", "abc", secure=False, same_site=value)
        def valid(self, value=value):
            self.assertIn("SameSite=None", serialize_cookie("sid", "abc", secure=True, same_site=value))
        _add_test(SerializeCookieTests, "test_samesite_none_%02d_requires_secure" % index, reject)
        _add_test(SerializeCookieTests, "test_samesite_none_%02d_valid" % index, valid)

    def partitioned_rejects(self):
        assert_error_code(self, "PARTITIONED_INVARIANT", serialize_cookie, "sid", "abc", secure=False, partitioned=True)
    _add_test(SerializeCookieTests, "test_partitioned_requires_secure", partitioned_rejects)


def _path_matrix():
    valid_paths = ["/", "/app", "/app/", "/a-b_c", "/%20", "/.", "/~x", "/123"]
    for index, path in enumerate(valid_paths):
        def check(self, path=path):
            self.assertIn("Path=" + path, serialize_cookie("sid", "abc", path=path))
        _add_test(SerializeCookieTests, "test_valid_path_%02d" % index, check)

    invalid_paths = [
        ("empty", ""),
        ("relative", "app"),
        ("dot", "."),
        ("semicolon", "/app;x"),
        ("space", "/app x"),
        ("quote", '/app"x'),
        ("backslash", "/app\\x"),
        ("cr", "/app\rx"),
        ("lf", "/app\nx"),
        ("tab", "/app\tx"),
        ("non_ascii", "/app\u00e9"),
    ]
    for label, path in invalid_paths:
        def check(self, path=path):
            expected = "CRLF" if "\r" in path or "\n" in path else ("CONTROL_CHARACTER" if "\t" in path else ("NON_ASCII" if any(ord(ch) > 127 for ch in path) else "INVALID_PATH"))
            assert_error_code(self, expected, serialize_cookie, "sid", "abc", path=path)
        _add_test(SerializeCookieTests, "test_invalid_path_%s" % label, check)


def _domain_matrix():
    valid = [
        "example.com",
        "sub.example.com",
        "example.co.uk",
        "a-b.example",
        "xn--bcher-kva.example",
        "127.example.com",
        "example.123",
        "EXAMPLE.COM",
        "ExAmPlE.CoM",
        "MiXeD.Sub.Example.COM",
        ("a" * 63) + ".example",
    ]
    for index, domain in enumerate(valid):
        def check(self, domain=domain):
            self.assertIn("Domain=" + domain.lower(), serialize_cookie("sid", "abc", domain=domain))
        _add_test(SerializeCookieTests, "test_valid_domain_%02d" % index, check)

    invalid = [
        ("empty", ""),
        ("single_label", "localhost"),
        ("bare_tld", "com"),
        ("trailing_dot", "example.com."),
        ("double_leading_dot", "..example.com"),
        ("double_middle_dot", "example..com"),
        ("leading_hyphen", "-example.com"),
        ("trailing_hyphen", "example-.com"),
        ("space", "example .com"),
        ("underscore", "ex_ample.com"),
        ("ipv4", "192.168.1.1"),
        ("ipv4_leading_zero", "192.168.001.1"),
        ("ipv4_out_of_range", "999.1.1.1"),
        ("ipv4_two_part_decimal", "127.1"),
        ("ipv4_three_part_decimal", "1.2.3"),
        ("ipv4_two_part_hex", "0x7f.1"),
        ("ipv4_two_part_octal", "0177.1"),
        ("ipv4_numeric_overflow_two_part", "1.2.256"),
        ("ipv4_numeric_hex_pair", "0xabcdef.123"),
        ("ipv4_too_many_numeric_parts", "1.2.3.4.5"),
        ("ipv6", "[2001:db8::1]"),
        ("ipv6_bare", "2001:db8::1"),
        ("non_ascii", "exampl\u00e9.com"),
        ("cr", "example.com\r"),
        ("lf", "example.com\n"),
        ("tab", "example.com\t"),
        ("numeric_single", "2130706433"),
        ("numeric_two_part", "127.1"),
        ("numeric_leading_zero", "0177.0.0.1"),
        ("numeric_hex", "0x7f000001"),
        ("repeated_dots", "example...com"),
    ]
    for label, domain in invalid:
        def check(self, domain=domain):
            if "\r" in domain or "\n" in domain:
                expected = "CRLF"
            elif "\t" in domain:
                expected = "CONTROL_CHARACTER"
            elif any(ord(ch) > 127 for ch in domain):
                expected = "NON_ASCII"
            else:
                expected = "INVALID_DOMAIN"
            assert_error_code(self, expected, serialize_cookie, "sid", "abc", domain=domain)
        _add_test(SerializeCookieTests, "test_invalid_domain_%s" % label, check)

    suffixes = [
        "com.au", "net.au", "org.au", "com.br", "com.cn", "edu.cn", "co.in", "co.jp",
        "ac.jp", "co.kr", "com.mx", "co.nz", "com.sg", "com.tr", "com.tw", "co.uk",
        "org.uk", "ac.uk", "gov.uk", "co.za",
    ]
    for index, suffix in enumerate(suffixes):
        def check(self, suffix=suffix):
            assert_error_code(self, "INVALID_DOMAIN", serialize_cookie, "sid", "abc", domain=suffix)
        _add_test(SerializeCookieTests, "test_common_public_suffix_%02d_rejects" % index, check)

    def too_long_domain(self):
        labels = ["a" * 63] * 5
        assert_error_code(self, "INVALID_DOMAIN", serialize_cookie, "sid", "abc", domain=".".join(labels))
    _add_test(SerializeCookieTests, "test_domain_total_length_rejects", too_long_domain)

    def too_long_label(self):
        assert_error_code(self, "INVALID_DOMAIN", serialize_cookie, "sid", "abc", domain=("a" * 64) + ".com")
    _add_test(SerializeCookieTests, "test_domain_label_length_rejects", too_long_label)


_valid_name_matrix()
_invalid_name_matrix()
_valid_value_matrix()
_invalid_value_matrix()
_same_site_matrix()
_host_prefix_matrix()
_secure_prefix_matrix()
_attribute_invariant_matrix()
_path_matrix()
_domain_matrix()


if __name__ == "__main__":
    unittest.main()
