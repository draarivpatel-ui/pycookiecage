"""Incoming Cookie header parsing, quoting, duplicate, and bounds tests."""

import unittest

from pycookiecage import parse_cookie_header

from _support import assert_error_code


def _add_test(cls, name, func):
    setattr(cls, name, func)
    func.__name__ = name


class ParseCookieHeaderTests(unittest.TestCase):
    def test_single_cookie_parses(self):
        self.assertEqual({"sid": "abc"}, parse_cookie_header("sid=abc"))

    def test_multiple_cookies_preserve_order(self):
        result = parse_cookie_header("a=1; b=2; c=3")
        self.assertEqual(["a", "b", "c"], list(result.keys()))
        self.assertEqual({"a": "1", "b": "2", "c": "3"}, result)

    def test_empty_value_is_allowed(self):
        self.assertEqual({"sid": ""}, parse_cookie_header("sid="))

    def test_value_may_contain_equals(self):
        self.assertEqual({"sid": "a=b=c"}, parse_cookie_header("sid=a=b=c"))

    def test_space_after_semicolon_is_tolerated(self):
        self.assertEqual({"a": "1", "b": "2"}, parse_cookie_header("a=1; b=2"))

    def test_repeated_spaces_after_semicolon_are_tolerated(self):
        self.assertEqual({"a": "1", "b": "2"}, parse_cookie_header("a=1;    b=2"))

    def test_space_before_first_pair_is_tolerated(self):
        self.assertEqual({"a": "1"}, parse_cookie_header("  a=1"))

    def test_trailing_space_in_value_rejects(self):
        assert_error_code(self, "INVALID_VALUE", parse_cookie_header, "a=1 ")

    def test_quoted_and_unquoted_values_remain_distinct(self):
        self.assertEqual({"a": '"abc"'}, parse_cookie_header('a="abc"'))
        self.assertNotEqual(parse_cookie_header('a="abc"')["a"], parse_cookie_header("a=abc")["a"])

    def test_empty_quoted_value_preserves_quotes(self):
        self.assertEqual({"a": '""'}, parse_cookie_header('a=""'))

    def test_quoted_inner_cookie_octets_parse(self):
        self.assertEqual({"a": '"x!y=z?"'}, parse_cookie_header('a="x!y=z?"'))

    def test_cookie_names_are_case_sensitive(self):
        result = parse_cookie_header("sid=1; SID=2; Sid=3")
        self.assertEqual({"sid": "1", "SID": "2", "Sid": "3"}, result)

    def test_duplicate_rejects_by_default(self):
        assert_error_code(self, "DUPLICATE_COOKIE", parse_cookie_header, "sid=1; sid=2")

    def test_duplicate_reject_explicit(self):
        assert_error_code(self, "DUPLICATE_COOKIE", parse_cookie_header, "sid=1; sid=2", duplicate_policy="reject")

    def test_duplicate_first_keeps_first(self):
        self.assertEqual({"sid": "1"}, parse_cookie_header("sid=1; sid=2", duplicate_policy="first"))

    def test_duplicate_last_keeps_last(self):
        self.assertEqual({"sid": "2"}, parse_cookie_header("sid=1; sid=2", duplicate_policy="last"))

    def test_duplicate_first_with_three_entries(self):
        self.assertEqual({"sid": "1"}, parse_cookie_header("sid=1; sid=2; sid=3", duplicate_policy="first"))

    def test_duplicate_last_with_three_entries(self):
        self.assertEqual({"sid": "3"}, parse_cookie_header("sid=1; sid=2; sid=3", duplicate_policy="last"))

    def test_case_variant_is_not_duplicate(self):
        self.assertEqual({"sid": "1", "SID": "2"}, parse_cookie_header("sid=1; SID=2"))

    def test_header_byte_limit_rejects_before_scanning(self):
        header = "x" * 100 + "=1"
        assert_error_code(self, "LIMIT_EXCEEDED", parse_cookie_header, header, max_header_bytes=10)

    def test_cookie_count_limit_enforced(self):
        assert_error_code(self, "LIMIT_EXCEEDED", parse_cookie_header, "a=1; b=2", max_cookies=1)

    def test_cookie_count_limit_exact_boundary_accepts(self):
        self.assertEqual({"a": "1", "b": "2"}, parse_cookie_header("a=1; b=2", max_cookies=2))

    def test_per_cookie_segment_limit_enforced(self):
        assert_error_code(self, "LIMIT_EXCEEDED", parse_cookie_header, "a=" + "x" * 20, max_cookie_bytes=10)

    def test_per_cookie_segment_limit_boundary_accepts(self):
        segment = "a=" + "x" * 8
        self.assertEqual({"a": "x" * 8}, parse_cookie_header(segment, max_cookie_bytes=10))

    def test_max_header_bytes_boundary_accepts(self):
        header = "a=1"
        self.assertEqual({"a": "1"}, parse_cookie_header(header, max_header_bytes=3))

    def test_hundred_kb_delimiter_flood_rejects_by_count_bound(self):
        header = "a=11" + ";a=1" * 24999
        self.assertEqual(100000, len(header.encode("ascii")))
        assert_error_code(
            self,
            "LIMIT_EXCEEDED",
            parse_cookie_header,
            header,
            max_header_bytes=100000,
            max_cookies=100,
            duplicate_policy="last",
        )

    def test_hundred_kb_header_at_count_bound_parses(self):
        pairs = []
        remaining = 100000
        index = 0
        while True:
            piece = "k{:03d}=".format(index) + "x" * 120
            cost = len(piece) + (1 if pairs else 0)
            if remaining - cost < 0:
                break
            pairs.append(piece)
            remaining -= cost
            index += 1
        header = ";".join(pairs)
        result = parse_cookie_header(
            header,
            max_header_bytes=100000,
            max_cookies=1000,
            max_cookie_bytes=4096,
        )
        self.assertEqual(len(pairs), len(result))
        self.assertLessEqual(len(header.encode("ascii")), 100000)

    def test_delimiter_flood_empty_segments_reject_before_count_exhaustion(self):
        assert_error_code(self, "PARSE_ERROR", parse_cookie_header, "a=1" + ";" * 1000, max_header_bytes=2000, max_cookies=1000)

    def test_non_string_header_rejects(self):
        assert_error_code(self, "INVALID_INPUT", parse_cookie_header, b"a=1")

    def test_empty_header_rejects(self):
        assert_error_code(self, "PARSE_ERROR", parse_cookie_header, "")

    def test_invalid_duplicate_policy_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", parse_cookie_header, "a=1", duplicate_policy="merge")

    def test_case_variant_duplicate_policy_rejects(self):
        assert_error_code(self, "INVALID_OPTIONS", parse_cookie_header, "a=1", duplicate_policy="REJECT")

    def test_zero_header_limit_rejects(self):
        assert_error_code(self, "INVALID_INPUT", parse_cookie_header, "a=1", max_header_bytes=0)

    def test_boolean_header_limit_rejects(self):
        assert_error_code(self, "INVALID_INPUT", parse_cookie_header, "a=1", max_header_bytes=True)

    def test_zero_cookie_count_rejects(self):
        assert_error_code(self, "INVALID_INPUT", parse_cookie_header, "a=1", max_cookies=0)

    def test_zero_cookie_bytes_rejects(self):
        assert_error_code(self, "INVALID_INPUT", parse_cookie_header, "a=1", max_cookie_bytes=0)


def _malformed_segment_matrix():
    cases = [
        ("missing_equals", "abc", "PARSE_ERROR"),
        ("empty_name", "=abc", "PARSE_ERROR"),
        ("leading_equals_only", "=", "PARSE_ERROR"),
        ("trailing_semicolon", "a=1;", "PARSE_ERROR"),
        ("leading_semicolon", ";a=1", "PARSE_ERROR"),
        ("double_semicolon", "a=1;;b=2", "PARSE_ERROR"),
        ("spaces_only_segment", "a=1;   ;b=2", "PARSE_ERROR"),
        ("name_with_space", "a b=1", "INVALID_NAME"),
        ("name_with_comma", "a,b=1", "INVALID_NAME"),
        ("name_with_semicolon_impossible_shape", "a=1;b;c=2", "PARSE_ERROR"),
    ]
    for label, header, code in cases:
        def check(self, header=header, code=code):
            assert_error_code(self, code, parse_cookie_header, header)
        _add_test(ParseCookieHeaderTests, "test_malformed_segment_%s" % label, check)


def _quote_matrix():
    invalid = [
        ("left_only", 'a="abc'),
        ("right_only", 'a=abc"'),
        ("single_quote_char", 'a="'),
        ("quote_in_middle", 'a=ab"c'),
        ("mismatched_extra_text", 'a="abc"x'),
        ("quoted_semicolon", 'a="x;y"'),
        ("quoted_comma", 'a="x,y"'),
        ("quoted_space", 'a="x y"'),
    ]
    for label, header in invalid:
        def check(self, header=header):
            assert_error_code(self, "INVALID_VALUE", parse_cookie_header, header)
        _add_test(ParseCookieHeaderTests, "test_invalid_quoted_value_%s" % label, check)

    valid = [
        "a=" + '""',
        "a=" + '"!"',
        "a=" + '"abc"',
        "a=" + '"a=b"',
        "a=" + '"[]{}"',
    ]
    for index, header in enumerate(valid):
        def check(self, header=header):
            result = parse_cookie_header(header)
            self.assertTrue(result["a"].startswith('"'))
            self.assertTrue(result["a"].endswith('"'))
        _add_test(ParseCookieHeaderTests, "test_valid_quoted_value_%02d" % index, check)


def _header_character_matrix():
    cases = [
        ("cr", "a=1\rb=2", "CRLF"),
        ("lf", "a=1\nb=2", "CRLF"),
        ("tab_before_pair", "a=1;\tb=2", "CONTROL_CHARACTER"),
        ("nul", "a=1\x00", "CONTROL_CHARACTER"),
        ("delete", "a=1\x7f", "CONTROL_CHARACTER"),
        ("non_ascii", "a=caf\u00e9", "NON_ASCII"),
    ]
    for label, header, code in cases:
        def check(self, header=header, code=code):
            assert_error_code(self, code, parse_cookie_header, header)
        _add_test(ParseCookieHeaderTests, "test_header_character_%s_rejects" % label, check)


def _invalid_value_matrix():
    cases = [
        ("space", "a=x y", "INVALID_VALUE"),
        ("semicolon_shape", "a=x;y", "PARSE_ERROR"),
        ("comma", "a=x,y", "INVALID_VALUE"),
        ("backslash", "a=x\\y", "INVALID_VALUE"),
        ("quote", 'a=x"y', "INVALID_VALUE"),
    ]
    for label, header, code in cases:
        def check(self, header=header, code=code):
            assert_error_code(self, code, parse_cookie_header, header)
        _add_test(ParseCookieHeaderTests, "test_parse_value_%s_rejects" % label, check)


def _valid_parse_matrix():
    values = ["!", "#", "$", "%", "&", "'", "*", "+", "-", ".", "/", ":", "=", "?", "@", "[", "]", "^", "_", "`", "{", "|", "}", "~"]
    for index, char in enumerate(values):
        def check(self, char=char):
            self.assertEqual({"a": "x" + char + "y"}, parse_cookie_header("a=x" + char + "y"))
        _add_test(ParseCookieHeaderTests, "test_parse_valid_cookie_octet_%02d" % index, check)


def _duplicate_matrix():
    policies = [("first", "1"), ("last", "3")]
    for policy, expected in policies:
        def check(self, policy=policy, expected=expected):
            result = parse_cookie_header("x=0; sid=1; z=9; sid=2; sid=3", duplicate_policy=policy)
            self.assertEqual(expected, result["sid"])
            self.assertEqual("0", result["x"])
            self.assertEqual("9", result["z"])
        _add_test(ParseCookieHeaderTests, "test_duplicate_%s_surrounding_entries" % policy, check)


_malformed_segment_matrix()
_quote_matrix()
_header_character_matrix()
_invalid_value_matrix()
_valid_parse_matrix()
_duplicate_matrix()


if __name__ == "__main__":
    unittest.main()
