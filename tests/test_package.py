"""Package metadata, public API, typing, workflow, and repository hygiene tests."""

import ast
import re
import subprocess
import unittest
from pathlib import Path

import pycookiecage
from pycookiecage import ERROR_CODES

ROOT = Path(__file__).resolve().parents[1]


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def project_files():
    skipped = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "venv"}
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skipped for part in path.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        yield path


class PackageMetadataTests(unittest.TestCase):
    def test_runtime_dependencies_are_empty(self):
        self.assertIn("dependencies = []", read("pyproject.toml"))

    def test_python_floor_is_39(self):
        self.assertIn('requires-python = ">=3.9"', read("pyproject.toml"))

    def test_project_name_and_version(self):
        text = read("pyproject.toml")
        self.assertIn('name = "pycookiecage"', text)
        self.assertIn('version = "1.0.0"', text)
        self.assertIn('license = "MIT"', text)
        self.assertEqual("1.0.0", pycookiecage.__version__)

    def test_project_urls_point_to_public_repository(self):
        text = read("pyproject.toml")
        self.assertIn('Homepage = "https://github.com/draarivpatel-ui/pycookiecage"', text)
        self.assertIn('Repository = "https://github.com/draarivpatel-ui/pycookiecage"', text)
        self.assertIn('Issues = "https://github.com/draarivpatel-ui/pycookiecage/issues"', text)

    def test_py_typed_is_present(self):
        self.assertTrue((ROOT / "src" / "pycookiecage" / "py.typed").is_file())

    def test_py_typed_is_packaged(self):
        self.assertIn('pycookiecage = ["py.typed"]', read("pyproject.toml"))

    def test_src_layout_is_used(self):
        self.assertIn('package-dir = { "" = "src" }', read("pyproject.toml"))
        self.assertTrue((ROOT / "src" / "pycookiecage" / "__init__.py").is_file())

    def test_console_script_is_configured(self):
        self.assertIn('pycookiecage = "pycookiecage.cli:main"', read("pyproject.toml"))

    def test_manifest_includes_complete_test_tree(self):
        self.assertIn("recursive-include tests *.py", read("MANIFEST.in"))


class WorkflowTests(unittest.TestCase):
    def test_ci_uses_ubuntu_2404(self):
        self.assertIn("runs-on: ubuntu-24.04", read(".github/workflows/ci.yml"))

    def test_ci_matrix_covers_python_39_to_313(self):
        text = read(".github/workflows/ci.yml")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)

    def test_ci_runs_unittest_suite(self):
        self.assertIn("PYTHONPATH=src python3 -m unittest discover -s tests", read(".github/workflows/ci.yml"))

    def test_ci_permissions_are_read_only(self):
        self.assertIn("contents: read", read(".github/workflows/ci.yml"))

    def test_publish_uses_oidc_trusted_publishing_permission(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("id-token: write", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)

    def test_publish_workflow_targets_pypi_environment(self):
        text = read(".github/workflows/publish.yml")
        self.assertIn("name: pypi", text)
        self.assertIn("url: https://pypi.org/p/pycookiecage", text)

    def test_publish_checkout_has_no_token_or_secret_echo(self):
        text = read(".github/workflows/publish.yml")
        self.assertNotIn("password:", text)
        self.assertNotIn("PYPI_API_TOKEN", text)


class DocumentationTests(unittest.TestCase):
    def test_required_documents_exist(self):
        for relative in (
            "README.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "LICENSE",
            "MANIFEST.in",
            "docs/good-first-issues.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
        ):
            self.assertTrue((ROOT / relative).is_file(), relative)

    def test_good_first_issues_has_ten_items(self):
        count = len(re.findall(r"^\d+\. \*\*", read("docs/good-first-issues.md"), re.MULTILINE))
        self.assertEqual(10, count)

    def test_readme_documents_signed_values_are_not_encrypted(self):
        text = read("README.md")
        self.assertIn("does not encrypt", text)
        self.assertIn("still readable", text)

    def test_readme_documents_public_suffix_limitation(self):
        self.assertIn("does not vendor the full Public Suffix List", read("README.md"))

    def test_readme_documents_single_header_parser_scope(self):
        self.assertIn("one complete incoming `Cookie` header", read("README.md"))

    def test_readme_documents_exact_test_count(self):
        text = read("README.md")
        match = re.search(r"contains (\d+) real deterministic tests", text)
        self.assertIsNotNone(match)
        self.assertNotIn("TEST_COUNT_PLACEHOLDER", text)

    def test_readme_test_count_has_matching_pass_count(self):
        text = read("README.md")
        contains = re.search(r"contains (\d+) real deterministic tests", text)
        passed = re.search(r"All (\d+) tests passed", text)
        self.assertIsNotNone(contains)
        self.assertIsNotNone(passed)
        self.assertEqual(contains.group(1), passed.group(1))

    def test_security_policy_has_private_reporting_path(self):
        self.assertIn("private security advisory", read("SECURITY.md"))

    def test_contributing_forbids_dashes(self):
        self.assertIn("em dashes or en dashes", read("CONTRIBUTING.md"))


class PublicApiTests(unittest.TestCase):
    def test_error_codes_are_unique(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))

    def test_error_codes_are_uppercase_machine_readable(self):
        for code in ERROR_CODES:
            self.assertRegex(code, r"^[A-Z0-9_]+$")

    def test_required_public_names_exist(self):
        for name in (
            "CookieCageError",
            "CookieJarGuard",
            "VerifiedCookie",
            "delete_cookie",
            "parse_cookie_header",
            "serialize_cookie",
            "sign_cookie_value",
            "verify_cookie_value",
        ):
            self.assertTrue(hasattr(pycookiecage, name), name)

    def test_all_exports_exist(self):
        for name in pycookiecage.__all__:
            self.assertTrue(hasattr(pycookiecage, name), name)

    def test_no_decode_unsafe_alias_exists(self):
        self.assertFalse(hasattr(pycookiecage, "decode_unsafe"))

    def test_verified_cookie_annotations_exist(self):
        annotations = pycookiecage.VerifiedCookie.__annotations__
        for name in ("value", "key_id", "rotated", "expires_at"):
            self.assertIn(name, annotations)


class SourceHygieneTests(unittest.TestCase):
    def test_source_has_no_third_party_imports(self):
        allowed = {
            "__future__",
            "argparse",
            "base64",
            "dataclasses",
            "datetime",
            "hashlib",
            "hmac",
            "json",
            "math",
            "re",
            "struct",
            "sys",
            "time",
            "typing",
            "pycookiecage",
        }
        for path in (ROOT / "src" / "pycookiecage").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                for name in names:
                    self.assertIn(name, allowed, "{} imports {}".format(path.name, name))

    def test_tracked_text_has_no_em_or_en_dashes(self):
        forbidden = (chr(0x2013), chr(0x2014))
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for char in forbidden:
                self.assertNotIn(char, text, "{} contains a Unicode dash".format(path))

    def test_tracked_text_has_no_local_private_markers(self):
        markers = (
            "/" + "Users/",
            "/" + "private/tmp/",
            "gmail" + ".com",
        )
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            for marker in markers:
                self.assertNotIn(marker, text, "{} contains a private marker".format(path))

    def test_no_pycache_files_are_tracked(self):
        completed = subprocess.run(
            ["git", "ls-files"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
        )
        if completed.returncode != 0 and not (ROOT / ".git").exists():
            self.skipTest("git metadata is not available")
        self.assertEqual(0, completed.returncode)
        tracked = completed.stdout.splitlines()
        matches = [name for name in tracked if "__pycache__/" in name or name.endswith((".pyc", ".pyo"))]
        self.assertEqual([], matches)

    def test_no_crlf_line_endings_in_text_files(self):
        for path in project_files():
            data = path.read_bytes()
            if b"\x00" in data:
                continue
            self.assertNotIn(b"\r\n", data, "{} contains CRLF".format(path))

    def test_no_co_author_trailer_in_repository_files(self):
        for path in project_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn("Co-" + "Authored-By:", text, "{} contains a co-author trailer".format(path))

    def test_gitattributes_enforces_lf_for_python(self):
        self.assertIn("*.py text eol=lf", read(".gitattributes"))

    def test_gitignore_excludes_pycache(self):
        self.assertIn("__pycache__/", read(".gitignore"))

    def test_library_modules_contain_no_print_statements_outside_cli(self):
        for path in (ROOT / "src" / "pycookiecage").glob("*.py"):
            if path.name == "cli.py":
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("print(", text, "{} contains print".format(path))

    def test_exceptions_do_not_interpolate_input_values(self):
        combined = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src" / "pycookiecage").glob("*.py"))
        self.assertNotIn("+ value +", combined)
        self.assertNotIn("+ secret +", combined)
        self.assertNotIn("+ signed_value +", combined)


if __name__ == "__main__":
    unittest.main()
