import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from pwaudit.breach import (
    BreachCheckError,
    count_in_range,
    fetch_range,
    pwned_count,
    sha1_parts,
)
from pwaudit.cli import main

# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


def fake_api(prefix):
    """Stand-in for HIBP: returns padded rows plus the real 'password' row."""
    rows = ["0018A45C4D1DEF81644B54AB7F969B88D65:0",
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2"]
    if prefix == PREFIX:
        rows.append(f"{SUFFIX}:10434004")
    return "\r\n".join(rows)


class Sha1Tests(unittest.TestCase):
    def test_known_vector(self):
        self.assertEqual(sha1_parts("password"), (PREFIX, SUFFIX))

    def test_prefix_and_suffix_lengths(self):
        prefix, suffix = sha1_parts("anything")
        self.assertEqual((len(prefix), len(suffix)), (5, 35))

    def test_prefix_validation(self):
        with self.assertRaises(ValueError):
            fetch_range("ABC")


class RangeParsingTests(unittest.TestCase):
    def test_found(self):
        self.assertEqual(count_in_range(fake_api(PREFIX), SUFFIX), 10434004)

    def test_not_found(self):
        self.assertEqual(count_in_range(fake_api("AAAAA"), SUFFIX), 0)

    def test_padding_rows_count_as_zero(self):
        self.assertEqual(count_in_range(f"{SUFFIX}:0\r\n", SUFFIX), 0)

    def test_malformed_line(self):
        with self.assertRaises(BreachCheckError):
            count_in_range(f"{SUFFIX}:abc", SUFFIX)


class PrivacyTests(unittest.TestCase):
    def test_only_prefix_leaves_the_machine(self):
        seen = []

        def spy(prefix):
            seen.append(prefix)
            return fake_api(prefix)

        self.assertEqual(pwned_count("password", spy), 10434004)
        self.assertEqual(seen, [PREFIX])
        self.assertNotIn(SUFFIX, seen[0])


class CliTests(unittest.TestCase):
    def run_cli(self, argv, fetch=fake_api):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv, fetch=fetch)
        return code, buf.getvalue()

    def write(self, lines):
        fd, path = tempfile.mkstemp(text=True)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        self.addCleanup(os.remove, path)
        return path

    def test_breached_password_flags_exit_1(self):
        code, out = self.run_cli(["-f", self.write(["password"])])
        self.assertEqual(code, 1)
        self.assertIn("10,434,004", out)

    def test_clean_strong_password_exits_0(self):
        code, out = self.run_cli(["-f", self.write(["vT8#nQ2!rXz5&Lm9@Wk4"])])
        self.assertEqual(code, 0)
        self.assertIn("not found in known breaches", out)

    def test_output_never_contains_the_password(self):
        pw = "vT8#nQ2!rXz5&Lm9@Wk4"
        _, text_out = self.run_cli(["-f", self.write([pw])])
        _, json_out = self.run_cli(["-f", self.write([pw]), "--json"])
        self.assertNotIn(pw, text_out)
        self.assertNotIn(pw, json_out)
        data = json.loads(json_out)
        self.assertEqual(data[0]["label"], "line 1")
        self.assertEqual(data[0]["breach_count"], 0)

    def test_offline_never_calls_network(self):
        def boom(prefix):
            raise AssertionError("network used in offline mode")

        code, out = self.run_cli(["-f", self.write(["vT8#nQ2!rXz5&Lm9@Wk4"]), "--offline"],
                                 fetch=boom)
        self.assertEqual(code, 0)
        self.assertIn("skipped", out)

    def test_network_failure_is_reported_not_crashed(self):
        def down(prefix):
            raise BreachCheckError("could not reach HIBP: timeout")

        code, out = self.run_cli(["-f", self.write(["vT8#nQ2!rXz5&Lm9@Wk4"])], fetch=down)
        self.assertEqual(code, 2)
        self.assertIn("unavailable", out)

    def test_bom_is_not_hashed_into_first_password(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write("﻿password\r\n".encode("utf-8"))
        self.addCleanup(os.remove, path)
        code, out = self.run_cli(["-f", path])
        self.assertEqual(code, 1)
        self.assertIn("10,434,004", out)

    def test_dictionary_option_replaces_builtin_list(self):
        pw = self.write(["zorblax-quimby-frazzle"])
        words = self.write(["zorblax", "quimby", "frazzle"])
        _, default = self.run_cli(["-f", pw, "--offline", "--json"])
        _, custom = self.run_cli(["-f", pw, "--offline", "--json", "--dictionary", words])
        self.assertLess(json.loads(custom)[0]["effective_bits"],
                        json.loads(default)[0]["effective_bits"])

    def test_missing_file(self):
        self.assertEqual(main(["-f", "/nonexistent/x.txt"]), 2)

    def test_same_prefix_is_fetched_once(self):
        calls = []

        def counting(prefix):
            calls.append(prefix)
            return fake_api(prefix)

        self.run_cli(["-f", self.write(["password", "password"])], fetch=counting)
        self.assertEqual(calls, [PREFIX])


if __name__ == "__main__":
    unittest.main()
