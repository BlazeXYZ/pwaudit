import unittest

from pwaudit.strength import (
    analyze,
    charset_info,
    format_duration,
    keyboard_runs,
    normalise,
    repeat_spans,
    sequence_runs,
)


class CharsetTests(unittest.TestCase):
    def test_pool_sizes(self):
        self.assertEqual(charset_info("abc"), (["lower"], 26))
        self.assertEqual(charset_info("aB3")[1], 62)
        self.assertEqual(charset_info("aB3!")[1], 95)


class PatternTests(unittest.TestCase):
    def test_sequences(self):
        self.assertEqual(sequence_runs("xabcdy"), [(1, 5)])
        self.assertEqual(sequence_runs("9876"), [(0, 4)])
        self.assertEqual(sequence_runs("ab"), [])

    def test_keyboard_walk(self):
        self.assertEqual(keyboard_runs("qwerty"), [(0, 6)])
        self.assertEqual(keyboard_runs("poiu"), [(0, 4)])
        self.assertEqual(keyboard_runs("qwe"), [])

    def test_repeated_block_prices_only_the_copies(self):
        self.assertEqual(repeat_spans("abcabc"), [(3, 6)])

    def test_leet_normalisation(self):
        self.assertEqual(normalise("P@ssw0rd"), "password")


class AnalyzeTests(unittest.TestCase):
    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            analyze("")

    def test_common_password_is_very_weak(self):
        for pw in ("password", "P@ssw0rd", "Password123!", "letmein"):
            r = analyze(pw)
            self.assertEqual(r.score, 0, pw)
            self.assertTrue(any("common" in f.lower() for f in r.findings), pw)

    def test_patterns_reduce_entropy(self):
        plain = analyze("kXv9#mQz2$wL")
        patterned = analyze("qwerty123456")
        self.assertLess(patterned.effective_bits, plain.effective_bits)
        self.assertLessEqual(patterned.score, 1)

    def test_repeats_and_years_are_flagged(self):
        self.assertTrue(any("Repeated" in f for f in analyze("aaaa").findings))
        self.assertTrue(any("year" in f for f in analyze("zq1987xt").findings))

    def test_random_long_password_is_strong(self):
        r = analyze("vT8#nQ2!rXz5&Lm9@Wk4")
        self.assertGreaterEqual(r.score, 3)
        self.assertEqual(r.findings, [])

    def test_passphrase_is_priced_per_word(self):
        # 4 words from ~1800 is about 43 bits plus separators, not 165 bits.
        r = analyze("correct horse battery staple")
        self.assertEqual(r.score, 2)
        self.assertLess(r.effective_bits, 60)
        self.assertTrue(any("4 dictionary words" in f for f in r.findings))

    def test_passphrase_variants_are_still_found(self):
        for pw in ("CorrectHorseBatteryStaple", "c0rrect-h0rse-b@ttery-st@ple"):
            self.assertLess(analyze(pw).effective_bits, 60, pw)

    def test_capitalisation_and_leet_add_a_little(self):
        plain = analyze("correct-horse-battery-staple").effective_bits
        styled = analyze("Correct-Horse-B4ttery-Staple").effective_bits
        self.assertGreater(styled, plain)
        self.assertLess(styled - plain, 10)

    def test_more_words_score_higher(self):
        four = analyze("river-candle-orbit-falcon").effective_bits
        six = analyze("river-candle-orbit-falcon-meadow-tiger").effective_bits
        self.assertGreater(six, four + 20)

    def test_finding_does_not_reveal_the_words(self):
        r = analyze("river-candle-orbit-falcon")
        self.assertFalse(any(w in " ".join(r.findings) for w in ("river", "candle")))

    def test_findings_never_quote_the_password(self):
        r = analyze("k9zxcvbnQ!7654mm")
        text = " ".join(r.findings)
        self.assertIn("Keyboard walk", text)
        self.assertIn("Sequential run", text)
        for fragment in ("zxcvbn", "7654"):
            self.assertNotIn(fragment, text)

    def test_custom_dictionary(self):
        r = analyze("zorblax-quimby-frazzle", dictionary=frozenset({"zorblax", "quimby", "frazzle"}))
        self.assertLess(r.effective_bits, 20)
        self.assertGreater(analyze("zorblax-quimby-frazzle").effective_bits, 100)

    def test_effective_never_exceeds_raw(self):
        for pw in ("abc123", "Zx9!Zx9!", "qwertyuiop", "Tr0ub4dor&3"):
            r = analyze(pw)
            self.assertLessEqual(r.effective_bits, r.raw_bits + 1e-9)

    def test_wordlist_override(self):
        self.assertEqual(analyze("x7!Qa9zLmW2#", frozenset({"x7!qa9zlmw2#"})).score, 0)


class DurationTests(unittest.TestCase):
    def test_formatting(self):
        self.assertEqual(format_duration(0.2), "instantly")
        self.assertEqual(format_duration(90), "about 2 minutes")
        self.assertEqual(format_duration(3600 * 5), "about 5 hours")
        self.assertEqual(format_duration(31_557_600 * 3), "about 3 years")
        self.assertEqual(format_duration(1e30), "over a billion years")


if __name__ == "__main__":
    unittest.main()
