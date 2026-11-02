"""Password strength estimation.

Model: every character costs log2(pool) bits, where pool is the size of the
character set the password draws from. Predictable structure (sequences,
keyboard walks, repeats, years, dictionary words, common passwords) is then
priced at what an attacker would actually spend to guess it, so the total
drops. It is a heuristic in the spirit of zxcvbn, not a replacement for it.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Assumed attacker speed: an offline attack on a fast, unsalted hash (MD5,
# SHA-1, NTLM) with about one current high-end GPU. A slow hash such as bcrypt
# or Argon2 would be millions of times slower. Stated in every report so the
# number is not mistaken for a fact about the world.
GUESSES_PER_SECOND = 1e11

CHEAP_BITS = 1.0        # cost of a character that is predictable from context
YEAR_BITS = 7.0         # a 4-digit year: roughly 130 plausible values
COMMON_CAP_BITS = 10.0  # a password on a common list falls in the first ~1000 guesses
MIN_WORD_LEN = 4        # shorter words match too often inside random strings

LEET = {
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "$": "s", "5": "s", "7": "t",
}

KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_WALKS = KEYBOARD_ROWS + tuple(row[::-1] for row in KEYBOARD_ROWS)

# Small embedded list so the tool works with zero setup. Pass a larger list
# (for example rockyou.txt) with --wordlist for real coverage.
COMMON_PASSWORDS = frozenset(
    """
    123456 123456789 12345678 12345 1234567 1234567890 password password1
    password123 passw0rd qwerty qwerty123 qwertyuiop abc123 111111 000000
    123123 654321 666666 121212 iloveyou admin administrator welcome login
    letmein monkey dragon master sunshine princess football baseball soccer
    hockey batman superman shadow michael jennifer jordan hunter ranger
    trustno1 starwars computer internet whatever freedom secret summer
    winter spring autumn flower cookie ginger pepper cheese buster tigger
    mustang access hello hello123 charlie donald loveme zaq12wsx
    1q2w3e4r 1qaz2wsx asdfgh asdfghjkl zxcvbn zxcvbnm changeme default guest
    root toor test test123 testing temp temp123 pass pass123 pa55word
    p@ssw0rd p@ssword google facebook twitter pokemon minecraft fortnite
    killer pass1234 love money rockyou naruto
    """.split()
)

RATINGS = ("Very weak", "Weak", "Fair", "Strong", "Excellent")

# Common English words. A passphrase attacker guesses whole words from a list
# like this, so a word costs log2(list size) bits, not log2(pool) per letter.
# Pass a bigger list (for example the EFF diceware list) with --dictionary.
_WORDS_FILE = Path(__file__).with_name("words.txt")


@dataclass
class StrengthResult:
    length: int
    charsets: list[str]
    pool_size: int
    raw_bits: float
    effective_bits: float
    score: int
    rating: str
    crack_time: str
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["raw_bits"] = round(self.raw_bits, 1)
        d["effective_bits"] = round(self.effective_bits, 1)
        return d


def load_wordlist(path: str | Path) -> frozenset[str]:
    """Load a newline-delimited wordlist, lowercased. Bad bytes are ignored."""
    with open(path, encoding="utf-8", errors="ignore") as fh:
        return frozenset(line.strip().lower() for line in fh if line.strip())


def load_dictionary(path: str | Path = _WORDS_FILE) -> frozenset[str]:
    """Load a word list for passphrase detection. Its size sets the per-word cost."""
    return load_wordlist(path)


DICTIONARY = load_dictionary()


def charset_info(password: str) -> tuple[list[str], int]:
    """Return (names of character classes used, pool size)."""
    names, pool = [], 0
    if any("a" <= c <= "z" for c in password):
        names.append("lower")
        pool += 26
    if any("A" <= c <= "Z" for c in password):
        names.append("upper")
        pool += 26
    if any("0" <= c <= "9" for c in password):
        names.append("digit")
        pool += 10
    if any(c in string.punctuation or c == " " for c in password):
        names.append("symbol")
        pool += 33
    if any(ord(c) > 127 for c in password):
        names.append("unicode")
        pool += 100
    return names, pool


def _is_ascii_alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def sequence_runs(password: str, min_len: int = 3) -> list[tuple[int, int]]:
    """Spans like 'abc', '4321' where each char is +1 or -1 from the last."""
    s, n = password.lower(), len(password)
    runs, i = [], 0
    while i < n - 1:
        delta = ord(s[i + 1]) - ord(s[i])
        if delta in (1, -1) and _is_ascii_alnum(s[i]) and _is_ascii_alnum(s[i + 1]):
            j = i + 1
            while (
                j + 1 < n
                and _is_ascii_alnum(s[j + 1])
                and ord(s[j + 1]) - ord(s[j]) == delta
            ):
                j += 1
            if j - i + 1 >= min_len:
                runs.append((i, j + 1))
            i = j
        else:
            i += 1
    return runs


def keyboard_runs(password: str, min_len: int = 4) -> list[tuple[int, int]]:
    """Spans that follow a keyboard row, forwards or backwards ('qwer', 'poiu')."""
    s, n = password.lower(), len(password)
    runs, i = [], 0
    while i < n:
        best = 0
        for length in range(min(n - i, 10), min_len - 1, -1):
            chunk = s[i:i + length]
            if any(chunk in walk for walk in _WALKS):
                best = length
                break
        if best:
            runs.append((i, i + best))
            i += best
        else:
            i += 1
    return runs


def repeat_spans(password: str) -> list[tuple[int, int]]:
    """Spans of the same char 3+ times, or the whole password as one repeated block."""
    spans = [m.span() for m in re.finditer(r"(.)\1{2,}", password, re.DOTALL)]
    block = re.fullmatch(r"(.+?)\1+", password, re.DOTALL)
    if block:
        # The first copy is paid in full; only the copies after it are cheap.
        spans.append((len(block.group(1)), len(password)))
    return spans


def year_spans(password: str) -> list[tuple[int, int]]:
    return [m.span() for m in re.finditer(r"(?<!\d)(?:19|20)\d{2}(?!\d)", password)]


def normalise(password: str) -> str:
    """Lowercase and undo common leetspeak, so 'P@ssw0rd' matches 'password'."""
    return "".join(LEET.get(c, c) for c in password.lower())


def is_common(password: str, common: frozenset[str]) -> bool:
    """True if the password, or its de-leeted form with trailing digits and
    symbols stripped, is on the list ('Summer2024!' -> 'summer')."""
    lowered = password.lower()
    norm = normalise(password)
    strip = string.digits + string.punctuation
    candidates = {lowered, norm, lowered.rstrip(strip), norm.rstrip(strip)}
    candidates.discard("")
    return any(c in common for c in candidates)


def word_bits(token: str, dictionary_bits: float) -> float:
    """Cost of guessing a dictionary word as written: the word, then its
    capitalisation (1 bit for 'Word' or 'WORD', 1 bit per capital otherwise),
    then 1 bit per leetspeak substitution."""
    uppers = sum(c.isupper() for c in token)
    letters = sum(c.isalpha() for c in token)
    if uppers == 0:
        case = 0.0
    elif uppers == letters or (uppers == 1 and token[0].isupper()):
        case = 1.0
    else:
        case = float(uppers)
    leet = sum(1 for c in token if c in LEET)
    return dictionary_bits + case + leet


def dictionary_words(password: str, cost: list[float],
                     dictionary: frozenset[str]) -> tuple[float, list[tuple[int, int]]]:
    """Cheapest way to spell the password as single characters and dictionary
    words, given each character's current cost.

    Dynamic programming over prefixes: best[j] is the cheapest cost of
    password[:j]. Returns (total bits, word spans used). Separators that repeat
    one already used between words cost almost nothing ('-' then '-' again).
    """
    n = len(password)
    if not dictionary or n < MIN_WORD_LEN:
        return sum(cost), []
    per_word = math.log2(len(dictionary))
    longest = min(max(map(len, dictionary)), n)
    lowered, norm = password.lower(), normalise(password)

    best = [0.0] + [math.inf] * n
    step: list[tuple[int, bool]] = [(0, False)] * (n + 1)
    for i in range(n):
        if best[i] + cost[i] < best[i + 1]:
            best[i + 1], step[i + 1] = best[i] + cost[i], (i, False)
        for j in range(i + MIN_WORD_LEN, min(n, i + longest) + 1):
            if lowered[i:j] in dictionary or norm[i:j] in dictionary:
                total = best[i] + word_bits(password[i:j], per_word)
                if total < best[j]:
                    best[j], step[j] = total, (i, True)

    spans, j = [], n
    while j:
        i, is_word = step[j]
        if is_word:
            spans.append((i, j))
        j = i
    spans.reverse()
    if len(spans) < 2:
        return best[n], spans

    # The DP charged every separator in full. After the first, they are
    # predictable: a passphrase almost always reuses one separator.
    in_word = {k for a, b in spans for k in range(a, b)}
    seen, refund = set(), 0.0
    for k, c in enumerate(password):
        if k in in_word or c.isalnum():
            continue
        if c in seen:
            refund += max(cost[k] - CHEAP_BITS, 0.0)
        seen.add(c)
    return best[n] - refund, spans


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    years = seconds / 31_557_600
    if years >= 1e9:
        return "over a billion years"
    if years >= 1:
        return f"about {years:,.0f} year{'s' if round(years) != 1 else ''}"
    for name, size in (("day", 86_400), ("hour", 3_600), ("minute", 60), ("second", 1)):
        if seconds >= size:
            count = round(seconds / size)
            return f"about {count:,} {name}{'s' if count != 1 else ''}"
    return "instantly"


def rating_for(bits: float) -> tuple[int, str]:
    for score, limit in enumerate((28, 36, 60, 80)):
        if bits < limit:
            return score, RATINGS[score]
    return 4, RATINGS[4]


def _lengths(spans: list[tuple[int, int]]) -> str:
    """Describe spans by size only. Printing them would leak the password."""
    return ", ".join(str(b - a) for a, b in spans) + " characters"


def analyze(password: str, common: frozenset[str] = COMMON_PASSWORDS,
            dictionary: frozenset[str] = DICTIONARY) -> StrengthResult:
    if not password:
        raise ValueError("password is empty")

    names, pool = charset_info(password)
    per_char = math.log2(pool)
    cost = [per_char] * len(password)
    raw_bits = per_char * len(password)
    findings: list[str] = []

    def price(spans, bits, skip_first=True):
        for start, end in spans:
            for k in range(start + (1 if skip_first else 0), end):
                cost[k] = min(cost[k], bits)

    seqs = sequence_runs(password)
    if seqs:
        price(seqs, CHEAP_BITS)
        findings.append(f"Sequential run ({_lengths(seqs)}), e.g. 'abc' or '4321'")
    walks = keyboard_runs(password)
    if walks:
        price(walks, CHEAP_BITS)
        findings.append(f"Keyboard walk ({_lengths(walks)}), e.g. 'qwerty'")
    reps = repeat_spans(password)
    if reps:
        price(reps, CHEAP_BITS, skip_first=False)
        findings.append("Repeated characters or repeated block")
    years = year_spans(password)
    if years:
        price(years, YEAR_BITS / 4, skip_first=False)
        findings.append("Contains a year, which is one of the first things attackers try")

    effective, words = dictionary_words(password, cost, dictionary)

    if is_common(password, common):
        effective = min(effective, COMMON_CAP_BITS)
        findings.append("Matches a common password or a trivial variation of one")
    elif len(words) >= 2:
        # Count only: listing the words would print most of the passphrase.
        findings.append(
            f"Built from {len(words)} dictionary words, each guessable as one "
            f"unit (~{math.log2(len(dictionary)):.1f} bits) rather than letter by letter"
        )

    if len(password) < 12:
        findings.append("Short: under 12 characters. Length is the cheapest win")
    if len(names) == 1:
        findings.append(f"Uses a single character class ({names[0]})")

    score, rating = rating_for(effective)
    # Average case: the attacker finds it after searching half the space.
    seconds = 2.0 ** (min(effective, 1000.0) - 1) / GUESSES_PER_SECOND

    return StrengthResult(
        length=len(password),
        charsets=names,
        pool_size=pool,
        raw_bits=raw_bits,
        effective_bits=effective,
        score=score,
        rating=rating,
        crack_time=format_duration(seconds),
        findings=findings,
    )
