"""Command-line interface.

Design rules: the password is never echoed, never accepted as a CLI argument
(it would land in shell history and the process list), and never written to
output. Batch results are labelled by line number only.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from functools import partial
from typing import Callable, Optional

from . import __version__
from .breach import BreachCheckError, fetch_range, pwned_count
from .strength import (
    COMMON_PASSWORDS,
    DICTIONARY,
    GUESSES_PER_SECOND,
    StrengthResult,
    analyze,
    load_dictionary,
    load_wordlist,
)

EXIT_OK, EXIT_FLAGGED, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pwaudit",
        description="Audit password strength and check breach exposure without "
        "revealing the password (HIBP k-anonymity).",
    )
    p.add_argument("-f", "--file", metavar="PATH",
                   help="audit one password per line ('-' reads stdin); "
                        "default is a hidden interactive prompt")
    p.add_argument("--offline", action="store_true",
                   help="skip the breach lookup; nothing leaves this machine")
    p.add_argument("--wordlist", metavar="PATH",
                   help="larger common-password list (e.g. rockyou.txt)")
    p.add_argument("--dictionary", metavar="PATH",
                   help="word list for passphrase scoring, replacing the built-in "
                        "one (e.g. the EFF diceware list)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="network timeout in seconds (default 10)")
    p.add_argument("--version", action="version", version=f"pwaudit {__version__}")
    return p


def read_passwords(args: argparse.Namespace) -> list[tuple[str, str]]:
    """Return [(label, password)]. Labels never contain password material."""
    if args.file:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        # A BOM (Notepad, PowerShell) would otherwise be hashed into the first
        # password, giving a wrong hash and a false "not found".
        lines = text.removeprefix("﻿").splitlines()
        return [(f"line {n}", line) for n, line in enumerate(lines, 1) if line]
    password = getpass.getpass("Password to audit (input hidden): ")
    return [("input", password)] if password else []


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def render_text(label: str, r: StrengthResult, breach: Optional[int],
                breach_note: str, color: bool) -> str:
    tone = {0: "31", 1: "31", 2: "33", 3: "32", 4: "32"}[r.score]
    if breach is None:
        breach_line = breach_note
    elif breach == 0:
        breach_line = _paint("not found in known breaches", "32", color)
    else:
        breach_line = _paint(f"FOUND {breach:,} times in known breaches", "31", color)

    rows = [
        ("Length", str(r.length)),
        ("Charset", f"{'+'.join(r.charsets)} (pool {r.pool_size})"),
        ("Entropy", f"{r.raw_bits:.1f} bits raw, {r.effective_bits:.1f} bits effective"),
        ("Rating", _paint(f"{r.rating} ({r.score}/4)", tone, color)),
        ("Crack time", f"{r.crack_time} (assumes {GUESSES_PER_SECOND:.0e} guesses/s, "
                       "offline attack on a fast hash)"),
        ("Breaches", breach_line),
    ]
    out = [f"[{label}]"] + [f"  {k:<11}{v}" for k, v in rows]
    if r.findings:
        out.append("  Findings")
        out += [f"    - {f}" for f in r.findings]
    return "\n".join(out)


def main(argv: Optional[list[str]] = None,
         fetch: Optional[Callable[[str], str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        common = COMMON_PASSWORDS
        if args.wordlist:
            common = load_wordlist(args.wordlist) | COMMON_PASSWORDS
        dictionary = load_dictionary(args.dictionary) if args.dictionary else DICTIONARY
        entries = read_passwords(args)
    except OSError as exc:
        print(f"pwaudit: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except (EOFError, KeyboardInterrupt):
        print("\npwaudit: cancelled", file=sys.stderr)
        return EXIT_ERROR

    if not entries:
        print("pwaudit: no passwords to audit", file=sys.stderr)
        return EXIT_ERROR

    # Passwords sharing a hash prefix reuse one request.
    base_fetch = fetch or partial(fetch_range, timeout=args.timeout)
    cache: dict[str, str] = {}

    def cached(prefix: str) -> str:
        if prefix not in cache:
            cache[prefix] = base_fetch(prefix)
        return cache[prefix]

    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not args.json
    flagged = errored = False
    report, blocks = [], []

    for label, password in entries:
        result = analyze(password, common, dictionary)
        breach: Optional[int] = None
        note = "skipped (--offline)"
        if not args.offline:
            try:
                breach = pwned_count(password, cached)
            except BreachCheckError as exc:
                note, errored = f"unavailable ({exc})", True
        if (breach or 0) > 0 or result.score <= 1:
            flagged = True
        report.append({"label": label, **result.to_dict(), "breach_count": breach,
                       "breach_checked": breach is not None})
        blocks.append(render_text(label, result, breach, note, color))

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("\n\n".join(blocks))
        if len(entries) > 1:
            weak = sum(1 for r in report if r["score"] <= 1)
            hit = sum(1 for r in report if (r["breach_count"] or 0) > 0)
            print(f"\nSummary: {len(entries)} audited, {weak} weak or worse, {hit} breached")

    return EXIT_FLAGGED if flagged else EXIT_ERROR if errored else EXIT_OK
