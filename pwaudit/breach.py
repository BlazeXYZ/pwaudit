"""Breach lookup against Have I Been Pwned using k-anonymity.

The password is hashed locally with SHA-1. Only the first 5 hex characters of
the hash (the prefix) are sent. The API returns every known suffix sharing that
prefix, and the comparison happens here. The server never sees the password or
the full hash.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from typing import Callable

from . import __version__

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = f"pwaudit/{__version__} (+https://github.com/BlazeXYZ/pwaudit)"


class BreachCheckError(RuntimeError):
    """The lookup could not be completed (network, rate limit, bad response)."""


def sha1_parts(password: str) -> tuple[str, str]:
    """Return (prefix, suffix) of the uppercase SHA-1 hex digest.

    SHA-1 is used because the HIBP range API is defined over it, not as a
    security primitive, hence usedforsecurity=False.
    """
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:5], digest[5:]


def fetch_range(prefix: str, timeout: float = 10.0) -> str:
    """GET the suffix list for a 5-character hash prefix."""
    if len(prefix) != 5:
        raise ValueError("prefix must be exactly 5 characters")
    request = urllib.request.Request(
        API_URL + prefix,
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise BreachCheckError(f"HIBP returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise BreachCheckError(f"could not reach HIBP: {exc}") from exc


def count_in_range(body: str, suffix: str) -> int:
    """Find our suffix in an API response and return its breach count.

    Add-Padding makes the API insert fake rows with a count of 0 to hide the
    response size, so a count of 0 means 'not found'.
    """
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            try:
                return int(count)
            except ValueError as exc:
                raise BreachCheckError(f"malformed line from HIBP: {line!r}") from exc
    return 0


def pwned_count(
    password: str,
    fetch: Callable[[str], str] = fetch_range,
) -> int:
    """How many times the password appears in known breaches (0 if never)."""
    prefix, suffix = sha1_parts(password)
    return count_in_range(fetch(prefix), suffix)
