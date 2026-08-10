"""
Content signatures used to confirm a successful inclusion and to fingerprint
the underlying operating system from a leaked file.

A signature is deliberately conservative: it must be extremely unlikely to
appear in an ordinary application response so that a match is high-confidence
evidence of file disclosure rather than a reflected payload or error page.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern


@dataclass
class Signature:
    name: str
    os: str  # "linux", "windows", "generic"
    pattern: Pattern
    # Weight contributes to the confidence score of a finding.
    weight: float = 1.0
    description: str = ""


def _rx(p: str) -> Pattern:
    return re.compile(p, re.IGNORECASE | re.MULTILINE)


# Ordered roughly by reliability. Multiple matches stack in the detector.
SIGNATURES: List[Signature] = [
    Signature(
        "etc_passwd",
        "linux",
        _rx(r"^root:.*?:0:0:.*?:.*?:(/[\w./-]*)$"),
        weight=1.0,
        description="/etc/passwd root account line",
    ),
    Signature(
        "etc_passwd_nobody",
        "linux",
        _rx(r"^(nobody|daemon|bin|sys):.*?:\d+:\d+:"),
        weight=0.6,
        description="/etc/passwd system account line",
    ),
    Signature(
        "etc_shadow",
        "linux",
        _rx(r"^root:[\$!*][^:]*:\d+:\d+:\d+:"),
        weight=1.0,
        description="/etc/shadow root hash line",
    ),
    Signature(
        "etc_hosts",
        "linux",
        _rx(r"^\s*127\.0\.0\.1\s+localhost"),
        weight=0.5,
        description="/etc/hosts loopback entry",
    ),
    Signature(
        "proc_self_environ",
        "linux",
        _rx(r"(PATH=/[^\x00]*|HTTP_USER_AGENT=|DOCUMENT_ROOT=)"),
        weight=0.7,
        description="/proc/self/environ variables",
    ),
    Signature(
        "proc_version",
        "linux",
        _rx(r"Linux version \d+\.\d+"),
        weight=0.8,
        description="/proc/version kernel banner",
    ),
    Signature(
        "sshd_config",
        "linux",
        _rx(r"^\s*(PermitRootLogin|PasswordAuthentication|Port)\s+\S+"),
        weight=0.5,
        description="sshd_config directive",
    ),
    Signature(
        "win_ini",
        "windows",
        _rx(r"\[(fonts|extensions|mci extensions|files)\]"),
        weight=0.9,
        description="Windows win.ini section header",
    ),
    Signature(
        "windows_hosts",
        "windows",
        _rx(r"#\s*(This is a sample HOSTS file|Copyright \(c\) 1993-\d+ Microsoft)"),
        weight=0.9,
        description="Windows drivers/etc/hosts banner",
    ),
    Signature(
        "boot_ini",
        "windows",
        _rx(r"\[boot loader\]|\[operating systems\]"),
        weight=0.8,
        description="Windows boot.ini",
    ),
    Signature(
        "sam_registry",
        "windows",
        _rx(r"regf"),
        weight=0.4,
        description="Windows registry hive magic",
    ),
    Signature(
        "php_open_tag",
        "generic",
        _rx(r"<\?php[\s\r\n]"),
        weight=0.5,
        description="Raw PHP source (wrapper source disclosure)",
    ),
]


# Distinctive strings that mark a php://filter base64 disclosure worth decoding.
BASE64_HINT = re.compile(r"^[A-Za-z0-9+/=\r\n]{40,}$", re.MULTILINE)


def match_signatures(body: str) -> List[Signature]:
    """Return every signature whose pattern is present in ``body``."""
    hits: List[Signature] = []
    for sig in SIGNATURES:
        if sig.pattern.search(body):
            hits.append(sig)
    return hits


def guess_os(hits: List[Signature]) -> Optional[str]:
    scores = {"linux": 0.0, "windows": 0.0}
    for h in hits:
        if h.os in scores:
            scores[h.os] += h.weight
    if scores["linux"] == scores["windows"] == 0:
        return None
    return "linux" if scores["linux"] >= scores["windows"] else "windows"
