"""
Lightweight target fingerprinting.

Before fuzzing, LFI-Machine probes the target once to guess the operating
system and server-side technology. This lets it pick the right probe files
(``/etc/passwd`` vs ``win.ini``), decide whether PHP wrapper techniques are
worth trying, and tailor log-poisoning paths — so the scan is fast and quiet
rather than a blind payload flood.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from lfimachine.core.http import HttpClient, Response
from lfimachine.core.target import InjectionPoint


@dataclass
class Fingerprint:
    os: Optional[str] = None            # "linux" | "windows"
    server: Optional[str] = None        # "apache" | "nginx" | "iis" | ...
    language: Optional[str] = None      # "php" | "java" | "asp.net" | ...
    php: bool = False
    notes: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def summary(self) -> str:
        parts = []
        if self.os:
            parts.append(self.os)
        if self.server:
            parts.append(self.server)
        if self.language:
            parts.append(self.language)
        return " / ".join(parts) if parts else "unknown"


_PHP_SESSION = re.compile(r"PHPSESSID", re.IGNORECASE)
_ASP_SESSION = re.compile(r"ASP\.NET_SessionId|ASPSESSIONID", re.IGNORECASE)
_JSP_SESSION = re.compile(r"JSESSIONID", re.IGNORECASE)


def _from_headers(fp: Fingerprint, headers: Dict[str, str]) -> None:
    lower = {k.lower(): v for k, v in headers.items()}
    server = lower.get("server", "").lower()
    powered = lower.get("x-powered-by", "").lower()
    set_cookie = lower.get("set-cookie", "")

    if "apache" in server:
        fp.server = "apache"
    elif "nginx" in server:
        fp.server = "nginx"
    elif "iis" in server or "microsoft" in server:
        fp.server = "iis"
        fp.os = fp.os or "windows"
    elif "litespeed" in server:
        fp.server = "litespeed"

    if "win" in server or "win64" in powered:
        fp.os = "windows"

    if "php" in powered or _PHP_SESSION.search(set_cookie):
        fp.php = True
        fp.language = "php"
        fp.confidence += 0.3
    if "asp.net" in powered or _ASP_SESSION.search(set_cookie):
        fp.language = "asp.net"
        fp.os = fp.os or "windows"
    if _JSP_SESSION.search(set_cookie):
        fp.language = "java"


def _from_url(fp: Fingerprint, url: str) -> None:
    if re.search(r"\.php(\?|$|/)", url, re.IGNORECASE):
        fp.php = True
        fp.language = fp.language or "php"
    elif re.search(r"\.(aspx?|asmx)(\?|$)", url, re.IGNORECASE):
        fp.language = fp.language or "asp.net"
        fp.os = fp.os or "windows"
    elif re.search(r"\.(jsp|do|action)(\?|$)", url, re.IGNORECASE):
        fp.language = fp.language or "java"


def _from_body(fp: Fingerprint, body: str) -> None:
    if re.search(r"<b>(Warning|Fatal error|Notice)</b>:.*(include|require|fopen)",
                 body, re.IGNORECASE):
        fp.php = True
        fp.language = "php"
        fp.confidence += 0.2
        fp.notes.append("PHP include/require error leaked in response")
    if re.search(r"C:\\(inetpub|windows|xampp|wamp)", body, re.IGNORECASE):
        fp.os = "windows"
    if re.search(r"/(var|etc|usr|home)/", body):
        fp.os = fp.os or "linux"


def run(client: HttpClient, point: InjectionPoint, url: str) -> Fingerprint:
    fp = Fingerprint()
    resp = point.send(client, "index")
    if resp.ok:
        _from_headers(fp, resp.headers)
        _from_body(fp, resp.text)
    _from_url(fp, url)

    # Default assumption: internet-facing web apps are overwhelmingly Linux.
    if fp.os is None:
        fp.os = "linux"
        fp.notes.append("OS unknown — defaulting to linux probes")
    else:
        fp.confidence += 0.3
    fp.confidence = min(fp.confidence, 1.0)
    return fp
