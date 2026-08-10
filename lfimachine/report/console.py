"""Human-readable console report."""
from __future__ import annotations

import sys
from typing import TextIO

from lfimachine.core.engine import ScanReport
from lfimachine.core.result import Finding, Severity
from lfimachine.utils import colors

_SEV_STYLE = {
    Severity.CRITICAL: ("red", "bold"),
    Severity.HIGH: ("bright_red",),
    Severity.MEDIUM: ("yellow",),
    Severity.LOW: ("cyan",),
    Severity.INFO: ("grey",),
}


def _sev_label(sev: Severity) -> str:
    return colors.paint(sev.value.upper().ljust(8), *_SEV_STYLE.get(sev, ()))


def render(report: ScanReport, stream: TextIO = sys.stdout) -> None:
    w = stream.write
    w("\n" + colors.bold("═" * 68) + "\n")
    w(colors.bold(f" Scan report — {report.target}") + "\n")
    w(colors.bold("═" * 68) + "\n")

    if report.fingerprint:
        w(f" Target profile : {report.fingerprint.summary()}\n")
    w(f" Injection pts  : {report.points_tested}\n")
    w(f" Requests sent  : {report.requests_sent}\n")

    if not report.findings:
        w("\n" + colors.green(" No LFI vulnerabilities detected.") + "\n\n")
        return

    verdict = (colors.red("VULNERABLE") if report.vulnerable
               else colors.yellow("SUSPICIOUS"))
    w(f" Verdict        : {verdict} — {len(report.findings)} finding(s)\n\n")

    for i, f in enumerate(report.findings, 1):
        _render_finding(w, i, f)

    w(colors.grey("─" * 68) + "\n")


def _render_finding(w, index: int, f: Finding) -> None:
    w(f"[{index}] {_sev_label(f.severity)} {colors.bold(f.title)}\n")
    w(f"     technique  : {f.technique}\n")
    w(f"     location   : {f.method} {f.parameter}\n")
    w(f"     confidence : {f.confidence:.0%}\n")
    if f.os_guess:
        w(f"     os         : {f.os_guess}\n")
    if f.payload:
        payload = f.payload if len(f.payload) < 200 else f.payload[:197] + "..."
        w(f"     payload    : {colors.cyan(payload)}\n")
    if f.encoder and f.encoder != "plain":
        w(f"     encoder    : {f.encoder}\n")
    if f.matched_signatures:
        w(f"     signatures : {', '.join(f.matched_signatures)}\n")
    if f.evidence:
        ev = f.evidence if len(f.evidence) < 180 else f.evidence[:177] + "..."
        w(f"     evidence   : {colors.grey(ev)}\n")
    if f.extra.get("secrets_found"):
        w(f"     secrets    : {colors.red(', '.join(f.extra['secrets_found']))}\n")
    if f.extra.get("saved_to"):
        w(f"     saved      : {f.extra['saved_to']}\n")
    w("\n")
