"""Machine-readable JSON / JSONL reports for CI and tooling integration."""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from lfimachine import __version__
from lfimachine.core.engine import ScanReport


def build(report: ScanReport) -> Dict[str, Any]:
    fp = report.fingerprint
    return {
        "tool": "lfimachine",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": report.target,
        "vulnerable": report.vulnerable,
        "fingerprint": {
            "os": fp.os if fp else None,
            "server": fp.server if fp else None,
            "language": fp.language if fp else None,
            "summary": fp.summary() if fp else None,
        },
        "stats": {
            "injection_points": report.points_tested,
            "requests_sent": report.requests_sent,
            "findings": len(report.findings),
        },
        "findings": [f.to_dict() for f in report.findings],
    }


def dumps(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(build(report), indent=indent, default=str)


def write(report: ScanReport, path: str, indent: int = 2) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dumps(report, indent=indent))


def write_many(reports: List[ScanReport], path: str) -> None:
    """Write one JSON object per line (JSONL) for multiple targets."""
    with open(path, "w", encoding="utf-8") as fh:
        for r in reports:
            fh.write(json.dumps(build(r), default=str) + "\n")
