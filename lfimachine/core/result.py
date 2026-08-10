"""Result data model shared by techniques, the engine and reporters."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Finding:
    """A single confirmed (or strongly-suspected) issue."""

    technique: str
    title: str
    severity: Severity
    confidence: float                 # 0.0 - 1.0
    url: str
    parameter: str
    method: str = "GET"
    payload: str = ""
    encoder: str = "plain"
    evidence: str = ""                # trimmed proof snippet
    matched_signatures: List[str] = field(default_factory=list)
    os_guess: Optional[str] = None
    status_code: Optional[int] = None
    response_length: Optional[int] = None
    remediation: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @property
    def sort_key(self) -> tuple:
        return (self.severity.rank, self.confidence)
