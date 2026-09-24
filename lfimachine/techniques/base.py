"""Base classes shared by every attack technique."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from lfimachine.core.baseline import Baseline
from lfimachine.core.fingerprint import Fingerprint
from lfimachine.core.http import HttpClient
from lfimachine.core.result import Finding
from lfimachine.core.target import InjectionPoint
from lfimachine.utils.logger import Logger


@dataclass
class TechniqueContext:
    client: HttpClient
    point: InjectionPoint
    baseline: Baseline
    fingerprint: Fingerprint
    logger: Logger
    # Tunables
    encoders: List[str] = field(default_factory=list)
    min_depth: int = 1
    max_depth: int = 12
    aggressive: bool = False
    rce: bool = False
    lhost: str = ""                 # for callback-style checks / marker
    stop_on_first: bool = True
    threads: int = 1                # worker budget for a single point's sweep
    max_attempts: int = 0           # per-probe request cap (0 = auto by profile)
    # Header-driven behaviour.
    auto_headers: bool = False      # test path-override / proxy headers
    spoof_headers: Dict[str, str] = field(default_factory=dict)
    extra_test_headers: List[str] = field(default_factory=list)
    # Live progress reporter (optional).
    progress: object = None
    # Populated as techniques learn about the target.
    confirmed_traversal: Optional[str] = None   # a working traversal prefix
    confirmed_encoder: str = "plain"
    os_confirmed: Optional[str] = None


class Technique:
    name: str = "base"
    description: str = ""
    #: Higher runs earlier. Detection techniques should outrank escalation ones.
    priority: int = 0
    #: If True, engine only runs it after an inclusion has been confirmed.
    requires_inclusion: bool = False

    def applicable(self, ctx: TechniqueContext) -> bool:
        return True

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:  # pragma: no cover
        raise NotImplementedError
