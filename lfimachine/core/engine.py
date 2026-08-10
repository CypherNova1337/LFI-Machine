"""
Scan orchestration.

The engine ties everything together:

1. Fingerprint the target once.
2. For each injection point, build a behavioural baseline.
3. Run detection techniques (traversal, wrappers) to confirm inclusion.
4. If confirmed and escalation is enabled, run RCE and harvesting techniques,
   reusing the exact working traversal/encoder discovered during detection.

Techniques are ordered by priority; ``requires_inclusion`` techniques are gated
until a confirmed inclusion exists for the current point. Injection points can
be scanned concurrently.
"""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from lfimachine.core import baseline as baseline_mod
from lfimachine.core import fingerprint as fp_mod
from lfimachine.core.http import HttpClient
from lfimachine.core.result import Finding
from lfimachine.core.target import InjectionPoint, Target
from lfimachine.techniques.base import Technique, TechniqueContext
from lfimachine.techniques.filter_chain_rce import FilterChainRceTechnique
from lfimachine.techniques.harvest import HarvestTechnique
from lfimachine.techniques.log_poison import LogPoisonTechnique, ProcEnvironTechnique
from lfimachine.techniques.traversal import TraversalTechnique
from lfimachine.techniques.wrappers import WrapperRceTechnique, WrapperSourceTechnique
from lfimachine.utils.logger import Logger


@dataclass
class ScanConfig:
    encoders: List[str] = field(default_factory=list)
    min_depth: int = 1
    max_depth: int = 12
    aggressive: bool = False
    rce: bool = False
    threads: int = 5
    stop_on_first: bool = True
    test_params: Optional[List[str]] = None
    include_cookies: bool = False
    include_headers: List[str] = field(default_factory=list)
    loot_dir: Optional[str] = None
    harvest: bool = False


@dataclass
class ScanReport:
    target: str
    fingerprint: Optional[fp_mod.Fingerprint] = None
    findings: List[Finding] = field(default_factory=list)
    points_tested: int = 0
    requests_sent: int = 0
    vulnerable: bool = False


class Engine:
    def __init__(self, client: HttpClient, config: ScanConfig, logger: Logger) -> None:
        self.client = client
        self.config = config
        self.log = logger

    def _build_techniques(self) -> List[Technique]:
        techs: List[Technique] = [
            TraversalTechnique(),
            WrapperSourceTechnique(),
            FilterChainRceTechnique(),
            WrapperRceTechnique(),
            LogPoisonTechnique(),
            ProcEnvironTechnique(),
        ]
        if self.config.harvest:
            techs.append(HarvestTechnique(loot_dir=self.config.loot_dir))
        techs.sort(key=lambda t: t.priority, reverse=True)
        return techs

    def scan(self, target: Target) -> ScanReport:
        report = ScanReport(target=target.url)
        points = target.injection_points(
            test_params=self.config.test_params,
            include_cookies=self.config.include_cookies,
            include_headers=self.config.include_headers,
        )
        if not points:
            self.log.warn(
                "No injection points found. Provide a parameter, a FUZZ marker "
                "in the URL, or POST data to test."
            )
            return report

        report.points_tested = len(points)
        self.log.info(f"Testing {len(points)} injection point(s) on {target.url}")

        # Fingerprint once using the first point.
        report.fingerprint = fp_mod.run(self.client, points[0], target.url)
        self.log.info(f"Fingerprint: {report.fingerprint.summary()} "
                      f"(confidence {report.fingerprint.confidence:.2f})")
        for note in report.fingerprint.notes:
            self.log.verbose(note)

        all_findings: List[Finding] = []
        if self.config.threads > 1 and len(points) > 1:
            with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
                futures = {
                    pool.submit(self._scan_point, pt, report.fingerprint): pt
                    for pt in points
                }
                for fut in as_completed(futures):
                    all_findings.extend(fut.result())
        else:
            for pt in points:
                all_findings.extend(self._scan_point(pt, report.fingerprint))

        # De-duplicate identical findings (same technique/param/title).
        seen = set()
        unique: List[Finding] = []
        for f in sorted(all_findings, key=lambda x: x.sort_key, reverse=True):
            key = (f.technique, f.parameter, f.title)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)

        report.findings = unique
        report.vulnerable = any(f.confidence >= 0.5 for f in unique)
        report.requests_sent = self.client.request_count
        return report

    def _scan_point(self, point: InjectionPoint, fingerprint: fp_mod.Fingerprint) -> List[Finding]:
        findings: List[Finding] = []
        marker = "LFIMK" + secrets.token_hex(3)
        self.log.verbose(f"Building baseline for {point.describe()}")
        bl = baseline_mod.build(self.client, point, marker)

        ctx = TechniqueContext(
            client=self.client,
            point=point,
            baseline=bl,
            fingerprint=fingerprint,
            logger=self.log,
            encoders=self.config.encoders,
            min_depth=self.config.min_depth,
            max_depth=self.config.max_depth,
            aggressive=self.config.aggressive,
            rce=self.config.rce,
            stop_on_first=self.config.stop_on_first,
            os_confirmed=fingerprint.os,
        )

        inclusion_confirmed = False
        for tech in self._build_techniques():
            if tech.requires_inclusion and not inclusion_confirmed:
                continue
            if not tech.applicable(ctx):
                continue
            try:
                for finding in tech.run(ctx):
                    findings.append(finding)
                    if finding.confidence >= 0.5 and "Inclusion" in finding.title:
                        inclusion_confirmed = True
                    if finding.technique == "path-traversal":
                        inclusion_confirmed = True
            except Exception as exc:  # a broken technique shouldn't kill the scan
                self.log.debug(f"technique {tech.name} raised: {exc}")

        return findings
