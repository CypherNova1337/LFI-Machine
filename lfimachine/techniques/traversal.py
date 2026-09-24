"""
Path-traversal detection.

This is the primary discovery technique. It probes OS-appropriate marker files
across a range of traversal depths, separator styles and WAF-bypass encodings,
scoring each response with the differential detector.

The payload/encoder sweep for a probe runs concurrently across a worker pool, so
even a single target URL uses the full thread budget instead of grinding through
thousands of combinations one at a time. The first combination that confirms a
known file is remembered on the context so escalation techniques (wrappers, log
poisoning) reuse the exact working traversal instead of rediscovering it.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Iterator, List, Optional, Tuple

from lfimachine.core import detector
from lfimachine.core.result import Finding, Severity
from lfimachine.payloads import encoders as enc
from lfimachine.payloads import traversal_gen, wordlists
from lfimachine.techniques.base import Technique, TechniqueContext

REMEDIATION = (
    "Never pass user input to filesystem/inclusion APIs. Map identifiers to an "
    "allowlist of known files, call basename()/realpath() and verify the result "
    "stays within an intended base directory, and disable allow_url_include."
)

# How many payloads to dispatch per concurrent wave before checking for a hit.
_WAVE_MULTIPLIER = 4

# Adaptive pruning: after this many high-signal probes, if essentially every
# response is just the app's error page (and near-uniform in size), stop
# hammering a parameter that clearly never reaches the filesystem. Disabled by
# --aggressive or an explicit --max-attempts.
_PRUNE_AFTER = 120
_PRUNE_RATIO = 0.98


class TraversalTechnique(Technique):
    name = "path-traversal"
    description = "Adaptive ../ traversal with encoding negotiation"
    priority = 100

    def _probe_files(self, ctx: TechniqueContext) -> List[dict]:
        os_name = ctx.os_confirmed or ctx.fingerprint.os or "linux"
        probes = list(wordlists.PROBES.get(os_name, []))
        # Always keep a linux probe as a fallback even on suspected windows,
        # because containers/WSL frequently expose /etc/passwd regardless.
        if os_name != "linux":
            probes += wordlists.PROBES["linux"][:1]
        return probes

    def run(self, ctx: TechniqueContext) -> Iterator[Finding]:
        encoder_order = ctx.encoders or enc.default_encoder_order(ctx.aggressive)
        for probe in self._probe_files(ctx):
            finding = self._probe(ctx, probe, encoder_order)
            if finding is None:
                continue
            yield finding
            if ctx.stop_on_first:
                return

    def _candidates(self, ctx, target_file, encoder_order) -> Iterator[Tuple[str, str, str]]:
        """Yield ``(raw_payload, encoder_name, encoded)`` lazily, bounded by the
        per-probe attempt budget so a sweep can never run away."""
        budget = ctx.max_attempts or (5000 if ctx.aggressive else 1200)
        emitted = 0
        for raw in traversal_gen.generate(
            target_file,
            min_depth=ctx.min_depth,
            max_depth=ctx.max_depth,
            aggressive=ctx.aggressive,
        ):
            is_path = not raw.startswith(("php://", "data://", "file://"))
            for enc_name, encoded in enc.variants(raw, encoder_order, is_path=is_path):
                yield raw, enc_name, encoded
                emitted += 1
                if emitted >= budget:
                    return

    def _probe(self, ctx, probe, encoder_order) -> Optional[Finding]:
        log = ctx.logger
        target_file = probe["path"]
        expected = probe["sig"]
        log.verbose(f"[{self.name}] probing {target_file} on {ctx.point.describe()}")

        progress = getattr(ctx, "progress", None)
        if progress:
            progress.activity(f"{self.name}")
            progress.point(f"{ctx.point.parameter or 'path'} · {target_file}")

        workers = max(1, getattr(ctx, "threads", 1))
        found: List[Finding] = []
        stop = threading.Event()

        # Adaptive-pruning state: if a parameter shows no sign of touching the
        # filesystem, we cut the sweep short instead of burning the full budget.
        stats = {"n": 0, "boring": 0, "lengths": set()}
        stats_lock = threading.Lock()

        def attempt(item: Tuple[str, str, str]) -> Optional[Finding]:
            if stop.is_set():
                return None
            raw, enc_name, encoded = item
            resp = ctx.point.send(ctx.client, encoded)
            det = detector.analyse(resp, ctx.baseline, encoded,
                                   expected_signature=expected)
            if resp.ok:
                # "Boring" = the response is indistinguishable from the app's
                # known error/not-found page, i.e. the payload changed nothing.
                boring = bool(ctx.baseline and ctx.baseline.looks_like_error(resp))
                with stats_lock:
                    stats["n"] += 1
                    if boring:
                        stats["boring"] += 1
                    if len(stats["lengths"]) < 8:
                        stats["lengths"].add(resp.length)
            if not det.confirmed:
                return None
            return Finding(
                technique=self.name,
                title=f"Local File Inclusion — {target_file} disclosed",
                severity=Severity.HIGH,
                confidence=det.confidence,
                url=resp.url or ctx.point.url,
                parameter=ctx.point.parameter or "<path>",
                method=ctx.point.method,
                payload=encoded,
                encoder=enc_name,
                evidence=det.evidence,
                matched_signatures=det.matched,
                os_guess=det.os_guess,
                status_code=resp.status_code,
                response_length=resp.length,
                remediation=REMEDIATION,
                extra={"detection_reason": det.reason, "raw_payload": raw},
            )

        def should_prune() -> bool:
            # After a high-signal preflight, a parameter whose responses are all
            # the app's error page (and near-uniform in size) is very unlikely to
            # be exploitable — stop rather than exhaust the budget.
            if ctx.aggressive or ctx.max_attempts:
                return False  # operator asked for exhaustive effort
            with stats_lock:
                n = stats["n"]
                if n < _PRUNE_AFTER:
                    return False
                error_ratio = stats["boring"] / n if n else 0.0
                return error_ratio >= _PRUNE_RATIO and len(stats["lengths"]) <= 2

        candidates = self._candidates(ctx, target_file, encoder_order)

        if workers == 1:
            for item in candidates:
                f = attempt(item)
                if f is not None:
                    self._lock_in(ctx, f, log)
                    return f
                if should_prune():
                    log.verbose(f"[{self.name}] pruning {target_file}: every one of "
                                f"{stats['n']} probes returned the error page")
                    return None
            return None

        # Concurrent sweep in bounded waves so we can stop early on the first hit.
        wave_size = workers * _WAVE_MULTIPLIER
        with ThreadPoolExecutor(max_workers=workers) as pool:
            while not stop.is_set():
                batch = []
                for _ in range(wave_size):
                    try:
                        batch.append(next(candidates))
                    except StopIteration:
                        break
                if not batch:
                    break
                for f in pool.map(attempt, batch):
                    if f is not None:
                        found.append(f)
                        stop.set()
                        break
                if not found and should_prune():
                    log.verbose(f"[{self.name}] pruning {target_file}: every one of "
                                f"{stats['n']} probes returned the error page")
                    break
        if found:
            best = max(found, key=lambda x: x.confidence)
            self._lock_in(ctx, best, log)
            return best
        return None

    def _lock_in(self, ctx, finding: Finding, log) -> None:
        ctx.confirmed_traversal = finding.extra.get("raw_payload")
        ctx.confirmed_encoder = finding.encoder
        ctx.os_confirmed = finding.os_guess or ctx.os_confirmed
        log.good(
            f"LFI confirmed via {self.name}: {ctx.point.describe()} -> "
            f"{finding.title.split('— ')[-1]} "
            f"(encoder={finding.encoder}, conf={finding.confidence})"
        )
