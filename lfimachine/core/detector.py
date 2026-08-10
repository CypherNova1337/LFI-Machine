"""
Detection & confidence scoring.

Combines hard content signatures (``payloads.signatures``) with the soft
differential model (``core.baseline``) to decide whether a response proves file
inclusion, and with what confidence. Reflected payloads are explicitly
penalised so an application that merely echoes ``../../etc/passwd`` back does
not register as vulnerable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from lfimachine.core.baseline import Baseline
from lfimachine.core.http import Response
from lfimachine.payloads import signatures


@dataclass
class Detection:
    confirmed: bool
    confidence: float
    matched: List[str] = field(default_factory=list)
    os_guess: Optional[str] = None
    evidence: str = ""
    reason: str = ""


def _evidence_snippet(body: str, sig_hits) -> str:
    for sig in sig_hits:
        m = sig.pattern.search(body)
        if m:
            start = max(0, m.start() - 20)
            end = min(len(body), m.end() + 120)
            snippet = body[start:end].replace("\r", "").strip()
            return snippet[:200]
    return body[:160].strip()


def analyse(
    resp: Response,
    baseline: Optional[Baseline],
    payload: str,
    *,
    expected_signature: Optional[str] = None,
) -> Detection:
    """
    Decide whether ``resp`` demonstrates file inclusion for ``payload``.

    ``expected_signature`` optionally names the signature we *expect* for the
    probed file (e.g. ``etc_passwd``); matching the expected signature is
    weighted higher than an incidental match.
    """
    if not resp.ok:
        return Detection(False, 0.0, reason="request failed")

    hits = signatures.match_signatures(resp.text)

    # Guard against reflection: if the app echoes the payload and the only
    # "evidence" is our own input, discount it.
    reflected = bool(baseline and baseline.reflects_input and payload in resp.text)

    if not hits:
        return Detection(
            False, 0.0, reason="no content signature matched"
        )

    weight = 0.0
    matched_names: List[str] = []
    for sig in hits:
        w = sig.weight
        if expected_signature and sig.name == expected_signature:
            w += 0.3
        weight += w
        matched_names.append(sig.name)

    # Normalise signature weight into a 0..0.85 band.
    sig_conf = min(weight / 1.3, 0.85)

    # Differential boost: a response unlike the baseline is more trustworthy.
    novelty = baseline.novelty(resp) if baseline else 0.4
    conf = min(sig_conf + novelty * 0.15, 0.99)

    reason = "content signature matched"
    if reflected:
        # The payload literal is present. If the signature match is ONLY the
        # payload text reflected (e.g. no real passwd structure), drop hard.
        # /etc/passwd style structural regexes are hard to forge via reflection,
        # so keep meaningful confidence but flag it.
        conf *= 0.6
        reason = "content signature matched (input is reflected — verify)"

    if baseline and baseline.looks_like_error(resp) and novelty < 0.2:
        conf *= 0.5
        reason = "signature matched but response resembles error page"

    os_guess = signatures.guess_os(hits)
    evidence = _evidence_snippet(resp.text, hits)

    confirmed = conf >= 0.5
    return Detection(
        confirmed=confirmed,
        confidence=round(conf, 3),
        matched=matched_names,
        os_guess=os_guess,
        evidence=evidence,
        reason=reason,
    )
