"""
Baseline and differential analysis.

False positives are the bane of LFI scanners: reflected payloads, generic error
pages and soft-404s all look like "something happened". LFI-Machine builds a
baseline model of the application's behaviour for each injection point by
sending benign and deliberately-invalid values, then measures every candidate
response against that model. A candidate is only interesting if it differs from
the baseline in a way a real inclusion would (new content, different length
band, disappearance of an error string) — not merely because our payload is
echoed back.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import List, Optional

from lfimachine.core.http import HttpClient, Response
from lfimachine.core.target import InjectionPoint

# Values used to profile normal vs. error behaviour without disclosing anything.
_BENIGN_VALUES = ["index", "home", "en", "1", "default"]
_INVALID_VALUES = [
    "lfimachine_nonexistent_zzz9182",
    "../../../../nonexistent_zzz9182",
    "\x00invalid",
]


@dataclass
class Baseline:
    benign: List[Response] = field(default_factory=list)
    invalid: List[Response] = field(default_factory=list)
    reflect_marker: str = ""
    reflects_input: bool = False
    invalid_status: Optional[int] = None
    invalid_signature: str = ""

    @property
    def benign_lengths(self) -> List[int]:
        return [r.length for r in self.benign if r.ok]

    @property
    def invalid_lengths(self) -> List[int]:
        return [r.length for r in self.invalid if r.ok]

    def _length_band(self, lengths: List[int]) -> tuple:
        if not lengths:
            return (0, 0)
        if len(lengths) == 1:
            v = lengths[0]
            return (max(0, v - 40), v + 40)
        mean = statistics.mean(lengths)
        try:
            spread = statistics.pstdev(lengths)
        except statistics.StatisticsError:
            spread = 0
        pad = max(spread * 2, 40)
        return (int(mean - pad), int(mean + pad))

    def looks_like_error(self, resp: Response) -> bool:
        """True if ``resp`` resembles the application's not-found/error state."""
        if not resp.ok:
            return True
        if self.invalid_status is not None and resp.status_code == self.invalid_status:
            lo, hi = self._length_band(self.invalid_lengths)
            if lo <= resp.length <= hi and resp.status_code >= 400:
                return True
        # Strong textual similarity to a known invalid response.
        if self.invalid_signature and self.invalid_signature in resp.text:
            return True
        return False

    def novelty(self, resp: Response) -> float:
        """
        Heuristic 0..1 describing how different ``resp`` is from the baseline.
        Higher means "more likely to contain new/disclosed content".
        """
        if not resp.ok:
            return 0.0
        score = 0.0
        blo, bhi = self._length_band(self.benign_lengths)
        if not (blo <= resp.length <= bhi):
            score += 0.4
        ilo, ihi = self._length_band(self.invalid_lengths)
        if self.invalid_lengths and not (ilo <= resp.length <= ihi):
            score += 0.2
        if self.invalid_signature and self.invalid_signature not in resp.text:
            score += 0.2
        if resp.status_code == 200:
            score += 0.2
        return min(score, 1.0)


def build(client: HttpClient, point: InjectionPoint, marker: str) -> Baseline:
    """Profile an injection point's benign and error behaviour."""
    bl = Baseline(reflect_marker=marker)

    # Detect reflection: does the app echo our raw input into the response?
    reflect = point.send(client, marker)
    if reflect.ok and marker in reflect.text:
        bl.reflects_input = True

    for value in _BENIGN_VALUES[:3]:
        r = point.send(client, value)
        if r.ok:
            bl.benign.append(r)

    for value in _INVALID_VALUES:
        r = point.send(client, value)
        if r.ok:
            bl.invalid.append(r)

    if bl.invalid:
        # Use the most common invalid status and a stable text fingerprint.
        bl.invalid_status = bl.invalid[0].status_code
        text = bl.invalid[0].text
        # A short, stable slice near the top tends to capture error boilerplate.
        bl.invalid_signature = text[:120].strip()
    return bl
