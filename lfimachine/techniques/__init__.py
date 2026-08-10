"""
Attack techniques.

Each technique is a self-contained module that, given a scan context, attempts
one class of LFI attack and yields ``Finding`` objects. The engine runs them in
a deliberate order (cheap/high-signal first) and can short-circuit once a
confirmed inclusion unlocks a more powerful escalation.
"""
from lfimachine.techniques.base import Technique, TechniqueContext  # noqa: F401
