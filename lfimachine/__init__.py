"""
LFI-Machine — an intelligent Local File Inclusion discovery and exploitation engine.

Unlike traditional fuzzers that spray a static list of ``../../../etc/passwd``
payloads, LFI-Machine reasons about the target: it fingerprints the stack,
establishes a response baseline, adapts traversal depth, negotiates WAF
encodings, and escalates confirmed inclusions to source disclosure and remote
code execution using PHP wrappers, filter chains and log poisoning.
"""

__title__ = "lfimachine"
__version__ = "1.0.0"
__author__ = "VoidSec-Hub"
__license__ = "MIT"

from lfimachine.core.result import Finding, Severity  # noqa: E402

__all__ = ["Finding", "Severity", "__version__"]
