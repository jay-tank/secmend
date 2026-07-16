"""Data structures passed between the detectors, providers, and renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SecretFinding:
    """A single detected secret occurrence.

    `preview` is already masked — the raw secret value is never stored here or
    sent to an LLM.
    """

    kind: str  # human name, e.g. "AWS Access Key ID"
    provider: str  # e.g. "AWS", "GitHub", "Stripe", "Generic"
    severity: str  # "critical" | "high" | "medium" | "low"
    exploitation_window: str  # how fast it's typically abused, e.g. "~minutes"
    preview: str  # masked sample, e.g. "AKIA****************WXYZ"
    source: str = "input"  # file path or "<stdin>"
    line: Optional[int] = None


@dataclass
class Remediation:
    """The structured remediation playbook an LLM produces for a set of findings."""

    summary: str
    severity: str  # overall severity of the exposure
    immediate_actions: List[str] = field(default_factory=list)  # revoke NOW
    rotation_steps: List[str] = field(default_factory=list)  # rotate + update refs
    history_scrub: List[str] = field(default_factory=list)  # purge from git history
    prevention: List[str] = field(default_factory=list)  # stop it recurring
    confidence: str = "unknown"  # "high" | "medium" | "low" | "unknown"
