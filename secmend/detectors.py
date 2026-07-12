"""Secret detection — pure, deterministic, and unit-testable.

Each Detector carries a regex plus the static metadata (provider, severity, and
typical exploitation window) that lets secmend report *how bad* a match is
without any network or LLM call. `scan_text` is the entry point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from .models import SecretFinding


@dataclass(frozen=True)
class Detector:
    kind: str
    provider: str
    severity: str
    exploitation_window: str
    pattern: Pattern[str]


def _c(rx: str) -> Pattern[str]:
    return re.compile(rx)


# Ordered most-specific → least-specific so a value matched by a precise vendor
# pattern isn't also double-counted by the generic assignment rule.
DETECTORS: List[Detector] = [
    Detector("AWS Access Key ID", "AWS", "critical", "~minutes",
             _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("GitHub Personal Access Token", "GitHub", "critical", "~minutes to hours",
             _c(r"\bghp_[A-Za-z0-9]{36}\b")),
    Detector("GitHub Fine-grained Token", "GitHub", "critical", "~minutes to hours",
             _c(r"\bgithub_pat_[0-9a-zA-Z_]{82}\b")),
    Detector("GitHub OAuth/Server Token", "GitHub", "high", "~hours",
             _c(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    Detector("GitLab Personal Access Token", "GitLab", "critical", "~minutes to hours",
             _c(r"\bglpat-[0-9A-Za-z_\-]{20}\b")),
    Detector("Stripe Secret Key", "Stripe", "critical", "~minutes",
             _c(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    Detector("Anthropic API Key", "Anthropic", "high", "~hours",
             _c(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    Detector("OpenAI API Key", "OpenAI", "high", "~hours",
             _c(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b")),
    Detector("Google API Key", "Google", "high", "~hours",
             _c(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Detector("Slack Token", "Slack", "high", "~hours",
             _c(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    Detector("Slack Webhook URL", "Slack", "medium", "~hours to days",
             _c(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]+")),
    Detector("SendGrid API Key", "SendGrid", "high", "~hours",
             _c(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    Detector("PyPI Upload Token", "PyPI", "high", "~hours",
             _c(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b")),
    Detector("Private Key", "Cryptographic", "critical", "immediate",
             _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    Detector("JSON Web Token", "Generic", "medium", "until expiry",
             _c(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    Detector("Generic Secret Assignment", "Generic", "medium", "varies",
             _c(r"(?i)\b[A-Z0-9_]*(?:password|passwd|secret|api[_-]?key|access[_-]?key|"
                r"token)[A-Z0-9_]*\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?")),
]


def mask(value: str) -> str:
    """Mask a secret for display: keep a little head/tail, hide the middle.

    Short values are fully masked so we never leak enough to be useful.
    """
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    head, tail = value[:4], value[-4:]
    return f"{head}{'*' * (len(value) - 8)}{tail}"


def scan_text(text: str, source: str = "input") -> List[SecretFinding]:
    """Scan text for secrets, returning one finding per unique (kind, match).

    De-duplicates identical matches of the same kind so repeated occurrences of
    one secret don't inflate the report.
    """
    findings: List[SecretFinding] = []
    seen: set[tuple[str, str]] = set()
    lines = text.splitlines()

    for det in DETECTORS:
        for m in det.pattern.finditer(text):
            raw = m.group(0)
            key = (det.kind, raw)
            if key in seen:
                continue
            seen.add(key)
            line_no = text.count("\n", 0, m.start()) + 1 if lines else None
            findings.append(
                SecretFinding(
                    kind=det.kind,
                    provider=det.provider,
                    severity=det.severity,
                    exploitation_window=det.exploitation_window,
                    preview=mask(raw),
                    source=source,
                    line=line_no,
                )
            )
    return findings
