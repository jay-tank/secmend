"""Provider interface, output parsing, and the built-in mock provider."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod

from ..models import Remediation


class ProviderError(Exception):
    """Raised for provider selection, configuration, or output-parsing failures."""


class LLMProvider(ABC):
    """A pluggable LLM backend. Implementations turn a prompt into raw text."""

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's raw text response (expected to contain JSON)."""


def parse_remediation(raw: str) -> Remediation:
    """Parse a model's raw response into a Remediation.

    Tolerates prose or ```json fences around the JSON object.
    """
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ProviderError(f"Model did not return JSON. Got: {raw[:200]!r}")
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Could not parse model output as JSON: {exc}") from exc

    return Remediation(
        summary=str(data.get("summary", "")),
        severity=str(data.get("severity", "unknown")),
        immediate_actions=list(data.get("immediate_actions", []) or []),
        rotation_steps=list(data.get("rotation_steps", []) or []),
        history_scrub=list(data.get("history_scrub", []) or []),
        prevention=list(data.get("prevention", []) or []),
        confidence=str(data.get("confidence", "unknown")),
    )


class MockProvider(LLMProvider):
    """Deterministic provider for tests and no-key demos (`--provider mock`)."""

    def complete(self, system: str, user: str) -> str:
        return json.dumps(
            {
                "summary": "A live credential was committed to the repository and "
                "must be treated as compromised.",
                "severity": "critical",
                "immediate_actions": [
                    "Revoke/disable the exposed credential in its provider console now.",
                    "Assume it is compromised — do not merely delete the line.",
                ],
                "rotation_steps": [
                    "Generate a replacement credential.",
                    "Store it in your secret manager / CI secrets, not in code.",
                    "Update every service that referenced the old value.",
                ],
                "history_scrub": [
                    "git rm --cached <file> && echo '<file>' >> .gitignore",
                    "Purge from history: `git filter-repo --path <file> --invert-paths` "
                    "(or BFG), then force-push.",
                ],
                "prevention": [
                    "Add a pre-commit secret scanner (gitleaks / detect-secrets).",
                    "Load secrets from environment or a secret manager at runtime.",
                ],
                "confidence": "low",
            }
        )
