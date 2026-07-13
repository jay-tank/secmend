"""Build the LLM prompt from findings.

Only the *metadata* of each finding (kind, provider, severity) is ever sent —
never the secret value. Previews are already masked by the detector.
"""

from __future__ import annotations

from typing import List

from .models import SecretFinding

SYSTEM_PROMPT = (
    "You are an incident-response engineer helping a developer remediate leaked "
    "secrets. You are given a list of secret types that were found in their code "
    "(the actual values are masked — you only see the type and provider). Produce "
    "a concrete, provider-specific remediation playbook.\n\n"
    "Respond ONLY with a JSON object of this exact shape:\n"
    "{\n"
    '  "summary": "one sentence on what leaked and the risk",\n'
    '  "severity": "critical | high | medium | low",\n'
    '  "immediate_actions": ["revoke/disable steps to run RIGHT NOW"],\n'
    '  "rotation_steps": ["how to generate a new secret and update all references"],\n'
    '  "history_scrub": ["exact git/BFG commands to purge it from history"],\n'
    '  "prevention": ["how to stop this recurring (e.g. pre-commit, secret manager)"],\n'
    '  "confidence": "high | medium | low"\n'
    "}\n"
    "Give exact, runnable commands and real console/dashboard paths for each "
    "provider. Order immediate_actions by urgency. Do not include any text "
    "outside the JSON."
)


def build_user_prompt(findings: List[SecretFinding]) -> str:
    """Render the (secret-free) findings into a compact prompt."""
    lines = ["The following secret types were detected in the codebase:", ""]
    for f in findings:
        loc = f.source
        if f.line:
            loc += f":{f.line}"
        lines.append(
            f"- {f.kind} ({f.provider}) — severity {f.severity}, "
            f"typically exploited in {f.exploitation_window} [{loc}]"
        )
    lines.append("")
    lines.append(
        "Provide the remediation playbook. If multiple providers are present, "
        "cover each. Assume the secret has already been pushed to a shared/remote "
        "git repository."
    )
    return "\n".join(lines)
