"""Render findings + a Remediation to the terminal (rich) or as JSON."""

from __future__ import annotations

import io
import json
from dataclasses import asdict
from typing import List, Optional

from .models import Remediation, SecretFinding

_SEVERITY_COLOR = {
    "critical": "bright_red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


def to_json(findings: List[SecretFinding], remediation: Optional[Remediation]) -> str:
    return json.dumps(
        {
            "findings": [asdict(f) for f in findings],
            "remediation": asdict(remediation) if remediation else None,
        },
        indent=2,
    )


def render_findings(findings: List[SecretFinding], color: bool = True) -> str:
    """Render the detected secrets table (offline — no LLM needed)."""
    from rich.console import Console
    from rich.markup import escape

    console = Console(record=True, no_color=not color, width=100, force_terminal=color, file=io.StringIO())

    if not findings:
        console.print("\n[green]✓ No secrets detected.[/green]\n")
        return console.export_text()

    console.print(f"\n[bold]🔑 {len(findings)} secret(s) detected:[/bold]")
    for f in findings:
        sev_color = _SEVERITY_COLOR.get(f.severity.lower(), "white")
        loc = escape(f.source)
        if f.line:
            loc += f":{f.line}"
        console.print(
            f"  [{sev_color}]●[/{sev_color}] [bold]{escape(f.kind)}[/bold] "
            f"([{sev_color}]{escape(f.severity)}[/{sev_color}]) "
            f"{escape(f.preview)}  [dim]{loc}[/dim]"
        )
    return console.export_text()


def render_remediation(remediation: Remediation, color: bool = True) -> str:
    """Render the remediation playbook. All LLM text is escaped for rich."""
    from rich.console import Console
    from rich.markup import escape

    console = Console(record=True, no_color=not color, width=100, force_terminal=color, file=io.StringIO())
    r = remediation

    sev_color = _SEVERITY_COLOR.get(r.severity.lower(), "white")
    console.print(
        f"\n[bold]🛠  Remediation[/bold] "
        f"([{sev_color}]{escape(r.severity)}[/{sev_color}]): {escape(r.summary)}"
    )

    sections = [
        ("🚨 Immediate actions", r.immediate_actions, "bright_red"),
        ("🔄 Rotate & update", r.rotation_steps, "yellow"),
        ("🧹 Scrub from git history", r.history_scrub, "cyan"),
        ("🛡  Prevent recurrence", r.prevention, "green"),
    ]
    for title, items, item_color in sections:
        if not items:
            continue
        console.print(f"\n[bold]{title}:[/bold]")
        for item in items:
            console.print(f"  [{item_color}]›[/{item_color}] {escape(item)}")

    console.print()
    return console.export_text()
