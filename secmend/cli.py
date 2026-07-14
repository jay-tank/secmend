"""Command-line entry point: secmend [path] [options]."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .collector import CollectorError, scan_path, scan_secret, scan_stdin
from .models import SecretFinding
from .prompt import SYSTEM_PROMPT, build_user_prompt
from .providers import ProviderError, get_provider
from .providers.base import parse_remediation
from .render import render_findings, render_remediation, to_json


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secmend",
        description="Find leaked secrets and get an exact remediation playbook.",
    )
    p.add_argument("path", nargs="?", help="File or directory to scan")
    p.add_argument("--stdin", action="store_true", help="Scan text piped on stdin")
    p.add_argument("--secret", help="Scan a single value passed directly")
    p.add_argument(
        "--provider",
        default=os.getenv("SECMEND_PROVIDER", "claude"),
        help="LLM provider for the remediation: claude | openai | ollama | mock (default: claude)",
    )
    p.add_argument("--model", help="Model override (else provider default or $SECMEND_MODEL)")
    p.add_argument(
        "--detect-only",
        action="store_true",
        help="Only detect + report secrets; skip the LLM remediation (fully offline)",
    )
    p.add_argument("--json", action="store_true", help="Output raw JSON instead of a report")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _gather(args) -> List[SecretFinding]:
    if args.secret:
        return scan_secret(args.secret)
    if args.stdin:
        return scan_stdin(sys.stdin)
    if args.path:
        return scan_path(args.path)
    raise CollectorError("nothing to scan — provide a path, --stdin, or --secret")


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    # 1. Detect secrets (pure, offline).
    try:
        findings = _gather(args)
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    color = not args.no_color

    # No secrets → report clean and exit 0.
    if not findings:
        if args.json:
            print(to_json(findings, None))
        else:
            print(render_findings(findings, color=color), end="")
        return 0

    # 2. Detection-only mode: report and stop (no LLM, exit non-zero to flag a leak).
    if args.detect_only:
        if args.json:
            print(to_json(findings, None))
        else:
            print(render_findings(findings, color=color), end="")
        return 1

    # 3. Ask the LLM for a remediation playbook.
    user_prompt = build_user_prompt(findings)
    try:
        provider = get_provider(args.provider, model=args.model)
        raw = provider.complete(SYSTEM_PROMPT, user_prompt)
        remediation = parse_remediation(raw)
    except ProviderError as exc:
        # Detection still succeeded — show it and explain the LLM failure.
        if not args.json:
            print(render_findings(findings, color=color), end="")
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # 4. Render findings + remediation.
    if args.json:
        print(to_json(findings, remediation))
    else:
        print(render_findings(findings, color=color), end="")
        print(render_remediation(remediation, color=color), end="")
    return 1  # non-zero: a leak was found (useful in CI / pre-commit hooks)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
