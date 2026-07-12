"""Gather text to scan — from files, a directory, stdin, or a raw string.

Reading/scanning is kept separate from CLI wiring so it's easy to unit-test.
"""

from __future__ import annotations

import os
from typing import List

from .detectors import scan_text
from .models import SecretFinding


class CollectorError(Exception):
    """Raised when input can't be read (missing path, unreadable file, etc.)."""


# Directories and files that never contain source-controlled secrets worth
# scanning — skipped when walking a directory to keep it fast and quiet.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
_MAX_FILE_BYTES = 2_000_000  # skip files larger than ~2 MB (likely binaries/assets)


def _read_file(path: str) -> str:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError as exc:
        raise CollectorError(f"could not read {path}: {exc}") from exc


def scan_path(path: str) -> List[SecretFinding]:
    """Scan a file or (recursively) a directory for secrets."""
    if not os.path.exists(path):
        raise CollectorError(f"path not found: {path}")

    if os.path.isfile(path):
        return scan_text(_read_file(path), source=path)

    findings: List[SecretFinding] = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            fpath = os.path.join(root, name)
            content = _read_file(fpath)
            if content:
                findings.extend(scan_text(content, source=fpath))
    return findings


def scan_stdin(stream) -> List[SecretFinding]:
    """Scan text piped in on stdin (e.g. `git diff | secmend --stdin`)."""
    return scan_text(stream.read(), source="<stdin>")


def scan_secret(value: str) -> List[SecretFinding]:
    """Scan a single value pasted with --secret."""
    return scan_text(value, source="<--secret>")
