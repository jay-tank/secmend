"""Tests for input gathering (files, directories, stdin, raw value)."""

import io
import os

import pytest

from secmend.collector import (
    CollectorError,
    scan_path,
    scan_secret,
    scan_stdin,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_scan_file_finds_secrets():
    findings = scan_path(os.path.join(FIXTURES, "leaky_config.py"))
    kinds = {f.kind for f in findings}
    assert "AWS Access Key ID" in kinds
    assert "GitHub Personal Access Token" in kinds


def test_scan_directory_walks_files():
    findings = scan_path(FIXTURES)
    assert any(f.kind == "AWS Access Key ID" for f in findings)


def test_scan_missing_path_raises():
    with pytest.raises(CollectorError):
        scan_path("/no/such/path/really")


def test_scan_stdin():
    stream = io.StringIO("key = AKIAIOSFODNN7EXAMPLE")
    findings = scan_stdin(stream)
    assert any(f.kind == "AWS Access Key ID" for f in findings)
    assert findings[0].source == "<stdin>"


def test_scan_secret_value():
    findings = scan_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    assert any(f.kind == "GitHub Personal Access Token" for f in findings)


def test_skip_dirs_are_ignored(tmp_path):
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "leak.js").write_text("k = AKIAIOSFODNN7EXAMPLE")
    (tmp_path / "app.py").write_text("safe = 1")
    findings = scan_path(str(tmp_path))
    assert findings == []
