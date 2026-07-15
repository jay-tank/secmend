"""Tests for rendering findings and remediation."""

from secmend.detectors import scan_text
from secmend.models import Remediation
from secmend.providers.base import MockProvider, parse_remediation
from secmend.render import render_findings, render_remediation, to_json


def _rem() -> Remediation:
    return parse_remediation(MockProvider().complete("s", "u"))


def test_render_findings_lists_kinds():
    findings = scan_text("k = AKIAIOSFODNN7EXAMPLE")
    out = render_findings(findings, color=False)
    assert "AWS Access Key ID" in out
    assert "critical" in out


def test_render_findings_clean():
    out = render_findings([], color=False)
    assert "No secrets detected" in out


def test_render_findings_never_shows_raw_secret():
    key = "AKIAIOSFODNN7EXAMPLE"
    out = render_findings(scan_text(key), color=False)
    assert key not in out


def test_render_remediation_sections():
    out = render_remediation(_rem(), color=False)
    assert "Immediate actions" in out
    assert "Scrub from git history" in out


def test_render_escapes_brackets():
    # Brackets in model output must be printed literally, not eaten by rich markup.
    rem = Remediation(summary="see [ERROR] token", severity="high",
                      immediate_actions=["check config[db][host]"])
    out = render_remediation(rem, color=False)
    assert "[ERROR]" in out
    assert "config[db][host]" in out


def test_to_json_roundtrip():
    findings = scan_text("k = AKIAIOSFODNN7EXAMPLE")
    out = to_json(findings, _rem())
    assert '"findings"' in out
    assert '"remediation"' in out
