"""Tests for prompt construction — critically, that no raw secret leaks into it."""

from secmend.detectors import scan_text
from secmend.prompt import SYSTEM_PROMPT, build_user_prompt


def test_prompt_lists_findings_by_kind():
    findings = scan_text("k = AKIAIOSFODNN7EXAMPLE")
    prompt = build_user_prompt(findings)
    assert "AWS Access Key ID" in prompt
    assert "AWS" in prompt


def test_prompt_never_contains_raw_secret():
    key = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(f"k = {key}")
    prompt = build_user_prompt(findings)
    assert key not in prompt  # only metadata + masked preview are sent


def test_system_prompt_requests_json_shape():
    assert "immediate_actions" in SYSTEM_PROMPT
    assert "history_scrub" in SYSTEM_PROMPT
    assert "JSON" in SYSTEM_PROMPT
