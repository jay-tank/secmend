"""Tests for the provider factory, output parsing, and the mock provider."""

import pytest

from secmend.providers import ProviderError, get_provider, parse_remediation
from secmend.providers.base import MockProvider


def test_get_mock_provider():
    assert isinstance(get_provider("mock"), MockProvider)


def test_unknown_provider_raises():
    with pytest.raises(ProviderError):
        get_provider("nope")


def test_mock_provider_returns_parseable_json():
    raw = MockProvider().complete("sys", "user")
    rem = parse_remediation(raw)
    assert rem.severity == "critical"
    assert rem.immediate_actions
    assert rem.history_scrub


def test_parse_tolerates_prose_and_fences():
    raw = 'Here you go:\n```json\n{"summary": "x", "severity": "high"}\n```\nThanks!'
    rem = parse_remediation(raw)
    assert rem.summary == "x"
    assert rem.severity == "high"


def test_parse_non_json_raises():
    with pytest.raises(ProviderError):
        parse_remediation("no json here at all")


def test_parse_defaults_missing_lists_to_empty():
    rem = parse_remediation('{"summary": "s", "severity": "low"}')
    assert rem.immediate_actions == []
    assert rem.rotation_steps == []
