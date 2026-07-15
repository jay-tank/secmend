"""Tests for the pure secret detectors."""

from secmend.detectors import mask, scan_text


def test_detects_aws_access_key():
    findings = scan_text("aws_key = AKIAIOSFODNN7EXAMPLE")
    kinds = [f.kind for f in findings]
    assert "AWS Access Key ID" in kinds
    aws = next(f for f in findings if f.kind == "AWS Access Key ID")
    assert aws.provider == "AWS"
    assert aws.severity == "critical"


def test_detects_github_pat():
    findings = scan_text("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    assert any(f.kind == "GitHub Personal Access Token" for f in findings)


def test_detects_stripe_key():
    # Assemble at runtime so no Stripe-shaped literal is ever committed
    # (which would trip GitHub push protection). Still a contiguous string at runtime.
    value = "sk_live_" + "abcdefghijklmnopqrstuvwx"
    findings = scan_text(f"stripe = {value}")
    assert any(f.kind == "Stripe Secret Key" for f in findings)


def test_detects_private_key_header():
    findings = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n")
    assert any(f.kind == "Private Key" for f in findings)


def test_generic_password_assignment():
    findings = scan_text('DB_PASSWORD = "s3cr3t-p@ssw0rd-value"')
    assert any(f.provider == "Generic" for f in findings)


def test_clean_text_has_no_findings():
    findings = scan_text("this is a normal line with no secrets\nport = 8080")
    assert findings == []


def test_line_numbers_are_reported():
    text = "line one\nsecret_token = 'abcdefgh12345678'\nline three"
    findings = scan_text(text)
    assert findings, "expected at least one finding"
    assert findings[0].line == 2


def test_duplicate_matches_deduped():
    key = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(f"{key}\n{key}\n{key}")
    aws = [f for f in findings if f.kind == "AWS Access Key ID"]
    assert len(aws) == 1


def test_preview_is_masked_never_raw():
    key = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_text(key)
    aws = next(f for f in findings if f.kind == "AWS Access Key ID")
    assert key not in aws.preview
    assert "*" in aws.preview


def test_mask_short_value_fully_hidden():
    assert set(mask("abcd")) == {"*"}


def test_mask_keeps_head_and_tail():
    masked = mask("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert "*" in masked
