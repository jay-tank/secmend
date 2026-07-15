"""End-to-end CLI tests using the offline mock provider."""

import os

from secmend.cli import main

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
LEAKY = os.path.join(FIXTURES, "leaky_config.py")


def test_scan_file_with_mock_returns_leak_exit_code(capsys):
    rc = main([LEAKY, "--provider", "mock", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 1  # a leak was found
    assert "AWS Access Key ID" in out
    assert "Immediate actions" in out


def test_detect_only_skips_remediation(capsys):
    rc = main([LEAKY, "--detect-only", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "secret(s) detected" in out
    assert "Immediate actions" not in out


def test_secret_flag(capsys):
    rc = main(["--secret", "AKIAIOSFODNN7EXAMPLE", "--provider", "mock", "--no-color"])
    assert rc == 1
    assert "AWS Access Key ID" in capsys.readouterr().out


def test_clean_input_exits_zero(capsys, tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing to see here\nport = 8080")
    rc = main([str(clean), "--provider", "mock", "--no-color"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No secrets detected" in out


def test_json_output(capsys):
    rc = main(["--secret", "AKIAIOSFODNN7EXAMPLE", "--provider", "mock", "--json"])
    out = capsys.readouterr().out
    assert rc == 1
    assert '"findings"' in out
    assert '"remediation"' in out


def test_no_input_errors(capsys):
    rc = main(["--no-color"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "nothing to scan" in err


def test_output_not_duplicated(capsys):
    # Regression: rich Console must not also write to stdout (would double output).
    main(["--secret", "AKIAIOSFODNN7EXAMPLE", "--provider", "mock", "--no-color"])
    out = capsys.readouterr().out
    assert out.count("secret(s) detected") == 1
    assert out.count("Immediate actions") == 1


def test_raw_secret_absent_from_output(capsys):
    key = "AKIAIOSFODNN7EXAMPLE"
    main(["--secret", key, "--provider", "mock", "--no-color"])
    assert key not in capsys.readouterr().out
