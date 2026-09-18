from __future__ import annotations

from pathlib import Path

from app.scanner.secrets import detect_secrets, shannon_entropy

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "secrets"


def _read_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def test_detect_secrets_positive_fixture_finds_three_rules() -> None:
    findings = detect_secrets("src/app/settings.py", _read_fixture("positive_sample.txt"))

    assert len(findings) == 3
    assert {finding.rule_id for finding in findings} == {
        "secret.github_pat",
        "secret.aws_access_key",
        "secret.generic_api_key",
    }


def test_detect_secrets_negative_fixture_returns_empty() -> None:
    findings = detect_secrets("src/app/settings.py", _read_fixture("negative_sample.txt"))

    assert findings == []


def test_detect_secrets_hashes_evidence_and_hides_raw_secret() -> None:
    findings = detect_secrets("src/app/config.py", "token = 'z9Y7x5W3v1T8s6R4q2P0m7N5'")

    assert len(findings) == 1
    finding = findings[0]
    assert len(finding.evidence_hash) == 64
    assert "z9Y7x5W3v1T8s6R4q2P0m7N5" not in finding.evidence_hash


def test_detect_secrets_skips_allowlisted_paths() -> None:
    findings = detect_secrets(
        "project/node_modules/lib/index.js",
        "api_key = 'z9Y7x5W3v1T8s6R4q2P0m7N5'",
    )

    assert findings == []


def test_detect_secrets_preserves_file_and_line_metadata() -> None:
    content = 'safe_line = true\napi_key = "x7Y9m1N3p5Q7r9S2t4V6w8X0"\n'

    findings = detect_secrets("src/app/secrets.env", content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.file_path == "src/app/secrets.env"
    assert finding.line_start == 2
    assert finding.line_end == 2


def test_shannon_entropy_returns_expected_ordering() -> None:
    low_entropy = shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    high_entropy = shannon_entropy("a9B2d4F6h8J0kLmN2pQr")

    assert low_entropy < high_entropy
    assert shannon_entropy("") == 0.0


def test_detect_secrets_identifies_private_keys() -> None:
    content = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y1+
    -----END RSA PRIVATE KEY-----
    """
    findings = detect_secrets("id_rsa", content)
    assert len(findings) == 1
    assert findings[0].rule_id == "secret.private_key"
    assert findings[0].severity == "critical"


def test_detect_secrets_identifies_aws_secret_key() -> None:
    aws_sec = f"{'aB3dE5fG'}{'7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z7A9'}"
    content_real = f"aws_secret_access_key = '{aws_sec}'"
    findings = detect_secrets(".env", content_real)
    assert len(findings) == 1
    assert findings[0].rule_id == "secret.aws_secret_key"
    assert findings[0].severity == "critical"


def test_detect_secrets_identifies_gcp_and_stripe_and_slack() -> None:
    # Construct synthetic test tokens dynamically to prevent GitHub Push Protection false-positives
    gcp = f"{'AI'}{'za'}SyD-1234567890abcdefghijklmnopqrstu"
    stripe = f"{'sk'}_{'live'}_51AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    slack = f"{'xo'}{'xb'}-123456789012-123456789012-aBcDeFgHiJkLmNoPqRsTuVw"
    openai = f"{'sk'}-{'proj'}-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    content = f"""
    gcp_key = "{gcp}"
    stripe = "{stripe}"
    slack = "{slack}"
    openai = "{openai}"
    """
    findings = detect_secrets("config.py", content)
    detected_rules = {f.rule_id for f in findings}
    assert "secret.gcp_api_key" in detected_rules
    assert "secret.stripe_key" in detected_rules
    assert "secret.slack_token" in detected_rules
    assert "secret.openai_api_key" in detected_rules

