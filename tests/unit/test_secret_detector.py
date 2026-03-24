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
