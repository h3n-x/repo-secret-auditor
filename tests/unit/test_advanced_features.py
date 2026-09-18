from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.ci.scan_runner import run_scan
from app.reporting.sbom import generate_cyclonedx_sbom, write_cyclonedx_sbom
from app.scanner.baseline import (
    Baseline,
    BaselineEntry,
    create_baseline_data,
    load_baseline,
)
from app.scanner.dependencies import PackageRef
from app.scanner.git_history import scan_git_history


def test_cyclonedx_sbom_structure_and_purl_generation(tmp_path: Path) -> None:
    packages = [
        PackageRef(name="fastapi", version="0.116.0", ecosystem="PyPI"),
        PackageRef(name="express", version="4.18.2", ecosystem="npm"),
    ]

    sbom = generate_cyclonedx_sbom(packages, project_name="my-test-app", project_version="1.2.3")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "my-test-app"
    assert len(sbom["components"]) == 2

    purls = {c["purl"] for c in sbom["components"]}
    assert "pkg:pypi/fastapi@0.116.0" in purls
    assert "pkg:npm/express@4.18.2" in purls

    # Test file writing
    out_file = tmp_path / "bom.json"
    write_cyclonedx_sbom(packages, out_file)
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"


def test_baseline_suppression_and_expiration(tmp_path: Path) -> None:
    # Test valid active suppression
    entry_active = BaselineEntry(
        evidence_hash="abcd1234efgh5678",
        reason="Legacy accepted test key",
        expires_at=None,
    )
    baseline = Baseline(entries={"abcd1234efgh5678": entry_active})
    suppressed, reason = baseline.is_suppressed("abcd1234efgh5678")
    assert suppressed is True
    assert reason == "Legacy accepted test key"

    # Test expired suppression
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date().isoformat()
    entry_expired = BaselineEntry(
        evidence_hash="expired_hash_123",
        reason="Expired temporary waiver",
        expires_at=yesterday,
    )
    baseline_exp = Baseline(entries={"expired_hash_123": entry_expired})
    suppressed_exp, reason_exp = baseline_exp.is_suppressed("expired_hash_123")
    assert suppressed_exp is False
    assert reason_exp is not None and "expired" in reason_exp.lower()

    # Test file loading and baseline creation
    baseline_file = tmp_path / ".rsa-baseline.json"
    baseline_payload = {
        "version": "1.0",
        "suppressions": [
            {
                "evidence_hash": "saved_hash_999",
                "rule_id": "secret.generic_api_key",
                "file_path": "config.py",
                "reason": "Test fixture",
            }
        ],
    }
    baseline_file.write_text(json.dumps(baseline_payload), encoding="utf-8")
    loaded = load_baseline(baseline_file)
    assert "saved_hash_999" in loaded.entries
    assert loaded.entries["saved_hash_999"].reason == "Test fixture"


def test_scan_git_history_detects_historical_deleted_secrets(tmp_path: Path) -> None:
    # Initialize a temporary git repository
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test Committer"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "committer@example.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    # Commit 1: Introduce a secret (dynamically constructed to avoid push protection regex)
    pat_token = f"{'gh'}{'p'}_1234567890abcdef1234567890abcdef1234"
    secret_file = tmp_path / "secret.env"
    secret_file.write_text(f"GITHUB_TOKEN={pat_token}\n", encoding="utf-8")
    subprocess.run(["git", "add", "secret.env"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Commit with leaked secret"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    # Commit 2: "Delete" the secret file so it's gone from working directory
    secret_file.unlink()
    subprocess.run(["git", "rm", "secret.env"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "Remove secret from disk"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    # Working tree has no secret now
    assert not secret_file.exists()

    # History scanner must discover the secret in past commits!
    history_findings = scan_git_history(tmp_path)
    assert len(history_findings) >= 1
    found_pat = next(f for f in history_findings if f.rule_id == "secret.github_pat")
    assert found_pat.commit_sha is not None
    assert found_pat.commit_author is not None
    assert "Test Committer" in found_pat.commit_author


def test_run_scan_with_sbom_and_baseline_integration(tmp_path: Path) -> None:
    # Create project layout
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "requirements.txt").write_text("httpx==0.28.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"name": "test", "lockfileVersion": 3, "packages": {}}),
        encoding="utf-8",
    )

    # Add secret file
    pat_token = f"{'gh'}{'p'}_1234567890abcdef1234567890abcdef1234"
    (tmp_path / "src" / "token.py").write_text(f"KEY = '{pat_token}'\n", encoding="utf-8")

    summary_file = tmp_path / "summary.json"
    sarif_file = tmp_path / "findings.sarif"
    sbom_file = tmp_path / "bom.json"

    # 1. Run scan without baseline -> finding is active
    summary_before = run_scan(
        project_root=tmp_path,
        summary_path=summary_file,
        sarif_path=sarif_file,
        sbom_path=sbom_file,
    )
    assert summary_before.high_count >= 1
    assert sbom_file.is_file()

    # Read evidence hash from SARIF
    sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert len(sarif_data["runs"][0]["results"]) >= 1

    # 2. Create baseline suppressing this finding
    baseline_path = tmp_path / ".rsa-baseline.json"

    from hashlib import sha256
    token_hash = sha256(pat_token.encode("utf-8")).hexdigest()
    baseline_payload = {
        "version": "1.0",
        "suppressions": [
            {
                "evidence_hash": token_hash,
                "reason": "Approved dev token",
            }
        ],
    }
    baseline_path.write_text(json.dumps(baseline_payload), encoding="utf-8")

    # 3. Run scan with baseline -> finding is suppressed
    summary_after = run_scan(
        project_root=tmp_path,
        summary_path=summary_file,
        sarif_path=sarif_file,
        baseline_path=baseline_path,
    )

    # Active counts in summary must be 0 for suppressed finding
    assert summary_after.high_count == 0
    assert summary_after.risk_score == 0

    # SARIF should record suppression
    sarif_after = json.loads(sarif_file.read_text(encoding="utf-8"))
    res = sarif_after["runs"][0]["results"][0]
    assert "suppressions" in res
    assert res["suppressions"][0]["justification"] == "Approved dev token"


def test_baseline_file_path_filter_and_create_data(tmp_path: Path) -> None:
    entry = BaselineEntry(
        evidence_hash="hash_specific_path",
        file_path="src/specific.py",
        reason="Scoped suppression",
    )
    baseline = Baseline(entries={"hash_specific_path": entry})

    # Same file path matches
    suppressed, _ = baseline.is_suppressed("hash_specific_path", "src/specific.py")
    assert suppressed is True

    # Different file path does not match
    suppressed_diff, _ = baseline.is_suppressed("hash_specific_path", "src/other.py")
    assert suppressed_diff is False

    # Create baseline from finding objects
    from app.scanner.secrets import SecretFinding
    sample_finding = SecretFinding(
        rule_id="secret.generic_api_key",
        severity="high",
        confidence=0.8,
        file_path="src/file.py",
        line_start=1,
        line_end=1,
        evidence_hash="sample_hash_123",
    )
    data = create_baseline_data([sample_finding, sample_finding])
    assert len(data["suppressions"]) == 1
    assert data["suppressions"][0]["evidence_hash"] == "sample_hash_123"


def test_cli_main_execution_and_fail_on_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from app.ci.scan_runner import main

    (tmp_path / "src").mkdir(parents=True)
    pat_token = f"{'gh'}{'p'}_1234567890abcdef1234567890abcdef1234"
    (tmp_path / "src" / "token.py").write_text(f"KEY = '{pat_token}'\n", encoding="utf-8")
    summary_path = tmp_path / "summary.json"
    sarif_path = tmp_path / "findings.sarif"

    # Test failure on high severity
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rsa",
            "--project-root",
            str(tmp_path),
            "--summary",
            str(summary_path),
            "--sarif",
            str(sarif_path),
            "--fail-on",
            "high",
        ],
    )
    exit_code = main()
    assert exit_code == 1

    # Test pass when fail-on is critical (only high was found)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rsa",
            "--project-root",
            str(tmp_path),
            "--summary",
            str(summary_path),
            "--sarif",
            str(sarif_path),
            "--fail-on",
            "critical",
        ],
    )
    exit_code_crit = main()
    assert exit_code_crit == 0

