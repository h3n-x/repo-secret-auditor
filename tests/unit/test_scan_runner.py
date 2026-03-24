from __future__ import annotations

import json
from pathlib import Path

from app.ci.scan_runner import run_scan
from app.scanner.dependencies import PackageRef, VulnerabilityMatch


class _FakeOsvClient:
    def __init__(self, responses: dict[str, list[VulnerabilityMatch]] | None = None) -> None:
        self._responses = responses or {}

    def query(self, package: PackageRef) -> list[VulnerabilityMatch]:
        return self._responses.get(package.name, [])


def _minimal_package_lock() -> str:
    return json.dumps({"name": "repo", "lockfileVersion": 3, "packages": {}})


def test_run_scan_generates_summary_and_sarif_for_secret_findings(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "config.py").write_text(
        'TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(_minimal_package_lock(), encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=_FakeOsvClient(),
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))

    assert summary["total_findings"] >= 1
    assert summary["high_count"] >= 1
    assert summary["risk_score"] > 0

    results = sarif["runs"][0]["results"]
    rule_ids = {result["ruleId"] for result in results}
    assert "secret.github_pat" in rule_ids


def test_run_scan_includes_dependency_vulnerability(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==0.116.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(_minimal_package_lock(), encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    fake_client = _FakeOsvClient(
        responses={
            "fastapi": [
                VulnerabilityMatch(
                    vuln_id="CVE-2026-12345",
                    summary="Fixture advisory",
                    severity="HIGH",
                    package_name="fastapi",
                    installed_version="0.116.0",
                    fixed_version="0.117.0",
                    advisory_url="https://osv.dev/vulnerability/CVE-2026-12345",
                )
            ]
        }
    )

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=fake_client,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))

    assert summary["total_findings"] == 1
    assert summary["high_count"] == 1

    rule_ids = {result["ruleId"] for result in sarif["runs"][0]["results"]}
    assert "dependency.cve-2026-12345" in rule_ids


def test_run_scan_handles_invalid_package_lock(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{invalid-json", encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=_FakeOsvClient(),
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["total_findings"] == 0


def test_severity_gate_fails_on_critical_findings(tmp_path: Path) -> None:
    """Validate that CRITICAL findings are counted and would fail the severity gate."""
    (tmp_path / "requirements.txt").write_text("vulnerable-pkg==1.0.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(_minimal_package_lock(), encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    fake_client = _FakeOsvClient(
        responses={
            "vulnerable-pkg": [
                VulnerabilityMatch(
                    vuln_id="CVE-2026-99999",
                    summary="Critical fixture vulnerability",
                    severity="CRITICAL",
                    package_name="vulnerable-pkg",
                    installed_version="1.0.0",
                    fixed_version="2.0.0",
                    advisory_url="https://osv.dev/vulnerability/CVE-2026-99999",
                )
            ]
        }
    )

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=fake_client,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    # Gate should fail: critical_count > 0
    assert summary["critical_count"] == 1
    assert summary["total_findings"] == 1


def test_severity_gate_fails_on_high_findings(tmp_path: Path) -> None:
    """Validate that HIGH findings are counted and would fail the severity gate."""
    (tmp_path / "requirements.txt").write_text("vulnerable-pkg==1.0.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(_minimal_package_lock(), encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    fake_client = _FakeOsvClient(
        responses={
            "vulnerable-pkg": [
                VulnerabilityMatch(
                    vuln_id="CVE-2026-88888",
                    summary="High severity fixture vulnerability",
                    severity="HIGH",
                    package_name="vulnerable-pkg",
                    installed_version="1.0.0",
                    fixed_version="2.0.0",
                    advisory_url="https://osv.dev/vulnerability/CVE-2026-88888",
                )
            ]
        }
    )

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=fake_client,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    # Gate should fail: high_count > 0
    assert summary["high_count"] == 1
    assert summary["total_findings"] == 1


def test_severity_gate_passes_on_low_and_medium_findings(tmp_path: Path) -> None:
    """Validate that only LOW/MEDIUM findings do NOT trigger the severity gate."""
    (tmp_path / "requirements.txt").write_text("pkg==1.0.0\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(_minimal_package_lock(), encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    fake_client = _FakeOsvClient(
        responses={
            "pkg": [
                VulnerabilityMatch(
                    vuln_id="CVE-2026-77777",
                    summary="Low severity fixture vulnerability",
                    severity="LOW",
                    package_name="pkg",
                    installed_version="1.0.0",
                    fixed_version="1.1.0",
                    advisory_url="https://osv.dev/vulnerability/CVE-2026-77777",
                ),
                VulnerabilityMatch(
                    vuln_id="CVE-2026-66666",
                    summary="Medium severity fixture vulnerability",
                    severity="MEDIUM",
                    package_name="pkg",
                    installed_version="1.0.0",
                    fixed_version="1.1.0",
                    advisory_url="https://osv.dev/vulnerability/CVE-2026-66666",
                ),
            ]
        }
    )

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=fake_client,
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    # Gate should pass: critical_count = 0 and high_count = 0
    assert summary["critical_count"] == 0
    assert summary["high_count"] == 0
    assert summary["medium_count"] == 1
    assert summary["low_count"] == 1
    assert summary["total_findings"] == 2


def test_run_scan_skips_heavy_and_excluded_paths(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir(parents=True)
    (tmp_path / "node_modules" / "ignored.js").write_text(
        'const token = "ghp_1234567890abcdef1234567890abcdef1234";\n',
        encoding="utf-8",
    )

    (tmp_path / "dist").mkdir(parents=True)
    (tmp_path / "dist" / "ignored.py").write_text(
        'TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n',
        encoding="utf-8",
    )

    (tmp_path / "src").mkdir(parents=True)
    (tmp_path / "src" / "valid.py").write_text(
        'TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"\n',
        encoding="utf-8",
    )

    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(_minimal_package_lock(), encoding="utf-8")

    summary_path = tmp_path / "artifacts" / "summary.json"
    sarif_path = tmp_path / "artifacts" / "findings.sarif"

    run_scan(
        project_root=tmp_path,
        summary_path=summary_path,
        sarif_path=sarif_path,
        osv_client=_FakeOsvClient(),
    )

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    result_paths = {
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for result in sarif["runs"][0]["results"]
    }

    assert "src/valid.py" in result_paths
    assert "node_modules/ignored.js" not in result_paths
    assert "dist/ignored.py" not in result_paths
