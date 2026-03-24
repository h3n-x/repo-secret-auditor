from __future__ import annotations

from dataclasses import dataclass

from app.reporting.sarif import build_sarif_report, sarif_json


@dataclass(frozen=True, slots=True)
class _FixtureFinding:
    id: int
    type: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    confidence: float
    recommendation: str | None


def _sample_findings() -> list[_FixtureFinding]:
    return [
        _FixtureFinding(
            id=101,
            type="secret",
            rule_id="secret.github_pat",
            file_path="src/app/config.py",
            line_start=12,
            line_end=12,
            severity="high",
            confidence=0.91,
            recommendation="Revoke and rotate the leaked token.",
        ),
        _FixtureFinding(
            id=102,
            type="dependency",
            rule_id="dependency.osv_cve",
            file_path="requirements.txt",
            line_start=3,
            line_end=3,
            severity="medium",
            confidence=0.73,
            recommendation="Upgrade to a fixed version.",
        ),
    ]


def test_build_sarif_report_has_2_1_0_contract() -> None:
    report = build_sarif_report(_sample_findings())

    assert report["version"] == "2.1.0"
    assert report["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(report["runs"]) == 1


def test_build_sarif_report_maps_results_and_levels() -> None:
    report = build_sarif_report(_sample_findings())
    run = report["runs"][0]
    results = run["results"]

    assert len(results) == 2
    first = results[0]
    second = results[1]

    assert first["ruleId"] == "secret.github_pat"
    assert first["level"] == "error"
    assert (
        first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app/config.py"
    )

    assert second["ruleId"] == "dependency.osv_cve"
    assert second["level"] == "warning"
    assert second["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_build_sarif_report_defines_unique_rules() -> None:
    findings = _sample_findings() + [
        _FixtureFinding(
            id=103,
            type="secret",
            rule_id="secret.github_pat",
            file_path="src/app/settings.py",
            line_start=7,
            line_end=7,
            severity="critical",
            confidence=0.95,
            recommendation="Rotate credential immediately.",
        )
    ]

    report = build_sarif_report(findings)
    rules = report["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 2
    rule_ids = {rule["id"] for rule in rules}
    assert rule_ids == {"secret.github_pat", "dependency.osv_cve"}


def test_sarif_json_returns_valid_json_text() -> None:
    payload = sarif_json(_sample_findings())

    assert '"version": "2.1.0"' in payload
    assert '"runs"' in payload
    assert '"ruleId": "secret.github_pat"' in payload
