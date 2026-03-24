from __future__ import annotations

import json
from typing import Any, Protocol, Sequence

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


class FindingLike(Protocol):
    @property
    def id(self) -> int: ...

    @property
    def type(self) -> str: ...

    @property
    def rule_id(self) -> str: ...

    @property
    def file_path(self) -> str: ...

    @property
    def line_start(self) -> int: ...

    @property
    def line_end(self) -> int: ...

    @property
    def severity(self) -> str: ...

    @property
    def confidence(self) -> float: ...

    @property
    def recommendation(self) -> str | None: ...


def build_sarif_report(
    findings: Sequence[FindingLike],
    *,
    tool_name: str = "Repo Secret & Dependency Auditor",
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    rules = _build_rules(findings)
    results = [_finding_to_result(finding) for finding in findings]

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/h3n-x/repo-secret-auditor",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def sarif_json(
    findings: Sequence[FindingLike],
    *,
    tool_name: str = "Repo Secret & Dependency Auditor",
    tool_version: str = "0.1.0",
) -> str:
    report = build_sarif_report(findings, tool_name=tool_name, tool_version=tool_version)
    return json.dumps(report, indent=2, sort_keys=True)


def _build_rules(findings: Sequence[FindingLike]) -> list[dict[str, Any]]:
    by_rule: dict[str, FindingLike] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, finding)

    return [
        {
            "id": rule_id,
            "name": _rule_name(rule_id, sample.type),
            "shortDescription": {"text": _rule_short_description(rule_id, sample.type)},
            "help": {
                "text": sample.recommendation or "Review and remediate this finding.",
            },
            "properties": {
                "precision": _precision_for_confidence(sample.confidence),
                "tags": [sample.type, sample.severity],
            },
        }
        for rule_id, sample in sorted(by_rule.items())
    ]


def _finding_to_result(finding: FindingLike) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {
            "text": (
                f"{finding.type} finding ({finding.severity}) in {finding.file_path}:"
                f" lines {finding.line_start}-{finding.line_end}."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {
                        "startLine": finding.line_start,
                        "endLine": finding.line_end,
                    },
                }
            }
        ],
        "properties": {
            "finding_id": finding.id,
            "confidence": round(finding.confidence, 2),
            "finding_type": finding.type,
        },
    }


def _sarif_level(severity: str) -> str:
    normalized = severity.strip().lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _precision_for_confidence(confidence: float) -> str:
    if confidence >= 0.85:
        return "very-high"
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"


def _rule_name(rule_id: str, finding_type: str) -> str:
    suffix = rule_id.split(".")[-1].replace("_", "-")
    return f"{finding_type}-{suffix}"


def _rule_short_description(rule_id: str, finding_type: str) -> str:
    detector = rule_id.replace("_", " ")
    return f"{finding_type.title()} detection by rule {detector}."
