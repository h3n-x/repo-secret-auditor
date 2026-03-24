from __future__ import annotations

from app.scanner.scoring import (
    FindingSignal,
    calculate_risk_score,
    generate_scan_summary,
    normalize_severity,
)


def test_normalize_severity_maps_common_aliases() -> None:
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("sev1") == "high"
    assert normalize_severity("moderate") == "medium"
    assert normalize_severity("informational") == "low"
    assert normalize_severity("not-classified") == "low"


def test_calculate_risk_score_reflects_severity_and_confidence() -> None:
    baseline = calculate_risk_score(
        [
            FindingSignal(severity="critical", confidence=1.0),
            FindingSignal(severity="high", confidence=1.0),
            FindingSignal(severity="medium", confidence=1.0),
            FindingSignal(severity="low", confidence=1.0),
        ]
    )
    weaker = calculate_risk_score(
        [
            FindingSignal(severity="critical", confidence=0.5),
            FindingSignal(severity="high", confidence=0.4),
            FindingSignal(severity="medium", confidence=0.3),
            FindingSignal(severity="low", confidence=0.2),
        ]
    )

    assert baseline > weaker
    assert baseline <= 100.0
    assert calculate_risk_score([]) == 0.0


def test_generate_scan_summary_aggregates_counts_and_score() -> None:
    signals = [
        FindingSignal(severity="critical", confidence=0.9),
        FindingSignal(severity="high", confidence=0.8),
        FindingSignal(severity="medium", confidence=0.7),
        FindingSignal(severity="low", confidence=0.6),
        FindingSignal(severity="unknown", confidence=0.5),
    ]

    summary = generate_scan_summary(signals)

    assert summary.total_findings == 5
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.low_count == 2
    assert 0.0 < summary.risk_score <= 100.0
