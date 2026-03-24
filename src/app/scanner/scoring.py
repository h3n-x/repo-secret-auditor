from __future__ import annotations

from dataclasses import dataclass

_CRITICAL_ALIASES = {"critical", "crit", "sev0", "blocker"}
_HIGH_ALIASES = {"high", "sev1", "major"}
_MEDIUM_ALIASES = {"medium", "med", "moderate", "sev2"}
_LOW_ALIASES = {"low", "minor", "info", "informational", "sev3", "unknown"}

_SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}


@dataclass(frozen=True, slots=True)
class FindingSignal:
    severity: str
    confidence: float = 1.0


@dataclass(frozen=True, slots=True)
class ScanSummaryAggregate:
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: float


def normalize_severity(raw_severity: str) -> str:
    normalized = raw_severity.strip().lower()

    if normalized in _CRITICAL_ALIASES:
        return "critical"
    if normalized in _HIGH_ALIASES:
        return "high"
    if normalized in _MEDIUM_ALIASES:
        return "medium"
    if normalized in _LOW_ALIASES:
        return "low"

    return "low"


def calculate_risk_score(signals: list[FindingSignal]) -> float:
    if not signals:
        return 0.0

    weighted_sum = 0.0
    max_weighted_sum = 4.0 * len(signals)

    for signal in signals:
        severity = normalize_severity(signal.severity)
        weight = _SEVERITY_WEIGHTS[severity]
        confidence = min(max(signal.confidence, 0.05), 1.0)
        weighted_sum += weight * confidence

    return round((weighted_sum / max_weighted_sum) * 100, 2)


def generate_scan_summary(signals: list[FindingSignal]) -> ScanSummaryAggregate:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    normalized_signals: list[FindingSignal] = []
    for signal in signals:
        normalized = normalize_severity(signal.severity)
        counts[normalized] += 1
        normalized_signals.append(FindingSignal(severity=normalized, confidence=signal.confidence))

    return ScanSummaryAggregate(
        total_findings=len(normalized_signals),
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        risk_score=calculate_risk_score(normalized_signals),
    )
