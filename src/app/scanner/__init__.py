"""Scanning engine package."""

from app.scanner.dependencies import (
    OsvClient,
    PackageRef,
    VulnerabilityMatch,
    audit_dependencies,
    parse_package_lock_json,
    parse_requirements_txt,
)
from app.scanner.scoring import (
    FindingSignal,
    ScanSummaryAggregate,
    calculate_risk_score,
    generate_scan_summary,
    normalize_severity,
)
from app.scanner.secrets import SecretFinding, detect_secrets, shannon_entropy

__all__ = [
    "OsvClient",
    "PackageRef",
    "FindingSignal",
    "ScanSummaryAggregate",
    "SecretFinding",
    "VulnerabilityMatch",
    "audit_dependencies",
    "calculate_risk_score",
    "detect_secrets",
    "generate_scan_summary",
    "normalize_severity",
    "parse_package_lock_json",
    "parse_requirements_txt",
    "shannon_entropy",
]
