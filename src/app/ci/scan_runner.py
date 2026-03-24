from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from app.reporting.sarif import sarif_json
from app.scanner.dependencies import (
    OsvClient,
    PackageRef,
    VulnerabilityMatch,
    parse_package_lock_json,
    parse_requirements_txt,
)
from app.scanner.scoring import (
    FindingSignal,
    ScanSummaryAggregate,
    generate_scan_summary,
    normalize_severity,
)
from app.scanner.secrets import SecretFinding, detect_secrets

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "vendor",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "tests",
    "plan",
    "spec",
    "dist",
    "build",
    "target",
    ".tox",
    ".cache",
    ".next",
}

DEFAULT_SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".txt",
    ".md",
    ".env",
    ".sh",
    ".sql",
}

DEFAULT_SCANNABLE_BASENAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "requirements.txt",
    "package-lock.json",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
}

MAX_SCANNED_FILE_SIZE_BYTES = 1_000_000
MAX_SCANNED_FILES = 5_000


class OsvClientLike(Protocol):
    def query(self, package: PackageRef) -> list[VulnerabilityMatch]: ...


@dataclass(frozen=True, slots=True)
class CiFinding:
    id: int
    type: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    confidence: float
    recommendation: str | None


def run_scan(
    *,
    project_root: Path,
    summary_path: Path,
    sarif_path: Path,
    osv_client: OsvClientLike | None = None,
) -> ScanSummaryAggregate:
    findings = collect_findings(project_root=project_root, osv_client=osv_client or OsvClient())

    summary = generate_scan_summary(
        [
            FindingSignal(severity=finding.severity, confidence=finding.confidence)
            for finding in findings
        ]
    )
    _write_summary(summary_path=summary_path, summary=summary)
    _write_sarif(sarif_path=sarif_path, findings=findings)
    return summary


def collect_findings(*, project_root: Path, osv_client: OsvClientLike) -> list[CiFinding]:
    findings: list[CiFinding] = []

    for secret in _collect_secret_findings(project_root):
        findings.append(_map_secret_finding(secret=secret, finding_id=len(findings) + 1))

    for vuln in _collect_dependency_findings(project_root=project_root, osv_client=osv_client):
        findings.append(_map_dependency_finding(vuln=vuln, finding_id=len(findings) + 1))

    return findings


def _collect_secret_findings(project_root: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []

    for file_path in _iter_scannable_files(project_root):
        relative_path = file_path.relative_to(project_root).as_posix()
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(detect_secrets(file_path=relative_path, content=content))

    return findings


def _collect_dependency_findings(
    *, project_root: Path, osv_client: OsvClientLike
) -> list[VulnerabilityMatch]:
    requirements_path = project_root / "requirements.txt"
    package_lock_path = project_root / "package-lock.json"

    requirements_content = ""
    package_lock_content = '{"name":"scan","lockfileVersion":3,"packages":{}}'

    if requirements_path.exists():
        requirements_content = requirements_path.read_text(encoding="utf-8")

    if package_lock_path.exists():
        package_lock_content = package_lock_path.read_text(encoding="utf-8")

    try:
        packages = [
            *parse_requirements_txt(requirements_content),
            *parse_package_lock_json(package_lock_content),
        ]
    except json.JSONDecodeError:
        return []

    findings: list[VulnerabilityMatch] = []
    for package in packages:
        findings.extend(osv_client.query(package))
    return findings


def _map_secret_finding(*, secret: SecretFinding, finding_id: int) -> CiFinding:
    return CiFinding(
        id=finding_id,
        type="secret",
        rule_id=secret.rule_id,
        file_path=secret.file_path,
        line_start=secret.line_start,
        line_end=secret.line_end,
        severity=normalize_severity(secret.severity),
        confidence=secret.confidence,
        recommendation="Revoke and rotate the exposed secret.",
    )


def _map_dependency_finding(*, vuln: VulnerabilityMatch, finding_id: int) -> CiFinding:
    safe_vuln_id = vuln.vuln_id.lower().replace(" ", "-").replace("_", "-")
    return CiFinding(
        id=finding_id,
        type="dependency",
        rule_id=f"dependency.{safe_vuln_id}",
        file_path="dependency-manifest",
        line_start=1,
        line_end=1,
        severity=normalize_severity(vuln.severity),
        confidence=0.95,
        recommendation=(
            f"Upgrade {vuln.package_name} from {vuln.installed_version}"
            + (f" to at least {vuln.fixed_version}." if vuln.fixed_version else ".")
        ),
    )


def _iter_scannable_files(project_root: Path) -> list[Path]:
    files: list[Path] = []

    for current_root, dir_names, file_names in os.walk(project_root, topdown=True):
        # Prune excluded directories early to avoid descending into huge trees.
        dir_names[:] = [name for name in dir_names if name not in DEFAULT_EXCLUDED_DIRS]

        current_path = Path(current_root)
        for file_name in sorted(file_names):
            if len(files) >= MAX_SCANNED_FILES:
                return files

            file_path = current_path / file_name
            if not _is_scannable_candidate(file_path):
                continue

            try:
                if file_path.stat().st_size > MAX_SCANNED_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            files.append(file_path)

    return files


def _is_scannable_candidate(file_path: Path) -> bool:
    base_name = file_path.name
    if base_name in DEFAULT_SCANNABLE_BASENAMES:
        return True

    suffix = file_path.suffix.lower()
    return suffix in DEFAULT_SCANNABLE_EXTENSIONS


def _write_summary(*, summary_path: Path, summary: ScanSummaryAggregate) -> None:
    summary_payload = {
        **asdict(summary),
        "generated_at": datetime.now(UTC).isoformat(),
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary_payload, indent=2, sort_keys=True), encoding="utf-8")


def _write_sarif(*, sarif_path: Path, findings: list[CiFinding]) -> None:
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(sarif_json(findings), encoding="utf-8")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run repository security scan.")
    parser.add_argument("--project-root", default=".", help="Repository root path to scan")
    parser.add_argument("--summary", required=True, help="Path to JSON summary output")
    parser.add_argument("--sarif", required=True, help="Path to SARIF output")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    project_root = Path(args.project_root).resolve()
    summary_path = Path(args.summary)
    sarif_path = Path(args.sarif)

    run_scan(project_root=project_root, summary_path=summary_path, sarif_path=sarif_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
