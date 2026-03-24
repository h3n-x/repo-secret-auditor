import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Finding, Scan, ScanStatus, ScanSummary


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def create_scan(self, repo_url: str, commit_sha: str | None = None) -> Scan:
        scan = Scan(repo_url=repo_url, commit_sha=commit_sha, status=ScanStatus.QUEUED.value)
        self._session.add(scan)
        self._session.flush()
        return scan

    def get_by_id(self, scan_id: int) -> Scan | None:
        return self._session.get(Scan, scan_id)

    def upsert_scan_summary(
        self,
        scan_id: int,
        *,
        total_findings: int,
        critical_count: int,
        high_count: int,
        medium_count: int,
        low_count: int,
        risk_score: float | None = None,
    ) -> ScanSummary:
        summary = self._session.get(ScanSummary, scan_id)
        if summary is None:
            summary = ScanSummary(scan_id=scan_id)
            self._session.add(summary)

        summary.total_findings = total_findings
        summary.critical_count = critical_count
        summary.high_count = high_count
        summary.medium_count = medium_count
        summary.low_count = low_count

        if risk_score is not None:
            scan = self.get_by_id(scan_id)
            if scan is not None:
                metadata = _safe_load_metadata(scan.metadata_json)
                metadata["risk_score"] = risk_score
                scan.metadata_json = json.dumps(metadata)

        self._session.flush()
        return summary

    def list_findings(
        self,
        scan_id: int,
        *,
        severity: str | None = None,
        finding_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[Finding], int]:
        base_stmt = select(Finding).where(Finding.scan_id == scan_id)

        if severity is not None:
            base_stmt = base_stmt.where(Finding.severity == severity)
        if finding_type is not None:
            base_stmt = base_stmt.where(Finding.type == finding_type)

        total_stmt = select(func.count()).select_from(base_stmt.subquery())
        total = self._session.scalar(total_stmt) or 0

        paged_stmt = base_stmt.order_by(Finding.id.asc()).limit(limit).offset(offset)
        findings = self._session.scalars(paged_stmt).all()

        return list(findings), int(total)


def _safe_load_metadata(raw_json: str | None) -> dict[str, object]:
    if raw_json is None:
        return {}

    try:
        parsed = json.loads(raw_json)
    except json.JSONDecodeError:
        return {}

    return parsed if isinstance(parsed, dict) else {}
