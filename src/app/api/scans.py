from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.schemas import (
    CreateScanRequest,
    CreateScanResponse,
    FindingItemResponse,
    FindingListResponse,
    ScanDetailResponse,
)
from app.db.dependencies import get_db_session
from app.db.models import FindingType, Severity
from app.repositories.scan_repository import ScanRepository
from app.security.logging import SecureLogger
from app.security.rate_limiting import GET_FINDINGS_RATE_LIMIT, POST_SCANS_RATE_LIMIT, limiter
from app.workers.queue import enqueue_scan

router = APIRouter(prefix="/scans", tags=["scans"])
logger = SecureLogger(__name__)


@router.post("", status_code=status.HTTP_202_ACCEPTED, response_model=CreateScanResponse)
@limiter.limit(POST_SCANS_RATE_LIMIT)
def create_scan(
    request: Request,
    payload: CreateScanRequest,
    session: Session = Depends(get_db_session),
) -> CreateScanResponse:
    """Create a new security scan for a repository.

    **Security Notes:**
    - Rate limited to 10 requests per minute per IP.
    - Git URL validated against whitelist (github.com, gitlab.com, etc.).
    - Git ref validated to prevent malicious input.
    - All logging is sanitized to hide secrets.
    """
    scan_repository = ScanRepository(session)

    logger.info(f"Creating scan for repo: {payload.repo_url}, ref: {payload.ref}")

    scan = scan_repository.create_scan(repo_url=str(payload.repo_url), commit_sha=payload.ref)
    job_id = enqueue_scan(scan.id)
    scan.metadata_json = json.dumps({"job_id": job_id})
    session.commit()

    logger.info(f"Scan created: scan_id={scan.id}, status=queued, job_id={job_id}")

    return CreateScanResponse(scan_id=scan.id, status="queued", job_id=job_id)


@router.get("/{scan_id}", response_model=ScanDetailResponse)
@limiter.limit(GET_FINDINGS_RATE_LIMIT)
def get_scan(
    request: Request,
    scan_id: int,
    session: Session = Depends(get_db_session),
) -> ScanDetailResponse:
    """Get details of a scan."""
    scan_repository = ScanRepository(session)
    scan = scan_repository.get_by_id(scan_id)

    if scan is None:
        logger.warning(f"Scan not found: scan_id={scan_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    summary = scan.summary

    return ScanDetailResponse(
        scan_id=scan.id,
        repo_url=scan.repo_url,
        commit_sha=scan.commit_sha,
        status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        total_findings=summary.total_findings if summary else 0,
        critical_count=summary.critical_count if summary else 0,
        high_count=summary.high_count if summary else 0,
        medium_count=summary.medium_count if summary else 0,
        low_count=summary.low_count if summary else 0,
    )


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
@limiter.limit(GET_FINDINGS_RATE_LIMIT)
def get_scan_findings(
    request: Request,
    scan_id: int,
    severity: str | None = Query(default=None),
    finding_type: str | None = Query(default=None, alias="type"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_db_session),
) -> FindingListResponse:
    """Get findings for a scan with optional filtering.

    **Security Notes:**
    - Rate limited to 30 requests per minute per IP.
    - Severity and type filters validated against allowed values.
    - Pagination enforced to prevent large result exfiltration.
    """
    scan_repository = ScanRepository(session)
    scan = scan_repository.get_by_id(scan_id)
    if scan is None:
        logger.warning(f"Scan not found: scan_id={scan_id}")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if severity is not None and severity not in {member.value for member in Severity}:
        logger.warning(f"Invalid severity filter: scan_id={scan_id}, severity={severity}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid severity filter",
        )

    if finding_type is not None and finding_type not in {member.value for member in FindingType}:
        logger.warning(f"Invalid type filter: scan_id={scan_id}, type={finding_type}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid type filter",
        )

    findings, total = scan_repository.list_findings(
        scan_id,
        severity=severity,
        finding_type=finding_type,
        limit=limit,
        offset=offset,
    )

    logger.info(
        f"Retrieved findings: scan_id={scan_id}, total={total}, "
        f"severity={severity}, type={finding_type}, limit={limit}, offset={offset}"
    )

    return FindingListResponse(
        version="v1",
        scan_id=scan_id,
        total=total,
        limit=limit,
        offset=offset,
        items=[
            FindingItemResponse(
                id=finding.id,
                type=finding.type,
                rule_id=finding.rule_id,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                severity=finding.severity,
                confidence=finding.confidence,
                recommendation=finding.recommendation,
            )
            for finding in findings
        ],
    )
