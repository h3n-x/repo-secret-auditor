from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, HttpUrl, field_validator

from app.security.validation import validate_git_ref, validate_git_url


class CreateScanRequest(BaseModel):
    repo_url: HttpUrl
    ref: str | None = None

    @field_validator("repo_url", mode="before")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate Git URL."""
        return validate_git_url(str(v))

    @field_validator("ref")
    @classmethod
    def validate_ref(cls, v: str | None) -> str | None:
        """Validate Git reference."""
        return validate_git_ref(v) if v else None


class CreateScanResponse(BaseModel):
    scan_id: int
    status: Literal["queued"]
    job_id: str


class ScanDetailResponse(BaseModel):
    scan_id: int
    repo_url: str
    commit_sha: str | None
    status: str
    started_at: datetime
    finished_at: datetime | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class FindingItemResponse(BaseModel):
    id: int
    type: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    confidence: float
    recommendation: str | None


class FindingListResponse(BaseModel):
    version: Literal["v1"]
    scan_id: int
    total: int
    limit: int
    offset: int
    items: list[FindingItemResponse]
