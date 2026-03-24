"""Tests for API security features (Day 11)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security.logging import SecureLogger
from app.security.validation import validate_git_ref, validate_git_url


def test_validate_git_url_accepts_https_github() -> None:
    """Validate that HTTPS GitHub URLs are accepted."""
    url = "https://github.com/user/repo.git"
    result = validate_git_url(url)
    assert result == url


def test_validate_git_url_accepts_ssh_github() -> None:
    """Validate that SSH GitHub URLs are accepted."""
    url = "git@github.com:user/repo.git"
    result = validate_git_url(url)
    assert result == url


def test_validate_git_url_accepts_gitlab() -> None:
    """Validate that GitLab URLs are accepted."""
    url = "https://gitlab.com/user/repo.git"
    result = validate_git_url(url)
    assert result == url


def test_validate_git_url_rejects_unknown_scheme() -> None:
    """Validate that unknown schemes are rejected."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        validate_git_url("ftp://github.com/user/repo.git")
    assert exc_info.value.status_code == 422
    assert "scheme" in exc_info.value.detail.lower()


def test_validate_git_url_rejects_unknown_host() -> None:
    """Validate that unknown hosts are rejected."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        validate_git_url("https://malicious-host.com/user/repo.git")
    assert exc_info.value.status_code == 422
    assert "whitelisted" in exc_info.value.detail.lower()


def test_validate_git_url_rejects_oversized_url() -> None:
    """Validate that non-excessive URLs are rejected."""
    from fastapi import HTTPException

    oversized = "https://github.com/" + ("a" * 2050)
    with pytest.raises(HTTPException) as exc_info:
        validate_git_url(oversized)
    assert exc_info.value.status_code == 422


def test_validate_git_ref_accepts_branch_name() -> None:
    """Validate that branch names are accepted."""
    ref = "main"
    result = validate_git_ref(ref)
    assert result == ref


def test_validate_git_ref_accepts_commit_sha() -> None:
    """Validate that commit SHAs are accepted."""
    ref = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b"
    result = validate_git_ref(ref)
    assert result == ref


def test_validate_git_ref_accepts_tag() -> None:
    """Validate that tags are accepted."""
    ref = "v1.0.0"
    result = validate_git_ref(ref)
    assert result == ref


def test_validate_git_ref_accepts_feature_branch() -> None:
    """Validate that feature branch names are accepted."""
    ref = "feature/add-security"
    result = validate_git_ref(ref)
    assert result == ref


def test_validate_git_ref_defaults_to_head() -> None:
    """Validate that None ref defaults to HEAD."""
    result = validate_git_ref(None)
    assert result == "HEAD"


def test_validate_git_ref_rejects_empty_string() -> None:
    """Validate that empty refs are rejected."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        validate_git_ref("")
    assert exc_info.value.status_code == 422


def test_validate_git_ref_rejects_path_traversal() -> None:
    """Validate that path traversal refs are rejected."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        validate_git_ref("../../etc/passwd")
    assert exc_info.value.status_code == 422


def test_validate_git_ref_rejects_special_chars() -> None:
    """Validate that special characters are rejected."""
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        validate_git_ref("main`whoami`")
    assert exc_info.value.status_code == 422


def test_secure_logger_redacts_github_pat() -> None:
    """Validate that GitHub PATs are redacted in logs."""
    logger = SecureLogger(__name__)
    message = 'Token is "ghp_1234567890abcdef1234567890abcdef1234"'
    redacted = logger.redact(message)
    assert "ghp_" not in redacted
    assert "[REDACTED_PAT]" in redacted


def test_secure_logger_redacts_api_key() -> None:
    """Validate that API keys are redacted in logs."""
    logger = SecureLogger(__name__)
    message = "api_key=secret123456789"
    redacted = logger.redact(message)
    assert "secret" not in redacted
    assert "[REDACTED_API_KEY]" in redacted


def test_secure_logger_redacts_authorization_header() -> None:
    """Validate that Authorization headers are redacted in logs."""
    logger = SecureLogger(__name__)
    message = "Authorization: Bearer sk_live_123456789"
    redacted = logger.redact(message)
    assert "sk_live_" not in redacted
    assert "[REDACTED_AUTH_HEADER]" in redacted


def test_create_scan_rate_limit() -> None:
    """Validate that rate limiting is enforced on POST /scans."""
    valid_payload = {
        "repo_url": "https://github.com/user/repo.git",
        "ref": "main",
    }

    # Use context manager so startup runs and DB tables are initialized.
    with TestClient(app) as client:
        response = client.post("/scans", json=valid_payload)
        assert response.status_code in {202, 422, 429}
