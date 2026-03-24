"""Input validation for API requests."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from fastapi import HTTPException, status


def validate_git_url(repo_url: str) -> str:
    """Validate and normalize a Git repository URL.

    Args:
        repo_url: The repository URL to validate.

    Returns:
        The normalized, valid URL.

    Raises:
        HTTPException: If the URL is invalid or unsafe.
    """
    if not repo_url or len(repo_url) > 2048:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="repo_url must be a valid URL between 1 and 2048 characters",
        )

    # Support scp-like SSH syntax: git@host:owner/repo.git
    scp_like_match = re.match(r"^(?P<user>[\w.-]+)@(?P<host>[\w.-]+):(?P<path>.+)$", repo_url)
    if scp_like_match:
        host = scp_like_match.group("host")
        allowed_hosts = {"github.com", "gitlab.com", "bitbucket.org", "gitea.io", "localhost"}
        is_localhost = host in {"localhost", "127.0.0.1"}
        is_known_host = any(
            host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts
        )
        if not (is_localhost or is_known_host):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"repo_url must point to a whitelisted Git host: {', '.join(allowed_hosts)}",
            )
        return repo_url

    parsed = urlparse(repo_url)

    allowed_schemes = {"http", "https", "git", "ssh"}
    if parsed.scheme not in allowed_schemes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"repo_url scheme must be one of: {', '.join(allowed_schemes)}",
        )

    allowed_hosts = {"github.com", "gitlab.com", "bitbucket.org", "gitea.io", "localhost"}
    is_localhost = parsed.hostname in {"localhost", "127.0.0.1"}
    is_known_host = bool(
        parsed.hostname
        and any(
            parsed.hostname == host or parsed.hostname.endswith(f".{host}")
            for host in allowed_hosts
        )
    )

    if not (is_localhost or is_known_host):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"repo_url must point to a whitelisted Git host: {', '.join(allowed_hosts)}",
        )

    return repo_url


def validate_git_ref(ref: str | None) -> str:
    """Validate a Git reference (branch, tag, or commit SHA).

    Args:
        ref: The Git reference to validate.

    Returns:
        The validated reference.

    Raises:
        HTTPException: If the reference is invalid.
    """
    if ref is None:
        return "HEAD"

    if len(ref) > 255:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ref must not exceed 255 characters",
        )

    if ref in {"", ".", "..", "*"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ref contains invalid characters or patterns",
        )

    if ".." in ref or ref.startswith("/") or ref.endswith("/") or "//" in ref:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ref contains invalid characters or patterns",
        )

    git_ref_pattern = r"^[a-zA-Z0-9._/-]+$"
    if not re.match(git_ref_pattern, ref):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "ref must only contain alphanumeric characters, dots, "
                "slashes, underscores, or hyphens"
            ),
        )

    return ref
