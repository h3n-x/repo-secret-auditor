"""Input validation for API requests with strict SSRF mitigation."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from fastapi import HTTPException, status

ALLOWED_GIT_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "gitea.io"})
ALLOWED_SCHEMES = frozenset({"https", "ssh"})


def validate_git_url(repo_url: str) -> str:
    """Validate and normalize a Git repository URL.

    Args:
        repo_url: The repository URL to validate.

    Returns:
        The normalized, valid URL.

    Raises:
        HTTPException: If the URL is invalid, unsafe, or targets local/internal infrastructure.
    """
    if not repo_url or len(repo_url) > 2048:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="repo_url must be a valid URL between 1 and 2048 characters",
        )

    # Support scp-like SSH syntax: git@host:owner/repo.git
    scp_like_match = re.match(r"^(?P<user>[\w.-]+)@(?P<host>[\w.-]+):(?P<path>.+)$", repo_url)
    if scp_like_match:
        host = scp_like_match.group("host").lower()
        if host in {"localhost", "127.0.0.1", "0.0.0.0"} or host.endswith(".localhost"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Access to localhost or internal network is strictly prohibited",
            )

        is_known_host = any(
            host == allowed or host.endswith(f".{allowed}") for allowed in ALLOWED_GIT_HOSTS
        )
        allowed_list = ", ".join(sorted(ALLOWED_GIT_HOSTS))
        if not is_known_host:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"repo_url must point to a whitelisted Git host: {allowed_list}",
            )
        return repo_url

    parsed = urlparse(repo_url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        allowed_schemes_list = ", ".join(sorted(ALLOWED_SCHEMES))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"repo_url scheme must be one of: {allowed_schemes_list}",
        )

    host = (parsed.hostname or "").lower()
    if not host or host in {"localhost", "127.0.0.1", "0.0.0.0"} or host.endswith(".localhost"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Access to localhost or internal network is strictly prohibited",
        )

    is_known_host = any(
        host == allowed or host.endswith(f".{allowed}") for allowed in ALLOWED_GIT_HOSTS
    )

    if not is_known_host:
        allowed_list = ", ".join(sorted(ALLOWED_GIT_HOSTS))
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"repo_url must point to a whitelisted Git host: {allowed_list}",
        )

    return repo_url


def validate_git_ref(ref: str | None) -> str:
    """Validate a Git reference (branch, tag, or commit SHA).

    Args:
        ref: The Git reference to validate.

    Returns:
        The validated reference.

    Raises:
        HTTPException: If the reference is invalid or suspicious.
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

    # Disallow leading dashes to prevent command-line option injection (e.g. -o, --upload-pack)
    if ref.startswith("-"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="ref must not start with a hyphen or dash",
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
