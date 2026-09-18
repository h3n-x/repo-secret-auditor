from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.scanner.secrets import (
    DEFAULT_ALLOWLIST_PATTERNS,
    SecretFinding,
    SecretRule,
    detect_secrets,
    get_default_rules,
    is_path_allowlisted,
)


@dataclass(frozen=True, slots=True)
class CommitMetadata:
    sha: str
    author: str
    date: str


def scan_git_history(
    repo_path: Path,
    *,
    rules: tuple[SecretRule, ...] | None = None,
    allowlist_patterns: tuple[str, ...] = DEFAULT_ALLOWLIST_PATTERNS,
    max_commits: int = 500,
    since_ref: str | None = None,
) -> list[SecretFinding]:
    """Scan git commit diffs across history for committed secrets.

    Analyzes additions ('+') across git commits with exact author and commit attribution.
    """
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        return []

    cmd = [
        "git",
        "log",
        "-p",
        f"-n{max_commits}",
        "--no-color",
        "--full-history",
    ]
    if since_ref:
        cmd.append(f"{since_ref}..HEAD")
    else:
        cmd.append("--all")

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    active_rules = rules if rules is not None else get_default_rules()
    findings: list[SecretFinding] = []
    seen: set[tuple[str, str, str]] = set()  # (sha, rule_id, evidence_hash)

    current_commit: CommitMetadata | None = None
    current_file: str | None = None
    diff_line_idx = 0

    diff_file_re = re.compile(r"^diff --git a/(.*?) b/(.*?)$")
    hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw_line in proc.stdout.splitlines():
        if raw_line.startswith("commit "):
            sha = raw_line.split()[1]
            current_commit = CommitMetadata(sha=sha, author="unknown", date="unknown")
            current_file = None
            continue

        if current_commit is not None:
            if raw_line.startswith("Author: "):
                current_commit = CommitMetadata(
                    sha=current_commit.sha,
                    author=raw_line[len("Author: ") :].strip(),
                    date=current_commit.date,
                )
                continue
            if raw_line.startswith("Date:   "):
                current_commit = CommitMetadata(
                    sha=current_commit.sha,
                    author=current_commit.author,
                    date=raw_line[len("Date:   ") :].strip(),
                )
                continue

        match_diff = diff_file_re.match(raw_line)
        if match_diff:
            current_file = match_diff.group(2)
            diff_line_idx = 0
            continue

        match_hunk = hunk_re.match(raw_line)
        if match_hunk:
            diff_line_idx = int(match_hunk.group(1))
            continue

        if current_file is None or current_commit is None:
            continue

        if is_path_allowlisted(current_file, allowlist_patterns):
            continue

        # Only inspect added lines in the diff
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            diff_line_idx += 1
            added_content = raw_line[1:]

            line_findings = detect_secrets(
                file_path=current_file,
                content=added_content,
                rules=active_rules,
                allowlist_patterns=allowlist_patterns,
            )

            for finding in line_findings:
                dedupe_key = (current_commit.sha, finding.rule_id, finding.evidence_hash)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                findings.append(
                    SecretFinding(
                        rule_id=finding.rule_id,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        file_path=current_file,
                        line_start=diff_line_idx,
                        line_end=diff_line_idx,
                        evidence_hash=finding.evidence_hash,
                        commit_sha=current_commit.sha,
                        commit_author=current_commit.author,
                        commit_date=current_commit.date,
                    )
                )
        elif not raw_line.startswith("-"):
            diff_line_idx += 1

    return findings
