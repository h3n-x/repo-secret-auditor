from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    evidence_hash: str
    rule_id: str | None = None
    file_path: str | None = None
    reason: str = "Accepted risk"
    expires_at: str | None = None  # ISO format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            # Handle ISO formats
            exp = datetime.fromisoformat(self.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            return datetime.now(UTC) > exp
        except ValueError:
            return False


@dataclass(frozen=True, slots=True)
class Baseline:
    entries: dict[str, BaselineEntry]  # keyed by evidence_hash

    def is_suppressed(
        self, evidence_hash: str, file_path: str | None = None
    ) -> tuple[bool, str | None]:
        entry = self.entries.get(evidence_hash)
        if entry is None:
            return False, None

        if entry.is_expired:
            return False, f"Suppression expired on {entry.expires_at}"

        if entry.file_path and file_path and entry.file_path != file_path:
            return False, None

        return True, entry.reason


def load_baseline(baseline_path: Path) -> Baseline:
    """Load baseline definitions from JSON file.

    Returns an empty Baseline if the file does not exist.
    """
    if not baseline_path.is_file():
        return Baseline(entries={})

    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return Baseline(entries={})

    raw_entries: list[dict[str, Any]] = data.get("suppressions", [])
    entries: dict[str, BaselineEntry] = {}

    for item in raw_entries:
        hash_val = item.get("evidence_hash")
        if not hash_val or not isinstance(hash_val, str):
            continue

        entries[hash_val] = BaselineEntry(
            evidence_hash=hash_val,
            rule_id=item.get("rule_id"),
            file_path=item.get("file_path"),
            reason=item.get("reason", "Accepted risk"),
            expires_at=item.get("expires_at"),
        )

    return Baseline(entries=entries)


def create_baseline_data(findings: list[Any]) -> dict[str, Any]:
    """Create structured JSON dictionary for a new baseline from findings."""
    suppressions = []
    seen: set[str] = set()

    for f in findings:
        evidence_hash = getattr(f, "evidence_hash", None)
        if not evidence_hash or evidence_hash in seen:
            continue
        seen.add(evidence_hash)

        suppressions.append(
            {
                "evidence_hash": evidence_hash,
                "rule_id": getattr(f, "rule_id", ""),
                "file_path": getattr(f, "file_path", ""),
                "reason": "Initial baseline baseline import",
                "expires_at": None,
            }
        )

    return {
        "$schema": "https://raw.githubusercontent.com/h3n-x/repo-secret-auditor/main/schemas/baseline.json",
        "version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "suppressions": suppressions,
    }
