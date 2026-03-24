from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatch
from hashlib import sha256


@dataclass(frozen=True, slots=True)
class SecretFinding:
    rule_id: str
    severity: str
    confidence: float
    file_path: str
    line_start: int
    line_end: int
    evidence_hash: str


@dataclass(frozen=True, slots=True)
class _SecretRule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: str
    base_confidence: float
    min_entropy: float
    extract_group: int = 0

    def extract_candidate(self, match: re.Match[str]) -> str:
        value = match.group(self.extract_group).strip()
        return value.strip("\"'")


DEFAULT_ALLOWLIST_PATTERNS: tuple[str, ...] = (
    "**/.git/**",
    "**/node_modules/**",
    "**/vendor/**",
)


_SECRET_RULES: tuple[_SecretRule, ...] = (
    _SecretRule(
        rule_id="secret.github_pat",
        pattern=re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
        severity="high",
        base_confidence=0.9,
        min_entropy=3.3,
        extract_group=1,
    ),
    _SecretRule(
        rule_id="secret.aws_access_key",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity="high",
        base_confidence=0.8,
        min_entropy=2.9,
        extract_group=1,
    ),
    _SecretRule(
        rule_id="secret.generic_api_key",
        pattern=re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?
            """
        ),
        severity="medium",
        base_confidence=0.7,
        min_entropy=3.5,
        extract_group=1,
    ),
)


def _normalize_path(file_path: str) -> str:
    return file_path.replace("\\", "/")


def is_path_allowlisted(file_path: str, allowlist_patterns: tuple[str, ...]) -> bool:
    normalized_path = _normalize_path(file_path)
    return any(fnmatch(normalized_path, pattern) for pattern in allowlist_patterns)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    length = len(value)
    frequencies = Counter(value)
    entropy = 0.0
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def _compute_confidence(base_confidence: float, entropy: float, min_entropy: float) -> float:
    entropy_delta = entropy - min_entropy
    adjusted = base_confidence + (entropy_delta * 0.1)
    return round(min(max(adjusted, 0.05), 0.99), 2)


def _hash_evidence(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.upper()
    placeholder_markers = ("EXAMPLE", "PLACEHOLDER", "YOUR_", "DUMMY", "SAMPLE")
    return any(marker in normalized for marker in placeholder_markers)


def detect_secrets(
    file_path: str,
    content: str,
    *,
    allowlist_patterns: tuple[str, ...] = DEFAULT_ALLOWLIST_PATTERNS,
) -> list[SecretFinding]:
    if is_path_allowlisted(file_path, allowlist_patterns):
        return []

    findings: list[SecretFinding] = []
    seen: set[tuple[str, int, str]] = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        for rule in _SECRET_RULES:
            for match in rule.pattern.finditer(line):
                candidate = rule.extract_candidate(match)
                if _looks_like_placeholder(candidate):
                    continue
                entropy = shannon_entropy(candidate)

                # Filter obviously weak tokens for the generic detector to reduce false positives.
                if rule.rule_id == "secret.generic_api_key" and entropy < (rule.min_entropy - 1.0):
                    continue

                evidence_hash = _hash_evidence(candidate)
                dedupe_key = (rule.rule_id, line_number, evidence_hash)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                findings.append(
                    SecretFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=_compute_confidence(
                            base_confidence=rule.base_confidence,
                            entropy=entropy,
                            min_entropy=rule.min_entropy,
                        ),
                        file_path=file_path,
                        line_start=line_number,
                        line_end=line_number,
                        evidence_hash=evidence_hash,
                    )
                )

    return findings
