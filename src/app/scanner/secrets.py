from __future__ import annotations

import functools
import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatch
from hashlib import sha256
from pathlib import Path
from typing import Any


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
class SecretRule:
    rule_id: str
    pattern: re.Pattern[str]
    severity: str = "high"
    description: str = ""
    base_confidence: float = 0.8
    min_entropy: float = 0.0
    extract_group: int = 1
    keywords: tuple[str, ...] = ()

    def extract_candidate(self, match: re.Match[str]) -> str:
        if 0 < self.extract_group <= len(match.groups()):
            value = match.group(self.extract_group)
        else:
            value = match.group(0)
        return value.strip().strip("\"'")


# Backward compatibility alias
_SecretRule = SecretRule

DEFAULT_ALLOWLIST_PATTERNS: tuple[str, ...] = (
    "**/.git/**",
    "**/node_modules/**",
    "**/vendor/**",
)


def load_rules_from_toml(toml_content: str) -> tuple[SecretRule, ...]:
    """Parse Gitleaks-compatible TOML rules into SecretRule objects."""
    data = tomllib.loads(toml_content)
    raw_rules: list[dict[str, Any]] = data.get("rules", [])
    rules: list[SecretRule] = []

    for item in raw_rules:
        rule_id = item.get("id")
        regex_pattern = item.get("regex")
        if not rule_id or not regex_pattern:
            continue

        severity = item.get("severity", "high")
        description = item.get("description", "")
        base_confidence = float(
            item.get("base_confidence", 0.9 if severity in {"critical", "high"} else 0.7)
        )
        min_entropy = float(item.get("entropy", 0.0))
        extract_group = int(item.get("secretGroup", 1))
        raw_keywords = item.get("keywords", [])
        keywords = tuple(k.lower() for k in raw_keywords if isinstance(k, str))

        compiled_pattern = re.compile(regex_pattern)
        rules.append(
            SecretRule(
                rule_id=rule_id,
                pattern=compiled_pattern,
                severity=severity,
                description=description,
                base_confidence=base_confidence,
                min_entropy=min_entropy,
                extract_group=extract_group,
                keywords=keywords,
            )
        )

    return tuple(rules)


def load_rules_from_file(rules_path: str | Path) -> tuple[SecretRule, ...]:
    """Load TOML rules from a given file path."""
    content = Path(rules_path).read_text(encoding="utf-8")
    return load_rules_from_toml(content)


@functools.cache
def get_default_rules() -> tuple[SecretRule, ...]:
    """Load default rules from rules.toml, with hardcoded fallback if file is missing."""
    rules_file = Path(__file__).parent / "rules.toml"
    if rules_file.is_file():
        return load_rules_from_file(rules_file)

    # Fallback rules if file is missing
    return (
        SecretRule(
            rule_id="secret.github_pat",
            pattern=re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
            severity="high",
            base_confidence=0.9,
            min_entropy=3.3,
            extract_group=1,
            keywords=("ghp_", "github_pat_"),
        ),
        SecretRule(
            rule_id="secret.aws_access_key",
            pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
            severity="high",
            base_confidence=0.8,
            min_entropy=2.9,
            extract_group=1,
            keywords=("akia",),
        ),
        SecretRule(
            rule_id="secret.generic_api_key",
            pattern=re.compile(
                r"""(?ix)\b(?:api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"""
            ),
            severity="medium",
            base_confidence=0.7,
            min_entropy=3.5,
            extract_group=1,
            keywords=("api_key", "token", "secret"),
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
    rules: tuple[SecretRule, ...] | None = None,
    allowlist_patterns: tuple[str, ...] = DEFAULT_ALLOWLIST_PATTERNS,
) -> list[SecretFinding]:
    if is_path_allowlisted(file_path, allowlist_patterns):
        return []

    active_rules = rules if rules is not None else get_default_rules()
    findings: list[SecretFinding] = []
    seen: set[tuple[str, int, str]] = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        line_lower = line.lower()
        for rule in active_rules:
            # Fast-path optimization: skip rule if none of its keywords appear in the line
            if rule.keywords and not any(kw in line_lower for kw in rule.keywords):
                continue

            for match in rule.pattern.finditer(line):
                candidate = rule.extract_candidate(match)
                if _looks_like_placeholder(candidate):
                    continue
                entropy = shannon_entropy(candidate)

                # Filter obviously weak tokens for generic detectors
                if rule.min_entropy > 0.0 and entropy < (rule.min_entropy - 1.0):
                    continue

                evidence_hash = _hash_evidence(candidate)
                dedupe_key = (rule.rule_id, line_number, evidence_hash)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                confidence = _compute_confidence(
                    base_confidence=rule.base_confidence,
                    entropy=entropy,
                    min_entropy=rule.min_entropy,
                )

                findings.append(
                    SecretFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=confidence,
                        file_path=file_path,
                        line_start=line_number,
                        line_end=line_number,
                        evidence_hash=evidence_hash,
                    )
                )

    return findings
