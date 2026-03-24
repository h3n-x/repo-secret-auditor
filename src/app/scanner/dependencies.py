from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

OSV_DEFAULT_URL = "https://api.osv.dev/v1/query"


@dataclass(frozen=True, slots=True)
class PackageRef:
    name: str
    version: str
    ecosystem: str


@dataclass(frozen=True, slots=True)
class VulnerabilityMatch:
    vuln_id: str
    summary: str
    severity: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    advisory_url: str | None


def parse_requirements_txt(content: str) -> list[PackageRef]:
    packages: list[PackageRef] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--", "git+", "http://", "https://")):
            continue

        if "==" not in line:
            continue

        left, right = line.split("==", maxsplit=1)
        name = left.split("[", maxsplit=1)[0].strip()
        version = right.split(";", maxsplit=1)[0].strip()

        if not name or not version:
            continue

        packages.append(PackageRef(name=name, version=version, ecosystem="PyPI"))

    return packages


def parse_package_lock_json(content: str) -> list[PackageRef]:
    payload = json.loads(content)
    packages: dict[tuple[str, str], PackageRef] = {}

    for package_name, package_version in _extract_packages_from_package_lock(payload):
        key = (package_name, package_version)
        packages[key] = PackageRef(name=package_name, version=package_version, ecosystem="npm")

    return list(packages.values())


def _extract_packages_from_package_lock(payload: dict[str, Any]) -> list[tuple[str, str]]:
    extracted: list[tuple[str, str]] = []

    modern_packages = payload.get("packages")
    if isinstance(modern_packages, dict):
        for package_path, package_info in modern_packages.items():
            if not package_path.startswith("node_modules/"):
                continue
            if not isinstance(package_info, dict):
                continue

            package_name = package_path.removeprefix("node_modules/")
            package_version = package_info.get("version")

            if isinstance(package_version, str) and package_version:
                extracted.append((package_name, package_version))

    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        extracted.extend(_walk_legacy_dependencies(dependencies))

    return extracted


def _walk_legacy_dependencies(tree: dict[str, Any]) -> list[tuple[str, str]]:
    collected: list[tuple[str, str]] = []

    for package_name, package_info in tree.items():
        if not isinstance(package_info, dict):
            continue

        package_version = package_info.get("version")
        if isinstance(package_version, str) and package_version:
            collected.append((package_name, package_version))

        nested = package_info.get("dependencies")
        if isinstance(nested, dict):
            collected.extend(_walk_legacy_dependencies(nested))

    return collected


class OsvClient:
    def __init__(
        self,
        *,
        api_url: str = OSV_DEFAULT_URL,
        timeout_seconds: float = 5.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.2,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api_url = api_url
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._sleep_fn = sleep_fn

    def query(self, package: PackageRef) -> list[VulnerabilityMatch]:
        payload = {
            "package": {"name": package.name, "ecosystem": package.ecosystem},
            "version": package.version,
        }

        response_json = self._query_with_retry(payload)
        vulnerabilities = response_json.get("vulns", []) if isinstance(response_json, dict) else []
        if not isinstance(vulnerabilities, list):
            return []

        findings: list[VulnerabilityMatch] = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            vuln_id = vulnerability.get("id")
            if not isinstance(vuln_id, str) or not vuln_id:
                continue

            findings.append(
                VulnerabilityMatch(
                    vuln_id=vuln_id,
                    summary=_read_summary(vulnerability),
                    severity=_read_severity(vulnerability),
                    package_name=package.name,
                    installed_version=package.version,
                    fixed_version=_read_fixed_version(vulnerability),
                    advisory_url=_read_advisory_url(vulnerability),
                )
            )

        return findings

    def _query_with_retry(self, payload: dict[str, Any]) -> dict[str, Any]:
        attempts = self._max_retries + 1

        for attempt in range(1, attempts + 1):
            try:
                return _http_post_json(
                    url=self._api_url,
                    payload=payload,
                    timeout_seconds=self._timeout_seconds,
                )
            except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                if attempt == attempts:
                    return {}

                backoff = self._backoff_seconds * attempt
                self._sleep_fn(backoff)

        return {}


def _http_post_json(url: str, payload: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    request = Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read().decode("utf-8")
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


def _read_summary(vulnerability: dict[str, Any]) -> str:
    summary = vulnerability.get("summary")
    if isinstance(summary, str) and summary:
        return summary
    details = vulnerability.get("details")
    if isinstance(details, str) and details:
        return details[:240]
    return "No summary available"


def _read_severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity:
            return severity.lower()

    severities = vulnerability.get("severity")
    if isinstance(severities, list) and severities:
        first = severities[0]
        if isinstance(first, dict):
            kind = first.get("type")
            score = first.get("score")
            if kind == "CVSS_V3" and isinstance(score, str):
                return _map_cvss_to_level(score)

    return "unknown"


def _read_fixed_version(vulnerability: dict[str, Any]) -> str | None:
    affected = vulnerability.get("affected")
    if not isinstance(affected, list):
        return None

    for item in affected:
        if not isinstance(item, dict):
            continue
        ranges = item.get("ranges")
        if not isinstance(ranges, list):
            continue
        for affected_range in ranges:
            if not isinstance(affected_range, dict):
                continue
            events = affected_range.get("events")
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                fixed = event.get("fixed")
                if isinstance(fixed, str) and fixed:
                    return fixed

    return None


def _read_advisory_url(vulnerability: dict[str, Any]) -> str | None:
    references = vulnerability.get("references")
    if not isinstance(references, list):
        return None

    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        if isinstance(url, str) and url:
            return url

    return None


def _map_cvss_to_level(cvss_score: str) -> str:
    try:
        numeric = float(cvss_score)
    except ValueError:
        return "unknown"

    if numeric >= 9.0:
        return "critical"
    if numeric >= 7.0:
        return "high"
    if numeric >= 4.0:
        return "medium"
    return "low"


def audit_dependencies(
    *,
    requirements_content: str,
    package_lock_content: str,
    osv_client: OsvClient,
) -> list[VulnerabilityMatch]:
    packages = [
        *parse_requirements_txt(requirements_content),
        *parse_package_lock_json(package_lock_content),
    ]

    findings: list[VulnerabilityMatch] = []
    for package in packages:
        findings.extend(osv_client.query(package))
    return findings
