from __future__ import annotations

import json
import math
import re
import time
import tomllib
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import URLError
from urllib.request import Request, urlopen

OSV_DEFAULT_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


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


def parse_cvss_vector_score(vector: str) -> float | None:
    """Parse CVSS v3.x vector string or numeric score and return base score float."""
    if not vector:
        return None

    try:
        return float(vector)
    except ValueError:
        pass

    # Process CVSS 3.x vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    parts = dict(item.split(":", 1) for item in vector.split("/") if ":" in item)
    if "AV" not in parts or "AC" not in parts:
        return None

    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_map = {"L": 0.77, "H": 0.44}
    ui_map = {"N": 0.85, "R": 0.62}
    scope_changed = parts.get("S") == "C"

    pr_val = parts.get("PR", "N")
    if scope_changed:
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
    else:
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}

    cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}

    av = av_map.get(parts.get("AV", "N"), 0.85)
    ac = ac_map.get(parts.get("AC", "L"), 0.77)
    pr = pr_map.get(pr_val, 0.85)
    ui = ui_map.get(parts.get("UI", "N"), 0.85)
    c = cia_map.get(parts.get("C", "N"), 0.0)
    i = cia_map.get(parts.get("I", "N"), 0.0)
    a = cia_map.get(parts.get("A", "N"), 0.0)

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0

    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if not scope_changed:
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    rounded = math.ceil(round(score, 4) * 10) / 10
    return min(max(rounded, 0.0), 10.0)


def _map_cvss_to_level(cvss_score: str) -> str:
    numeric = parse_cvss_vector_score(cvss_score)
    if numeric is None:
        return "unknown"

    if numeric >= 9.0:
        return "critical"
    if numeric >= 7.0:
        return "high"
    if numeric >= 4.0:
        return "medium"
    return "low"


def _read_severity(vulnerability: dict[str, Any]) -> str:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        severity = database_specific.get("severity")
        if isinstance(severity, str) and severity:
            return severity.lower()

    severities = vulnerability.get("severity")
    if isinstance(severities, list) and severities:
        for item in severities:
            if isinstance(item, dict):
                score = item.get("score")
                if isinstance(score, str):
                    level = _map_cvss_to_level(score)
                    if level != "unknown":
                        return level

    return "unknown"


def _read_summary(vulnerability: dict[str, Any]) -> str:
    summary = vulnerability.get("summary")
    if isinstance(summary, str) and summary:
        return summary
    details = vulnerability.get("details")
    if isinstance(details, str) and details:
        return details[:240]
    return "No summary available"


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


def parse_requirements_txt(content: str) -> list[PackageRef]:
    """Parse requirements.txt supporting pinned and range versions."""
    packages: list[PackageRef] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line.startswith(("-r", "--", "git+", "http://", "https://")):
            continue

        # Strip inline comments and environment markers
        line = line.split("#", 1)[0].strip()
        line = line.split(";", 1)[0].strip()

        # Match package name and version specifiers
        # Handles: package==1.0.0, package>=2.0, package~=1.2, package[extra]==1.0
        match = re.match(
            r"^([A-Za-z0-9_\-\.]+)(?:\[[^\]]*\])?\s*([=><~^!]+)?\s*([A-Za-z0-9_\-\.]+)?",
            line,
        )
        if not match:
            continue

        name = match.group(1).strip()
        version = match.group(3)

        if not name:
            continue

        version_str = version.strip() if version else "0.0.0"
        packages.append(PackageRef(name=name, version=version_str, ecosystem="PyPI"))

    return packages


def parse_poetry_lock(content: str) -> list[PackageRef]:
    """Parse poetry.lock extracting package names and versions."""
    if not content:
        return []

    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    raw_packages = data.get("package", [])
    packages: list[PackageRef] = []
    for pkg in raw_packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            packages.append(PackageRef(name=name, version=version, ecosystem="PyPI"))

    return packages


def parse_package_lock_json(content: str) -> list[PackageRef]:
    """Parse package-lock.json v1, v2, and v3 formats."""
    if not content.strip():
        return []

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


class OsvClient:
    def __init__(
        self,
        *,
        api_url: str = OSV_DEFAULT_URL,
        batch_url: str = OSV_BATCH_URL,
        timeout_seconds: float = 5.0,
        max_retries: int = 2,
        backoff_seconds: float = 0.2,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self._api_url = api_url
        self._batch_url = batch_url
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._backoff_seconds = backoff_seconds
        self._sleep_fn = sleep_fn

    def query(self, package: PackageRef) -> list[VulnerabilityMatch]:
        payload = {
            "package": {"name": package.name, "ecosystem": package.ecosystem},
            "version": package.version,
        }

        response_json = self._query_with_retry(self._api_url, payload)
        vulnerabilities = response_json.get("vulns", []) if isinstance(response_json, dict) else []
        if not isinstance(vulnerabilities, list):
            return []

        return self._extract_findings(package, vulnerabilities)

    def query_batch(self, packages: list[PackageRef]) -> list[VulnerabilityMatch]:
        """Query multiple packages in a single batch request using /v1/querybatch."""
        if not packages:
            return []

        batch_payload = {
            "queries": [
                {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}, "version": pkg.version}
                for pkg in packages
            ]
        }

        response_json = self._query_with_retry(self._batch_url, batch_payload)
        results = response_json.get("results", []) if isinstance(response_json, dict) else []

        if isinstance(results, list) and len(results) == len(packages):
            all_findings: list[VulnerabilityMatch] = []
            for pkg, result in zip(packages, results):
                if isinstance(result, dict):
                    vulns = result.get("vulns", [])
                    if isinstance(vulns, list):
                        all_findings.extend(self._extract_findings(pkg, vulns))
            return all_findings

        # Fallback to serial queries if batch API returned unexpected payload
        fallback_findings: list[VulnerabilityMatch] = []
        for pkg in packages:
            fallback_findings.extend(self.query(pkg))
        return fallback_findings

    def _extract_findings(
        self, package: PackageRef, vulnerabilities: list[Any]
    ) -> list[VulnerabilityMatch]:
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

    def _query_with_retry(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        attempts = self._max_retries + 1

        for attempt in range(1, attempts + 1):
            try:
                return _http_post_json(
                    url=url,
                    payload=payload,
                    timeout_seconds=self._timeout_seconds,
                )
            except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                if attempt == attempts:
                    return {}

                backoff = self._backoff_seconds * attempt
                self._sleep_fn(backoff)

        return {}


def audit_dependencies(
    *,
    requirements_content: str = "",
    package_lock_content: str = "",
    poetry_lock_content: str = "",
    osv_client: OsvClient,
) -> list[VulnerabilityMatch]:
    packages = [
        *parse_requirements_txt(requirements_content),
        *parse_package_lock_json(package_lock_content),
        *parse_poetry_lock(poetry_lock_content),
    ]

    findings: list[VulnerabilityMatch] = []
    for package in packages:
        findings.extend(osv_client.query(package))
    return findings
