from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.scanner.dependencies import PackageRef


def _format_purl(package: PackageRef) -> str:
    eco = package.ecosystem.lower()
    if "pypi" in eco or "python" in eco:
        return f"pkg:pypi/{package.name.lower()}@{package.version}"
    if "npm" in eco or "node" in eco:
        return f"pkg:npm/{package.name}@{package.version}"
    return f"pkg:generic/{package.name}@{package.version}"


def generate_cyclonedx_sbom(
    packages: list[PackageRef],
    *,
    project_name: str = "project",
    project_version: str = "0.1.0",
) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 compliant Software Bill of Materials (SBOM) dictionary."""
    timestamp = datetime.now(UTC).isoformat()
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    components = []
    seen: set[str] = set()

    for pkg in packages:
        purl = _format_purl(pkg)
        if purl in seen:
            continue
        seen.add(purl)

        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": pkg.name,
                "version": pkg.version,
                "purl": purl,
                "scope": "required",
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "repo-secret-auditor",
                    "name": "repo-secret-auditor",
                    "version": "0.2.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:generic/{project_name}@{project_version}",
                "name": project_name,
                "version": project_version,
            },
        },
        "components": components,
    }


def write_cyclonedx_sbom(
    packages: list[PackageRef],
    output_path: Path,
    *,
    project_name: str = "project",
    project_version: str = "0.1.0",
) -> None:
    """Write CycloneDX 1.5 SBOM JSON to disk."""
    data = generate_cyclonedx_sbom(
        packages,
        project_name=project_name,
        project_version=project_version,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
