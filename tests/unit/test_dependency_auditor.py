from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, cast
from unittest.mock import patch
from urllib.error import URLError

from app.scanner.dependencies import (
    OsvClient,
    PackageRef,
    _map_cvss_to_level,
    audit_dependencies,
    parse_cvss_vector_score,
    parse_package_lock_json,
    parse_poetry_lock,
    parse_requirements_txt,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "dependencies"


def _read_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text(encoding="utf-8")


def test_parse_requirements_txt_extracts_pinned_packages() -> None:
    parsed = parse_requirements_txt(_read_fixture("requirements_sample.txt"))

    assert [(item.name, item.version, item.ecosystem) for item in parsed] == [
        ("fastapi", "0.116.0", "PyPI"),
        ("requests", "2.32.3", "PyPI"),
    ]


def test_parse_package_lock_json_extracts_dependencies() -> None:
    parsed = parse_package_lock_json(_read_fixture("package-lock.sample.json"))

    as_set = {(item.name, item.version, item.ecosystem) for item in parsed}
    assert as_set == {
        ("lodash", "4.17.20", "npm"),
        ("express", "4.18.3", "npm"),
    }


def test_osv_client_returns_controlled_cve_fixture() -> None:
    def fake_response(_: object, timeout: float) -> _FakeHttpResponse:
        assert timeout == 5.0
        return _FakeHttpResponse(
            json.dumps(
                {
                    "vulns": [
                        {
                            "id": "CVE-2026-12345",
                            "summary": "Controlled fixture vulnerability",
                            "database_specific": {"severity": "HIGH"},
                            "references": [{"url": "https://osv.dev/vulnerability/CVE-2026-12345"}],
                            "affected": [
                                {
                                    "ranges": [
                                        {"events": [{"introduced": "0"}, {"fixed": "0.117.0"}]}
                                    ]
                                }
                            ],
                        }
                    ]
                }
            )
        )

    client = OsvClient()
    package = PackageRef(name="fastapi", version="0.116.0", ecosystem="PyPI")

    with _patch_urlopen(fake_response):
        results = client.query(package)

    assert len(results) == 1
    result = results[0]
    assert result.vuln_id == "CVE-2026-12345"
    assert result.severity == "high"
    assert result.fixed_version == "0.117.0"


def test_osv_client_handles_network_errors_with_retry() -> None:
    call_count: dict[str, int] = {"tries": 0}
    sleep_calls: list[float] = []

    def failing_response(_: object, timeout: float) -> _FakeHttpResponse:
        assert timeout == 1.5
        call_count["tries"] = call_count["tries"] + 1
        raise URLError("timeout")

    client = OsvClient(
        timeout_seconds=1.5, max_retries=2, backoff_seconds=0.1, sleep_fn=sleep_calls.append
    )
    package = PackageRef(name="requests", version="2.32.3", ecosystem="PyPI")

    with _patch_urlopen(failing_response):
        results = client.query(package)

    assert results == []
    assert call_count["tries"] == 3
    assert sleep_calls == [0.1, 0.2]


def test_audit_dependencies_aggregates_python_and_npm_results() -> None:
    sample_requirements = "fastapi==0.116.0"
    sample_package_lock = json.dumps(
        {
            "name": "x",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
            },
        }
    )

    def mixed_response(request: object, timeout: float) -> _FakeHttpResponse:
        assert timeout == 5.0
        request_with_data = cast(Any, request) if hasattr(request, "data") else None
        if request_with_data is None:
            return _FakeHttpResponse(json.dumps({"vulns": []}))

        body = json.loads(request_with_data.data.decode("utf-8"))
        package_name = body["package"]["name"]
        vuln_map = {
            "fastapi": "CVE-2026-12345",
            "lodash": "CVE-2021-23337",
        }

        if package_name not in vuln_map:
            return _FakeHttpResponse(json.dumps({"vulns": []}))

        return _FakeHttpResponse(
            json.dumps(
                {
                    "vulns": [
                        {
                            "id": vuln_map[package_name],
                            "summary": "Fixture advisory",
                            "database_specific": {"severity": "MEDIUM"},
                            "affected": [],
                            "references": [],
                        }
                    ]
                }
            )
        )

    with _patch_urlopen(mixed_response):
        findings = audit_dependencies(
            requirements_content=sample_requirements,
            package_lock_content=sample_package_lock,
            osv_client=OsvClient(),
        )

    assert {item.vuln_id for item in findings} == {"CVE-2026-12345", "CVE-2021-23337"}
 
 
def test_parse_cvss_vector_score_calculates_critical_score() -> None:
    critical_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    score = parse_cvss_vector_score(critical_vector)
    assert score == 9.8
    assert _map_cvss_to_level(critical_vector) == "critical"

    medium_vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"
    med_score = parse_cvss_vector_score(medium_vector)
    assert med_score is not None and 2.0 <= med_score <= 4.0
    assert _map_cvss_to_level(medium_vector) == "low"

    # Numeric score string
    assert parse_cvss_vector_score("7.5") == 7.5
    assert _map_cvss_to_level("7.5") == "high"


def test_parse_requirements_txt_supports_range_specifiers() -> None:
    content = """
    # Comments should be ignored
    flask>=2.3.0
    requests~=2.28.0; python_version > '3.8'
    uvicorn[standard]<=0.34.0
    pydantic==2.5.0
    """
    packages = parse_requirements_txt(content)
    pkg_map = {p.name: p.version for p in packages}
    assert pkg_map["flask"] == "2.3.0"
    assert pkg_map["requests"] == "2.28.0"
    assert pkg_map["uvicorn"] == "0.34.0"
    assert pkg_map["pydantic"] == "2.5.0"


def test_parse_poetry_lock_extracts_packages() -> None:
    sample_poetry = """
    [[package]]
    name = "certifi"
    version = "2024.2.2"
    description = "Python package for providing Mozilla's CA Bundle."
    optional = false
    python-versions = ">=3.6"

    [[package]]
    name = "urllib3"
    version = "2.2.1"
    description = "HTTP library with thread-safe connection pooling, file post, and more."
    optional = false
    python-versions = ">=3.8"
    """
    packages = parse_poetry_lock(sample_poetry)
    assert len(packages) == 2
    assert packages[0] == PackageRef(name="certifi", version="2024.2.2", ecosystem="PyPI")
    assert packages[1] == PackageRef(name="urllib3", version="2.2.1", ecosystem="PyPI")


def test_osv_client_query_batch_returns_matches() -> None:
    def batch_response(request: object, timeout: float) -> _FakeHttpResponse:
        return _FakeHttpResponse(
            json.dumps(
                {
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "GHSA-1234",
                                    "summary": "Sample vuln",
                                    "database_specific": {"severity": "CRITICAL"},
                                    "references": [],
                                    "affected": [],
                                }
                            ]
                        }
                    ]
                }
            )
        )

    client = OsvClient()
    pkgs = [PackageRef(name="requests", version="2.0.0", ecosystem="PyPI")]
    with _patch_urlopen(batch_response):
        matches = client.query_batch(pkgs)

    assert len(matches) == 1
    assert matches[0].vuln_id == "GHSA-1234"
    assert matches[0].severity == "critical"


class _FakeHttpResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload.encode("utf-8")


class _patch_urlopen:
    def __init__(self, fake_urlopen: Callable[[object, float], _FakeHttpResponse]) -> None:
        self._fake_urlopen = fake_urlopen
        self._patcher: Any = None

    def __enter__(self) -> None:
        self._patcher = patch("app.scanner.dependencies.urlopen", self._fake_urlopen)
        self._patcher.start()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._patcher is not None:
            self._patcher.stop()
