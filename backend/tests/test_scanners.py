import pytest
from app.core.scanners import (
    scan_osint_dns,
    scan_headers_and_tls,
    scan_cors,
    scan_sensitive_paths,
    scan_ports_and_services
)
from app.core.patchgen import PatchGenerator

@pytest.mark.asyncio
async def test_osint_dns_scanner_schema():
    res = await scan_osint_dns("example.com")
    assert res["status"] == "success"
    assert "metadata" in res
    assert "findings" in res
    assert isinstance(res["findings"], list)

@pytest.mark.asyncio
async def test_headers_scanner_schema():
    res = await scan_headers_and_tls("https://example.com", "example.com")
    assert res["status"] == "success"
    assert "metadata" in res
    assert "findings" in res
    assert isinstance(res["findings"], list)

@pytest.mark.asyncio
async def test_cors_scanner_schema():
    res = await scan_cors("https://example.com")
    assert res["status"] == "success"
    assert "metadata" in res
    assert "findings" in res

@pytest.mark.asyncio
async def test_patch_generator():
    findings = [
        {
            "title": "Missing Content-Security-Policy",
            "category": "headers",
            "severity": "MEDIUM",
            "cvss_score": 6.1
        },
        {
            "title": "Permissive CORS Wildcard",
            "category": "cors",
            "severity": "HIGH",
            "cvss_score": 8.0
        }
    ]
    patches = await PatchGenerator.synthesize_all_patches(findings, "testdomain.com")
    assert len(patches) >= 2
    types = [p["patch_type"] for p in patches]
    assert "nginx" in types
    assert "fastapi" in types
    assert any("Content-Security-Policy" in p["diff_content"] for p in patches)
