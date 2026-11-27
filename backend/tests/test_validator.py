import pytest
from app.core.validator import validate_and_normalize_target, TargetValidationError

def test_valid_public_domain():
    url, host, ip = validate_and_normalize_target("example.com")
    assert url == "https://example.com"
    assert host == "example.com"
    assert ip is not None

def test_valid_public_https_url():
    url, host, ip = validate_and_normalize_target("https://example.com/test")
    assert url == "https://example.com/test"
    assert host == "example.com"

def test_blocked_loopback_ip():
    with pytest.raises(TargetValidationError) as exc:
        validate_and_normalize_target("http://127.0.0.1:8080", allow_local_override=False)
    assert "Blocked SSRF/Private Target" in str(exc.value) or "blocked" in str(exc.value)

def test_blocked_rfc1918_private_ip():
    with pytest.raises(TargetValidationError) as exc:
        validate_and_normalize_target("http://192.168.1.1", allow_local_override=False)
    assert "Blocked SSRF/Private Target" in str(exc.value)

def test_blocked_cloud_metadata():
    with pytest.raises(TargetValidationError) as exc:
        validate_and_normalize_target("http://169.254.169.254/latest/meta-data/", allow_local_override=False)
    assert "Blocked SSRF/Private Target" in str(exc.value) or "blocked" in str(exc.value)

def test_allowed_local_target_when_flag_enabled():
    url, host, ip = validate_and_normalize_target("http://127.0.0.1:8000", allow_local_override=True)
    assert host == "127.0.0.1"
    assert ip == "127.0.0.1"
