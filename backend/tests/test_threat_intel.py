"""
Focused unit tests for app.services.threat_intel (Phase 4).

Every test mocks `requests.get` - no real network call is ever made, and
no database is needed since `get_ip_reputation()` is pure (string in,
dict out). Each test uses its own IP address to avoid interference from
the module-level TTL cache between tests, except the dedicated caching
test, which deliberately reuses one IP to prove the cache is used.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from app.services import threat_intel


@pytest.fixture(autouse=True)
def configured_api_key(monkeypatch):
    """Most tests need a non-empty key so the "not_configured" short-circuit doesn't fire."""
    monkeypatch.setattr(threat_intel.settings, "abuseipdb_api_key", "test-key")


def _mock_response(status_code=200, json_data=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data if json_data is not None else {}
    return response


def test_ok_response_returns_expected_fields():
    payload = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 42,
            "countryName": "United States",
            "countryCode": "US",
            "isp": "Google LLC",
            "domain": "google.com",
            "totalReports": 7,
            "lastReportedAt": "2026-08-01T00:00:00+00:00",
        }
    }
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(200, payload)) as mock_get:
        result = threat_intel.get_ip_reputation("8.8.8.8")

    assert mock_get.called
    assert result["status"] == "ok"
    rep = result["reputation"]
    assert rep["ip_address"] == "8.8.8.8"
    assert rep["abuse_confidence_score"] == 42
    assert rep["country"] == "United States"
    assert rep["isp"] == "Google LLC"
    assert rep["domain"] == "google.com"
    assert rep["total_reports"] == 7
    assert rep["last_reported_at"] == "2026-08-01T00:00:00+00:00"
    assert rep["provider"] == "AbuseIPDB"
    assert "queried_at" in rep
    # Nothing beyond the documented fields leaks through.
    assert set(rep.keys()) == {
        "ip_address", "abuse_confidence_score", "country", "isp", "domain",
        "total_reports", "last_reported_at", "provider", "queried_at",
    }


def test_timeout_maps_to_unavailable():
    with patch.object(threat_intel.requests, "get", side_effect=requests.Timeout()):
        result = threat_intel.get_ip_reputation("8.8.4.4")
    assert result["status"] == "unavailable"


def test_connection_error_maps_to_unavailable():
    with patch.object(threat_intel.requests, "get", side_effect=requests.ConnectionError()):
        result = threat_intel.get_ip_reputation("1.1.1.1")
    assert result["status"] == "unavailable"


def test_generic_request_exception_maps_to_unavailable():
    with patch.object(threat_intel.requests, "get", side_effect=requests.RequestException("boom")):
        result = threat_intel.get_ip_reputation("1.0.0.1")
    assert result["status"] == "unavailable"


def test_rate_limit_response_maps_to_rate_limited():
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(429)):
        result = threat_intel.get_ip_reputation("9.9.9.9")
    assert result["status"] == "rate_limited"


def test_unauthorized_response_maps_to_invalid_api_key():
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(401)):
        result = threat_intel.get_ip_reputation("208.67.222.222")
    assert result["status"] == "invalid_api_key"


def test_forbidden_response_maps_to_invalid_api_key():
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(403)):
        result = threat_intel.get_ip_reputation("208.67.220.220")
    assert result["status"] == "invalid_api_key"


def test_malformed_json_body_maps_to_unavailable_without_raising():
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(200, {"unexpected": "shape"})):
        result = threat_intel.get_ip_reputation("4.4.4.4")
    assert result["status"] == "unavailable"


def test_other_non_200_status_maps_to_unavailable():
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(500)):
        result = threat_intel.get_ip_reputation("5.5.5.5")
    assert result["status"] == "unavailable"


def test_missing_api_key_short_circuits_without_network_call(monkeypatch):
    monkeypatch.setattr(threat_intel.settings, "abuseipdb_api_key", "")
    with patch.object(threat_intel.requests, "get") as mock_get:
        result = threat_intel.get_ip_reputation("6.6.6.6")
    assert result["status"] == "not_configured"
    mock_get.assert_not_called()


def test_invalid_ip_short_circuits_without_network_call():
    with patch.object(threat_intel.requests, "get") as mock_get:
        result = threat_intel.get_ip_reputation("not-an-ip")
    assert result["status"] == "invalid_ip"
    mock_get.assert_not_called()


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", "::1"])
def test_private_or_local_ip_short_circuits_without_network_call(ip):
    with patch.object(threat_intel.requests, "get") as mock_get:
        result = threat_intel.get_ip_reputation(ip)
    assert result["status"] == "private_ip"
    mock_get.assert_not_called()


def test_successful_lookup_is_cached_and_provider_called_once():
    payload = {"data": {"ipAddress": "3.3.3.3", "abuseConfidenceScore": 0}}
    with patch.object(threat_intel.requests, "get", return_value=_mock_response(200, payload)) as mock_get:
        first = threat_intel.get_ip_reputation("3.3.3.3")
        second = threat_intel.get_ip_reputation("3.3.3.3")

    assert first["status"] == "ok"
    assert second["status"] == "ok"
    assert mock_get.call_count == 1
