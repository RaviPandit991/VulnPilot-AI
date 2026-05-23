"""Regression tests for the CVE API parser.

Reproduces the production failure observed on 2026-05-23:
    AttributeError: 'str' object has no attribute 'get'
when CIRCL returned a list of bare CVE-ID strings.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from utils import cve_api


class _FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _clear_cache():
    cve_api._cache.clear()
    yield
    cve_api._cache.clear()


def _patched(payload):
    return patch.object(
        cve_api.requests, "get", return_value=_FakeResponse(payload)
    )


def test_list_of_dicts_parses():
    payload = [
        {"id": "CVE-2014-0160", "summary": "Heartbleed", "cvss": 7.5},
        {"id": "CVE-2016-2107", "summary": "Padding oracle", "cvss": 5.9},
    ]
    with _patched(payload):
        out = cve_api.lookup("openbsd", "openssh")
    assert [e.cve_id for e in out] == ["CVE-2014-0160", "CVE-2016-2107"]
    assert out[0].cvss == 7.5
    assert out[0].severity == "HIGH"


def test_list_of_strings_does_not_crash():
    """The original bug: CIRCL returns a list of CVE IDs, not dicts."""
    payload = ["CVE-2021-44228", "CVE-2021-45046"]
    with _patched(payload):
        out = cve_api.lookup("apache", "log4j")
    assert [e.cve_id for e in out] == ["CVE-2021-44228", "CVE-2021-45046"]
    # No score available - severity stays None.
    assert all(e.cvss is None for e in out)


def test_results_wrapper_with_mixed_items():
    payload = {
        "results": [
            "CVE-2017-0144",  # bare string
            {"id": "CVE-2020-0796", "summary": "SMBGhost", "cvss": 10.0},
            42,  # garbage that must be skipped
            {"summary": "no id"},  # dict without id - skipped
        ]
    }
    with _patched(payload):
        out = cve_api.lookup("microsoft", "windows")
    ids = [e.cve_id for e in out]
    assert "CVE-2017-0144" in ids
    assert "CVE-2020-0796" in ids
    assert len(out) == 2  # ints and id-less dicts dropped


def test_nvd_style_nested_payload():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-12345",
                    "descriptions": [
                        {"lang": "en", "value": "Remote code execution"}
                    ],
                },
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8}}
                    ]
                },
            }
        ]
    }
    with _patched(payload):
        out = cve_api.lookup("vendor", "product")
    assert len(out) == 1
    assert out[0].cve_id == "CVE-2023-12345"
    assert out[0].cvss == 9.8
    assert out[0].severity == "CRITICAL"
    assert "Remote code execution" in out[0].summary


def test_http_error_returns_empty_list():
    with patch.object(
        cve_api.requests, "get", return_value=_FakeResponse({}, status=503)
    ):
        out = cve_api.lookup("a", "b")
    assert out == []


def test_invalid_json_returns_empty_list():
    class _BadJson(_FakeResponse):
        def json(self):
            raise ValueError("not json")

    with patch.object(
        cve_api.requests, "get", return_value=_BadJson(None)
    ):
        out = cve_api.lookup("a", "b")
    assert out == []


def test_severity_thresholds():
    assert cve_api._severity_for(9.5) == "CRITICAL"
    assert cve_api._severity_for(7.0) == "HIGH"
    assert cve_api._severity_for(5.0) == "MEDIUM"
    assert cve_api._severity_for(2.0) == "LOW"
    assert cve_api._severity_for(0.0) == "NONE"
    assert cve_api._severity_for(None) is None


def test_unwrap_results_flattens_nested():
    assert cve_api._unwrap_results([1, 2]) == [1, 2]
    assert cve_api._unwrap_results({"results": [1, 2]}) == [1, 2]
    assert cve_api._unwrap_results({"data": [3]}) == [3]
    assert cve_api._unwrap_results({"x": {"y": [9]}}) == [9]
    assert cve_api._unwrap_results(None) == []
    assert cve_api._unwrap_results({}) == []
