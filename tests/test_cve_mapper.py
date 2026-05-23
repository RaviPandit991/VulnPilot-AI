"""Tests for the CVE mapper's per-service fault tolerance."""
from __future__ import annotations

from unittest.mock import patch

from ai_engine import cve_mapper
from scanner.service_detector import DetectedService
from utils.cve_api import CVEEntry


def _svc(name, product=None, version=None, port=22):
    return DetectedService(
        port=port, name=name, product=product, version=version,
    )


def test_one_failing_service_does_not_kill_others():
    services = [
        _svc("ssh", "openssh", "8.2p1", port=22),
        _svc("http", "apache", "2.4.49", port=80),
        _svc("smb", "samba", "4.5.16", port=445),
    ]

    def fake_lookup(vendor, product, **kw):
        if product == "apache":
            raise RuntimeError("simulated upstream failure")
        return [CVEEntry(cve_id=f"CVE-FAKE-{product}", summary="x", cvss=5.0)]

    with patch.object(cve_mapper, "lookup", side_effect=fake_lookup):
        out = cve_mapper.map_services(services)

    assert len(out) == 3
    # ssh and smb succeeded
    by_port = {o.service.port: o for o in out}
    assert by_port[22].cves and by_port[22].cves[0].cve_id == "CVE-FAKE-openssh"
    assert by_port[445].cves and by_port[445].cves[0].cve_id == "CVE-FAKE-samba"
    # http failed but produced a row with empty cves, not an exception
    assert by_port[80].cves == []


def test_service_without_product_yields_empty_cves():
    services = [_svc("unknown", product=None, port=9999)]
    out = cve_mapper.map_services(services)
    assert len(out) == 1
    assert out[0].cves == []
