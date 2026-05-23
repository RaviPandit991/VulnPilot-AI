"""Map detected services to CVE entries."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from scanner.service_detector import DetectedService
from utils.cve_api import CVEEntry, filter_by_version, lookup
from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ServiceCVEs:
    service: DetectedService
    cves: List[CVEEntry]


def map_services(services: list[DetectedService]) -> list[ServiceCVEs]:
    out: list[ServiceCVEs] = []
    for svc in services:
        try:
            out.append(_map_one(svc))
        except Exception as exc:
            # Never let a single service kill the whole pipeline.
            log.warning(
                "CVE mapping failed for %s:%s/%s (%s) - continuing: %s",
                svc.name, svc.port, svc.protocol, svc.product, exc,
            )
            out.append(ServiceCVEs(service=svc, cves=[]))
    return out


def _map_one(svc: DetectedService) -> ServiceCVEs:
    vendor, product = svc.vendor_product
    if not product:
        return ServiceCVEs(service=svc, cves=[])

    # CIRCL requires a vendor; fall back to product as both for best-effort.
    candidates = lookup(vendor or product, product)
    narrowed = (
        filter_by_version(candidates, svc.version) if svc.version else candidates
    )

    # Take top 10 by CVSS desc to keep noise down.
    narrowed.sort(key=lambda c: (c.cvss or 0.0), reverse=True)
    log.info(
        "Service %s/%s v=%s -> %d CVEs",
        vendor, product, svc.version, len(narrowed),
    )
    return ServiceCVEs(service=svc, cves=narrowed[:10])
