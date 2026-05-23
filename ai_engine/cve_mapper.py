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
        vendor, product = svc.vendor_product
        if not product:
            out.append(ServiceCVEs(service=svc, cves=[]))
            continue

        # CIRCL requires a vendor; fall back to product as both for best-effort.
        candidates = lookup(vendor or product, product)
        narrowed = filter_by_version(candidates, svc.version) if svc.version else candidates

        # Take top 10 by CVSS desc to keep noise down.
        narrowed.sort(key=lambda c: (c.cvss or 0.0), reverse=True)
        out.append(ServiceCVEs(service=svc, cves=narrowed[:10]))
        log.info(
            "Service %s/%s v=%s -> %d CVEs",
            vendor, product, svc.version, len(narrowed),
        )
    return out
