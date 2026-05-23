"""CVE lookup helpers.

Default backend is CIRCL (https://cve.circl.lu/) which exposes a free, no-auth
JSON API and supports CPE-based search. NVD support is provided as a fallback.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

from utils.logger import get_logger

log = get_logger(__name__)

_CIRCL_SEARCH = "https://cve.circl.lu/api/search/{vendor}/{product}"
_NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "VulnPilot-AI/0.1 (authorized security testing)"

_cache: dict[str, tuple[float, list["CVEEntry"]]] = {}


@dataclass
class CVEEntry:
    cve_id: str
    summary: str
    cvss: float | None = None
    severity: str | None = None
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def _severity_for(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _circl_lookup(vendor: str, product: str, timeout: float) -> list[CVEEntry]:
    url = _CIRCL_SEARCH.format(vendor=vendor, product=product)
    try:
        resp = requests.get(
            url, headers={"User-Agent": _USER_AGENT}, timeout=timeout
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.warning("CIRCL lookup failed for %s/%s: %s", vendor, product, exc)
        return []

    data = resp.json() or {}
    results = data.get("results") or data.get("data") or []
    out: list[CVEEntry] = []
    for item in results:
        cve_id = item.get("id") or item.get("cveMetadata", {}).get("cveId")
        if not cve_id:
            continue
        cvss = item.get("cvss")
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None
        out.append(
            CVEEntry(
                cve_id=cve_id,
                summary=item.get("summary", "")[:500],
                cvss=cvss,
                severity=_severity_for(cvss),
                references=item.get("references", [])[:5],
                raw=item,
            )
        )
    return out


def lookup(
    vendor: str,
    product: str,
    *,
    cache_seconds: int = 86_400,
    timeout: float = 10.0,
) -> list[CVEEntry]:
    """Return a list of CVEs for the given vendor/product, with simple caching."""
    if not vendor or not product:
        return []

    key = f"{vendor.lower()}::{product.lower()}"
    now = time.time()
    cached = _cache.get(key)
    if cached and now - cached[0] < cache_seconds:
        return cached[1]

    entries = _circl_lookup(vendor.lower(), product.lower(), timeout)
    _cache[key] = (now, entries)
    return entries


def filter_by_version(entries: list[CVEEntry], version: str | None) -> list[CVEEntry]:
    """Loose filter: keep entries whose summary or raw vulnerable-product lists
    mention the version. This is a heuristic - real version comparison should
    use CPE matching."""
    if not version:
        return entries
    needle = version.lower()
    out: list[CVEEntry] = []
    for entry in entries:
        haystacks = [entry.summary.lower()]
        vp = entry.raw.get("vulnerable_product") or []
        if isinstance(vp, list):
            haystacks.extend(str(x).lower() for x in vp)
        if any(needle in h for h in haystacks):
            out.append(entry)
    return out
