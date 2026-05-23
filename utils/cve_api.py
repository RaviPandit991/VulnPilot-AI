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


def _coerce_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _entry_from_dict(item: dict) -> CVEEntry | None:
    """Build a CVEEntry from any of the dict shapes CIRCL has used over time."""
    cve_id = (
        item.get("id")
        or (item.get("cveMetadata") or {}).get("cveId")
        or (item.get("cve") or {}).get("id")
        or item.get("CVE_ID")
    )
    if not cve_id:
        return None

    summary = (
        item.get("summary")
        or item.get("description")
        or _extract_nested_summary(item)
        or ""
    )

    cvss = _coerce_float(item.get("cvss")) or _extract_nested_cvss(item)

    refs = item.get("references") or []
    if isinstance(refs, list):
        refs = [str(r) for r in refs[:5]]
    else:
        refs = []

    return CVEEntry(
        cve_id=str(cve_id),
        summary=str(summary)[:500],
        cvss=cvss,
        severity=_severity_for(cvss),
        references=refs,
        raw=item,
    )


def _extract_nested_summary(item: dict) -> str | None:
    """Pull description text out of NVD-style nested structures."""
    cve = item.get("cve")
    if isinstance(cve, dict):
        desc = cve.get("descriptions") or cve.get("description") or {}
        if isinstance(desc, dict):
            data = desc.get("description_data") or []
            if data and isinstance(data, list) and isinstance(data[0], dict):
                return data[0].get("value")
        if isinstance(desc, list) and desc and isinstance(desc[0], dict):
            return desc[0].get("value")
    return None


def _extract_nested_cvss(item: dict) -> float | None:
    """Find a CVSS score in any of the common nested shapes."""
    for key in ("cvss3", "cvss2"):
        v = _coerce_float(item.get(key))
        if v is not None:
            return v
    metrics = item.get("metrics") or {}
    if isinstance(metrics, dict):
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(k) or []
            if arr and isinstance(arr, list) and isinstance(arr[0], dict):
                inner = arr[0].get("cvssData") or {}
                v = _coerce_float(inner.get("baseScore"))
                if v is not None:
                    return v
    return None


def _unwrap_results(data: Any) -> list:
    """Return a flat list of CVE items from whatever shape the API returned."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "data", "vulnerabilities", "cves"):
            v = data.get(key)
            if isinstance(v, list):
                return v
        for v in data.values():
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                inner = _unwrap_results(v)
                if inner:
                    return inner
    return []


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

    try:
        data = resp.json()
    except ValueError:
        log.warning("CIRCL returned non-JSON for %s/%s", vendor, product)
        return []

    # CIRCL / Vulnerability-Lookup has shipped multiple shapes over time:
    #   * list of dicts (each is a full CVE record)
    #   * list of strings (just CVE IDs)
    #   * {"results": [...]} or {"data": [...]} wrapping either of the above
    #   * NVD-style {"vulnerabilities": [{"cve": {...}}]}
    # We normalize all of them.
    results = _unwrap_results(data)

    out: list[CVEEntry] = []
    skipped = 0
    for item in results:
        try:
            if isinstance(item, str):
                # API returned a bare CVE ID. Keep it as a minimal entry so
                # the operator at least knows it exists.
                out.append(CVEEntry(cve_id=item, summary=""))
            elif isinstance(item, dict):
                entry = _entry_from_dict(item)
                if entry is not None:
                    out.append(entry)
                else:
                    skipped += 1
            else:
                skipped += 1
        except Exception as exc:  # never let one bad row kill the lookup
            log.debug("Skipped malformed CVE row for %s/%s: %s",
                      vendor, product, exc)
            skipped += 1

    if skipped:
        log.debug("Skipped %d malformed rows for %s/%s",
                  skipped, vendor, product)
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
