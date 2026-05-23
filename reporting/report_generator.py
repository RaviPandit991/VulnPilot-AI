"""JSON / Markdown report generation."""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ai_engine.cve_mapper import ServiceCVEs
from ai_engine.decision_engine import ServicePlan
from exploit_engine.metasploit_client import ModuleResult
from utils.logger import get_logger

log = get_logger(__name__)


def _to_dict(obj: Any) -> Any:
    if is_dataclass(obj):
        return {k: _to_dict(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    return obj


def build_report(
    target: str,
    operator: str,
    mode: str,
    mapped: List[ServiceCVEs],
    plans: List[ServicePlan],
    results: List[ModuleResult],
) -> Dict[str, Any]:
    return {
        "metadata": {
            "tool": "VulnPilot AI",
            "version": "0.1.0",
            "target": target,
            "operator": operator,
            "mode": mode,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "services": [
            {
                "port": m.service.port,
                "protocol": m.service.protocol,
                "name": m.service.name,
                "product": m.service.product,
                "version": m.service.version,
                "cves": [_to_dict(c) for c in m.cves],
            }
            for m in mapped
        ],
        "plans": [
            {
                "port": p.service.port,
                "service": p.service.name,
                "cve_count": p.cve_count,
                "recommendations": [_to_dict(r) for r in p.recommendations],
            }
            for p in plans
        ],
        "validation_results": [_to_dict(r) for r in results],
        "summary": _summarize(mapped, results),
    }


def _summarize(mapped: List[ServiceCVEs], results: List[ModuleResult]) -> Dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for entry in mapped:
        for cve in entry.cves:
            sev = (cve.severity or "informational").lower()
            counts[sev] = counts.get(sev, 0) + 1
    return {
        "open_services": len(mapped),
        "total_cves": sum(counts.values()),
        "severity_counts": counts,
        "validation_status_counts": _count_statuses(results),
    }


def _count_statuses(results: List[ModuleResult]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in results:
        out[r.status] = out.get(r.status, 0) + 1
    return out


def write_json(report: Dict[str, Any], output_dir: str) -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    target = report["metadata"]["target"].replace("/", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(output_dir) / f"report-{target}-{ts}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("Wrote JSON report: %s", path)
    return path


def write_markdown(report: Dict[str, Any], output_dir: str) -> Path:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    target = report["metadata"]["target"].replace("/", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(output_dir) / f"report-{target}-{ts}.md"

    lines: list[str] = []
    md = report["metadata"]
    lines.append(f"# VulnPilot AI Report - {md['target']}")
    lines.append("")
    lines.append(f"- Operator: `{md['operator']}`")
    lines.append(f"- Mode: `{md['mode']}`")
    lines.append(f"- Generated: {md['generated_at']}")
    lines.append("")
    lines.append("## Summary")
    s = report["summary"]
    lines.append(f"- Open services: **{s['open_services']}**")
    lines.append(f"- CVEs: **{s['total_cves']}** "
                 f"(C:{s['severity_counts'].get('critical',0)} "
                 f"H:{s['severity_counts'].get('high',0)} "
                 f"M:{s['severity_counts'].get('medium',0)} "
                 f"L:{s['severity_counts'].get('low',0)})")
    lines.append("")
    lines.append("## Services")
    for svc in report["services"]:
        lines.append(
            f"### {svc['port']}/{svc['protocol']} - {svc['name'] or '?'} "
            f"{svc['product'] or ''} {svc['version'] or ''}".rstrip()
        )
        if svc["cves"]:
            lines.append("")
            lines.append("| CVE | CVSS | Severity | Summary |")
            lines.append("|-----|------|----------|---------|")
            for c in svc["cves"]:
                summary = (c.get("summary") or "").replace("|", "\\|")[:140]
                lines.append(
                    f"| {c.get('cve_id')} | {c.get('cvss') or ''} | "
                    f"{c.get('severity') or ''} | {summary} |"
                )
        else:
            lines.append("_No CVEs matched._")
        lines.append("")

    lines.append("## Validation Results")
    for r in report["validation_results"]:
        lines.append(
            f"- `{r['module']}` ({r['action']}) -> **{r['status']}** "
            f"in {r['duration_seconds']:.1f}s"
        )
    lines.append("")
    lines.append("## Remediation")
    lines.append(_remediation_block(report))

    path.write_text("\n".join(lines), encoding="utf-8")
    log.info("Wrote Markdown report: %s", path)
    return path


def _remediation_block(report: Dict[str, Any]) -> str:
    tips = [
        "- Patch identified services to the latest stable version.",
        "- Disable weak ciphers/algorithms identified by SSH/TLS scanners.",
        "- Restrict exposed management ports (RDP, SMB) to VPN-only.",
        "- Enforce strong authentication and rotate default credentials.",
        "- Re-run VulnPilot AI after remediation to confirm fixes.",
    ]
    return "\n".join(tips)
