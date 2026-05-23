"""PDF export using reportlab."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from utils.logger import get_logger

log = get_logger(__name__)


def write_pdf(report: Dict[str, Any], output_dir: str) -> Path:
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
        from reportlab.lib import colors
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("reportlab not installed") from exc

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    target = report["metadata"]["target"].replace("/", "_")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(output_dir) / f"report-{target}-{ts}.pdf"

    doc = SimpleDocTemplate(str(path), pagesize=LETTER)
    styles = getSampleStyleSheet()
    story = []

    md = report["metadata"]
    story.append(Paragraph(f"VulnPilot AI Report - {md['target']}", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Operator: {md['operator']}", styles["Normal"]))
    story.append(Paragraph(f"Mode: {md['mode']}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {md['generated_at']}", styles["Normal"]))
    story.append(Spacer(1, 12))

    s = report["summary"]
    story.append(Paragraph("Summary", styles["Heading2"]))
    story.append(
        Paragraph(
            f"Open services: {s['open_services']} | CVEs: {s['total_cves']}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Services and CVEs", styles["Heading2"]))
    rows = [["Port", "Service", "Product", "Version", "CVE", "CVSS", "Sev"]]
    for svc in report["services"]:
        if not svc["cves"]:
            rows.append([
                svc["port"], svc["name"] or "", svc["product"] or "",
                svc["version"] or "", "-", "-", "-",
            ])
            continue
        for c in svc["cves"]:
            rows.append([
                svc["port"], svc["name"] or "", svc["product"] or "",
                svc["version"] or "", c.get("cve_id"),
                c.get("cvss") or "", c.get("severity") or "",
            ])

    table = Table(rows, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Validation Results", styles["Heading2"]))
    for r in report["validation_results"]:
        story.append(
            Paragraph(
                f"{r['module']} ({r['action']}) -> {r['status']} "
                f"in {r['duration_seconds']:.1f}s",
                styles["Normal"],
            )
        )

    doc.build(story)
    log.info("Wrote PDF report: %s", path)
    return path
