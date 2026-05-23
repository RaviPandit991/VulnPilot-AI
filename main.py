"""VulnPilot AI - CLI entry point and pipeline orchestrator.

Workflow:
    Target -> Port Scan -> Service Detection -> CVE Mapping
           -> AI Recommender -> Safe Module Selection
           -> Metasploit Validation -> Report
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from typing import List, Optional

from ai_engine import cve_mapper, decision_engine
from configs.settings import get_settings
from database.db import init_db, session_scope
from database.models import ExploitRun, Scan, Service, Vulnerability
from exploit_engine import metasploit_client, module_selector
from exploit_engine.metasploit_client import (
    MetasploitClient,
    MetasploitDisabled,
    ModuleResult,
)
from reporting import report_generator
from scanner import nmap_scanner, rustscan_scanner
from utils.auth_check import AuthorizationError, require_authorization
from utils.logger import get_logger, setup_logging

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def run_pipeline(
    target: str,
    *,
    operator: str,
    mode: str = "safe",
    scan_id: Optional[int] = None,
    engine: Optional[str] = None,
    auth_ref: Optional[str] = None,
    nmap_args: Optional[str] = None,
) -> dict:
    """Execute the full scan pipeline. Returns the generated report dict.

    Any exception inside a stage is caught and the scan row is marked
    `error` (or `partial` if at least the recon stage produced data).
    """
    settings = get_settings()
    engine = engine or settings.get("scanner.engine", "nmap")
    nmap_args = nmap_args or settings.get(
        "scanner.nmap_args", "-sV -sC -T4 --top-ports 1000"
    )

    # 1) Persist scan row (or update existing one queued by the dashboard)
    with session_scope() as s:
        if scan_id:
            scan_row = s.get(Scan, scan_id)
            if not scan_row:
                raise ValueError(f"Scan id {scan_id} not found")
            scan_row.status = "running"
        else:
            scan_row = Scan(
                target=target, operator=operator, mode=mode,
                status="running", authorization_ref=auth_ref,
            )
            s.add(scan_row)
            s.flush()
            scan_id = scan_row.id

    services: list = []
    mapped: list = []
    plans: list = []
    results: list[ModuleResult] = []
    final_status = "complete"
    error_note: str | None = None

    try:
        # 2) Recon
        log.info("[1/5] Port + service scan (%s)", engine)
        if engine == "rustscan":
            services = rustscan_scanner.scan(
                target, settings.get("scanner.rustscan_args", "")
            )
        else:
            services = nmap_scanner.scan(target, nmap_args)

        # 3) CVE mapping
        log.info("[2/5] CVE mapping for %d services", len(services))
        mapped = cve_mapper.map_services(services)

        # 4) Decision engine
        log.info("[3/5] Building safe-validation plan")
        plans = decision_engine.build_plan(mapped)
        if settings.get("ai.use_local_llm"):
            plans = decision_engine.llm_augment(plans, settings.get("ai.llm_model"))

        # 5) Module selection (allowlist enforced)
        selections = module_selector.select(target, plans)
        log.info("[4/5] %d safe modules selected", len(selections))

        # 6) Metasploit validation (opt-in)
        msf_cfg = settings.section("metasploit")
        if msf_cfg.get("enabled"):
            try:
                client = MetasploitClient(
                    host=msf_cfg.get("host", "127.0.0.1"),
                    port=int(msf_cfg.get("port", 55553)),
                    username=msf_cfg.get("username", "msf"),
                    password=msf_cfg.get("password", "msf"),
                    ssl=bool(msf_cfg.get("ssl", False)),
                    enabled=True,
                )
                client.connect()
                results = metasploit_client.run_all(client, selections)
            except MetasploitDisabled as exc:
                log.warning("Skipping Metasploit step: %s", exc)
            except Exception:
                log.exception("Metasploit validation failed")
        else:
            log.info("Metasploit disabled in config; skipping validation step.")

    except Exception as exc:
        log.exception("Scan pipeline failed mid-run")
        error_note = f"{type(exc).__name__}: {exc}"
        # If recon already produced services, the report is still useful.
        final_status = "partial" if services else "error"

    # 7) Persist findings (best-effort)
    try:
        _persist(scan_id, mapped, results)
    except Exception:
        log.exception("Persisting findings failed")

    # 8) Report - always attempt, even on partial runs
    log.info("[5/5] Generating report")
    try:
        report = report_generator.build_report(
            target=target, operator=operator, mode=mode,
            mapped=mapped, plans=plans, results=results,
        )
        out_dir = settings.get("reporting.output_dir", "reports")
        formats = settings.get("reporting.formats", ["json", "markdown"])
        if "json" in formats:
            report_generator.write_json(report, out_dir)
        if "markdown" in formats:
            report_generator.write_markdown(report, out_dir)
        if "pdf" in formats:
            try:
                from reporting.pdf_export import write_pdf
                write_pdf(report, out_dir)
            except Exception:
                log.exception("PDF export failed (non-fatal)")
    except Exception as exc:
        log.exception("Report generation failed")
        error_note = error_note or f"report: {exc}"
        final_status = "error"
        report = {"error": str(exc)}

    with session_scope() as s:
        scan_row = s.get(Scan, scan_id)
        if scan_row:
            scan_row.status = final_status
            scan_row.finished_at = datetime.now(timezone.utc)
            if error_note:
                scan_row.notes = error_note[:2000]

    return report


def _persist(scan_id: int, mapped, results: List[ModuleResult]) -> None:
    with session_scope() as s:
        for entry in mapped:
            svc_row = Service(
                scan_id=scan_id,
                port=entry.service.port,
                protocol=entry.service.protocol,
                name=entry.service.name,
                product=entry.service.product,
                version=entry.service.version,
                banner=entry.service.banner,
                state=entry.service.state,
            )
            s.add(svc_row)
            s.flush()
            for cve in entry.cves:
                s.add(
                    Vulnerability(
                        scan_id=scan_id,
                        service_id=svc_row.id,
                        cve_id=cve.cve_id,
                        summary=cve.summary,
                        cvss=cve.cvss,
                        severity=cve.severity,
                    )
                )
        for r in results:
            s.add(
                ExploitRun(
                    scan_id=scan_id,
                    module=r.module,
                    action=r.action,
                    options=str(r.options),
                    result=r.output,
                    status=r.status,
                    safe_mode=True,
                )
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        auth = require_authorization(
            args.target,
            operator=args.operator,
            mode=args.mode,
            non_interactive=args.non_interactive,
            written_auth_ref=args.auth_ref,
        )
    except AuthorizationError as exc:
        print(f"AUTHORIZATION REQUIRED: {exc}", file=sys.stderr)
        return 2

    init_db()
    report = run_pipeline(
        target=auth.target,
        operator=auth.operator,
        mode=auth.mode,
        engine=args.engine,
        auth_ref=auth.written_authorization_ref,
    )
    s = report["summary"]
    print(
        f"Done. {s['open_services']} services, {s['total_cves']} CVEs "
        f"(C:{s['severity_counts'].get('critical',0)} "
        f"H:{s['severity_counts'].get('high',0)})."
    )
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from dashboard.app import create_app
    create_app().run(host=args.host, port=args.port, debug=False)
    return 0


def _cmd_initdb(_: argparse.Namespace) -> int:
    init_db()
    print("Database initialized.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnpilot",
        description="VulnPilot AI - authorized pentest automation",
    )
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a full scan pipeline against a target")
    scan.add_argument("--target", required=True, help="IP or hostname")
    scan.add_argument("--operator", default=None, help="Operator identity for audit")
    scan.add_argument("--mode", choices=("safe", "audit", "exploit"), default="safe")
    scan.add_argument("--engine", choices=("nmap", "rustscan"), default=None)
    scan.add_argument("--auth-ref", dest="auth_ref",
                      help="Reference to written authorization (SOW/ticket)")
    scan.add_argument("--non-interactive", action="store_true",
                      help="Require VULNPILOT_AUTHORIZED=1 instead of prompt")
    scan.add_argument("--i-have-authorization", dest="ack",
                      action="store_true", help=argparse.SUPPRESS)
    scan.set_defaults(func=_cmd_scan)

    dash = sub.add_parser("dashboard", help="Launch the web dashboard")
    dash.add_argument("--host", default=None)
    dash.add_argument("--port", type=int, default=None)
    dash.set_defaults(func=_cmd_dashboard)

    init_cmd = sub.add_parser("initdb", help="Initialize the database schema")
    init_cmd.set_defaults(func=_cmd_initdb)

    # Optional add-on: exploit-test feature. See exploit_engine/exploit_runner.
    from exploit_engine.exploit_cli import register_exploit_subcommand
    register_exploit_subcommand(sub)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    setup_logging(level=get_settings().get("logging.level", "INFO"),
                  log_file=get_settings().get("logging.file"))
    parser = build_parser()
    args = parser.parse_args(argv)

    # Apply dashboard defaults from config
    if args.command == "dashboard":
        s = get_settings()
        args.host = args.host or s.get("dashboard.host", "127.0.0.1")
        args.port = args.port or int(s.get("dashboard.port", 5000))

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
