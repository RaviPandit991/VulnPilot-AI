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
from exploit_engine import exploit_catalog, metasploit_client, module_selector
from exploit_engine.exploit_runner import (
    ExploitDisabled,
    ExploitNotAllowed,
    ExploitOutcome,
    ExploitRunner,
)
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
) -> dict:
    """Execute the full scan pipeline. Returns the generated report dict."""
    settings = get_settings()
    engine = engine or settings.get("scanner.engine", "nmap")

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

    # 2) Recon
    log.info("[1/5] Port + service scan (%s)", engine)
    if engine == "rustscan":
        services = rustscan_scanner.scan(
            target, settings.get("scanner.rustscan_args", "")
        )
    else:
        services = nmap_scanner.scan(
            target, settings.get("scanner.nmap_args", "-sV -sC -T4 --top-ports 1000")
        )

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
    results: List[ModuleResult] = []
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

    # 7) Persist findings
    _persist(scan_id, mapped, results)

    # 8) Report
    log.info("[5/5] Generating report")
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

    with session_scope() as s:
        scan_row = s.get(Scan, scan_id)
        if scan_row:
            scan_row.status = "complete"
            scan_row.finished_at = datetime.now(timezone.utc)

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


# ---------------------------------------------------------------------------
# Exploit subcommand
# ---------------------------------------------------------------------------
def _cmd_exploit(args: argparse.Namespace) -> int:
    """Run a single exploit template against a target port.

    Defaults to `check`-only (validates vulnerability without delivering a
    payload). Pass --actually-exploit AND set VULNPILOT_ALLOW_EXPLOIT=1 to
    actually fire the exploit.
    """
    settings = get_settings()

    # 1) List catalog and exit if requested
    if args.list_catalog:
        _print_catalog()
        return 0

    if not args.target:
        print("--target is required (or use --list-catalog).", file=sys.stderr)
        return 2

    # 2) Resolve which template(s) to run
    templates = _resolve_templates(args)
    if not templates:
        if args.module:
            print(f"Unknown exploit template: {args.module!r}", file=sys.stderr)
            print("Use --list-catalog to see available templates.", file=sys.stderr)
        else:
            print(
                f"No exploit templates match port {args.port}. "
                "Try --list-catalog to see what's supported.",
                file=sys.stderr,
            )
        return 2

    # 3) Authorization gate (mode is forced to 'exploit')
    try:
        auth = require_authorization(
            args.target,
            operator=args.operator,
            mode="exploit",
            non_interactive=args.non_interactive,
            written_auth_ref=args.auth_ref,
        )
    except AuthorizationError as exc:
        print(f"AUTHORIZATION REQUIRED: {exc}", file=sys.stderr)
        return 2

    # 4) Decide check-only vs actually-exploit. Config can globally force check-only.
    force_check_only_cfg = bool(settings.get("exploit.force_check_only", False))
    check_only = True
    if args.actually_exploit and not force_check_only_cfg:
        check_only = False
    elif args.actually_exploit and force_check_only_cfg:
        log.warning(
            "exploit.force_check_only=true in config; ignoring --actually-exploit"
        )

    # 5) Build Metasploit client (must be enabled in config)
    msf_cfg = settings.section("metasploit")
    if not msf_cfg.get("enabled"):
        print(
            "Metasploit integration is disabled in config. "
            "Set metasploit.enabled: true in configs/config.yaml and run msfrpcd.",
            file=sys.stderr,
        )
        return 3

    client = MetasploitClient(
        host=msf_cfg.get("host", "127.0.0.1"),
        port=int(msf_cfg.get("port", 55553)),
        username=msf_cfg.get("username", "msf"),
        password=msf_cfg.get("password", "msf"),
        ssl=bool(msf_cfg.get("ssl", False)),
        enabled=True,
    )
    try:
        client.connect()
    except MetasploitDisabled as exc:
        print(f"Metasploit unavailable: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        log.exception("Could not connect to msfrpcd")
        print(f"Could not connect to msfrpcd: {exc}", file=sys.stderr)
        return 3

    # 6) Build runner (re-validates authorization + env)
    try:
        runner = ExploitRunner(client, authorization=auth)
    except ExploitDisabled as exc:
        print(f"Exploit feature gated: {exc}", file=sys.stderr)
        return 2

    # 7) Persist a Scan row so ExploitRun has a parent
    init_db()
    with session_scope() as s:
        scan_row = Scan(
            target=auth.target,
            operator=auth.operator,
            mode="exploit",
            status="running",
            authorization_ref=auth.written_authorization_ref,
        )
        s.add(scan_row)
        s.flush()
        scan_id = scan_row.id

    # 8) Run each selected template
    exploit_cfg = settings.section("exploit")
    timeout = float(exploit_cfg.get("timeout_seconds", 180))
    lhost = args.lhost or exploit_cfg.get("default_lhost") or None
    lport = args.lport or exploit_cfg.get("default_lport") or None
    payload = args.payload or exploit_cfg.get("default_payload") or None

    outcomes: list[ExploitOutcome] = []
    for template in templates:
        try:
            outcome = runner.run(
                template,
                auth.target,
                check_only=check_only,
                port=args.port,
                payload=payload,
                lhost=lhost,
                lport=int(lport) if lport else None,
                force=args.force,
                timeout=timeout,
            )
        except ExploitNotAllowed as exc:
            print(f"Refused to run {template.id}: {exc}", file=sys.stderr)
            continue
        outcomes.append(outcome)
        _persist_exploit_outcome(scan_id, outcome)
        _print_outcome(outcome)

    # 9) Mark scan complete
    with session_scope() as s:
        scan_row = s.get(Scan, scan_id)
        if scan_row:
            scan_row.status = "complete"
            scan_row.finished_at = datetime.now(timezone.utc)

    # Exit code: 0 if any outcome was vulnerable/session-opened/completed,
    # 1 if all errored, 0 otherwise.
    if outcomes and all(o.status == "error" for o in outcomes):
        return 1
    return 0


def _resolve_templates(args: argparse.Namespace):
    """Pick template(s) to run based on --module or --port."""
    if args.module:
        tpl = exploit_catalog.get(args.module)
        return [tpl] if tpl else []
    if args.port:
        return exploit_catalog.find_for_port(args.port, service=args.service)
    return []


def _print_catalog() -> None:
    print("Available exploit templates:")
    print(f"{'ID':<28} {'PORT':<6} {'SVC':<10} {'RISK':<10} TITLE")
    print("-" * 90)
    for tpl in exploit_catalog.list_all():
        cves = ",".join(tpl.cve_ids) if tpl.cve_ids else "-"
        print(
            f"{tpl.id:<28} {tpl.default_port:<6} {tpl.service:<10} "
            f"{tpl.risk:<10} {tpl.title}"
        )
        if tpl.cve_ids:
            print(f"{'':<28} CVEs: {cves}")
    print()
    print("All listed modules are also pinned in module_selector.EXPLOIT_ALLOWLIST.")


def _print_outcome(o: ExploitOutcome) -> None:
    line = (
        f"[{o.status.upper():<14}] {o.module}  action={o.action}  "
        f"target={o.target}:{o.port}  in {o.duration_seconds:.1f}s"
    )
    print(line)
    if o.session_id:
        print(f"  session: {o.session_id}")
    for note in o.notes:
        print(f"  note: {note}")
    snippet = o.output.strip().splitlines()
    for ln in snippet[-6:]:
        print(f"  | {ln}")


def _persist_exploit_outcome(scan_id: int, outcome: ExploitOutcome) -> None:
    with session_scope() as s:
        s.add(
            ExploitRun(
                scan_id=scan_id,
                module=outcome.module,
                action=outcome.action,
                options=str(outcome.options),
                result=(outcome.output or "")[:8000],
                status=outcome.status,
                safe_mode=(outcome.action == "check"),
            )
        )


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

    expl = sub.add_parser(
        "exploit",
        help="Test a single exploit against a target port (check-only by default)",
    )
    expl.add_argument("--target", help="IP or hostname (must be in authorized scope)")
    expl.add_argument("--port", type=int, help="Target port to test")
    expl.add_argument("--service", help="Service hint (ftp, smb, http, ...)")
    expl.add_argument("--module", help="Exploit template id (see --list-catalog)")
    expl.add_argument("--list-catalog", action="store_true",
                      help="Print the exploit catalog and exit")
    expl.add_argument("--operator", default=None, help="Operator identity for audit")
    expl.add_argument("--auth-ref", dest="auth_ref",
                      help="Reference to written authorization (SOW/ticket)")
    expl.add_argument("--actually-exploit", action="store_true",
                      help="Run the real exploit, not just check(). "
                           "Requires VULNPILOT_ALLOW_EXPLOIT=1.")
    expl.add_argument("--payload", default=None,
                      help="Override default payload (only used with --actually-exploit)")
    expl.add_argument("--lhost", default=None, help="Reverse-handler listen host")
    expl.add_argument("--lport", type=int, default=None,
                      help="Reverse-handler listen port")
    expl.add_argument("--force", action="store_true",
                      help="Allow high-risk modules (e.g. EternalBlue) to actually exploit")
    expl.add_argument("--non-interactive", action="store_true",
                      help="Require VULNPILOT_AUTHORIZED=1 instead of prompt")
    expl.add_argument("--i-have-authorization", dest="ack",
                      action="store_true", help=argparse.SUPPRESS)
    expl.set_defaults(func=_cmd_exploit)

    init_cmd = sub.add_parser("initdb", help="Initialize the database schema")
    init_cmd.set_defaults(func=_cmd_initdb)

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
