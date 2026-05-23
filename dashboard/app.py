"""Flask web dashboard for VulnPilot AI - Attack Control Center.

Pages:
    GET  /              -> dashboard overview
    GET  /recon         -> Attack Control Center (main scan UI)
    GET  /scans         -> scan history table
    GET  /reports       -> report file browser
    GET  /settings      -> read-only config + safety policy view
    GET  /targets       -> placeholder
    GET  /exploits      -> placeholder
    GET  /sessions      -> placeholder
    GET  /ai            -> placeholder

REST API:
    GET  /api/scans                       -> list scans
    GET  /api/scans/<id>                  -> scan detail
    POST /api/scans                       -> queue a new scan
    GET  /api/scans/<id>/report.json      -> raw report download
    GET  /api/logs?lines=N                -> tail recent log lines
    GET  /api/scope                       -> top findings + AI rec
    GET  /api/dashboard-stats             -> KPI numbers + severity counts
    GET  /api/reports                     -> list generated report files
    GET  /api/reports/<filename>          -> download a report
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, abort, jsonify, render_template, request, send_file
from sqlalchemy import desc, func, select

from configs.settings import get_settings
from database.db import init_db, session_scope
from database.models import ExploitRun, Scan, Service, Vulnerability
from utils.auth_check import AuthorizationError, require_authorization
from utils.logger import get_logger

log = get_logger(__name__)

# In-memory ring buffer for log lines so the UI feed has data even if no
# rotating log file is configured.
_LOG_BUFFER: list[dict] = []
_LOG_BUFFER_MAX = 500


class _UIBufferHandler(logging.Handler):
    """Mirror records into the in-memory ring buffer feeding /api/logs."""

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover
        try:
            sev = {
                "DEBUG": "info", "INFO": "info", "WARNING": "warn",
                "ERROR": "error", "CRITICAL": "error",
            }.get(record.levelname, "info")
            msg = record.getMessage()
            if "ai_engine" in record.name or "decision" in record.name:
                sev = "ai"
            elif "complete" in msg.lower() or "queued" in msg.lower():
                sev = "success"
            entry = {
                "time": datetime.fromtimestamp(record.created, tz=timezone.utc)
                          .strftime("%Y-%m-%d %H:%M:%S"),
                "severity": sev,
                "message": msg,
                "logger": record.name,
            }
            _LOG_BUFFER.append(entry)
            if len(_LOG_BUFFER) > _LOG_BUFFER_MAX:
                del _LOG_BUFFER[: len(_LOG_BUFFER) - _LOG_BUFFER_MAX]
        except Exception:
            pass


def _install_ui_log_handler() -> None:
    """Idempotently attach the UI buffer handler to the root logger."""
    root = logging.getLogger()
    if any(isinstance(h, _UIBufferHandler) for h in root.handlers):
        return
    handler = _UIBufferHandler(level=logging.INFO)
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    settings = get_settings()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.get("dashboard.secret_key", "change-me")
    init_db()
    _install_ui_log_handler()

    # ----------------- Pages -----------------
    @app.get("/")
    def index():
        return render_template("dashboard.html", active="dashboard")

    @app.get("/dashboard")
    def dashboard_home():
        return render_template("dashboard.html", active="dashboard")

    @app.get("/recon")
    def recon():
        return render_template("recon.html", active="recon")

    @app.get("/scans")
    def scans():
        return render_template("scans.html", active="scans")

    @app.get("/reports", endpoint="reports")
    def reports_page():
        return render_template("reports.html", active="reports")

    @app.get("/settings")
    def settings():
        cfg_path = Path(__file__).parent.parent / "configs" / "config.yaml"
        try:
            yaml_text = cfg_path.read_text(encoding="utf-8")
        except OSError:
            yaml_text = "# config.yaml not found"
        s = get_settings()
        return render_template(
            "settings.html",
            active="settings",
            config_yaml=yaml_text,
            version=s.get("app.version", "0.1.0"),
            engine=s.get("scanner.engine", "nmap"),
            db_url=s.get("database.url", ""),
            msf_enabled=bool(s.get("metasploit.enabled", False)),
        )

    # Placeholder pages mapped to the nav rail
    @app.get("/targets")
    def targets():
        return render_template(
            "_simple_page.html", active="targets",
            page_title="Targets", icon="crosshair",
            description=("Group multiple hosts into engagements with shared "
                         "authorization context. Coming soon."),
        )

    @app.get("/exploits")
    def exploits():
        return render_template(
            "_simple_page.html", active="exploits",
            page_title="Exploits", icon="zap",
            description=("Curated, allowlist-only Metasploit auxiliary modules. "
                         "Available once you enable Metasploit in config."),
        )

    @app.get("/sessions")
    def sessions():
        return render_template(
            "_simple_page.html", active="sessions",
            page_title="Sessions", icon="terminal",
            description=("Active Metasploit sessions and console output. "
                         "Read-only - VulnPilot does not stage payloads."),
        )

    @app.get("/ai")
    def ai_assistant():
        return render_template(
            "_simple_page.html", active="ai",
            page_title="AI Assistant", icon="bot",
            description=("Conversational analysis of your scan findings. "
                         "Local-LLM hook coming soon - rule-based engine "
                         "is already active."),
        )

    # ----------------- REST: scans -----------------
    @app.get("/api/scans")
    def list_scans():
        with session_scope() as s:
            rows = s.execute(select(Scan).order_by(desc(Scan.id)).limit(50)).scalars()
            return jsonify([_scan_summary(r) for r in rows])

    @app.get("/api/scans/<int:scan_id>")
    def scan_detail(scan_id: int):
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if not scan:
                return jsonify({"error": "not found"}), 404
            return jsonify(_scan_full(scan))

    @app.get("/api/scans/<int:scan_id>/report.json")
    def scan_report_json(scan_id: int):
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if not scan:
                return jsonify({"error": "not found"}), 404
            return jsonify(_scan_full(scan))

    @app.post("/api/scans")
    def queue_scan():
        payload: Dict[str, Any] = request.get_json(force=True, silent=True) or {}
        target = payload.get("target")
        operator = payload.get("operator", "web-user")
        mode = payload.get("mode", "safe")
        auth_ref = payload.get("authorization_ref")
        scan_profile = (payload.get("scan_profile") or "standard").lower()
        if not target:
            return jsonify({"error": "target required"}), 400

        try:
            require_authorization(
                target, operator=operator, mode=mode,
                non_interactive=True, written_auth_ref=auth_ref,
            )
        except AuthorizationError as exc:
            return jsonify({"error": str(exc)}), 403

        scan_id = _create_scan_row(target, operator, mode, auth_ref)
        threading.Thread(
            target=_run_scan_background,
            args=(scan_id, target, operator, mode, scan_profile),
            daemon=True,
        ).start()
        return jsonify({"id": scan_id, "status": "queued"}), 202

    # ----------------- REST: live logs -----------------
    @app.get("/api/logs")
    def get_logs():
        try:
            n = max(1, min(int(request.args.get("lines", 100)), _LOG_BUFFER_MAX))
        except ValueError:
            n = 100
        return jsonify(_LOG_BUFFER[-n:])

    # ----------------- REST: scope (CVE cards) -----------------
    @app.get("/api/scope")
    def get_scope():
        with session_scope() as s:
            latest = s.execute(
                select(Scan).order_by(desc(Scan.id)).limit(1)
            ).scalar_one_or_none()
            if not latest:
                return jsonify({"findings": [], "stats": {}, "recommendation": ""})

            findings: List[Dict[str, Any]] = []
            services = {svc.id: svc for svc in latest.services}
            for v in sorted(
                latest.vulnerabilities,
                key=lambda x: x.cvss or 0.0, reverse=True,
            )[:30]:
                svc = services.get(v.service_id)
                findings.append({
                    "cve_id": v.cve_id,
                    "title": _title_from_summary(v.summary),
                    "severity": (v.severity or "INFO").lower(),
                    "cvss": v.cvss,
                    "summary": v.summary,
                    "service_label": _service_label(svc),
                    "port": svc.port if svc else 0,
                    "recommended_module": _recommended_module(svc),
                })

            stats = {
                "total_findings": len(latest.vulnerabilities),
                "exploitable": sum(
                    1 for v in latest.vulnerabilities if (v.cvss or 0) >= 7
                ),
            }
            recommendation = _ai_recommendation(latest, findings)
            return jsonify({
                "findings": findings, "stats": stats,
                "recommendation": recommendation,
                "scan_id": latest.id,
            })

    # ----------------- REST: dashboard stats -----------------
    @app.get("/api/dashboard-stats")
    def dashboard_stats():
        with session_scope() as s:
            total_scans = s.scalar(select(func.count()).select_from(Scan)) or 0
            total_findings = s.scalar(
                select(func.count()).select_from(Vulnerability)
            ) or 0
            sev_counts: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0,
                "low": 0, "informational": 0,
            }
            rows = s.execute(
                select(Vulnerability.severity, func.count())
                .group_by(Vulnerability.severity)
            ).all()
            for sev, n in rows:
                key = (sev or "informational").lower()
                if key in sev_counts:
                    sev_counts[key] = n
                else:
                    sev_counts["informational"] += n
            return jsonify({
                "scans": total_scans,
                "findings": total_findings,
                "critical": sev_counts["critical"],
                "high": sev_counts["high"],
                "severity_counts": sev_counts,
            })

    # ----------------- REST: report files -----------------
    @app.get("/api/reports")
    def list_reports():
        out_dir = Path(get_settings().get("reporting.output_dir", "reports"))
        if not out_dir.exists():
            return jsonify([])
        files = []
        for p in sorted(out_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
            if not p.is_file():
                continue
            stat = p.stat()
            files.append({
                "name": p.name,
                "format": p.suffix.lstrip(".").lower() or "bin",
                "size": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                              .isoformat(),
                "path": str(p),
            })
        return jsonify(files)

    @app.get("/api/reports/<path:filename>")
    def download_report(filename: str):
        # Reject path traversal
        if "/" in filename or "\\" in filename or ".." in filename:
            abort(400)
        out_dir = Path(get_settings().get("reporting.output_dir", "reports")).resolve()
        target = (out_dir / filename).resolve()
        try:
            target.relative_to(out_dir)
        except ValueError:
            abort(400)
        if not target.is_file():
            abort(404)
        return send_file(target, as_attachment=True)

    # ----------------- REST: services + scope + actions -----------------
    @app.get("/api/scans/latest/services")
    def latest_scan_services():
        """Return services from the most recent scan, with CVE rollups
        and in_scope flag. This drives the DISCOVERED + SCOPE panels."""
        with session_scope() as s:
            scan = s.execute(
                select(Scan).order_by(desc(Scan.id)).limit(1)
            ).scalar_one_or_none()
            if not scan:
                return jsonify({"scan": None, "services": []})

            # Build CVE index per service
            cves_by_svc: Dict[int, list] = {}
            for v in scan.vulnerabilities:
                cves_by_svc.setdefault(v.service_id or 0, []).append(v)

            services = []
            for svc in scan.services:
                svc_cves = cves_by_svc.get(svc.id, [])
                max_cvss = max((c.cvss or 0.0 for c in svc_cves), default=0.0)
                top = sorted(svc_cves, key=lambda x: x.cvss or 0.0, reverse=True)[:3]
                services.append({
                    "id": svc.id,
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "name": svc.name or "?",
                    "product": svc.product,
                    "version": svc.version,
                    "banner": svc.banner,
                    "in_scope": bool(svc.in_scope),
                    "notes": svc.notes,
                    "cve_count": len(svc_cves),
                    "max_cvss": max_cvss,
                    "max_severity": (_severity_label(max_cvss) or "info").lower(),
                    "top_cves": [
                        {"cve_id": c.cve_id, "cvss": c.cvss,
                         "severity": (c.severity or "info").lower(),
                         "summary": (c.summary or "")[:200]}
                        for c in top
                    ],
                    "recommended_module": _recommended_module(svc),
                    "suggested_command": _suggest_command(svc, scan.target),
                })
            services.sort(key=lambda x: x["port"])
            return jsonify({
                "scan": {
                    "id": scan.id, "target": scan.target,
                    "status": scan.status, "mode": scan.mode,
                    "started_at": scan.started_at.isoformat() if scan.started_at else None,
                    "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                    "notes": scan.notes,
                },
                "services": services,
            })

    @app.get("/api/msf/status")
    def msf_status():
        """Return whether Metasploit RPC is configured and reachable."""
        msf_cfg = get_settings().section("metasploit")
        if not msf_cfg.get("enabled"):
            return jsonify({
                "enabled": False,
                "reachable": False,
                "message": "metasploit.enabled is false in configs/config.yaml",
            })
        host = msf_cfg.get("host", "127.0.0.1")
        port = int(msf_cfg.get("port", 55553))
        # Cheap TCP probe rather than a full RPC handshake.
        import socket
        try:
            with socket.create_connection((host, port), timeout=2.0):
                pass
            reachable = True
            message = f"msfrpcd reachable at {host}:{port}"
        except OSError as exc:
            reachable = False
            message = (f"Cannot reach msfrpcd at {host}:{port}: {exc}. "
                       "Start it with: msfrpcd -P <password> -S -a 127.0.0.1")
        return jsonify({
            "enabled": True, "reachable": reachable,
            "host": host, "port": port, "message": message,
        })

    @app.post("/api/services/<int:service_id>/scope")
    def toggle_service_scope(service_id: int):
        payload = request.get_json(silent=True) or {}
        in_scope = bool(payload.get("in_scope", True))
        with session_scope() as s:
            svc = s.get(Service, service_id)
            if not svc:
                return jsonify({"error": "service not found"}), 404
            svc.in_scope = in_scope
            return jsonify({"id": service_id, "in_scope": in_scope})

    @app.get("/api/services/<int:service_id>/cves")
    def list_service_cves(service_id: int):
        with session_scope() as s:
            svc = s.get(Service, service_id)
            if not svc:
                return jsonify({"error": "service not found"}), 404
            cves = sorted(
                [v for v in svc.scan.vulnerabilities if v.service_id == service_id],
                key=lambda x: x.cvss or 0.0, reverse=True,
            )
            return jsonify([
                {"cve_id": v.cve_id, "cvss": v.cvss,
                 "severity": (v.severity or "info").lower(),
                 "summary": v.summary}
                for v in cves
            ])

    @app.post("/api/services/<int:service_id>/action")
    def run_service_action(service_id: int):
        """Execute a per-service action.

        Supported actions:
          banner   - return captured Nmap banner text
          command  - return a recommended msfconsole/nmap command string
          check    - run the recommended Metasploit auxiliary check
          note     - persist a free-text operator note (body: {note: str})
        """
        payload = request.get_json(silent=True) or {}
        action = (payload.get("action") or "").lower()
        with session_scope() as s:
            svc = s.get(Service, service_id)
            if not svc:
                return jsonify({"error": "service not found"}), 404
            target = svc.scan.target

            if action == "banner":
                output = svc.banner or "(no banner captured by Nmap; try a deeper scan)"
                return jsonify({"action": "banner", "output": output})

            if action == "command":
                return jsonify({
                    "action": "command",
                    "output": _suggest_command(svc, target),
                })

            if action == "note":
                svc.notes = (payload.get("note") or "")[:2000] or None
                return jsonify({"action": "note", "note": svc.notes})

            if action == "check":
                return _do_msf_check(s, svc, target)

            return jsonify({"error": f"unknown action: {action}"}), 400

    # ----------------- Error handlers -----------------
    @app.errorhandler(500)
    def _internal_error(exc):
        log.exception("500 on %s %s", request.method, request.path)
        debug = os.environ.get("VULNPILOT_DEBUG_UI") == "1"
        body = {
            "error": "internal server error",
            "path": request.path,
        }
        if debug:
            body["exception"] = repr(exc)
            body["traceback"] = traceback.format_exc().splitlines()
        if request.path.startswith("/api/"):
            return jsonify(body), 500
        # HTML fallback
        return (
            f"<pre style='background:#0f172a;color:#e2e8f0;padding:1rem;"
            f"font-family:monospace;font-size:12px'>500 on {request.path}\n\n"
            f"{repr(exc) if debug else 'Set VULNPILOT_DEBUG_UI=1 to see details.'}"
            f"</pre>",
            500,
        )

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _scan_summary(r: Scan) -> dict:
    return {
        "id": r.id, "target": r.target, "operator": r.operator,
        "mode": r.mode, "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    }


def _scan_full(scan: Scan) -> dict:
    return {
        "id": scan.id, "target": scan.target, "mode": scan.mode,
        "status": scan.status, "operator": scan.operator,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "notes": scan.notes,
        "services": [
            {"id": svc.id, "port": svc.port, "protocol": svc.protocol,
             "name": svc.name, "product": svc.product, "version": svc.version}
            for svc in scan.services
        ],
        "vulnerabilities": [
            {"id": v.id, "cve_id": v.cve_id, "cvss": v.cvss,
             "severity": v.severity, "summary": v.summary}
            for v in scan.vulnerabilities
        ],
        "exploit_runs": [
            {"module": r.module, "action": r.action,
             "status": r.status, "safe_mode": r.safe_mode}
            for r in scan.exploit_runs
        ],
    }


def _service_label(svc) -> str:
    if not svc:
        return "?"
    bits = [f"{svc.port}/{svc.protocol}"]
    if svc.name: bits.append(svc.name)
    if svc.product: bits.append(svc.product)
    if svc.version: bits.append(svc.version)
    return " · ".join(bits)


def _title_from_summary(summary: str | None) -> str:
    if not summary:
        return "Vulnerability"
    return summary.split(".")[0][:80] or "Vulnerability"


def _recommended_module(svc) -> str:
    """Map an Nmap service name to a *safe* Metasploit auxiliary scanner.

    Returns 'manual review' when no MSF aux scanner is appropriate -
    typically the operator should run the suggested nmap NSE command
    instead (see _suggest_command()).
    """
    if not svc or not svc.name:
        return "manual review"
    name = svc.name.lower()
    table = {
        # SSH
        "ssh": "auxiliary/scanner/ssh/ssh_version",
        # HTTP/HTTPS - use the version probe; Tomcat-specific stuff is below
        "http": "auxiliary/scanner/http/http_version",
        "https": "auxiliary/scanner/http/http_version",
        "http-proxy": "auxiliary/scanner/http/http_version",
        "http-alt": "auxiliary/scanner/http/http_version",
        # SMB
        "smb": "auxiliary/scanner/smb/smb_version",
        "microsoft-ds": "auxiliary/scanner/smb/smb_ms17_010",
        "netbios-ssn": "auxiliary/scanner/smb/smb_version",
        # FTP
        "ftp": "auxiliary/scanner/ftp/anonymous",
        "ftp-data": "auxiliary/scanner/ftp/ftp_version",
        # Telnet
        "telnet": "auxiliary/scanner/telnet/telnet_version",
        # Mail
        "smtp": "auxiliary/scanner/smtp/smtp_version",
        "smtps": "auxiliary/scanner/smtp/smtp_version",
        "pop3": "auxiliary/scanner/pop3/pop3_version",
        "pop3s": "auxiliary/scanner/pop3/pop3_version",
        "imap": "auxiliary/scanner/imap/imap_version",
        "imaps": "auxiliary/scanner/imap/imap_version",
        # Databases
        "mysql": "auxiliary/scanner/mysql/mysql_version",
        "postgresql": "auxiliary/scanner/postgres/postgres_version",
        "postgres": "auxiliary/scanner/postgres/postgres_version",
        "mssql": "auxiliary/scanner/mssql/mssql_ping",
        "ms-sql-s": "auxiliary/scanner/mssql/mssql_ping",
        "redis": "auxiliary/scanner/redis/redis_server",
        "oracle": "auxiliary/scanner/oracle/tnslsnr_version",
        # Remote access
        "rdp": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        "ms-wbt-server": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        "vnc": "auxiliary/scanner/vnc/vnc_none_auth",
        # Network services
        "snmp": "auxiliary/scanner/snmp/snmp_enum",
        "ntp": "auxiliary/scanner/ntp/ntp_monlist",
        "domain": "auxiliary/scanner/dns/dns_amp",
        "dns": "auxiliary/scanner/dns/dns_amp",
        "ldap": "auxiliary/scanner/ldap/ldap_login",
        "ldaps": "auxiliary/scanner/ldap/ldap_login",
        # File sharing
        "nfs": "auxiliary/scanner/nfs/nfsmount",
        "rpcbind": "auxiliary/scanner/portmap/portmap_amp",
        "sunrpc": "auxiliary/scanner/portmap/portmap_amp",
        # Virtualization
        "vmware-auth": "auxiliary/scanner/vmware/esx_fingerprint",
        # Services with no good MSF aux scanner - fall through to "manual
        # review" which will tell the user to use the Command button:
        # ajp13, ircd, nntp, x11, finger, distccd, ident, time, daytime,
        # bindshell, exec, login, shell (Metasploitable's r-services),
        # tomcat (covered by http_version + nmap NSE), couchdb,
        # elasticsearch, etc.
    }
    return table.get(name, "manual review")


def _severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "INFO"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0:
        return "LOW"
    return "INFO"


def _suggest_command(svc, target: str) -> str:
    """Return a copy-pasteable command for the service.

    For services without a Metasploit aux scanner this is the primary
    safe-investigation tool the operator should reach for.
    """
    name = (svc.name or "").lower()
    port = svc.port
    if name == "ssh":
        return (
            f"# Banner + algos + cipher audit\n"
            f"nmap -sV -p {port} --script ssh2-enum-algos,ssh-auth-methods {target}"
        )
    if name in ("http", "https", "http-proxy", "http-alt"):
        scheme = "https" if name == "https" else "http"
        return (
            f"# HTTP fingerprint + common files\n"
            f"nmap -sV -p {port} --script http-enum,http-headers,http-methods,"
            f"http-title,http-server-header {target}\n"
            f"curl -sI {scheme}://{target}:{port}/"
        )
    if name in ("smb", "microsoft-ds", "netbios-ssn"):
        return (
            f"# SMB version + EternalBlue check (non-exploit)\n"
            f"nmap -sV -p {port} --script smb-protocols,smb2-security-mode,"
            f"smb-enum-shares,smb-vuln-ms17-010 {target}"
        )
    if name in ("ajp13", "ajp"):
        return (
            f"# AJP13 (Tomcat) - Ghostcat CVE-2020-1938 detection\n"
            f"nmap -sV -p {port} --script ajp-headers,ajp-methods,ajp-request,"
            f"ajp-auth {target}"
        )
    if name == "ftp":
        return (
            f"# FTP version + anon login + bounce check\n"
            f"nmap -sV -p {port} --script ftp-anon,ftp-syst,ftp-bounce {target}"
        )
    if name == "telnet":
        return (
            f"# Telnet banner + supported encryption\n"
            f"nmap -sV -p {port} --script telnet-encryption,telnet-ntlm-info {target}"
        )
    if name == "mysql":
        return (
            f"# MySQL info + empty-password + variables\n"
            f"nmap -sV -p {port} --script mysql-info,mysql-empty-password,"
            f"mysql-variables {target}"
        )
    if name in ("postgresql", "postgres"):
        return (
            f"# PostgreSQL version probe (avoid pgsql-brute - not safe)\n"
            f"nmap -sV -p {port} {target}"
        )
    if name in ("mssql", "ms-sql-s"):
        return (
            f"# MSSQL info + ntlm-info\n"
            f"nmap -sV -p {port} --script ms-sql-info,ms-sql-ntlm-info {target}"
        )
    if name == "redis":
        return (
            f"# Redis info (NOAUTH if exposed)\n"
            f"nmap -sV -p {port} --script redis-info {target}"
        )
    if name == "mongodb":
        return (
            f"# MongoDB build info (avoid mongodb-brute)\n"
            f"nmap -sV -p {port} --script mongodb-info {target}"
        )
    if name == "smtp":
        return (
            f"# SMTP banner + commands + open relay test\n"
            f"nmap -sV -p {port} --script smtp-commands,smtp-enum-users,"
            f"smtp-open-relay {target}"
        )
    if name in ("pop3", "pop3s"):
        return (
            f"# POP3 capabilities\n"
            f"nmap -sV -p {port} --script pop3-capabilities,pop3-ntlm-info {target}"
        )
    if name in ("imap", "imaps"):
        return (
            f"# IMAP capabilities\n"
            f"nmap -sV -p {port} --script imap-capabilities,imap-ntlm-info {target}"
        )
    if name in ("ldap", "ldaps"):
        return (
            f"# LDAP root DSE + naming contexts\n"
            f"nmap -sV -p {port} --script ldap-rootdse,ldap-search {target}"
        )
    if name in ("dns", "domain"):
        return (
            f"# DNS recursion + zone transfer attempt\n"
            f"nmap -sV -p {port} --script dns-recursion,dns-zone-transfer "
            f"--script-args dns-zone-transfer.domain=<DOMAIN> {target}"
        )
    if name == "ntp":
        return (
            f"# NTP info + monlist amplification check\n"
            f"nmap -sV -p {port} --script ntp-info,ntp-monlist -sU {target}"
        )
    if name == "snmp":
        return (
            f"# SNMP system info (try public/private; -sU for UDP)\n"
            f"nmap -sV -p {port} -sU --script snmp-info,snmp-sysdescr,"
            f"snmp-interfaces {target}"
        )
    if name in ("ms-wbt-server", "rdp"):
        return (
            f"# RDP - BlueKeep non-exploit check + encryption\n"
            f"nmap -sV -p {port} --script rdp-vuln-ms12-020,rdp-enum-encryption,"
            f"rdp-ntlm-info {target}"
        )
    if name == "vnc":
        return (
            f"# VNC info (auth methods)\n"
            f"nmap -sV -p {port} --script vnc-info,vnc-title {target}"
        )
    if name == "nfs":
        return (
            f"# NFS shares + mounts\n"
            f"nmap -sV -p {port} --script nfs-ls,nfs-showmount,nfs-statfs {target}"
        )
    if name in ("rpcbind", "sunrpc"):
        return (
            f"# RPC services exposed via portmapper\n"
            f"nmap -sV -p {port} --script rpcinfo {target}\n"
            f"rpcinfo -p {target}"
        )
    if name in ("exec", "shell", "login"):
        return (
            f"# Berkeley r-services (ancient, on Metasploitable)\n"
            f"nmap -sV -p {port} {target}\n"
            f"# rsh / rlogin / rexec - no NSE coverage; banner grab manually."
        )
    if name == "distccd":
        return (
            f"# distcc CVE-2004-2687 - command exec via build daemon\n"
            f"nmap -sV -p {port} --script distcc-cve2004-2687 {target}"
        )
    if name == "x11":
        return (
            f"# X11 access without auth check\n"
            f"nmap -sV -p {port} --script x11-access {target}"
        )
    if name == "ircd":
        return (
            f"# IRC info + UnrealIRCd backdoor (CVE-2010-2075)\n"
            f"nmap -sV -p {port} --script irc-info,irc-unrealircd-backdoor {target}"
        )
    if name == "finger":
        return (
            f"# Finger user enumeration\n"
            f"nmap -sV -p {port} --script finger {target}"
        )
    return f"# Generic version + default scripts\nnmap -sV -sC -p {port} {target}"


def _ai_recommendation(scan: Scan, findings: list[dict]) -> str:
    if not findings:
        return ("Scan complete with no high-confidence CVE matches. Verify "
                "service banners manually and consider an authenticated scan.")
    top = findings[0]
    return (
        f"Highest-impact finding: {top['cve_id']} (CVSS "
        f"{top.get('cvss') or '?'}) on {top['service_label']}. Run the "
        f"{top.get('recommended_module','recommended check')} module in "
        f"safe mode to validate before reporting."
    )


def _human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    s = float(n)
    for u in units:
        if s < 1024 or u == units[-1]:
            return f"{s:.1f} {u}"
        s /= 1024
    return f"{n} B"


def _create_scan_row(target: str, operator: str, mode: str, auth_ref: str | None) -> int:
    with session_scope() as s:
        scan = Scan(
            target=target, operator=operator, mode=mode,
            status="queued", authorization_ref=auth_ref,
        )
        s.add(scan); s.flush()
        return scan.id


def _run_scan_background(scan_id: int, target: str, operator: str, mode: str,
                          scan_profile: str = "standard") -> None:
    from main import run_pipeline
    profile_args = {
        "quick":    "-sV -T4 --top-ports 100",
        "standard": "-sV -sC -T4 --top-ports 1000",
        "deep":     "-sV -sC -T4 -p-",
    }
    nmap_args = profile_args.get(scan_profile)
    try:
        run_pipeline(
            target=target, operator=operator, mode=mode, scan_id=scan_id,
            nmap_args=nmap_args,
        )
    except Exception:
        log.exception("Background scan %s failed", scan_id)
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if scan:
                scan.status = "error"


def _do_msf_check(s, svc, target: str):
    """Run the recommended Metasploit auxiliary scanner against `svc`.

    Called from the per-service action handler. Blocks the request for up
    to ~75 seconds; auxiliary scanners typically finish in 5-30s. Persists
    the resulting ExploitRun row regardless of outcome so operators can
    audit what was attempted.
    """
    from exploit_engine.module_selector import SelectedModule, is_safe
    from exploit_engine.metasploit_client import (
        MetasploitClient, MetasploitDisabled,
    )

    msf_cfg = get_settings().section("metasploit")
    if not msf_cfg.get("enabled"):
        return jsonify({
            "action": "check",
            "status": "skipped",
            "output": (
                "Metasploit RPC is disabled.\n"
                "1. Start the daemon:\n"
                "     msfrpcd -P <password> -S -a 127.0.0.1\n"
                "2. Edit configs/config.yaml -> metasploit.enabled: true\n"
                "3. Restart the dashboard."
            ),
        }), 200

    module_path = _recommended_module(svc)
    if module_path == "manual review":
        cmd = _suggest_command(svc, target)
        return jsonify({
            "action": "check",
            "status": "skipped",
            "output": (
                f"No safe Metasploit auxiliary scanner is registered for "
                f"service '{svc.name}'.\n\n"
                f"Use the COMMAND button instead - it returns this nmap NSE "
                f"recipe tailored for {svc.name}:\n\n"
                f"{cmd}"
            ),
        })
    if not is_safe(module_path):
        return jsonify({
            "action": "check",
            "status": "blocked",
            "output": (f"Module {module_path} blocked by safety allowlist."),
        }), 403

    selection = SelectedModule(
        module=module_path,
        action="check",
        options={"RHOSTS": target, "RPORT": svc.port},
        target_host=target,
        target_port=svc.port,
        rationale="Operator-initiated safe check via dashboard",
        severity_hint="informational",
    )

    client = MetasploitClient(
        host=msf_cfg.get("host", "127.0.0.1"),
        port=int(msf_cfg.get("port", 55553)),
        username=msf_cfg.get("username", "msf"),
        password=msf_cfg.get("password", "msf"),
        ssl=bool(msf_cfg.get("ssl", False)),
        enabled=True,
    )

    # Persist the run record up-front in 'running' state so the audit
    # trail survives even if the call hangs or crashes.
    run = ExploitRun(
        scan_id=svc.scan_id,
        module=module_path,
        action="check",
        options=str(selection.options),
        status="running",
        safe_mode=True,
        result="(in progress)",
    )
    s.add(run)
    s.flush()
    run_id = run.id

    log.info("MSF check %s -> %s:%s starting (run #%s)",
             module_path, target, svc.port, run_id)

    try:
        result = client.run(selection, timeout=60.0)
    except MetasploitDisabled as exc:
        run.status = "skipped"
        run.result = f"MSF disabled: {exc}"
        return jsonify({
            "action": "check", "status": "skipped",
            "output": str(exc),
        }), 200
    except Exception as exc:
        log.exception("MSF check failed")
        run.status = "error"
        run.result = f"{type(exc).__name__}: {exc}"
        return jsonify({
            "action": "check", "status": "error", "module": module_path,
            "output": (
                f"MSF call failed: {exc}\n\n"
                "Check that msfrpcd is running and the password in "
                "configs/config.yaml matches what you passed to it.\n"
                "Verify with: ss -ltnp | grep 55553"
            ),
        }), 500

    # Persist final result
    run.status = result.status
    run.result = result.output[-4000:] if result.output else ""

    log.info(
        "MSF check %s finished status=%s in %.1fs",
        module_path, result.status, result.duration_seconds,
    )

    return jsonify({
        "action": "check",
        "status": result.status,
        "module": module_path,
        "duration_seconds": round(result.duration_seconds, 1),
        "run_id": run_id,
        "output": (result.output or "(no output captured)")[-3000:],
    })


if __name__ == "__main__":  # pragma: no cover
    settings = get_settings()
    create_app().run(
        host=settings.get("dashboard.host", "127.0.0.1"),
        port=settings.get("dashboard.port", 5000),
        debug=False,
    )
