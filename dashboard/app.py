"""Flask web dashboard for VulnPilot AI.

Endpoints:
    GET  /                       -> dashboard UI
    GET  /api/scans              -> list scans
    GET  /api/scans/<id>         -> scan detail with services + vulnerabilities
    POST /api/scans              -> queue a new scan (requires authorization payload)
    GET  /api/exploit/catalog    -> list available exploit templates
                                   (optional ?port=21&service=ftp filters)
    POST /api/exploit/run        -> run a single exploit template against a target
                                   (requires authorization + VULNPILOT_ALLOW_EXPLOIT=1)
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request
from sqlalchemy import select

from configs.settings import get_settings
from database.db import init_db, session_scope
from database.models import ExploitRun, Scan, Service, Vulnerability
from exploit_engine import exploit_catalog
from exploit_engine.exploit_runner import (
    ExploitDisabled,
    ExploitNotAllowed,
    ExploitRunner,
)
from exploit_engine.metasploit_client import MetasploitClient, MetasploitDisabled
from utils.auth_check import AuthorizationError, require_authorization
from utils.logger import get_logger

log = get_logger(__name__)


def create_app() -> Flask:
    settings = get_settings()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = settings.get("dashboard.secret_key", "change-me")
    init_db()

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/scans")
    def list_scans():
        with session_scope() as s:
            rows = s.execute(select(Scan).order_by(Scan.id.desc()).limit(50)).scalars()
            data = [
                {
                    "id": r.id,
                    "target": r.target,
                    "operator": r.operator,
                    "mode": r.mode,
                    "status": r.status,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                }
                for r in rows
            ]
        return jsonify(data)

    @app.get("/api/scans/<int:scan_id>")
    def scan_detail(scan_id: int):
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if not scan:
                return jsonify({"error": "not found"}), 404
            services = [
                {
                    "id": svc.id, "port": svc.port, "protocol": svc.protocol,
                    "name": svc.name, "product": svc.product, "version": svc.version,
                }
                for svc in scan.services
            ]
            vulns = [
                {
                    "cve_id": v.cve_id, "cvss": v.cvss, "severity": v.severity,
                    "summary": v.summary,
                }
                for v in scan.vulnerabilities
            ]
            runs = [
                {
                    "module": r.module, "action": r.action,
                    "status": r.status, "safe_mode": r.safe_mode,
                }
                for r in scan.exploit_runs
            ]
            return jsonify(
                {
                    "id": scan.id, "target": scan.target, "mode": scan.mode,
                    "status": scan.status, "operator": scan.operator,
                    "services": services, "vulnerabilities": vulns,
                    "exploit_runs": runs,
                }
            )

    @app.post("/api/scans")
    def queue_scan():
        payload: Dict[str, Any] = request.get_json(force=True, silent=True) or {}
        target = payload.get("target")
        operator = payload.get("operator", "web-user")
        mode = payload.get("mode", "safe")
        auth_ref = payload.get("authorization_ref")
        if not target:
            return jsonify({"error": "target required"}), 400

        try:
            require_authorization(
                target,
                operator=operator,
                mode=mode,
                non_interactive=True,
                written_auth_ref=auth_ref,
            )
        except AuthorizationError as exc:
            return jsonify({"error": str(exc)}), 403

        scan_id = _create_scan_row(target, operator, mode, auth_ref)
        threading.Thread(
            target=_run_scan_background,
            args=(scan_id, target, operator, mode),
            daemon=True,
        ).start()
        return jsonify({"id": scan_id, "status": "queued"}), 202

    # ---- Exploit feature ---------------------------------------------------
    @app.get("/api/exploit/catalog")
    def exploit_catalog_list():
        port_arg = request.args.get("port", type=int)
        service = request.args.get("service")
        product = request.args.get("product")
        if port_arg:
            templates = exploit_catalog.find_for_port(
                port_arg, service=service, product=product
            )
        else:
            templates = exploit_catalog.list_all()
        return jsonify(
            {
                "exploit_enabled": os.environ.get("VULNPILOT_ALLOW_EXPLOIT") == "1",
                "force_check_only": bool(
                    settings.get("exploit.force_check_only", False)
                ),
                "templates": [_template_to_dict(t) for t in templates],
            }
        )

    @app.post("/api/exploit/run")
    def exploit_run():
        payload: Dict[str, Any] = request.get_json(force=True, silent=True) or {}
        target = payload.get("target")
        operator = payload.get("operator", "web-user")
        auth_ref = payload.get("authorization_ref")
        template_id = payload.get("template_id")
        port_override = payload.get("port")
        msf_payload = payload.get("payload")
        lhost = payload.get("lhost")
        lport = payload.get("lport")
        check_only = bool(payload.get("check_only", True))
        force = bool(payload.get("force", False))
        confirmation = payload.get("confirmation", "")

        if not target or not template_id:
            return jsonify({"error": "target and template_id are required"}), 400
        if not auth_ref:
            return jsonify({"error": "authorization_ref is required"}), 400
        if confirmation != "I AUTHORIZE":
            return jsonify(
                {"error": "Type 'I AUTHORIZE' in the confirmation field to proceed."}
            ), 403

        template = exploit_catalog.get(template_id)
        if template is None:
            return jsonify({"error": f"unknown template: {template_id!r}"}), 404

        # Authorization gate (forces mode=exploit, runs in non-interactive mode
        # which requires VULNPILOT_AUTHORIZED=1 + VULNPILOT_ALLOW_EXPLOIT=1).
        try:
            auth = require_authorization(
                target,
                operator=operator,
                mode="exploit",
                non_interactive=True,
                written_auth_ref=auth_ref,
            )
        except AuthorizationError as exc:
            return jsonify({"error": str(exc)}), 403

        # Build msf client
        msf_cfg = settings.section("metasploit")
        if not msf_cfg.get("enabled"):
            return jsonify(
                {"error": "Metasploit is disabled in configs/config.yaml"}
            ), 503
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
            return jsonify({"error": str(exc)}), 503
        except Exception as exc:
            log.exception("msfrpcd connect failed")
            return jsonify({"error": f"msfrpcd connect failed: {exc}"}), 503

        # Build runner (re-validates env)
        try:
            runner = ExploitRunner(client, authorization=auth)
        except ExploitDisabled as exc:
            return jsonify({"error": str(exc)}), 403

        # Config-level brake
        if settings.get("exploit.force_check_only", False) and not check_only:
            check_only = True

        # Persist parent scan row
        scan_id = _create_scan_row(target, operator, "exploit", auth_ref)
        with session_scope() as s:
            row = s.get(Scan, scan_id)
            if row:
                row.status = "running"

        exploit_cfg = settings.section("exploit")
        timeout = float(exploit_cfg.get("timeout_seconds", 180))

        try:
            outcome = runner.run(
                template,
                target,
                check_only=check_only,
                port=int(port_override) if port_override else None,
                payload=msf_payload or exploit_cfg.get("default_payload") or None,
                lhost=lhost or exploit_cfg.get("default_lhost") or None,
                lport=int(lport) if lport else (exploit_cfg.get("default_lport") or None),
                force=force,
                timeout=timeout,
            )
        except ExploitNotAllowed as exc:
            return jsonify({"error": str(exc)}), 403

        # Persist outcome and finalize scan
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
            row = s.get(Scan, scan_id)
            if row:
                row.status = "complete"
                row.finished_at = datetime.now(timezone.utc)

        return jsonify(
            {
                "scan_id": scan_id,
                "outcome": {
                    "template_id": outcome.template_id,
                    "module": outcome.module,
                    "action": outcome.action,
                    "target": outcome.target,
                    "port": outcome.port,
                    "status": outcome.status,
                    "session_id": outcome.session_id,
                    "duration_seconds": outcome.duration_seconds,
                    "notes": outcome.notes,
                    "output": outcome.output,
                },
            }
        ), 200

    return app


def _template_to_dict(t) -> Dict[str, Any]:
    return {
        "id": t.id,
        "title": t.title,
        "module": t.module,
        "service": t.service,
        "default_port": t.default_port,
        "cve_ids": list(t.cve_ids),
        "risk": t.risk,
        "default_payload": t.default_payload,
        "targets_product": list(t.targets_product),
        "supports_check": t.supports_check,
        "notes": t.notes,
    }


def _create_scan_row(target: str, operator: str, mode: str, auth_ref: str | None) -> int:
    with session_scope() as s:
        scan = Scan(
            target=target, operator=operator, mode=mode,
            status="queued", authorization_ref=auth_ref,
        )
        s.add(scan)
        s.flush()
        return scan.id


def _run_scan_background(scan_id: int, target: str, operator: str, mode: str) -> None:
    """Background worker. Imported lazily to avoid circular imports at startup."""
    from main import run_pipeline  # noqa: WPS433 - intentional lazy import

    try:
        run_pipeline(target=target, operator=operator, mode=mode, scan_id=scan_id)
    except Exception:
        log.exception("Background scan %s failed", scan_id)
        with session_scope() as s:
            scan = s.get(Scan, scan_id)
            if scan:
                scan.status = "error"


if __name__ == "__main__":  # pragma: no cover
    settings = get_settings()
    create_app().run(
        host=settings.get("dashboard.host", "127.0.0.1"),
        port=settings.get("dashboard.port", 5000),
        debug=False,
    )
