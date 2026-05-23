"""Flask web dashboard for VulnPilot AI.

Endpoints:
    GET  /                  -> dashboard UI
    GET  /api/scans         -> list scans
    GET  /api/scans/<id>    -> scan detail with services + vulnerabilities
    POST /api/scans         -> queue a new scan (requires authorization payload)
"""
from __future__ import annotations

import threading
from typing import Any, Dict

from flask import Flask, jsonify, render_template, request
from sqlalchemy import select

from configs.settings import get_settings
from database.db import init_db, session_scope
from database.models import ExploitRun, Scan, Service, Vulnerability
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

    return app


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
