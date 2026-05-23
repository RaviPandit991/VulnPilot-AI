"""Nmap-backed port + service scanner."""
from __future__ import annotations

from typing import List

from scanner.service_detector import DetectedService
from utils.logger import get_logger

log = get_logger(__name__)


def scan(target: str, args: str = "-sV -sC -T4 --top-ports 1000") -> List[DetectedService]:
    """Run an Nmap scan and return normalized services.

    Requires `python-nmap` and `nmap` binary on PATH.
    """
    try:
        import nmap  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "python-nmap is not installed. Run: pip install python-nmap"
        ) from exc

    log.info("Starting Nmap scan: target=%s args=%s", target, args)
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=args)

    services: List[DetectedService] = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, info in scanner[host][proto].items():
                if info.get("state") != "open":
                    continue
                services.append(
                    DetectedService(
                        port=int(port),
                        protocol=proto,
                        state=info.get("state", "open"),
                        name=info.get("name"),
                        product=info.get("product") or None,
                        version=info.get("version") or None,
                        extrainfo=info.get("extrainfo") or None,
                        banner=info.get("script", {}).get("banner"),
                        cpe=[c for c in [info.get("cpe")] if c],
                    )
                )
    log.info("Nmap scan complete: %d open services", len(services))
    return services
