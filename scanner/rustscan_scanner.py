"""RustScan wrapper - fast port discovery, then hand off to Nmap for service ID."""
from __future__ import annotations

import shutil
import subprocess
from typing import List

from scanner import nmap_scanner
from scanner.service_detector import DetectedService
from utils.logger import get_logger

log = get_logger(__name__)


def _rustscan_ports(target: str, args: str) -> list[int]:
    if not shutil.which("rustscan"):
        raise RuntimeError("rustscan binary not found on PATH")

    cmd = ["rustscan", "-a", target, "--no-banner", "--greppable"] + args.split()
    log.info("Running RustScan: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"rustscan failed: {proc.stderr.strip()}")

    # Greppable output: "ip -> [22,80,443]"
    ports: list[int] = []
    for line in proc.stdout.splitlines():
        if "->" in line and "[" in line:
            chunk = line.split("[", 1)[1].rstrip("]\n ")
            for part in chunk.split(","):
                part = part.strip()
                if part.isdigit():
                    ports.append(int(part))
    return sorted(set(ports))


def scan(target: str, rustscan_args: str = "-b 4500 -t 2000 --ulimit 5000") -> List[DetectedService]:
    """Discover ports with RustScan, then service-fingerprint with Nmap."""
    ports = _rustscan_ports(target, rustscan_args)
    if not ports:
        log.info("RustScan found no open ports on %s", target)
        return []
    port_list = ",".join(str(p) for p in ports)
    return nmap_scanner.scan(target, args=f"-sV -sC -p {port_list}")
