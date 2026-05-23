"""Per-service rule packs.

Each rule pack maps a service name to a list of *safe* validation actions.
Actions point at Metasploit auxiliary modules with `RUN_AS=check` semantics or
read-only banner inspections. Anything destructive must NOT live here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Recommendation:
    title: str
    rationale: str
    metasploit_module: str | None = None
    action: str = "check"               # check | scan | banner
    severity_hint: str = "informational"
    options: dict = field(default_factory=dict)


# NOTE: All modules below are auxiliary scanners used in `check`/`scan` mode.
# They do not deliver payloads.
DEFAULT_RULES: Dict[str, List[Recommendation]] = {
    "ssh": [
        Recommendation(
            title="SSH version banner inspection",
            rationale="Identify outdated OpenSSH versions with known CVEs.",
            metasploit_module="auxiliary/scanner/ssh/ssh_version",
            action="scan",
        ),
        Recommendation(
            title="Weak SSH algorithms",
            rationale="Detect deprecated KEX/cipher/MAC algorithms.",
            metasploit_module="auxiliary/scanner/ssh/ssh_enum_algos",
            action="scan",
        ),
    ],
    "http": [
        Recommendation(
            title="HTTP server fingerprint",
            rationale="Detect server software and version banners.",
            metasploit_module="auxiliary/scanner/http/http_version",
            action="scan",
        ),
        Recommendation(
            title="Common files / robots.txt",
            rationale="Identify exposed admin paths or backups.",
            metasploit_module="auxiliary/scanner/http/robots_txt",
            action="scan",
        ),
    ],
    "smb": [
        Recommendation(
            title="SMB protocol versions",
            rationale="Detect SMBv1 and unsigned shares.",
            metasploit_module="auxiliary/scanner/smb/smb_version",
            action="scan",
        ),
        Recommendation(
            title="EternalBlue check (non-exploit)",
            rationale="Probe for MS17-010 vulnerability without exploitation.",
            metasploit_module="auxiliary/scanner/smb/smb_ms17_010",
            action="check",
            severity_hint="critical",
        ),
    ],
    "ftp": [
        Recommendation(
            title="FTP banner / anonymous login",
            rationale="Check for anonymous FTP and outdated banners.",
            metasploit_module="auxiliary/scanner/ftp/anonymous",
            action="scan",
        ),
    ],
    "mysql": [
        Recommendation(
            title="MySQL version probe",
            rationale="Identify MySQL version for CVE matching.",
            metasploit_module="auxiliary/scanner/mysql/mysql_version",
            action="scan",
        ),
    ],
    "postgresql": [
        Recommendation(
            title="PostgreSQL version probe",
            rationale="Identify PostgreSQL version for CVE matching.",
            metasploit_module="auxiliary/scanner/postgres/postgres_version",
            action="scan",
        ),
    ],
    "rdp": [
        Recommendation(
            title="BlueKeep (CVE-2019-0708) check",
            rationale="Non-exploit probe for CVE-2019-0708.",
            metasploit_module="auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
            action="check",
            severity_hint="critical",
        ),
    ],
}
