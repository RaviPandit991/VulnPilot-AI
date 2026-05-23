"""Authorization gate.

Every scan that touches a remote target MUST pass through `require_authorization`.
This module also enforces a coarse target allowlist so the framework cannot be
casually pointed at arbitrary public addresses.
"""
from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass
from typing import Iterable

# Target ranges considered safe-by-default for lab testing.
# Public targets must be opted-in via VULNPILOT_ALLOW_PUBLIC=1 AND user confirmation.
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::1/128"),
]


class AuthorizationError(Exception):
    """Raised when the user has not provided required authorization."""


@dataclass
class Authorization:
    target: str
    operator: str
    mode: str
    public_target_acknowledged: bool
    written_authorization_ref: str | None


def _is_private(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # Hostname - cannot determine without DNS; treat as public for safety.
        return False
    return any(ip in net for net in _PRIVATE_NETWORKS)


def _confirm(prompt: str) -> bool:
    """Interactive yes/no confirmation. Auto-fails in non-tty environments."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(f"{prompt} [type 'I AUTHORIZE' to confirm]: ").strip()
    except EOFError:
        return False
    return answer == "I AUTHORIZE"


_BANNER = """
================================================================================
                          VulnPilot AI - LEGAL NOTICE
================================================================================
You are about to perform active security testing against a remote target.

By proceeding you confirm:
  * You own the target system OR have explicit written authorization to test it.
  * You accept full responsibility for any consequences of this scan.
  * You understand unauthorized scanning may violate computer-misuse laws.

If any of the above is NOT true, abort now (Ctrl+C).
================================================================================
"""


def require_authorization(
    target: str,
    *,
    operator: str | None = None,
    mode: str = "safe",
    non_interactive: bool = False,
    written_auth_ref: str | None = None,
) -> Authorization:
    """Block execution until the operator confirms authorization.

    Parameters
    ----------
    target : str
        IP or hostname being scanned.
    operator : str
        Identity of the person running the scan (logged in audit trail).
    mode : str
        One of `safe`, `audit`, `exploit`.
    non_interactive : bool
        If True, `VULNPILOT_AUTHORIZED=1` env var is required instead of prompt.
    written_auth_ref : str
        Reference to written authorization (e.g. SOW/ticket id) for audit.
    """
    print(_BANNER)

    public = not _is_private(target)
    allow_public = os.environ.get("VULNPILOT_ALLOW_PUBLIC") == "1"

    if public and not allow_public:
        raise AuthorizationError(
            f"Target {target!r} is not in a private/lab network. "
            "Set VULNPILOT_ALLOW_PUBLIC=1 and provide written authorization "
            "to scan public hosts."
        )

    if mode not in {"safe", "audit", "exploit"}:
        raise AuthorizationError(f"Unknown mode: {mode!r}")

    if mode == "exploit" and os.environ.get("VULNPILOT_ALLOW_EXPLOIT") != "1":
        raise AuthorizationError(
            "Exploit mode is disabled. Set VULNPILOT_ALLOW_EXPLOIT=1 only in a "
            "controlled lab and pass --i-have-authorization."
        )

    if non_interactive:
        if os.environ.get("VULNPILOT_AUTHORIZED") != "1":
            raise AuthorizationError(
                "Non-interactive run requires VULNPILOT_AUTHORIZED=1."
            )
    else:
        if not _confirm(
            f"Confirm you are authorized to test {target} in mode={mode}"
        ):
            raise AuthorizationError("Authorization not granted by operator.")

    return Authorization(
        target=target,
        operator=operator or os.environ.get("USER", "unknown"),
        mode=mode,
        public_target_acknowledged=public,
        written_authorization_ref=written_auth_ref,
    )


def filter_to_authorized(targets: Iterable[str]) -> list[str]:
    """Return only targets that are private (lab) addresses."""
    return [t for t in targets if _is_private(t)]
