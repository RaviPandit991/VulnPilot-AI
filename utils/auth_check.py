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


def _lab_mode_enabled() -> bool:
    """Return True if `safety.lab_mode` is set to true in config.yaml.

    Lab mode is the operator-edited equivalent of setting both env vars
    on every launch. The check is wrapped in a try/except so this module
    stays importable even if settings are missing (e.g. during unit
    tests or first-time setup before config.yaml is created).
    """
    try:
        from configs.settings import get_settings  # local import - avoid cycles
        return bool(get_settings().get("safety.lab_mode", False))
    except Exception:
        return False

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
    """Return True iff `target` lives in a private/lab network.

    Resolution order:
      1. If `target` is already an IP literal, check it against
         _PRIVATE_NETWORKS directly.
      2. Otherwise treat it as a hostname and try a DNS lookup. If
         ANY of the resolved A/AAAA records is in a private network,
         return True - this lets operators target lab hosts by their
         mDNS name (e.g. `metasploitable.local`).
      3. If DNS fails (timeout, NXDOMAIN, no network, ...) we fall
         back to "public" so the operator can opt in via
         VULNPILOT_ALLOW_PUBLIC=1 if they really mean it.
    """
    # Step 1: direct IP literal
    try:
        ip = ipaddress.ip_address(target)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        pass

    # Step 2: hostname -> DNS lookup. We use getaddrinfo so we cover
    # both IPv4 and IPv6 in a single call. socket import is local so
    # this module stays cheap to import even when network is down.
    import socket
    try:
        # AF_UNSPEC + SOCK_STREAM gives one entry per A/AAAA record.
        infos = socket.getaddrinfo(target, None, socket.AF_UNSPEC,
                                   socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return False  # treat as public on resolution failure

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if any(ip in net for net in _PRIVATE_NETWORKS):
            return True
    return False


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

    # Lab mode (configs/config.yaml -> safety.lab_mode: true) skips the
    # env-var gates entirely. The operator has explicitly opted in by
    # editing the config file; we still log a one-line warning so this
    # is never silent.
    lab_mode = _lab_mode_enabled()
    if lab_mode:
        print(
            "[auth] safety.lab_mode=true - env-var gates bypassed. "
            "Disable in configs/config.yaml before running outside the lab.",
            file=sys.stderr,
        )

    if (mode == "exploit"
            and os.environ.get("VULNPILOT_ALLOW_EXPLOIT") != "1"
            and not lab_mode):
        raise AuthorizationError(
            "Exploit mode is disabled. Set VULNPILOT_ALLOW_EXPLOIT=1 only in a "
            "controlled lab and pass --i-have-authorization. "
            "(Or set safety.lab_mode: true in configs/config.yaml.)"
        )

    if non_interactive:
        if os.environ.get("VULNPILOT_AUTHORIZED") != "1" and not lab_mode:
            raise AuthorizationError(
                "Non-interactive run requires VULNPILOT_AUTHORIZED=1. "
                "(Or set safety.lab_mode: true in configs/config.yaml.)"
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
