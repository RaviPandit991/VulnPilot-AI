# VulnPilot AI

An AI-assisted cybersecurity automation framework for **authorized** penetration
testing and vulnerability validation in controlled environments.

> WARNING - LEGAL & ETHICAL USE ONLY
>
> This tool is intended **exclusively** for security testing of systems you own
> or for which you have explicit written authorization. Unauthorized scanning
> or exploitation of systems is illegal in most jurisdictions and may violate
> the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and
> equivalent laws worldwide. The authors disclaim all liability for misuse.

## Features

- Automated reconnaissance with Nmap / RustScan
- Service and version enumeration
- CVE mapping (NVD / CIRCL)
- Rule-based AI decision engine for safe check selection
- Metasploit RPC integration (safe-validation mode by default)
- JSON / Markdown / PDF reports with CVSS severity
- Flask web dashboard with real-time scan status
- SQLite/PostgreSQL persistence of scans and findings

## Architecture

```
Target -> Port Scan -> Service Detection -> CVE Mapping
       -> AI Recommender -> Safe Validation -> Report
```

## Project layout

```
scanner/         Port + service scanning
exploit_engine/  Metasploit RPC + safe module selection
ai_engine/       Rule-based / LLM decision engine
reporting/       Report generation (JSON, MD, PDF)
dashboard/       Flask web UI
database/        SQLAlchemy models & session
utils/           Authorization gate, logger, CVE API
configs/         Configuration files
main.py          CLI orchestrator
```

## Prerequisites

- Python 3.10+
- `nmap` installed and on PATH
- (Optional) `rustscan` on PATH for fast scans
- (Optional) Metasploit RPC daemon: `msfrpcd -P <pass> -S -a 127.0.0.1`

## Install

```bash
git clone https://github.com/RaviPandit991/VulnPilot-AI.git
cd VulnPilot-AI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

CLI scan (will prompt for authorization):

```bash
python main.py scan --target 192.168.56.101 --mode safe
```

Launch dashboard:

```bash
python main.py dashboard --host 127.0.0.1 --port 5000
```

## Safety model

VulnPilot operates in three modes; **`safe` is the default**:

| Mode      | Behavior                                                       |
| --------- | -------------------------------------------------------------- |
| `safe`    | Recon + CVE mapping + non-intrusive validation (check actions) |
| `audit`   | Adds login bruteforce-disabled auxiliary checks                |
| `exploit` | Disabled by default. Requires `--i-have-authorization` flag    |

Destructive modules (DoS, file overwrite, payload-staging) are filtered out by
the module selector's allowlist regardless of mode.

## Exploit testing feature

The exploit feature lets you validate a finding by running a single
**curated** exploit module against a target port. It is the natural follow-up
to a `safe`-mode scan that surfaced a vulnerable service.

### Layered safety controls

A run requires **all** of the following to succeed:

1. `metasploit.enabled: true` in `configs/config.yaml` and `msfrpcd` reachable.
2. `VULNPILOT_ALLOW_EXPLOIT=1` in the process environment.
3. The operator passes through `require_authorization(mode="exploit", ...)` -
   either an interactive `I AUTHORIZE` prompt or `VULNPILOT_AUTHORIZED=1` for
   non-interactive runs.
4. Target is in a private/lab network (`10/8`, `172.16/12`, `192.168/16`,
   `127/8`) unless `VULNPILOT_ALLOW_PUBLIC=1` is also set.
5. The Metasploit module path must appear by **exact match** in
   `exploit_engine.module_selector.EXPLOIT_ALLOWLIST`. Adding entries there is
   a deliberate code-review step, separate from adding to the catalog.
6. Default action is `check` - validates vulnerability without delivering a
   payload. Switching to a real exploit run is a separate explicit flag.
7. Modules tagged `EXPLOIT_HIGH_RISK` (e.g. EternalBlue, BSOD risk) are forced
   to check-only unless the operator additionally passes `--force` / `force=true`.
8. Every run is persisted to the `exploit_runs` table with the operator
   identity, authorization reference, options (passwords redacted), and result.

### Catalog

Available templates (run `python main.py exploit --list-catalog` to see live):

| ID | Service | Default port | CVE | Risk |
| -- | ------- | ------------ | --- | ---- |
| `vsftpd_234_backdoor`        | ftp     | 21   | CVE-2011-2523 | critical |
| `samba_usermap_script`       | smb     | 139  | CVE-2007-2447 | critical |
| `distcc_exec`                | distccd | 3632 | CVE-2004-2687 | critical |
| `unreal_ircd_3281_backdoor`  | irc     | 6667 | CVE-2010-2075 | critical |
| `java_rmi_server`            | java-rmi| 1099 | -             | high     |
| `tomcat_mgr_upload`          | http    | 8080 | -             | high     |
| `ms17_010_eternalblue`       | smb     | 445  | CVE-2017-0144 | critical (forced check-only without `--force`) |

### CLI

```bash
# Show catalog
python main.py exploit --list-catalog

# Check-only (default) - safest, no payload delivered
export VULNPILOT_ALLOW_EXPLOIT=1
python main.py exploit \
    --target 192.168.56.101 \
    --port 21 \
    --auth-ref SOW-2026-001

# Run a specific template by id
python main.py exploit \
    --target 192.168.56.101 \
    --module vsftpd_234_backdoor \
    --auth-ref SOW-2026-001

# Actually exploit (lab targets only). Requires both env vars.
export VULNPILOT_AUTHORIZED=1
python main.py exploit \
    --target 192.168.56.101 \
    --module vsftpd_234_backdoor \
    --actually-exploit \
    --lhost 192.168.56.1 --lport 4444 \
    --auth-ref SOW-2026-001 \
    --non-interactive
```

Exit codes:
- `0` - at least one outcome completed (vulnerable / not-vulnerable / completed / session-opened)
- `1` - all outcomes errored
- `2` - authorization or input validation failed
- `3` - Metasploit RPC unavailable

### Dashboard

The web dashboard's "Exploit Test" card mirrors the CLI:

- Loads the catalog from `GET /api/exploit/catalog` on page load.
- Displays a red banner if the server is missing `VULNPILOT_ALLOW_EXPLOIT=1`
  or has `exploit.force_check_only: true` in config.
- Mode toggle defaults to "Check only". Switching to "Actually exploit"
  reveals payload / LHOST / LPORT / force-high-risk inputs.
- Submit requires the operator to type `I AUTHORIZE` in the confirmation
  field and provide a written authorization reference.
- POSTs to `/api/exploit/run` and shows the outcome JSON inline.

### Configuration

```yaml
# configs/config.yaml
metasploit:
  enabled: true              # required for exploit feature

exploit:
  default_lhost: "192.168.56.1"
  default_lport: 4444
  default_payload: ""        # empty -> use template's recommended payload
  timeout_seconds: 180
  force_check_only: false    # org-wide brake: forces check-only even if user
                             # passes --actually-exploit
```

### Adding a new exploit template

1. Add an `ExploitTemplate` entry to
   `exploit_engine/exploit_catalog.py::CATALOG`.
2. Add the **exact** module path to
   `exploit_engine/module_selector.py::EXPLOIT_ALLOWLIST`.
3. If the module has high collateral risk (BSOD, kernel corruption), also add
   it to `EXPLOIT_HIGH_RISK`.
4. Get the change reviewed before merging.

## License

MIT - see LICENSE. Use responsibly.
