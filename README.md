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

## License

MIT - see LICENSE. Use responsibly.
