# VulnPilot AI — Complete Guide (Kali Linux)

Authorized penetration testing and vulnerability validation framework, built
specifically with Kali Linux operators in mind.

> **LEGAL & ETHICAL NOTICE**
> Use this tool **only** against systems you own or for which you hold
> explicit written authorization. Unauthorized scanning or exploitation is
> illegal under the Computer Fraud and Abuse Act (US), the Computer Misuse
> Act (UK), the IT Act (India), and equivalent laws worldwide. The authors
> disclaim all liability for misuse. The framework's authorization gate
> exists to remind you of this — do not bypass it.

---

## Table of Contents

1. [Purpose](#1-purpose)
2. [How It Works](#2-how-it-works)
3. [Project Layout](#3-project-layout)
4. [Prerequisites on Kali Linux](#4-prerequisites-on-kali-linux)
5. [Installation](#5-installation)
6. [Configuration](#6-configuration)
7. [Running Your First Scan](#7-running-your-first-scan)
8. [Using the Web Dashboard](#8-using-the-web-dashboard)
9. [Modes & the Safety Model](#9-modes--the-safety-model)
10. [Setting Up a Lab Target](#10-setting-up-a-lab-target)
11. [Enabling Metasploit Integration](#11-enabling-metasploit-integration)
12. [Reports](#12-reports)
13. [Troubleshooting](#13-troubleshooting)
14. [FAQ](#14-faq)
15. [Quick Reference Cheatsheet](#15-quick-reference-cheatsheet)

---

## 1. Purpose

**VulnPilot AI** is a smart penetration-testing assistant that automates the
boring, repetitive parts of vulnerability assessment so you can focus on
analysis and reporting. It:

- Scans a target with **Nmap** or **RustScan**
- Detects open ports, services, and versions
- Maps detected versions to known **CVEs** via the CIRCL CVE database
- Uses a **rule-based AI decision engine** to recommend safe validation checks
- Drives **Metasploit auxiliary scanners** (read-only, allowlisted) over RPC
- Produces **JSON / Markdown / PDF reports** with severity ratings and
  remediation tips
- Stores everything in **SQLite/PostgreSQL** for historical tracking
- Exposes a **Flask web dashboard** for managing and reviewing scans

**Who is it for?** Authorized red-teamers, blue-teamers running internal
assessments, students learning offensive security on lab VMs, and developers
auditing their own infrastructure.

**What it deliberately is *not***: a "hack any IP" button. Every active
operation is gated behind an authorization prompt and a hard module
allowlist. Destructive exploits, DoS modules, and post-exploitation tools
are filtered out by design.

---

## 2. How It Works

```
   ┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌─────────────┐
   │  Target  │───▶│   Nmap / │───▶│   Service    │───▶│  CVE Map    │
   │ (lab IP) │    │ RustScan │    │  Detector    │    │ (CIRCL API) │
   └──────────┘    └──────────┘    └──────────────┘    └──────┬──────┘
                                                              │
   ┌─────────────┐    ┌──────────────┐    ┌──────────────┐    │
   │  Reports    │◀───│  Metasploit  │◀───│  Decision    │◀───┘
   │ JSON/MD/PDF │    │  RPC client  │    │  Engine +    │
   └─────────────┘    │  (safe-only) │    │  Allowlist   │
                      └──────────────┘    └──────────────┘
```

Pipeline stages:

1. **Authorization gate** — refuses to proceed without explicit operator confirmation; blocks public IPs unless `VULNPILOT_ALLOW_PUBLIC=1`.
2. **Recon** — port scan + service/version fingerprinting.
3. **CVE mapping** — looks up vendor/product on CIRCL, keeps the top 10 by CVSS.
4. **Decision engine** — selects safe checks from per-service rule packs (SSH, HTTP, SMB, FTP, MySQL, PostgreSQL, RDP).
5. **Module selector** — enforces a hard allowlist (`auxiliary/scanner/*` only) and denylist (`exploit/*`, `dos/*`, `payload/*`, `post/*`, `*_overflow$`).
6. **Validation** — runs allowlisted Metasploit auxiliary scanners (`check`/`scan` actions only) if MSF is enabled.
7. **Persistence** — writes everything to the SQLite DB.
8. **Reporting** — produces JSON, Markdown, and PDF artifacts.

---

## 3. Project Layout

```
VulnPilot-AI/
├── main.py                      CLI orchestrator: scan / dashboard / initdb
├── requirements.txt             Python deps
├── README.md                    Short overview
├── docs/
│   ├── USAGE.md                 This file
│   └── generate_pdf.py          Local PDF generator for this guide
├── configs/
│   ├── config.yaml              Editable config (engine, MSF, ports, DB)
│   └── settings.py              YAML loader
├── scanner/
│   ├── nmap_scanner.py          python-nmap wrapper
│   ├── rustscan_scanner.py      RustScan wrapper -> hands off to Nmap
│   └── service_detector.py      DetectedService dataclass + CPE parser
├── ai_engine/
│   ├── decision_engine.py       Rule-based recommender + LLM hook
│   ├── rules.py                 Per-service rule packs (safe checks only)
│   └── cve_mapper.py            Service -> CVE list
├── exploit_engine/
│   ├── metasploit_client.py     pymetasploit3 wrapper, classifies output
│   └── module_selector.py       Allowlist / denylist enforcement
├── reporting/
│   ├── report_generator.py      JSON + Markdown
│   └── pdf_export.py            PDF via reportlab
├── dashboard/
│   ├── app.py                   Flask app + REST API
│   ├── templates/index.html
│   └── static/{app.css, app.js}
├── database/
│   ├── db.py                    SQLAlchemy session manager
│   └── models.py                Scan / Service / Vulnerability / ExploitRun
└── utils/
    ├── auth_check.py            Authorization gate (mandatory)
    ├── cve_api.py               CIRCL/NVD lookup with caching
    └── logger.py                Project-wide logger
```

---

## 4. Prerequisites on Kali Linux

**Good news**: Kali ships with most of what you need. You only need to verify
versions and add Python 3.10+ if you're on an older Kali release.

### Verify what you already have

```bash
python3 --version       # need >= 3.10
nmap --version          # preinstalled on Kali
rustscan --version      # preinstalled on Kali 2022.x+
msfconsole --version    # preinstalled on Kali (Metasploit)
git --version           # preinstalled
pip3 --version          # preinstalled
```

### If anything is missing

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap git curl

# If rustscan is missing on your Kali release:
sudo apt install -y rustscan
# fallback: install via cargo (see Troubleshooting)

# If Metasploit is missing:
sudo apt install -y metasploit-framework
```

---

## 5. Installation

### 5.1 Clone the repository

```bash
cd ~
git clone https://github.com/RaviPandit991/VulnPilot-AI.git
cd VulnPilot-AI
git checkout feat/scaffold        # until the PR is merged into main
```

### 5.2 Create a Python virtual environment

Always use a venv on Kali — it keeps VulnPilot's deps isolated from system
Python (Kali enforces PEP 668 and will refuse `pip install` outside a venv).

```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should now see `(.venv)` at the start of your shell prompt.

### 5.3 Install Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs `python-nmap`, `pymetasploit3`, `SQLAlchemy`, `Flask`,
`reportlab`, and friends. The whole thing should take 30–90 seconds.

### 5.4 Initialize the database

```bash
python main.py initdb
```

Creates `data/vulnpilot.db` (SQLite) with all tables.

### 5.5 Smoke test

```bash
python main.py --help
python main.py scan --help
```

If both print help text, you're installed correctly.

---

## 6. Configuration

All defaults live in `configs/config.yaml`. Open it with any editor:

```bash
nano configs/config.yaml
```

### Frequently edited keys

| Key                      | Default                                | Purpose                                                                |
| ------------------------ | -------------------------------------- | ---------------------------------------------------------------------- |
| `app.mode`               | `safe`                                 | Default mode if not overridden on the CLI                              |
| `scanner.engine`         | `nmap`                                 | Set to `rustscan` for faster port discovery on large ranges            |
| `scanner.nmap_args`      | `-sV -sC -T4 --top-ports 1000`         | Add `-p-` to scan all 65k ports (slower)                               |
| `metasploit.enabled`     | `false`                                | Flip to `true` after starting `msfrpcd`                                |
| `metasploit.password`    | `msf`                                  | **Change this** before enabling                                        |
| `database.url`           | `sqlite:///data/vulnpilot.db`          | Use `postgresql+psycopg://user:pw@host/db` for production              |
| `reporting.formats`      | `[json, markdown, pdf]`                | Drop `pdf` to skip PDF generation                                      |
| `dashboard.port`         | `5000`                                 | Web UI port                                                            |
| `dashboard.secret_key`   | `change-me-in-production`              | **Change this** before exposing the dashboard anywhere                 |
| `logging.level`          | `INFO`                                 | Set to `DEBUG` while troubleshooting                                   |

### Environment variables

| Variable                     | Effect                                                                  |
| ---------------------------- | ----------------------------------------------------------------------- |
| `VULNPILOT_AUTHORIZED=1`     | Skip the interactive prompt (only with `--non-interactive`)             |
| `VULNPILOT_ALLOW_PUBLIC=1`   | Permit scanning of public (non-RFC1918) targets                         |
| `VULNPILOT_ALLOW_EXPLOIT=1`  | Required to use `--mode exploit` (still allowlist-restricted)           |
| `VULNPILOT_LOG_LEVEL`        | Override `logging.level` for one session                                |
| `VULNPILOT_LOG_FILE`         | Override the rotating log file path                                     |

---

## 7. Running Your First Scan

### 7.1 Smoke test against your own loopback

This won't find anything interesting, but it proves the pipeline works:

```bash
python main.py scan --target 127.0.0.1 --mode safe --auth-ref "self-test"
```

You'll see the legal banner. Type **`I AUTHORIZE`** (uppercase, exact match)
and press Enter. The scan runs, and you should see output like:

```
2026-05-23 21:03:14 | INFO    | scanner.nmap_scanner | Starting Nmap scan...
2026-05-23 21:03:18 | INFO    | scanner.nmap_scanner | Nmap scan complete: 2 open services
2026-05-23 21:03:18 | INFO    | __main__              | [2/5] CVE mapping for 2 services
...
Done. 2 services, 0 CVEs (C:0 H:0).
```

Reports are written to `reports/`:

```bash
ls reports/
# report-127.0.0.1-20260523T210320Z.json
# report-127.0.0.1-20260523T210320Z.md
# report-127.0.0.1-20260523T210320Z.pdf
```

### 7.2 Common CLI patterns

```bash
# Default safe scan with Nmap
python main.py scan --target 192.168.56.101

# Use RustScan for fast port discovery (still hands off to Nmap for service ID)
python main.py scan --target 192.168.56.101 --engine rustscan

# Tag your operator identity and authorization reference for audit
python main.py scan --target 192.168.56.101 \
    --operator alice@corp \
    --auth-ref SOW-2026-001

# Non-interactive (e.g. cron / CI) — requires VULNPILOT_AUTHORIZED=1
VULNPILOT_AUTHORIZED=1 python main.py scan \
    --target 192.168.56.101 --non-interactive --auth-ref auto-audit
```

### 7.3 What happens during a scan

The CLI logs every stage:

```
[1/5] Port + service scan (nmap)
[2/5] CVE mapping for N services
[3/5] Building safe-validation plan
[4/5] M safe modules selected
[5/5] Generating report
```

If any stage fails, the scan row in the DB is marked `error` and the stack
trace is in `logs/vulnpilot.log` (or wherever you set `logging.file`).

---

## 8. Using the Web Dashboard

```bash
python main.py dashboard --host 127.0.0.1 --port 5000
```

Open http://127.0.0.1:5000 in Firefox (Kali's default).

You can:

- **Queue a new scan** — fill in target, operator, mode, authorization ref
- **See running and finished scans** — table refreshes every 5 seconds
- **Click a row** to view its services, CVEs, and Metasploit run results

⚠ **Do not bind to `0.0.0.0`** unless the dashboard sits behind a VPN, SSH
tunnel, or auth proxy. The dashboard has no built-in auth in this scaffold
(adding auth is on the roadmap).

---

## 9. Modes & the Safety Model

| Mode      | Recon | CVE map | Banner checks | MSF aux scans | Exploit modules | Notes                                            |
| --------- | :---: | :-----: | :-----------: | :-----------: | :-------------: | ------------------------------------------------ |
| `safe`    |   ✅  |   ✅    |       ✅      |       ✅      |       ❌        | Default. No login attempts.                      |
| `audit`   |   ✅  |   ✅    |       ✅      |       ✅      |       ❌        | Adds extra auxiliary scanners.                   |
| `exploit` |   ✅  |   ✅    |       ✅      |       ✅      |   *blocked*     | Even in this mode the allowlist blocks payloads. |

The hard guarantees enforced by `exploit_engine/module_selector.py`:

- **Allowlist:** only `auxiliary/scanner/*`, `auxiliary/gather/*`, and
  `auxiliary/admin/http/*` modules can be loaded.
- **Denylist (regex):** `^exploit/`, `dos/`, `_overflow$`, `payload/`, `post/`
  are rejected before they ever hit Metasploit.
- **Authorization gate:** every CLI scan and every dashboard-queued scan
  passes through `utils/auth_check.py` first.
- **Network gate:** non-RFC1918 targets are blocked unless
  `VULNPILOT_ALLOW_PUBLIC=1` is set.

---

## 10. Setting Up a Lab Target

You need a deliberately vulnerable VM on a private network. **Never point
this at production without written authorization.**

### Option A: Metasploitable 2 (easiest)

```bash
# Download
mkdir -p ~/labs && cd ~/labs
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip

# Open the .vmx in VMware Workstation/Player or convert and import into VirtualBox.
# Set network to "Host-only" so it's only reachable from your Kali host.
```

Login (lab only, do not deploy elsewhere): `msfadmin` / `msfadmin`.

Inside the VM, run `ifconfig` to find the IP (typically `192.168.56.x` on
host-only nets), then from Kali:

```bash
python main.py scan --target 192.168.56.101 --auth-ref "lab-self-owned"
```

### Option B: Metasploitable 3 (modern)

Build with Vagrant (Windows or Ubuntu target):

```bash
sudo apt install -y vagrant virtualbox
git clone https://github.com/rapid7/metasploitable3.git
cd metasploitable3
./build.sh ubuntu1404         # or windows_2008 for the Windows target
vagrant up ub1404
```

Default IP: `192.168.56.4`.

### Option C: VulnHub VMs / DVWA / OWASP Juice Shop

Any deliberately vulnerable VM in a private network works.

---

## 11. Enabling Metasploit Integration

Metasploit is **off by default**. To turn it on in a lab:

### 11.1 Initialize the MSF database (first time only)

```bash
sudo msfdb init
```

### 11.2 Start the RPC daemon

In a separate terminal, leave this running:

```bash
msfrpcd -P S3cretRPCPass! -S -a 127.0.0.1
```

- `-P` sets the RPC password (use a strong one)
- `-S` disables SSL (loopback only — fine for `127.0.0.1`)
- `-a 127.0.0.1` binds to localhost so nothing external can connect

### 11.3 Update VulnPilot config

```bash
nano configs/config.yaml
```

```yaml
metasploit:
  host: 127.0.0.1
  port: 55553
  username: msf
  password: "S3cretRPCPass!"     # match what you passed to msfrpcd
  ssl: false
  enabled: true
```

### 11.4 Re-run a scan

```bash
python main.py scan --target 192.168.56.101 --mode safe --auth-ref "lab"
```

The `[4/5]` stage will now load auxiliary scanners against detected services.
Results appear in `reports/*-*.md` under **Validation Results** and in
the `exploit_runs` table.

### 11.5 Stop the daemon when done

```bash
pkill -f msfrpcd
```

---

## 12. Reports

After every scan, three artifacts are written to `reports/`:

```
report-<target>-<timestamp>.json     full machine-readable
report-<target>-<timestamp>.md       markdown for GitHub / Obsidian / etc.
report-<target>-<timestamp>.pdf      printable PDF for stakeholders
```

The Markdown and PDF include:

- Metadata (target, operator, mode, generated_at)
- Summary (open services, total CVEs, severity breakdown)
- Per-service tables of matched CVEs with CVSS
- Validation results from Metasploit auxiliary scanners
- Generic remediation guidance (patch, harden, restrict, re-scan)

The JSON is the canonical output — feed it into your own tooling, ticketing
systems, or SIEM.

---

## 13. Troubleshooting

### "ModuleNotFoundError: No module named 'yaml'"
You forgot to activate the venv or run `pip install -r requirements.txt`.

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### "externally-managed-environment" error on `pip install`
Kali enforces PEP 668. You must use a venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Do **not** pass `--break-system-packages` to fix this — that pollutes system
Python and will eventually break apt.

### "AUTHORIZATION REQUIRED: Target ... is not in a private/lab network"
You pointed it at a public IP. Either pick a lab IP, or if you genuinely have
written authorization for the public target:

```bash
VULNPILOT_ALLOW_PUBLIC=1 python main.py scan --target <ip> --auth-ref <ref>
```

### Nmap returns "0 services"
Some Kali setups need `sudo` for SYN scans. Either:

```bash
sudo .venv/bin/python main.py scan --target ...
```

…or change `scanner.nmap_args` in `config.yaml` to `-sT -sV -sC` (TCP connect
scan, no root required).

### "rustscan: command not found"
Install it (Kali repo first, cargo as fallback):

```bash
sudo apt install -y rustscan
# or
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
cargo install rustscan
```

Or just stick with the Nmap engine — RustScan is optional.

### "Cannot connect to msfrpcd" / connection refused
`msfrpcd` isn't running. In a separate terminal:

```bash
msfrpcd -P yourpass -S -a 127.0.0.1
```

Wait ~10 seconds for it to start, then re-run the scan.

### CVE lookups return nothing
The CIRCL API is occasionally rate-limited or down. Cached results live in
memory only — restart the process to clear. CVE results are best-effort: a
"clean" report doesn't mean the target is patched, it means nothing matched
the heuristic. Always validate manually.

### Dashboard won't load
Check the port isn't taken:

```bash
ss -ltnp | grep 5000
```

Pick a different port:

```bash
python main.py dashboard --port 8080
```

---

## 14. FAQ

**Q: Can I scan a domain name?**
Yes — `--target example.lab` works. The auth gate treats hostnames as public
unless they resolve at scan time, so set `VULNPILOT_ALLOW_PUBLIC=1` if needed.

**Q: Does it support IPv6?**
Yes for the auth gate (loopback + `fc00::/7` are allowed). Whether Nmap
returns useful results for an IPv6 target depends on your `nmap_args`; add
`-6` if you need it.

**Q: Can I scan multiple targets at once?**
Not in this scaffold — single target per CLI invocation. Multi-target /
CIDR support is on the roadmap. As a workaround, loop in shell:

```bash
for t in 192.168.56.{101..110}; do
  python main.py scan --target "$t" --non-interactive --auth-ref "lab-batch"
done
```

(with `VULNPILOT_AUTHORIZED=1` exported)

**Q: Where does scan history live?**
`data/vulnpilot.db` (SQLite). Inspect with `sqlite3 data/vulnpilot.db
'.tables'` or any DB browser.

**Q: How do I delete a scan?**
For now, drop the row directly:

```bash
sqlite3 data/vulnpilot.db "DELETE FROM scans WHERE id = 5;"
```

(`Service`, `Vulnerability`, `ExploitRun` rows cascade.)

**Q: Can I add my own service rules?**
Yes — edit `ai_engine/rules.py`. Add a new key to `DEFAULT_RULES` matching
the Nmap service name (`ssh`, `http`, etc.) with a list of `Recommendation`
objects. Modules **must** match the safe-prefix allowlist.

**Q: Does it support Active Directory testing?**
Not in this scaffold. AD-specific modules and Kerberos checks are on the
roadmap.

**Q: Is the LLM hook actually using an LLM?**
Only if you opt in (`ai.use_local_llm: true` and supply a model). Default
behavior is pure rule-based.

---

## 15. Quick Reference Cheatsheet

```bash
# One-time setup
git clone https://github.com/RaviPandit991/VulnPilot-AI.git
cd VulnPilot-AI && git checkout feat/scaffold
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py initdb

# Common operations (all from inside venv)
python main.py scan --target <ip> --auth-ref <ref>
python main.py scan --target <ip> --engine rustscan
python main.py dashboard --port 5000
python main.py initdb

# With Metasploit (separate terminal)
msfrpcd -P yourpass -S -a 127.0.0.1
# then set metasploit.enabled: true in configs/config.yaml

# Inspect results
ls reports/
sqlite3 data/vulnpilot.db ".tables"
sqlite3 data/vulnpilot.db "SELECT id, target, status FROM scans;"

# Tail logs
tail -f logs/vulnpilot.log

# Generate this guide as a PDF (reportlab must be installed)
python docs/generate_pdf.py
```

---

**Remember**: VulnPilot AI reduces *time*, not *responsibility*. Every scan
you launch is something you have to be ready to justify. Use it on systems
you own, document your authorization, and validate findings manually before
you act on them.
