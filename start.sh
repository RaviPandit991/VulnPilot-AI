#!/usr/bin/env bash
# VulnPilot AI - one-command launcher.
#
# Activates the venv (if present), sets the safety env vars, prints a
# pre-flight summary, then launches the dashboard. Designed for a
# controlled lab where the operator doesn't want to retype the same
# environment variables every session.
#
# Usage:
#   ./start.sh              # foreground
#   ./start.sh --no-msf     # skip the msfrpcd reachability check
#
# Safety:
#   - This script ONLY sets env vars in its own process - it does NOT
#     export them globally or modify shell rc files.
#   - The two safety gates in utils/auth_check.py still apply at
#     request time. This script just sets them automatically because
#     you have explicitly opted in by running it.

set -euo pipefail

# Move to the script's directory so relative paths work.
cd "$(dirname "$0")"

echo "===== VulnPilot AI launcher ====="

# ---------------- venv activation ----------------
if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
  echo "  venv:        $(which python)"
else
  echo "  venv:        (none found at .venv - using system python)"
  echo "               If you hit ImportErrors, create one with:"
  echo "                  python3 -m venv .venv"
  echo "                  source .venv/bin/activate"
  echo "                  pip install -r requirements.txt"
fi

# ---------------- safety env vars ----------------
# These are the two gates checked by utils/auth_check.py. We set them
# because the operator explicitly invoked this lab launcher. The gates
# stay in the code so a plain `python -m dashboard.app` still requires
# them - this only changes the *launcher* experience, not the *runtime*
# safety contract.
#
# ALTERNATIVE: edit configs/config.yaml -> safety.lab_mode: true
# That makes the dashboard work without any env vars or this launcher.
export VULNPILOT_ALLOW_EXPLOIT=1
export VULNPILOT_AUTHORIZED=1
echo "  env:         VULNPILOT_ALLOW_EXPLOIT=1  VULNPILOT_AUTHORIZED=1"

# ---------------- optional msfrpcd reachability check ----------------
SKIP_MSF_CHECK=0
for arg in "$@"; do
  if [[ "$arg" == "--no-msf" ]]; then
    SKIP_MSF_CHECK=1
  fi
done

if [[ $SKIP_MSF_CHECK -eq 0 ]]; then
  if command -v ss >/dev/null 2>&1 \
     && ss -ltn 2>/dev/null | grep -q ':55553\b'; then
    echo "  msfrpcd:     listening on 127.0.0.1:55553  (good)"
  else
    cat <<'EOM'
  msfrpcd:     NOT listening on 127.0.0.1:55553

      The Exploit and Sessions tabs need msfrpcd running. Open
      another terminal and start it BEFORE clicking Run Exploit:

          msfrpcd -P msf -S -a 127.0.0.1 -U msf

      (Pass --no-msf to skip this check.)
EOM
  fi
fi

# ---------------- nuclei reachability check (informational only) ----------------
if command -v nuclei >/dev/null 2>&1; then
  echo "  nuclei:      $(nuclei -version 2>&1 | head -1 | tr -d '\n')"
else
  echo "  nuclei:      not installed (Nuclei tab will show install hint)"
  echo "               Install:  sudo apt install nuclei  &&  nuclei -update-templates"
fi

# ---------------- launch ----------------
echo
echo "  Launching dashboard at http://127.0.0.1:5000"
echo "  Press Ctrl+C to stop."
echo
exec python -m dashboard.app
