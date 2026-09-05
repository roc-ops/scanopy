#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════
# PROFINET DCP Test Environment — VM/LXC setup
#
# The host harness only: installs Python (stdlib only, no scapy needed — see dcp-sim.py's own
# doc), copies the sim script, and creates a systemd unit that answers DCP Identify requests on
# the VM's real interface. Mirrors tools/snmp/lxc/setup.sh's shape for a single simulated device
# rather than 22 — there is only one PROFINET device to simulate right now.
#
# Run as root, on the VM:
#   ./setup.sh [interface] [name]
#
# `interface` defaults to eth0 (matching the SNMP VM's convention); `name` is the Name of Station
# the sim answers with, default `scanopy-dcp-sim`.
# ══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IFACE="${1:-eth0}"
DEVICE_NAME="${2:-scanopy-dcp-sim}"

INSTALL_DIR="/opt/dcp-sim"

echo "=== PROFINET DCP Test Environment Setup ==="

# ── 1. Install Python 3 (stdlib only — no scapy) ───────────────────────
if ! command -v python3 &>/dev/null; then
    echo "Installing python3..."
    apt-get update -qq && apt-get install -y -qq python3 >/dev/null
fi

# ── 2. Install the sim script ──────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/dcp-sim.py" "$INSTALL_DIR/dcp-sim.py"
chmod +x "$INSTALL_DIR/dcp-sim.py"

# ── 3. systemd unit ─────────────────────────────────────────────────────
# AF_PACKET raw sockets need CAP_NET_RAW; running as root is the simplest way to get it on a
# single-purpose test VM. Restarts on failure the same way the SNMP agents' units do.
cat > /etc/systemd/system/dcp-sim.service << UNIT
[Unit]
Description=PROFINET DCP Identify responder (test fixture)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/dcp-sim.py ${IFACE} --name "${DEVICE_NAME}"
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now dcp-sim.service

echo
echo "dcp-sim running on ${IFACE} as '${DEVICE_NAME}'."
echo "Check status: systemctl status dcp-sim"
echo "Check log:    journalctl -u dcp-sim -f"
