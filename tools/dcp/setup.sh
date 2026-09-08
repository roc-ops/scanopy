#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════
# PROFINET DCP Test Environment — VM/LXC setup
#
# Shares a host with the SNMP lab (tools/snmp/) rather than needing its own VM: two macvlan
# children of the same parent interface the SNMP devices already hang off, one for the sim, one
# for a verification client to run dcp-verify.py (or, later, a daemon) from. Same pattern as
# `mv-snmp0`..`mv-snmp27` (`ip link add ... type macvlan mode bridge`), a separate oneshot
# systemd unit owning link creation so a reboot recreates them (mirrors
# tools/snmp/lxc/setup.sh's `snmp-lab-network.service`) — but no IP addressing, since DCP is raw
# Ethernet with nothing to route. Two macvlan siblings under the same bridge-mode parent can talk
# to each other; the parent interface itself cannot reach its own macvlan children (a kernel
# macvlan limitation, not a bug here) — that's why the sim and the verify client each need their
# own child interface rather than sharing the parent.
#
# No conflict with the SNMP devices: DCP has no IP at all (nothing to collide with `mv-snmp*`'s
# 192.168.7.x addresses), and the sim only reacts to EtherType 0x8892 frames, which the SNMP
# devices never send.
#
# Run as root, on the VM:
#   ./setup.sh [parent-interface] [name]
#
# `parent-interface` defaults to eth0 (matching the SNMP VM); `name` is the Name of Station the
# sim answers with, default `scanopy-dcp-sim`.
# ══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IFACE="${1:-eth0}"
DEVICE_NAME="${2:-scanopy-dcp-sim}"

INSTALL_DIR="/opt/dcp-sim"
SIM_IFACE="mv-dcp0"
VERIFY_IFACE="mv-dcp-verify"

echo "=== PROFINET DCP Test Environment Setup ==="

# ── 1. Install Python 3 (stdlib only — no scapy) ───────────────────────
if ! command -v python3 &>/dev/null; then
    echo "Installing python3..."
    apt-get update -qq && apt-get install -y -qq python3 >/dev/null
fi

# ── 2. macvlan children of $IFACE — one for the sim, one for a verify client ──
echo "Installing dcp-lab-network.service (macvlan links, no addressing needed)..."
cat > /usr/local/bin/dcp-lab-network-up.sh << EOF
#!/bin/bash
set -euo pipefail
for mvname in ${SIM_IFACE} ${VERIFY_IFACE}; do
    if ip link show "\$mvname" &>/dev/null; then
        echo "  \$mvname already exists"
    else
        ip link add "\$mvname" link "${IFACE}" type macvlan mode bridge
        echo "  Created \$mvname"
    fi
    ip link set "\$mvname" up
    # A NIC only accepts frames addressed to its own MAC (or broadcast) by default — an
    # arbitrary multicast destination like DCP's 01:0e:cf:00:00:00 is silently dropped before
    # a raw socket ever sees it unless the interface is either in promiscuous mode or has
    # explicitly joined that multicast group. Promiscuous is the simpler of the two for a
    # single-purpose test interface (this dropped every request on first deploy — the sim's
    # own log showed nothing received at all, which is what sent me looking for this).
    ip link set "\$mvname" promisc on
done
EOF
chmod +x /usr/local/bin/dcp-lab-network-up.sh

cat > /etc/systemd/system/dcp-lab-network.service << EOF
[Unit]
Description=Create DCP lab macvlan interfaces
After=sys-subsystem-net-devices-${IFACE}.device
Requires=sys-subsystem-net-devices-${IFACE}.device
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/dcp-lab-network-up.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dcp-lab-network.service

# ── 3. Install the sim script ──────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/dcp-sim.py" "$INSTALL_DIR/dcp-sim.py"
cp "$SCRIPT_DIR/dcp-verify.py" "$INSTALL_DIR/dcp-verify.py"
chmod +x "$INSTALL_DIR/dcp-sim.py" "$INSTALL_DIR/dcp-verify.py"

# ── 4. Sim systemd unit, bound to its own macvlan child ─────────────────
# AF_PACKET raw sockets need CAP_NET_RAW; running as root is the simplest way to get it on a
# single-purpose test VM. Restarts on failure the same way the SNMP agents' units do.
cat > /etc/systemd/system/dcp-sim.service << UNIT
[Unit]
Description=PROFINET DCP Identify responder (test fixture)
After=dcp-lab-network.service
Requires=dcp-lab-network.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/dcp-sim.py ${SIM_IFACE} --name "${DEVICE_NAME}"
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now dcp-sim.service

echo
echo "dcp-sim running on ${SIM_IFACE} (child of ${IFACE}) as '${DEVICE_NAME}'."
echo "Check status: systemctl status dcp-sim"
echo "Check log:    journalctl -u dcp-sim -f"
echo
echo "Verify from this same VM (a sibling macvlan is required — the parent"
echo "interface itself cannot reach its own macvlan children):"
echo "  ${INSTALL_DIR}/dcp-verify.py ${VERIFY_IFACE}"
