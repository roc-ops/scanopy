#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════
# PROFINET DCP Test Environment — deploy/verify/status, mirroring
# tools/snmp/snmp-test-env.sh's shape for a single simulated device.
#
# Designed to share a host with the SNMP lab (tools/snmp/) rather than needing its own VM:
# setup.sh creates two macvlan children of DCP_IFACE — one for the sim, one for a verification
# client — the same pattern tools/snmp/lxc/setup.sh already uses for its 28 devices. No IP
# addressing, no conflict with the SNMP devices' 192.168.7.x addresses (DCP has no IP at all),
# and the sim only reacts to EtherType 0x8892.
#
# Usage: tools/dcp/dcp-test-env.sh deploy|verify|status
#
# Override via env: DCP_VM_HOST (required), DCP_SSH_KEY (default ~/.ssh/dcp-test-vm),
# DCP_IFACE (the *parent* interface on the VM the macvlan children attach to, default eth0),
# DCP_DEVICE_NAME (default scanopy-dcp-sim).
# ══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_KEY="${DCP_SSH_KEY:-$HOME/.ssh/dcp-test-vm}"
IFACE="${DCP_IFACE:-eth0}"
DEVICE_NAME="${DCP_DEVICE_NAME:-scanopy-dcp-sim}"
REMOTE_DIR="/root/dcp-test"
SIM_IFACE="mv-dcp0"
VERIFY_IFACE="mv-dcp-verify"

require_vm_host() {
    if [ -z "${DCP_VM_HOST:-}" ]; then
        echo "DCP_VM_HOST is not set — point it at the VM's management address." >&2
        echo "(Raw DCP traffic itself goes out \$DCP_IFACE on the VM, not this address —" >&2
        echo " this is only how deploy/status reach the VM over SSH/ping.)" >&2
        exit 1
    fi
    echo "$DCP_VM_HOST"
}

ssh_opts() {
    if [ -f "$SSH_KEY" ]; then
        echo "-i" "$SSH_KEY" "-o" "StrictHostKeyChecking=accept-new"
    else
        echo "-o" "StrictHostKeyChecking=accept-new"
    fi
}

cmd_deploy() {
    local vm_host
    vm_host="$(require_vm_host)"
    read -ra opts <<< "$(ssh_opts)"
    echo "→ copying tools/dcp to the VM"
    ssh "${opts[@]}" "root@${vm_host}" "mkdir -p ${REMOTE_DIR}"
    scp "${opts[@]}" -q "$SCRIPT_DIR/dcp-sim.py" "$SCRIPT_DIR/dcp-verify.py" "$SCRIPT_DIR/setup.sh" \
        "root@${vm_host}:${REMOTE_DIR}/"
    echo "→ running setup.sh on the VM (parent interface=${IFACE}, name=${DEVICE_NAME})"
    ssh "${opts[@]}" "root@${vm_host}" "bash ${REMOTE_DIR}/setup.sh ${IFACE} '${DEVICE_NAME}'"
    echo
    echo "Deploy complete. Verify from the VM itself (a sibling macvlan is required — the"
    echo "parent interface cannot reach its own macvlan children):"
    echo "  ssh root@${vm_host} /opt/dcp-sim/dcp-verify.py ${VERIFY_IFACE}"
}

cmd_verify() {
    local vm_host
    vm_host="$(require_vm_host)"
    read -ra opts <<< "$(ssh_opts)"
    echo "→ checking dcp-sim.service is active on the VM"
    ssh "${opts[@]}" "root@${vm_host}" "systemctl is-active dcp-sim.service"
    echo "→ running the real protocol-level check from ${VERIFY_IFACE} (the sim's sibling)"
    ssh "${opts[@]}" "root@${vm_host}" "/opt/dcp-sim/dcp-verify.py ${VERIFY_IFACE}"
}

cmd_status() {
    local vm_host
    vm_host="$(require_vm_host)"
    if ping -c 1 -W 2 "$vm_host" >/dev/null 2>&1; then
        echo "✓ $vm_host reachable"
    else
        echo "✗ $vm_host unreachable"
        exit 1
    fi
}

case "${1:-}" in
    deploy) cmd_deploy ;;
    verify) cmd_verify ;;
    status) cmd_status ;;
    *)
        echo "Usage: $0 {deploy|verify|status}"
        echo ""
        echo "  deploy — copy dcp-sim.py + setup.sh to the VM and (re)install the systemd unit"
        echo "  verify — confirm the systemd unit is active (see its own output for the real"
        echo "           protocol-level check, which needs a different vantage point)"
        echo "  status — ping the VM's management address"
        exit 1
        ;;
esac
