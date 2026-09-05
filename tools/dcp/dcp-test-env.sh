#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════
# PROFINET DCP Test Environment — deploy/verify/status, mirroring
# tools/snmp/snmp-test-env.sh's shape for a single simulated device.
#
# The fixture is one VM/LXC running dcp-sim.py (see setup.sh), on a segment the
# daemon under test can also reach — raw Ethernet does not route, so this is not
# optional the way it is for SNMP's IP-reachable agents.
#
# Usage: tools/dcp/dcp-test-env.sh deploy|verify|status
#
# Override via env: DCP_VM_HOST (required), DCP_SSH_KEY (default ~/.ssh/dcp-test-vm),
# DCP_IFACE (interface name on the VM, default eth0), DCP_DEVICE_NAME (default scanopy-dcp-sim).
# ══════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SSH_KEY="${DCP_SSH_KEY:-$HOME/.ssh/dcp-test-vm}"
IFACE="${DCP_IFACE:-eth0}"
DEVICE_NAME="${DCP_DEVICE_NAME:-scanopy-dcp-sim}"
REMOTE_DIR="/root/dcp-test"

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
    scp "${opts[@]}" -q "$SCRIPT_DIR/dcp-sim.py" "$SCRIPT_DIR/setup.sh" "root@${vm_host}:${REMOTE_DIR}/"
    echo "→ running setup.sh on the VM (interface=${IFACE}, name=${DEVICE_NAME})"
    ssh "${opts[@]}" "root@${vm_host}" "bash ${REMOTE_DIR}/setup.sh ${IFACE} '${DEVICE_NAME}'"
    echo
    echo "Deploy complete. Verify from a host on the same L2 segment as \$DCP_IFACE:"
    echo "  sudo tools/dcp/dcp-verify.py <your-interface-on-that-segment>"
}

cmd_verify() {
    local vm_host
    vm_host="$(require_vm_host)"
    read -ra opts <<< "$(ssh_opts)"
    echo "→ checking dcp-sim.service is active on the VM"
    ssh "${opts[@]}" "root@${vm_host}" "systemctl is-active dcp-sim.service"
    echo
    echo "That confirms the service is running — it does not confirm DCP actually answers."
    echo "Run dcp-verify.py from a host with a real interface on the same L2 segment as"
    echo "the VM's \$DCP_IFACE (raw Ethernet does not route, so SSH reachability to the VM's"
    echo "management address does not establish this):"
    echo "  sudo tools/dcp/dcp-verify.py <that-interface>"
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
