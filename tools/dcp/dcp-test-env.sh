#!/bin/bash
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════
# A real raw-socket link for the PROFINET DCP `--ignored` live test.
#
# DCP is raw Ethernet with a custom EtherType and a multicast destination — Docker's default
# bridge NATs rather than carrying that, and there is no TCP/UDP port to `docker run -p` forward
# (see `tools/probe-servers/` for that shape, which doesn't fit here). A Linux veth pair does
# carry real multicast Ethernet frames, entirely locally, with no external infrastructure: this
# script creates one pair and nothing else. Both ends stay in the default network namespace —
# there's no need for namespace isolation just to prove two raw sockets on two real interfaces
# can exchange a real frame.
#
# Linux only (needs `ip link add type veth`, root or CAP_NET_ADMIN). Not runnable on macOS/BSD.
#
#   sudo ./dcp-test-env.sh up
#   cd backend && cargo test --lib -- --ignored dcp_live
#   sudo ./dcp-test-env.sh down
#
# What this proves and what it doesn't: a real round-trip over the actual kernel/NIC-driver path
# a scripted fake channel can't exercise (real EtherType/multicast filtering, real byte-order on
# the wire) — our own encoder against our own decoder. It does NOT prove interop with a real
# PROFINET device. See DCP-TEST-ENV.md for that (Tier 2, not provisioned by this script).
# ══════════════════════════════════════════════════════════════════════

IFACE_A="dcp-test-a"
IFACE_B="dcp-test-b"

case "${1:-up}" in
  up)
    if ip link show "$IFACE_A" >/dev/null 2>&1; then
        echo "$IFACE_A already exists; run 'down' first if this is stale."
        exit 1
    fi
    ip link add "$IFACE_A" type veth peer name "$IFACE_B"
    ip link set "$IFACE_A" up
    ip link set "$IFACE_B" up
    echo "veth pair up: $IFACE_A <-> $IFACE_B"
    ;;
  down)
    ip link del "$IFACE_A" 2>/dev/null || echo "nothing to remove"
    ;;
  *)
    echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
