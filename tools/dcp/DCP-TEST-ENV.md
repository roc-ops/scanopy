# PROFINET DCP Test Environment

**Status: proposed, not provisioned.** §12 of the OT-discovery scoping report is blunt about this
gap: DCP needs a responder on the same L2 segment and no such environment exists. This document is
a concrete proposal for closing it, written because designing it is cheap and useful even before
anyone provisions it — not a description of something already running.

## What exists today (Tier 1 — in-repo, no external infrastructure)

`dcp-test-env.sh` + the `--ignored` test `dcp_live_round_trip_over_a_real_veth_pair`
(`backend/src/daemon/discovery/service/network/dcp/live_test.rs`) round-trip a real DCP Identify
exchange over a real Linux veth pair. This proves the daemon's own encoder against its own decoder
over the actual kernel/NIC-driver path — real EtherType/multicast filtering, real byte order —
which the in-memory unit tests (`packet.rs`, `identify.rs`) cannot exercise. **It does not prove
interop with a real PROFINET device.** Linux-only, needs root/CAP_NET_ADMIN; this session (macOS
sandbox, no root) never ran it — see the branch's Work Summary.

## What's missing (Tier 2 — a genuine third-party responder)

The precedent this project already has for "test a probe against a real implementation" is
`tools/probe-servers/` + `live_servers.rs`: real protocol servers in local Docker containers,
built from source (`Dockerfile.kerberos` et al.) when no suitable image exists. DCP can't reuse
that shape directly — Docker's default bridge network NATs rather than carrying raw multicast
Ethernet, and there's no TCP/UDP port to `docker run -p` forward. Two adjustments, same principle:

**A real, spec-conformant device stack, not a hand-rolled mock.** [p-net](https://github.com/rtlabs-com/p-net)
(RT-Labs, BSD-3, C) is an open-source PROFINET device stack used for real vendor
pre-certification — genuinely independent of this codebase's own understanding of the wire
format, which is the entire point: it would catch a mistaken byte-layout claim this branch's own
tests, built from the same understanding, structurally cannot. Its `pn_dev` sample application
already answers DCP Identify out of the box.

**Networking: `Dockerfile.p-net` + a macvlan network, or a small Proxmox VM.** Raw L2 multicast
needs the container (or VM) to have a real presence on the segment:
- **Docker `macvlan`**: `docker network create -d macvlan --subnet=<segment> -o parent=<host-nic>
  dcp-segment`, then run the p-net container attached to it. Lighter weight than a VM, but ties
  the daemon-under-test to running on the same host's network namespace as the container (or a
  second macvlan endpoint) — workable for local manual verification, awkward for CI.
- **A dedicated Proxmox VM**, mirroring `tools/snmp/lxc/`'s existing pattern (a host harness
  script + systemd units) on its own segment/VLAN the test daemon can also reach. Closer to how
  the SNMP simulator environment already works, and the natural home if this is meant to be a
  standing environment other engineers reach for, not a one-off.

**Recommendation**: start with the Docker macvlan route for a first manual verification pass (low
setup cost, answers "does a real device stack accept our exact bytes" quickly), and only invest in
the Proxmox VM if DCP verification becomes a recurring need the way SNMP's already is.

## What Tier 2 would prove, and what it still wouldn't

Answers the two biggest unverified claims in the branch: whether a real implementation's Identify
Response is unicast or multicast (`packet.rs`'s module doc flags this as unconfirmed), and whether
the exact block/TLV layout this branch built from Wireshark's dissector matches what a real stack
sends. It would **not** prove interop with any specific vendor's device in the field — p-net is a
reference stack, not a Siemens/Rockwell/Beckhoff PLC, and §11 of the scoping report's own caution
about vendor-specific quirks (S7comm's COTP behaviour, for the closest analogy) applies here too:
real hardware can diverge from a reference implementation in ways only a real device surfaces.
