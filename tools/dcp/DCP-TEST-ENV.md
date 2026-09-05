# PROFINET DCP Test Environment

Mirrors `tools/snmp/`'s shape: a real fixture on a real VM, and a real daemon scan against it —
not an in-process mock standing in for both sides. §12 of the OT-discovery scoping report says
plainly that no such environment exists yet; this is it, plus what's still needed to stand it up.

## What this is

`dcp-sim.py` is a standalone PROFINET DCP Identify responder — a fake device. It does **not**
import or share code with `backend/src/daemon/discovery/service/network/dcp/`, on purpose: a sim
built from the client's own encoder/decoder can only confirm the client agrees with itself. Written
independently from the same wire-format reference (Wireshark's `packet-pn-dcp.c` dissector — see
`dcp/packet.rs`'s own module doc), so a daemon scan against it is a real test of whether the two
independent implementations agree on the wire format, the way a real `snmpd` agent is for SNMP.

Stdlib-only Python (`socket` with `AF_PACKET`), matching `tools/snmp/lxc/snmp-bulk-refuser.py`'s
own precedent — no scapy dependency to install. Linux-only (`AF_PACKET` is Linux-specific), so it
runs on the VM, not on a developer's Mac.

## What's deployed vs. what's still needed

**Written, and its pure encode/decode logic checked locally** (`build_identify_response`/
`parse_identify_request` round-tripped against `dcp-verify.py`'s own independent parse/build —
see the two scripts' docstrings): `dcp-sim.py`, `setup.sh` (systemd unit installer), `dcp-verify.py`
(a standalone protocol-level check — send one Identify Request, print whatever answers — the DCP
equivalent of `snmpget` in `tools/snmp/snmp-test-env.sh verify`), `dcp-test-env.sh`
(deploy/verify/status orchestration).

**Not yet provisioned**: the VM itself. `dcp-test-env.sh deploy` needs `DCP_VM_HOST` pointed at a
real box — this session has no Proxmox access to create one. Once a VM/LXC exists with a network
interface on a segment reachable by wherever the daemon will run:

```
export DCP_VM_HOST=<vm-management-address>
tools/dcp/dcp-test-env.sh deploy
```

## The part that's genuinely different from SNMP: reachability

SNMP is IP/UDP — the lab VM just needs to be routable, and `verify`/a real daemon scan can run
from anywhere with IP reachability. **DCP is raw Ethernet and does not route.** Whatever runs
`dcp-verify.py` or the actual daemon-under-test needs a real NIC on the *same L2 segment* as the
VM's DCP-facing interface — SSH/ping reachability to the VM's management address does not
establish this. In practice that means either the daemon runs on the Proxmox host itself (bridged
to the same segment), or another VM/LXC is bridged to it.

## Running a real daemon scan against it

Once the VM is up and `dcp-verify.py` confirms it answers:

1. Run a Scanopy daemon (this branch's build) on a host with a NIC on the sim's segment, with that
   interface in its `--interfaces` allowlist (or no filter, to include everything).
2. Point it at a real (or dev) Scanopy server and run discovery.
3. Confirm: a host appears with no IP addresses, one interface carrying the sim's MAC, sourced
   `AttributeSource::ProfinetDcp`, and (if the response's Name of Station block parsed) a name
   matching whatever `--name` the sim was deployed with.

This is the actual end-to-end proof the unit tests (`dcp/packet.rs`, `dcp/identify.rs`) cannot
provide on their own — they're honest about testing this daemon's understanding of the wire format
against itself, not against an independent implementation or a real device.

## What this still doesn't prove

`dcp-sim.py` is a reference implementation written for this purpose, not a real PROFINET device —
it settles whether the daemon's parser/builder agree with an independent reading of the same spec
material, not whether a real Siemens/Rockwell/Beckhoff device behaves identically. In particular it
does not resolve the unicast-vs-multicast question `dcp/packet.rs`'s module doc flags as unverified
— `dcp-sim.py` replies unicast because that's what the daemon's current receive filter assumes, not
because it's confirmed as the real-world answer. For that, the options are the same as before:
IEC 61158-6-10 itself, or a genuine third-party stack. RT-Labs' [p-net](https://github.com/rtlabs-com/p-net)
(BSD-3, used for real vendor pre-certification) remains the candidate if that level of confidence is
ever needed — its `pn_dev` sample app already answers DCP Identify — but building and deploying it
is a larger lift than this simple responder and hasn't been done here.
