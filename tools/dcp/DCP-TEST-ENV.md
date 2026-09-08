# PROFINET DCP Test Environment

Mirrors `tools/snmp/`'s shape: a real fixture on a real host, and a real daemon scan against it —
not an in-process mock standing in for both sides. §12 of the OT-discovery scoping report says
plainly that no such environment exists yet; this is it.

**Status: deployed and verified working**, on the same host as the SNMP lab
(`root@192.168.7.230`, key `~/.ssh/snmp-test-vm` — see "Sharing a host with the SNMP lab" below).
A real multicast Identify Request sent from one macvlan interface was answered by `dcp-sim.py` on
a sibling macvlan interface, over real raw sockets on real Linux network devices — not simulated,
not mocked. Confirmed 2026-09-08:
```
$ ssh root@192.168.7.230 /opt/dcp-sim/dcp-verify.py mv-dcp-verify
sent Identify Request from 22:1b:b7:fe:82:36 (xid=0xfbcf946), waiting 3.0s...
  ANSWERED by 8a:2e:53:fe:33:50  name_of_station='scanopy-dcp-sim'
```

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

## Sharing a host with the SNMP lab

Rather than a dedicated VM, the DCP sim shares the SNMP lab's existing host (`snmp-test`,
`root@192.168.7.230`, key `~/.ssh/snmp-test-vm` — already trusted, set up for `make snmp-deploy`).
`setup.sh` creates two `macvlan` children of `eth0` — `mv-dcp0` (the sim) and `mv-dcp-verify` (a
verification client) — the identical pattern `tools/snmp/lxc/setup.sh` already uses for its 28
`mv-snmp0`..`mv-snmp27` devices, via the same oneshot-systemd-unit approach
(`dcp-lab-network.service`, mirroring `snmp-lab-network.service`) so a reboot recreates them. No
conflict with the SNMP devices: DCP has no IP at all (nothing to collide with `mv-snmp*`'s
192.168.7.x addresses), and the sim only reacts to EtherType `0x8892`, which SNMP never sends.

**Two macvlan children, not one, because of a real Linux limitation**: the parent interface
(`eth0`, the VM's own IP stack) cannot reach its own macvlan children — sibling-to-sibling works in
`bridge` mode, parent-to-child does not. So the sim and anything talking to it (the verify client,
or eventually a daemon) each need their own child interface.

**The gotcha that actually broke the first deploy**: a NIC only accepts frames addressed to its
own MAC (or broadcast) by default. DCP's multicast destination (`01:0e:cf:00:00:00`) is neither, so
without either promiscuous mode or explicitly joining that multicast group, the kernel drops the
Identify Request before any raw socket sees it — the sim's own log showed *nothing* received at
all on the first attempt, which is what gave it away. `setup.sh` now sets both macvlan interfaces
promiscuous. This is specific to the Python sim/verify scripts (plain `AF_PACKET` sockets); the
actual Rust daemon code doesn't need this fix — `pnet::datalink::Config::default()` already sets
`promiscuous: true`, confirmed by reading `pnet_datalink`'s own source, and both `dcp/channel.rs`
and `arp/broadcast.rs` build their config via `..Default::default()`.

Redeploy or update the sim:
```
export DCP_VM_HOST=192.168.7.230
export DCP_SSH_KEY=~/.ssh/snmp-test-vm
tools/dcp/dcp-test-env.sh deploy
```
`dcp-lab-network.service` is `Type=oneshot, RemainAfterExit=yes` — if it's already active, a plain
`deploy` (which calls `enable --now`) won't necessarily re-run it to pick up a script change; force
that with `ssh root@192.168.7.230 systemctl restart dcp-lab-network.service`.

## The part that's genuinely different from SNMP: reachability

SNMP is IP/UDP — the lab host just needs to be routable, and `verify`/a real daemon scan can run
from anywhere with IP reachability. **DCP is raw Ethernet and does not route.** Whatever runs
`dcp-verify.py` or the actual daemon-under-test needs a real NIC on the *same L2 segment* — in
practice, its own macvlan child of `eth0` on this same host (a real daemon binary would need one
too, the same way `mv-dcp-verify` stands in for it here), or another host bridged to that segment.

## Running a real daemon scan against it

The sim is confirmed answering (see the transcript above). What's left is pointing an actual
Scanopy daemon at it:

1. Run a Scanopy daemon (this branch's build) on a host with a NIC on the sim's segment — the
   natural choice is a third macvlan child of `eth0` on this same VM, mirroring `mv-dcp-verify`.
2. Point it at a real (or dev) Scanopy server and run discovery.
3. Confirm: a host appears with no IP addresses, one interface carrying the sim's MAC
   (`8a:2e:53:fe:33:50`), sourced `AttributeSource::ProfinetDcp`, named `scanopy-dcp-sim` (from the
   Identify Response's Name of Station block).

This is the last piece of end-to-end proof the unit tests (`dcp/packet.rs`, `dcp/identify.rs`)
can't provide on their own — they're honest about testing this daemon's understanding of the wire
format against itself; `dcp-verify.py` proved it against an independent implementation; only a real
daemon run proves the *whole* path (submission, minting, provenance, L2 visibility) end to end.

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
