# PROFINET DCP Test Environment

A real fixture and a real daemon scan against it — not an in-process mock standing in for both
sides. §12 of the OT-discovery scoping report says plainly that no such environment exists yet;
this is it.

**Runs locally, on this Mac** — the same machine the installed daemon-under-test runs on, on the
same interface it actually scans. DCP is raw Ethernet and does not route, so that's what makes a
real scan able to reach the sim at all.

## History: why this isn't on the SNMP lab VM

The first version of this shared the SNMP lab's remote Proxmox VM (`tools/snmp/`'s host), the
same way the SNMP fixtures do — two `macvlan` children of the VM's `eth0`, one for the sim, one
for a verification client, confirmed answering real DCP Identify traffic between them
(2026-09-08). That precedent doesn't carry over to DCP the way it does to SNMP: SNMP is routable
UDP, so a lab host anywhere with IP connectivity works. **DCP is raw Ethernet, addressed to a
multicast MAC, and does not cross an L3 boundary.** A daemon running on this Mac, on its own LAN,
can never see a sim on a remote VM's segment no matter how the two are IP-numbered — confirmed
the hard way: a real scan run here found nothing, because the daemon's own subnet (`en0`,
`192.168.4.0/22`) and the VM's (`192.168.7.0/24` on a physically separate network reached over a
routed link) are not the same L2 segment, whatever the address ranges suggest on paper. Moved
local rather than adding a second host on that segment, since the daemon-under-test already runs
here.

## What this is

`dcp-sim.py` is a standalone PROFINET DCP Identify responder — a fake device. It does **not**
import or share code with `backend/src/daemon/discovery/service/network/dcp/`, on purpose: a sim
built from the client's own encoder/decoder can only confirm the client agrees with itself.
Written independently from the same wire-format reference (Wireshark's `packet-pn-dcp.c`
dissector — see `dcp/packet.rs`'s own module doc), so a daemon scan against it is a real test of
whether the two independent implementations agree on the wire format, the way a real `snmpd`
agent is for SNMP.

`dcp-verify.py` sends one Identify request and prints whatever answers — the same role
`snmpget`/`snmpwalk` play for the SNMP lab: a protocol-level check independent of both the daemon
and the sim's own responder logic, to confirm the fixture actually answers before trusting a full
daemon scan against it.

Both talk raw Ethernet through `bpf_raw.py` — macOS's `/dev/bpf*` character device, driven
directly via `ioctl`/`read`/`write` (stdlib + `fcntl` only, no scapy). macOS has no Linux
`AF_PACKET`, so this is the real equivalent: the same mechanism
`backend/vendor/pnet_datalink/src/bpf.rs` uses for the daemon itself. `bpf_raw.py`'s ioctl
request codes and the `bpf_hdr`/`ifreq` struct layouts it hand-packs are cross-checked against a
small compiled C program against this machine's actual SDK headers
(`net/bpf.h`), not just against the vendored Rust source — both agree exactly.

## Running it

```
tools/dcp/dcp-test-env.sh start    # launches dcp-sim.py in the background on $DCP_IFACE (default en0)
tools/dcp/dcp-test-env.sh verify   # sends one real Identify request, prints whatever answers
tools/dcp/dcp-test-env.sh status
tools/dcp/dcp-test-env.sh stop
```

Set `DCP_IFACE` if the installed daemon scans on something other than `en0`. Both `start` and
`verify` need `sudo` — `/dev/bpf*` is root-owned (`crw-------`). `start` runs `dcp-sim.py` under
`sudo` in the background, has it write its own pid to `/tmp/dcp-sim.pid` once it's actually bound
and listening (not derived from shell-level `$!` after `sudo cmd &`, which isn't reliable across
sudo configurations), and logs to `/tmp/dcp-sim.log`.

## What's confirmed and what isn't

**Confirmed:** the protocol logic itself — `dcp-sim.py` answered a real `dcp-verify.py` Identify
request correctly when both ran on the VM's two macvlan siblings (2026-09-08, before the move
described above). That logic is untouched by the move; only the raw-socket layer under it
changed from `AF_PACKET` to `bpf_raw.py`.

**Not yet confirmed:** whether macOS's BPF actually delivers a frame written by one process's
`/dev/bpf*` fd to a *different* process's `/dev/bpf*` fd bound to the same physical interface —
the mechanism `dcp-sim.py` (answering) and a real daemon scan (asking) depend on when both run on
this Mac's same `en0`. The port to `bpf_raw.py` was built on BSD's documented BPF architecture
(the tap point sits in the driver's transmit path itself, shared by every listener regardless of
which fd wrote the frame — the same reason `tcpdump` on a machine sees its own outgoing traffic),
not on a live test: this session could not get a working `sudo` session to run one. Confirm with:

```
tools/dcp/dcp-test-env.sh start
tools/dcp/dcp-test-env.sh verify
```

If `verify` sees an answer, the mechanism is confirmed and a real daemon scan (with the sim
running) should find `scanopy-dcp-sim` as a no-IP, MAC-only host the same way. If `verify` times
out with the sim confirmed running (`status`), that assumption was wrong and this needs a
different approach — say so rather than trusting the reasoning over the result.

## Running a real daemon scan against it

1. `tools/dcp/dcp-test-env.sh start` (confirm with `verify` first).
2. Run discovery from the installed daemon on this Mac, same as any other scan.
3. Confirm in the DB: a host with no IP addresses, one interface carrying the sim's MAC,
   sourced `AttributeSource::ProfinetDcp`, named `scanopy-dcp-sim` (from the Identify Response's
   Name of Station block).

This is the last piece of end-to-end proof the unit tests (`dcp/packet.rs`, `dcp/identify.rs`)
can't provide on their own — they're honest about testing this daemon's understanding of the wire
format against itself; `dcp-verify.py` proves it against an independent implementation; only a
real daemon run proves the *whole* path (submission, minting, provenance, L2 visibility) end to
end.

## What this still doesn't prove

`dcp-sim.py` is a reference implementation written for this purpose, not a real PROFINET device —
it settles whether the daemon's parser/builder agree with an independent reading of the same spec
material, not whether a real Siemens/Rockwell/Beckhoff device behaves identically. In particular
it does not resolve the unicast-vs-multicast question `dcp/packet.rs`'s module doc flags as
unverified — `dcp-sim.py` replies unicast because that's what the daemon's current receive filter
assumes, not because it's confirmed as the real-world answer. For that, the options are the same
as before: IEC 61158-6-10 itself, or a genuine third-party stack. RT-Labs'
[p-net](https://github.com/rtlabs-com/p-net) (BSD-3, used for real vendor pre-certification)
remains the candidate if that level of confidence is ever needed — its `pn_dev` sample app
already answers DCP Identify — but building and deploying it is a larger lift than this simple
responder and hasn't been done here.
