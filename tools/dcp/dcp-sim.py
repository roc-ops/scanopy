#!/usr/bin/env python3
"""A standalone PROFINET DCP Identify responder — a fake device for the daemon to scan.

Independent of `backend/src/daemon/discovery/service/network/dcp/`: this does not import or
reuse that code, on purpose. A sim built from the client's own encoder/decoder can only ever
confirm the client agrees with itself; it shares nothing with the daemon so the daemon's parser
and this script's builder have to agree on the wire format itself, and a mismatch in either
direction shows up as a real scan failure — the same value the SNMP lab's real `snmpd` agents
have over an in-process mock. Written from the wire format Wireshark's `packet-pn-dcp.c`
dissector documents (see `dcp/packet.rs`'s own module doc for the same reference) — same source
material as the Rust side, independently implemented, no shared code.

Runs locally on this Mac, on the same interface (and so the same L2 segment) the daemon under
test itself scans on — DCP is raw Ethernet and does not route, so "same host as the daemon" is
what makes a real scan able to reach this at all (see DCP-TEST-ENV.md). Raw frame I/O goes
through `bpf_raw.py` (macOS `/dev/bpf*`, stdlib + ioctl only, no scapy) instead of Linux's
`AF_PACKET` the original VM-hosted version used — protocol logic below (frame building/parsing)
is unchanged from that version.

    sudo ./dcp-sim.py en0 --name press-line-3

Answers every Identify Request it sees on `en0` with an Identify Response echoing the request's
Xid, carrying the given name in a Device Properties / Name of Station block, sent unicast back to
the requester's own MAC. (Unicast is this script's own choice for the reply, matching what the
daemon's receive-side filter currently assumes — it does not settle whether a *real* PROFINET
device replies unicast or multicast, which is still an open question noted in `dcp/packet.rs`.)
"""

import argparse
import os
import struct
import sys

import bpf_raw

ETHERTYPE_PROFINET = 0x8892
DCP_IDENTIFY_MULTICAST = bytes.fromhex("010ecf000000")

FRAME_ID_DCP_IDENT_REQ = 0xFEFE
FRAME_ID_DCP_IDENT_RES = 0xFEFF

SERVICE_ID_IDENTIFY = 0x05
SERVICE_TYPE_REQUEST = 0x00
SERVICE_TYPE_RESPONSE_SUCCESS = 0x01

OPTION_DEVICE = 0x02
SUBOPTION_DEVICE_NAME_OF_STATION = 0x02


def build_identify_response(dest_mac: bytes, src_mac: bytes, xid: int, name: str) -> bytes:
    name_bytes = name.encode("utf-8")
    block = bytes([OPTION_DEVICE, SUBOPTION_DEVICE_NAME_OF_STATION]) + struct.pack(
        ">H", len(name_bytes)
    ) + name_bytes
    if len(name_bytes) % 2 == 1:
        block += b"\x00"  # blocks pad to an even total length

    dcp_header = struct.pack(
        ">HBBIHH",
        FRAME_ID_DCP_IDENT_RES,
        SERVICE_ID_IDENTIFY,
        SERVICE_TYPE_RESPONSE_SUCCESS,
        xid,
        0,  # reserved on a response
        len(block),
    )
    ethernet_header = dest_mac + src_mac + struct.pack(">H", ETHERTYPE_PROFINET)
    return ethernet_header + dcp_header + block


def parse_identify_request(frame: bytes):
    """Returns (source_mac, xid) if `frame` is a well-formed Identify Request, else None."""
    if len(frame) < 14 + 12:
        return None
    dest_mac, src_mac, ethertype = frame[0:6], frame[6:12], struct.unpack(">H", frame[12:14])[0]
    if ethertype != ETHERTYPE_PROFINET:
        return None
    if dest_mac != DCP_IDENTIFY_MULTICAST:
        return None  # this sim only answers the multicast identify group, like a real station

    payload = frame[14:]
    frame_id, service_id, service_type, xid = struct.unpack(">HBBI", payload[0:8])
    if frame_id != FRAME_ID_DCP_IDENT_REQ:
        return None
    if service_id != SERVICE_ID_IDENTIFY or service_type != SERVICE_TYPE_REQUEST:
        return None
    return src_mac, xid


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("interface", help="interface to listen/answer on, e.g. en0")
    parser.add_argument("--name", default="scanopy-dcp-sim", help="Name of Station to answer with")
    parser.add_argument(
        "--pidfile",
        help="write our own pid here once bound and listening, for a wrapper script to track "
        "us reliably when backgrounded under sudo (shell-level $! after 'sudo ... &' isn't "
        "trustworthy across sudo configurations)",
    )
    args = parser.parse_args()

    own_mac = bpf_raw.get_mac(args.interface)
    fd = bpf_raw.open_bpf(args.interface)

    if args.pidfile:
        with open(args.pidfile, "w") as f:
            f.write(str(os.getpid()))

    print(f"listening on {args.interface} ({own_mac.hex(':')}), answering as '{args.name}'", file=sys.stderr)

    while True:
        frame = bpf_raw.read_frame(fd, timeout_s=None)
        if frame is None:
            continue  # shouldn't happen — blocking wait
        # No MAC-based self-loopback check here on purpose: this sim runs on the same physical
        # interface as the daemon-under-test (and dcp-verify.py), so every local sender shares
        # en0's one hardware MAC as its source address — a MAC comparison would silently
        # discard a legitimate request from the daemon along with our own echoed frames. There
        # is nothing to filter anyway: we only ever send Responses, never Requests, so the only
        # thing that could loop back to us is one of our own Responses, and
        # parse_identify_request already rejects anything that isn't a Request by content
        # (frame_id/service_type), which correctly excludes it without needing a MAC check.
        parsed = parse_identify_request(frame)
        if parsed is None:
            continue
        requester_mac, xid = parsed
        response = build_identify_response(requester_mac, own_mac, xid, args.name)
        bpf_raw.write_frame(fd, response)
        print(f"answered identify request from {requester_mac.hex(':')} (xid={xid:#x})", file=sys.stderr)


if __name__ == "__main__":
    main()
