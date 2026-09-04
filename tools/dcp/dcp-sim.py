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

Stdlib only (`socket` with `AF_PACKET`), matching `snmp-bulk-refuser.py`'s own precedent — no
scapy dependency to install on the VM. Linux only (`AF_PACKET` is Linux-specific).

    sudo ./dcp-sim.py eth0 --name press-line-3

Answers every Identify Request it sees on `eth0` with an Identify Response echoing the request's
Xid, carrying the given name in a Device Properties / Name of Station block, sent unicast back to
the requester's own MAC. (Unicast is this script's own choice for the reply, matching what the
daemon's receive-side filter currently assumes — it does not settle whether a *real* PROFINET
device replies unicast or multicast, which is still an open question noted in `dcp/packet.rs`.)
"""

import argparse
import socket
import struct
import sys

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
    parser.add_argument("interface", help="interface to listen/answer on, e.g. eth0")
    parser.add_argument("--name", default="scanopy-dcp-sim", help="Name of Station to answer with")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_PROFINET))
    sock.bind((args.interface, 0))
    own_mac = sock.getsockname()[4]

    print(f"listening on {args.interface} ({own_mac.hex(':')}), answering as '{args.name}'", file=sys.stderr)

    while True:
        frame, _ = sock.recvfrom(2048)
        if frame[6:12] == own_mac:
            continue  # our own outgoing frame, looped back
        parsed = parse_identify_request(frame)
        if parsed is None:
            continue
        requester_mac, xid = parsed
        response = build_identify_response(requester_mac, own_mac, xid, args.name)
        sock.send(response)
        print(f"answered identify request from {requester_mac.hex(':')} (xid={xid:#x})", file=sys.stderr)


if __name__ == "__main__":
    main()
