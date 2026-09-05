#!/usr/bin/env python3
"""Send one PROFINET DCP Identify request and print whatever answers.

A protocol-level check independent of the daemon and of dcp-sim.py's own responder logic — the
same role `snmpget`/`snmpwalk` play in `tools/snmp/snmp-test-env.sh`'s `verify`: confirm the
fixture actually answers before trusting a full daemon scan against it. Must run on a host with a
real interface on the same L2 segment as the sim (raw Ethernet does not route) — typically the
Proxmox host itself, or another VM/LXC on the same bridge.

    sudo ./dcp-verify.py eth0
"""

import argparse
import secrets
import socket
import struct
import sys
import time

ETHERTYPE_PROFINET = 0x8892
DCP_IDENTIFY_MULTICAST = bytes.fromhex("010ecf000000")
FRAME_ID_DCP_IDENT_REQ = 0xFEFE
FRAME_ID_DCP_IDENT_RES = 0xFEFF
SERVICE_ID_IDENTIFY = 0x05
SERVICE_TYPE_REQUEST = 0x00
SERVICE_TYPE_RESPONSE_SUCCESS = 0x01
OPTION_DEVICE = 0x02
SUBOPTION_DEVICE_NAME_OF_STATION = 0x02


def build_identify_request(src_mac: bytes, xid: int) -> bytes:
    block = bytes([0xFF, 0xFF, 0, 0])  # All-Selector, no value
    dcp_header = struct.pack(">HBBIHH", FRAME_ID_DCP_IDENT_REQ, SERVICE_ID_IDENTIFY, SERVICE_TYPE_REQUEST, xid, 100, len(block))
    return DCP_IDENTIFY_MULTICAST + src_mac + struct.pack(">H", ETHERTYPE_PROFINET) + dcp_header + block


def parse_name_of_station(block: bytes):
    i = 0
    while i + 4 <= len(block):
        option, suboption, length = block[i], block[i + 1], struct.unpack(">H", block[i + 2 : i + 4])[0]
        value = block[i + 4 : i + 4 + length]
        if option == OPTION_DEVICE and suboption == SUBOPTION_DEVICE_NAME_OF_STATION:
            return value.decode(errors="replace")
        i += 4 + length + (length % 2)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("interface")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_PROFINET))
    sock.bind((args.interface, 0))
    sock.settimeout(args.timeout)
    own_mac = sock.getsockname()[4]

    xid = secrets.randbits(24) | 0x0F000000
    sock.send(build_identify_request(own_mac, xid))
    print(f"sent Identify Request from {own_mac.hex(':')} (xid={xid:#x}), waiting {args.timeout}s...")

    deadline = time.monotonic() + args.timeout
    found = 0
    while time.monotonic() < deadline:
        try:
            frame, _ = sock.recvfrom(2048)
        except socket.timeout:
            break
        if frame[6:12] == own_mac:
            continue
        payload = frame[14:]
        if len(payload) < 12:
            continue
        frame_id, service_id, service_type, got_xid, _reserved, data_length = struct.unpack(">HBBIHH", payload[0:12])
        if frame_id != FRAME_ID_DCP_IDENT_RES or service_id != SERVICE_ID_IDENTIFY:
            continue
        if service_type != SERVICE_TYPE_RESPONSE_SUCCESS or got_xid != xid:
            print(f"  ignored a reply with the wrong xid/type from {frame[6:12].hex(':')}")
            continue
        name = parse_name_of_station(payload[12 : 12 + data_length])
        print(f"  ANSWERED by {frame[6:12].hex(':')}  name_of_station={name!r}")
        found += 1

    if found == 0:
        print("no reply — nothing answered the Identify multicast on this interface", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
