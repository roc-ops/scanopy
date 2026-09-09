#!/usr/bin/env python3
"""A UDP shim that makes one agent refuse GETBULK on a named subtree.

GH #668's switch3 timed out every GETBULK on its LLDP neighbour columns and answered `snmpwalk`,
which is GETNEXT, on the same columns without trouble. Reproducing that needs an agent that will
not serve bulk and will serve getnext, and net-snmp has no setting for it: `pass` refuses nothing,
and `max-getbulk-repeats` returns *fewer* varbinds rather than nothing at all.

Slowness cannot stand in for it either, which is what the first attempt got wrong. snmpd drives a
`pass` script serially, so a handler that sleeps makes a GETBULK of 20 occupy the agent for 20
sleeps; the client gives up after its 5s timeout and the GETNEXT it sends next is still queued
behind the very bulk it was meant to escape. Any sleep long enough to fail the bulk fails the
getnext too. Measured on the VM at 9.03s for three calls of a 3s sleep.

So the refusal belongs in front of the agent rather than inside it. This drops the datagram — the
silence a client sees when a device does not answer — and costs the agent nothing, so a getnext
arriving 5s later is served immediately.

    snmp-bulk-refuser.py --listen 192.168.7.216:161 --upstream 127.0.0.1:16216 \\
                         --refuse 1.0.8802.1.1.2.1.4

Everything that is not a refused GETBULK is relayed untouched, including SNMPv3, whose PDU this
deliberately does not try to read. Parsing is fail-open throughout: a packet this cannot make sense
of is forwarded, because a shim that goes silent on a parse bug turns one unreadable column into a
device that has vanished, and that is a far more confusing fixture than the one it replaced.
"""

import argparse
import socket
import socketserver
import sys
import threading

# BER tags. Only the ones needed to reach the first varbind of a v1/v2c GETBULK.
SEQUENCE = 0x30
INTEGER = 0x02
OCTET_STRING = 0x04
OBJECT_IDENTIFIER = 0x06
GETBULK_PDU = 0xA5

UPSTREAM_TIMEOUT = 10.0


class Unparseable(Exception):
    """The packet is not a shape this understands, so it is somebody else's to interpret."""


def read_tlv(buf, i):
    """One BER tag-length-value at `i` → (tag, value_start, value_len, next_index)."""
    try:
        tag = buf[i]
        length = buf[i + 1]
        i += 2
        if length & 0x80:
            count = length & 0x7F
            # Indefinite length (count == 0) does not appear in SNMP and is not handled.
            if count == 0 or count > 4:
                raise Unparseable
            length = int.from_bytes(buf[i : i + count], "big")
            i += count
        if i + length > len(buf):
            raise Unparseable
        return tag, i, length, i + length
    except IndexError:
        raise Unparseable from None


def decode_oid(raw):
    """BER object identifier → tuple of sub-ids.

    The first byte packs the first two arcs as `40 * a + b`, which for the LLDP MIB's `1.0.8802…`
    is 40 — the case that would look wrong if it were not spelled out.
    """
    if not raw:
        raise Unparseable
    out = [raw[0] // 40, raw[0] % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            out.append(value)
            value = 0
    return tuple(out)


def getbulk_target(packet):
    """The first varbind OID of a v1/v2c GETBULK, or None if the packet is anything else.

    Walks only as far as it must: the outer SEQUENCE, past version and community, and into the PDU
    only when the tag says GETBULK. A v3 message fails the community check and leaves here, which
    is the intended outcome — its PDU may be encrypted and is none of this shim's business.
    """
    tag, body, _, _ = read_tlv(packet, 0)
    if tag != SEQUENCE:
        raise Unparseable

    tag, _, _, i = read_tlv(packet, body)
    if tag != INTEGER:  # version
        raise Unparseable
    tag, _, _, i = read_tlv(packet, i)
    if tag != OCTET_STRING:  # community
        raise Unparseable

    tag, pdu, _, _ = read_tlv(packet, i)
    if tag != GETBULK_PDU:
        return None

    # request-id, non-repeaters, max-repetitions.
    j = pdu
    for _ in range(3):
        tag, _, _, j = read_tlv(packet, j)
        if tag != INTEGER:
            raise Unparseable

    tag, varbinds, _, _ = read_tlv(packet, j)
    if tag != SEQUENCE:
        raise Unparseable
    tag, varbind, _, _ = read_tlv(packet, varbinds)
    if tag != SEQUENCE:
        raise Unparseable
    tag, oid, oid_len, _ = read_tlv(packet, varbind)
    if tag != OBJECT_IDENTIFIER:
        raise Unparseable
    return decode_oid(packet[oid : oid + oid_len])


def is_refused(packet, prefixes):
    """Whether to drop this datagram on the floor."""
    try:
        target = getbulk_target(packet)
    except Unparseable:
        return False
    if target is None:
        return False
    return any(target[: len(p)] == p for p in prefixes)


def serve(listen, upstream, prefixes, log):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, client = self.request
            if is_refused(packet, prefixes):
                # No reply, no error, no upstream call: the device simply does not answer, which
                # is what the walk under test has to survive.
                log(f"drop getbulk from {self.client_address[0]}")
                return
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as out:
                out.settimeout(UPSTREAM_TIMEOUT)
                try:
                    out.sendto(packet, upstream)
                    reply, _ = out.recvfrom(65535)
                except OSError as error:
                    log(f"upstream {upstream[0]}:{upstream[1]} did not answer: {error}")
                    return
            client.sendto(reply, self.client_address)

    class Server(socketserver.ThreadingUDPServer):
        # The agent behind this is one process; several devices' shims share the host. Reusing the
        # address lets a restart take over immediately rather than waiting out TIME_WAIT.
        allow_reuse_address = True
        daemon_threads = True
        max_packet_size = 65535

    with Server(listen, Handler) as server:
        log(f"listening on {listen[0]}:{listen[1]} → {upstream[0]}:{upstream[1]}")
        log("refusing getbulk under " + ", ".join(".".join(map(str, p)) for p in prefixes))
        server.serve_forever()


def address(text):
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"expected HOST:PORT, got {text!r}")
    return (host, int(port))


def prefix(text):
    try:
        return tuple(int(part) for part in text.strip(".").split("."))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a dotted OID: {text!r}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", type=address, required=True)
    parser.add_argument("--upstream", type=address, required=True)
    parser.add_argument(
        "--refuse",
        type=prefix,
        action="append",
        required=True,
        metavar="OID",
        help="drop GETBULK whose first varbind is at or under this subtree; repeatable",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    def log(message):
        if not args.quiet:
            print(f"[bulk-refuser] {message}", file=sys.stderr, flush=True)

    serve(args.listen, args.upstream, args.refuse, log)


if __name__ == "__main__":
    threading.current_thread().name = "bulk-refuser"
    main()
