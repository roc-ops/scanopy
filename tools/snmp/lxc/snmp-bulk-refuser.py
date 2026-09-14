#!/usr/bin/env python3
"""A UDP shim that makes one agent refuse GETBULK, either by dropping it or by answering it with an
error status.

GH #668's switch3 timed out every GETBULK on its LLDP neighbour columns and answered `snmpwalk`,
which is GETNEXT, on the same columns without trouble. Reproducing that needs an agent that will
not serve bulk and will serve getnext, and net-snmp has no setting for it: `pass` refuses nothing,
and `max-getbulk-repeats` returns *fewer* varbinds rather than nothing at all.

Slowness cannot stand in for it either, which is what the first attempt got wrong. snmpd drives a
`pass` script serially, so a handler that sleeps makes a GETBULK of 20 occupy the agent for 20
sleeps; the client gives up after its 5s timeout and the GETNEXT it sends next is still queued
behind the very bulk it was meant to escape. Any sleep long enough to fail the bulk fails the
getnext too. Measured on the VM at 9.03s for three calls of a 3s sleep.

So the refusal belongs in front of the agent rather than inside it. `--refuse` drops the datagram —
the silence a client sees when a device does not answer — and costs the agent nothing, so a getnext
arriving 5s later is served immediately.

GH #710's Hikvision refuses differently: a GETBULK asking for more repetitions than it will serve
comes back at once, as a Response carrying an error status and the request's own varbinds echoed.
`pass` never sees the repetition count, so that also has to happen here. `--reject-above N` answers
any GETBULK with max-repetitions above N that way, with `--error-status` (default genErr, 5), and
forwards the rest.

    snmp-bulk-refuser.py --listen 192.168.7.216:161 --upstream 127.0.0.1:16216 \\
                         --refuse 1.0.8802.1.1.2.1.4
    snmp-bulk-refuser.py --listen 192.168.7.223:161 --upstream 127.0.0.1:16223 \\
                         --reject-above 10 --error-status 5

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

# BER tags. Only the ones needed to take apart a v1/v2c GETBULK and build its error Response.
SEQUENCE = 0x30
INTEGER = 0x02
OCTET_STRING = 0x04
OBJECT_IDENTIFIER = 0x06
RESPONSE_PDU = 0xA2
GETBULK_PDU = 0xA5

UPSTREAM_TIMEOUT = 10.0

# What `decide` returns for a GETBULK that gets no answer at all.
DROP = object()


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


def encode_tlv(tag, value):
    """One BER tag-length-value, definite length."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(body)]) + body + value


def encode_integer(value):
    """A non-negative BER INTEGER, which is all an error status or error index ever is. The extra
    byte keeps a value with its top bit set from reading as negative."""
    return encode_tlv(INTEGER, value.to_bytes(value.bit_length() // 8 + 1, "big"))


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


class Getbulk:
    """The parts of a GETBULK this shim acts on, raw TLVs kept verbatim for the echo."""

    def __init__(self, header, request_id, max_repetitions, varbinds, target):
        self.header = header  # version and community TLVs
        self.request_id = request_id  # request-id TLV
        self.max_repetitions = max_repetitions
        self.varbinds = varbinds  # the whole varbind-list TLV
        self.target = target  # first varbind's OID


def parse_getbulk(packet):
    """A v1/v2c GETBULK taken apart, or None if the packet is anything else.

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
    header = packet[body:i]

    tag, pdu, _, _ = read_tlv(packet, i)
    if tag != GETBULK_PDU:
        return None

    tag, _, _, j = read_tlv(packet, pdu)
    if tag != INTEGER:  # request-id
        raise Unparseable
    request_id = packet[pdu:j]
    tag, _, _, j = read_tlv(packet, j)
    if tag != INTEGER:  # non-repeaters
        raise Unparseable
    tag, reps, reps_len, j = read_tlv(packet, j)
    if tag != INTEGER:  # max-repetitions
        raise Unparseable
    max_repetitions = int.from_bytes(packet[reps : reps + reps_len], "big", signed=True)

    tag, varbinds, _, end = read_tlv(packet, j)
    if tag != SEQUENCE:
        raise Unparseable
    tag, varbind, _, _ = read_tlv(packet, varbinds)
    if tag != SEQUENCE:
        raise Unparseable
    tag, oid, oid_len, _ = read_tlv(packet, varbind)
    if tag != OBJECT_IDENTIFIER:
        raise Unparseable
    return Getbulk(
        header, request_id, max_repetitions, packet[j:end], decode_oid(packet[oid : oid + oid_len])
    )


def error_response(bulk, error_status):
    """The Response an agent sends when it refuses a request: same request id, the request's
    varbinds echoed, and an error index pointing at the first of them (RFC 3416 §4.2)."""
    pdu = bulk.request_id + encode_integer(error_status) + encode_integer(1) + bulk.varbinds
    return encode_tlv(SEQUENCE, bulk.header + encode_tlv(RESPONSE_PDU, pdu))


def decide(packet, prefixes, reject_above, error_status):
    """What to do with one datagram: `DROP`, the bytes of an answer to send, or None to relay it."""
    try:
        bulk = parse_getbulk(packet)
    except Unparseable:
        return None
    if bulk is None:
        return None
    if any(bulk.target[: len(p)] == p for p in prefixes):
        return DROP
    if reject_above is not None and bulk.max_repetitions > reject_above:
        return error_response(bulk, error_status)
    return None


def serve(listen, upstream, prefixes, reject_above, error_status, log):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, client = self.request
            verdict = decide(packet, prefixes, reject_above, error_status)
            if verdict is DROP:
                # No reply, no error, no upstream call: the device simply does not answer, which
                # is what the walk under test has to survive.
                log(f"drop getbulk from {self.client_address[0]}")
                return
            if verdict is not None:
                log(f"answer getbulk from {self.client_address[0]} with error-status {error_status}")
                client.sendto(verdict, self.client_address)
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
        if prefixes:
            log("refusing getbulk under " + ", ".join(".".join(map(str, p)) for p in prefixes))
        if reject_above is not None:
            log(f"answering getbulk above {reject_above} repetitions with error-status {error_status}")
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
        default=[],
        metavar="OID",
        help="drop GETBULK whose first varbind is at or under this subtree; repeatable",
    )
    parser.add_argument(
        "--reject-above",
        type=int,
        metavar="N",
        help="answer GETBULK with max-repetitions above N with an error status",
    )
    parser.add_argument(
        "--error-status",
        type=int,
        default=5,
        metavar="S",
        help="error status for --reject-above (default 5, genErr)",
    )
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    if not args.refuse and args.reject_above is None:
        parser.error("give --refuse, --reject-above, or both")

    def log(message):
        if not args.quiet:
            print(f"[bulk-refuser] {message}", file=sys.stderr, flush=True)

    serve(args.listen, args.upstream, args.refuse, args.reject_above, args.error_status, log)


if __name__ == "__main__":
    threading.current_thread().name = "bulk-refuser"
    main()
