"""Minimal DNS wire format: build queries, parse replies. Used for DNS lookups and mDNS discovery."""

from __future__ import annotations

import contextlib
import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass(frozen=True)
class Record:
    name: str
    type: str
    ttl: int
    value: str


@dataclass(frozen=True)
class Message:
    id: int
    rcode: str
    truncated: bool
    answers: list[Record]
    records: list[Record]  # answers + authority + additional


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        if len(raw) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(questions: list[tuple[str, int]], txid: int = 0, recursion: bool = True) -> bytes:
    flags = 0x0100 if recursion else 0
    header = struct.pack(">HHHHHH", txid, flags, len(questions), 0, 0, 0)
    return header + b"".join(encode_name(n) + struct.pack(">HH", t, 1) for n, t in questions)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels, end, jumps = [], None, 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if jumps > 32:
                raise ValueError("pointer loop")
            if end is None:
                end = offset + 2
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumps += 1
            continue
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), end if end is not None else offset


def _rdata(rtype: int, data: bytes, off: int, rdlen: int) -> str:
    raw = data[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(raw)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    if rtype in (2, 5, 12):
        return _read_name(data, off)[0]
    if rtype == 15:
        return f"{struct.unpack('>H', raw[:2])[0]} {_read_name(data, off + 2)[0]}"
    if rtype == 33:
        prio, weight, port = struct.unpack(">HHH", raw[:6])
        return f"{prio} {weight} {port} {_read_name(data, off + 6)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(raw):
            n = raw[i]
            parts.append(raw[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
            i += n + 1
        return " | ".join(parts)
    if rtype == 6:
        mname, o = _read_name(data, off)
        rname, o = _read_name(data, o)
        serial = struct.unpack(">I", data[o:o + 4])[0]
        return f"{mname} {rname} serial={serial}"
    return raw.hex()


def parse_message(data: bytes) -> Message:
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):
        offset = _read_name(data, offset)[1] + 4
    records: list[Record] = []
    for _ in range(an + ns + ar):
        name, offset = _read_name(data, offset)
        rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        records.append(Record(name, TYPE_NAMES.get(rtype, str(rtype)), ttl, _rdata(rtype, data, offset, rdlen)))
        offset += rdlen
    return Message(txid, RCODES.get(flags & 0xF, str(flags & 0xF)), bool(flags & 0x0200), records[:an], records)


def query(name: str, rtype: str, server: str, timeout: float = 2.5) -> tuple[Message, float]:
    """Send one UDP query to ``server``; returns (message, elapsed_ms). Raises OSError on timeout."""
    qtype = TYPES[rtype.upper()]
    if qtype == 12 and not name.endswith(".arpa"):
        with contextlib.suppress(ValueError):  # PTR for a plain IP: build the reverse name for the user
            name = ipaddress.ip_address(name).reverse_pointer
    txid = random.randint(0, 0xFFFF)
    packet = build_query([(name, qtype)], txid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendto(packet, (server, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            msg = parse_message(data)
            if msg.id == txid:
                return msg, (time.perf_counter() - start) * 1000
