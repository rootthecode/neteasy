import struct
import threading

import pytest

from neteasy import dnswire
from neteasy.discovery import Hint, apply_mdns, apply_ssdp
from neteasy.fingerprint import guess_device
from neteasy.tools import TOOLS, JobManager, line, parse_ports


def _rr(name: str, rtype: int, rdata: bytes, ttl: int = 120) -> bytes:
    return dnswire.encode_name(name) + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def _reply(*records: bytes, rcode: int = 0) -> bytes:
    return struct.pack(">HHHHHH", 7, 0x8180 | rcode, 0, len(records), 0, 0) + b"".join(records)


def test_dns_roundtrip_with_compression():
    # answer name uses a compression pointer back to offset 12 (first record's name)
    first = _rr("example.com", 1, bytes([93, 184, 216, 34]))
    pointer_rr = b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 60, 6) + struct.pack(">H", 10) + b"\xc0\x0c"
    msg = dnswire.parse_message(_reply(first, pointer_rr))
    assert msg.rcode == "NOERROR"
    assert [(r.type, r.value) for r in msg.answers] == [("A", "93.184.216.34"), ("MX", "10 example.com")]


def test_dns_nxdomain_and_query_build():
    assert dnswire.parse_message(_reply(rcode=3)).rcode == "NXDOMAIN"
    q = dnswire.build_query([("a.b", 1)], txid=0x1234)
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x01a\x01b\x00\x00\x01\x00\x01")


def test_mdns_hint_extracts_identity():
    data = _reply(
        _rr("_companion-link._tcp.local", 12, dnswire.encode_name("Sara's iPhone._companion-link._tcp.local")),
        _rr("Saras-iPhone.local", 1, bytes([192, 168, 0, 50])),
        _rr("Sara's iPhone._device-info._tcp.local", 16, bytes([16]) + b"model=iPhone14,2"),
    )
    hint = Hint()
    apply_mdns(hint, "192.168.0.50", dnswire.parse_message(data))
    assert hint.friendly == "Sara's iPhone"
    assert hint.mdns_name == "Saras-iPhone"
    assert hint.model == "iPhone14,2"
    assert "_companion-link._tcp" in hint.services
    g = guess_device(ttl=64, ports=[], vendor=None, name=hint.friendly, bonjour=sorted(hint.services), model=hint.model)
    assert (g.os, g.kind) == ("iOS", "phone")


def test_ssdp_and_upnp_fingerprints():
    hint = Hint()
    apply_ssdp(hint, b"HTTP/1.1 200 OK\r\nSERVER: Linux/4.4 UPnP/1.0 Samsung TV\r\nLOCATION: http://1.2.3.4/d.xml\r\n\r\n")
    assert hint.upnp_location == "http://1.2.3.4/d.xml"
    assert guess_device(ttl=64, ports=[], vendor=None, name=None, upnp=hint.upnp_server).kind == "tv"
    assert guess_device(ttl=None, ports=[], vendor=None, name=None, bonjour=["_googlecast._tcp"]).kind == "tv"


def test_parse_ports():
    assert parse_ports("22, 80,443") == [22, 80, 443]
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]
    assert 3389 in parse_ports("common")
    assert len(parse_ports("all")) == 65535
    with pytest.raises(ValueError):
        parse_ports("0-10")


def test_job_manager_streams_and_trims(monkeypatch):
    def fake(params, stop):
        for i in range(params["n"]):
            yield line(f"l{i}")
        yield {"stats": {"Done": params["n"]}}

    monkeypatch.setitem(TOOLS, "fake", fake)
    jm = JobManager()
    jm.MAX_EVENTS = 10
    job = jm.start("fake", {"n": 25})
    for t in threading.enumerate():
        if t.name == "tool-fake":
            t.join(5)
    r = jm.poll(job, 0)
    assert r["done"] and r["next"] == 25 and r["stats"] == {"Done": 25}
    assert [e["text"] for e in r["events"]][-1] == "l24" and len(r["events"]) == 10
    assert jm.poll(job, 25)["events"] == []  # offsets stay monotonic after trimming


def test_job_manager_reports_bad_input():
    jm = JobManager()
    job = jm.start("ping", {"host": ""})
    for t in threading.enumerate():
        if t.name == "tool-ping":
            t.join(5)
    events = jm.poll(job, 0)["events"]
    assert events and events[-1]["level"] == "bad"
    with pytest.raises(ValueError):
        jm.start("nope", {})
