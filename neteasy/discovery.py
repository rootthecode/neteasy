"""Broadcast discovery: mDNS/Bonjour and SSDP/UPnP.

Catches devices that ignore ARP/ping while dozing (phones, TVs, smart speakers) and yields rich
identity data: friendly names ("Sara's iPhone"), Apple model ids, advertised services, UPnP vendor/model.
"""

from __future__ import annotations

import logging
import re
import select
import socket
import time
import urllib.request
from dataclasses import dataclass, field
from threading import Event

from . import dnswire

log = logging.getLogger(__name__)

MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)

MDNS_SERVICES = (
    "_services._dns-sd._udp.local", "_device-info._tcp.local", "_companion-link._tcp.local",
    "_apple-mobdev2._tcp.local", "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
    "_androidtvremote2._tcp.local", "_adb-tls-connect._tcp.local", "_spotify-connect._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local", "_scanner._tcp.local",
    "_http._tcp.local", "_workstation._tcp.local", "_smb._tcp.local", "_ssh._tcp.local", "_hap._tcp.local",
    "_amzn-wplay._tcp.local", "_sonos._tcp.local", "_rdlink._tcp.local",
)
SSDP_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
    b"MX: 2\r\nST: ssdp:all\r\n\r\n"
)


@dataclass
class Hint:
    """What a device told us about itself over multicast."""

    mdns_name: str | None = None  # host name, e.g. "Saras-iPhone"
    friendly: str | None = None  # service instance name, e.g. "Sara's iPhone"
    model: str | None = None  # from _device-info TXT, e.g. "iPhone14,2"
    services: set[str] = field(default_factory=set)
    upnp_server: str | None = None
    upnp_location: str | None = None


def _service_type(name: str) -> str | None:
    """'_ipp._tcp.local' -> '_ipp._tcp'; instance names and others -> None."""
    m = re.search(r"(_[\w-]+\._(?:tcp|udp))\.local$", name)
    return m.group(1) if m and name.startswith("_") else None


def apply_mdns(hint: Hint, src_ip: str, msg: dnswire.Message) -> None:
    for r in msg.records:
        if r.type == "PTR":
            if r.name == "_services._dns-sd._udp.local":
                svc = _service_type(r.value)
                if svc:
                    hint.services.add(svc)
                continue
            svc = _service_type(r.name)
            if svc:
                hint.services.add(svc)
                instance = r.value.split("._", 1)[0]
                if instance and not instance.startswith("_") and svc != "_device-info._tcp":
                    hint.friendly = hint.friendly or instance.replace("\\032", " ")
        elif r.type == "A" and r.value == src_ip and r.name.endswith(".local"):
            hint.mdns_name = hint.mdns_name or r.name[: -len(".local")]
        elif r.type == "TXT":
            m = re.search(r"(?:^|\| )model=([^|]+)", r.value)
            if m:
                hint.model = hint.model or m.group(1).strip()
        elif r.type == "SRV":
            target = r.value.split()[-1]
            if target.endswith(".local") and not hint.mdns_name:
                hint.mdns_name = target[: -len(".local")]


def apply_ssdp(hint: Hint, payload: bytes) -> None:
    headers = {}
    for line in payload.decode("utf-8", errors="replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    hint.upnp_server = hint.upnp_server or headers.get("server")
    hint.upnp_location = hint.upnp_location or headers.get("location")


def broadcast_discover(local_ip: str, duration: float, stop: Event) -> dict[str, Hint]:
    """Send mDNS (legacy-unicast, so replies come straight back to us) and SSDP probes; collect replies."""
    hints: dict[str, Hint] = {}
    mdns_query = dnswire.build_query([(s, 12) for s in MDNS_SERVICES], recursion=False)
    socks = []
    try:
        for _ in range(2):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            s.bind((local_ip, 0))
            s.setblocking(False)
            socks.append(s)
        mdns, ssdp = socks
        sends = [0.0, 1.0, 2.5]  # repeat: dozing Wi-Fi clients may miss the first multicast
        start = time.monotonic()
        while (elapsed := time.monotonic() - start) < duration and not stop.is_set():
            while sends and elapsed >= sends[0]:
                sends.pop(0)
                for sock, packet, addr in ((mdns, mdns_query, MDNS_ADDR), (ssdp, SSDP_SEARCH, SSDP_ADDR)):
                    try:
                        sock.sendto(packet, addr)
                    except OSError as exc:
                        log.debug("multicast send failed: %s", exc)
            ready, _, _ = select.select(socks, [], [], 0.2)
            for sock in ready:
                try:
                    data, (ip, _) = sock.recvfrom(9000)
                except OSError:
                    continue
                hint = hints.setdefault(ip, Hint())
                try:
                    if sock is mdns:
                        apply_mdns(hint, ip, dnswire.parse_message(data))
                    else:
                        apply_ssdp(hint, data)
                except (ValueError, IndexError, UnicodeError) as exc:
                    log.debug("bad reply from %s: %s", ip, exc)
    finally:
        for s in socks:
            s.close()
    return hints


def upnp_describe(location: str, timeout: float = 2.0) -> dict[str, str]:
    """Fetch a UPnP device description: friendlyName, manufacturer, modelName."""
    try:
        with urllib.request.urlopen(location, timeout=timeout) as resp:
            xml = resp.read(65536).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return {}
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName"):
        m = re.search(rf"<{tag}>([^<]{{1,120}})</{tag}>", xml)
        if m:
            out[tag] = m.group(1).strip()
    return out
