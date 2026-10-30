"""LAN scanner: discovers hosts, then enriches them (names, ports, vendor, OS).

Discovery uses several independent signals so quiet devices are not missed:
  1. ARP sweep of the subnet (sees firewalled PCs), with ICMP for TTL/latency
  2. mDNS + SSDP multicast queries in parallel (phones, Apple/Cast/smart-TV gear announce themselves)
  3. the OS neighbour cache (anything that recently talked on the LAN)
  4. a second ARP pass for silent addresses, overlapped with enrichment (Wi-Fi clients in power-save
     often miss the first ARP request)

Runs in a background thread; the UI polls :meth:`Scanner.snapshot` for progressive results.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field

from . import discovery, probes
from .fingerprint import VendorDB, guess_device, is_randomized_mac
from .netinfo import NetworkInfo

log = logging.getLogger(__name__)

MAX_HOSTS = 1024
DISCOVERY_WORKERS = 256
ENRICH_WORKERS = 192
BROADCAST_SECONDS = 5.0

PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 135: "RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 515: "LPD", 548: "AFP", 554: "RTSP", 631: "IPP", 3389: "RDP",
    5555: "ADB", 5900: "VNC", 8008: "Cast", 8009: "Cast", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9100: "Printer", 62078: "iOS sync",
}

ISOLATION_NOTE = ("Only the router answered. If phones/PCs are connected, this Wi-Fi probably has client "
                  "(AP) isolation or they are on a guest network — check the router's client list (Admin).")


@dataclass
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    netbios: str | None = None
    workgroup: str | None = None
    mdns_name: str | None = None
    friendly: str | None = None
    model: str | None = None
    bonjour: list[str] = field(default_factory=list)
    upnp_server: str | None = None
    upnp_location: str | None = None
    upnp_name: str | None = None
    upnp_maker: str | None = None
    upnp_model: str | None = None
    ttl: int | None = None
    rtt_ms: float | None = None
    ports: list[int] = field(default_factory=list)
    found_by: list[str] = field(default_factory=list)
    os: str = "Identifying…"
    kind: str = "unknown"
    confidence: str = "low"
    is_gateway: bool = False
    is_self: bool = False
    randomized_mac: bool = False
    online: bool = True  # answered in the latest scan
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def name(self) -> str:
        short_host = self.hostname.split(".")[0] if self.hostname else ""
        return (self.netbios or self.friendly or self.upnp_name or self.mdns_name or short_host
                or self.vendor or "")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["name"] = self.name
        d["services"] = [{"port": p, "name": PORTS.get(p, str(p))} for p in sorted(self.ports)]
        return d


def plan_targets(ip: str, netmask: str) -> tuple[list[str], str | None]:
    """Hosts to probe. Huge subnets are narrowed to the local /24 to keep scans quick."""
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    note = None
    if net.num_addresses - 2 > MAX_HOSTS:
        note = f"Subnet {net} is large; scanning {ipaddress.IPv4Network(f'{ip}/24', strict=False)} only."
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return [str(h) for h in net.hosts()], note


class Scanner:
    def __init__(self, vendors: VendorDB) -> None:
        self._vendors = vendors
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._gateway = ""
        self._network_key: tuple[str, str] | None = None
        self._devices: dict[str, Device] = {}
        self._reset()

    def _reset(self, keep_devices: bool = False) -> None:
        """New scan state. Devices are kept across rescans of the same network so phones that
        doze through one scan stay listed (as offline) instead of vanishing."""
        if not keep_devices:
            self._devices = {}
        self._seen: set[str] = set()  # IPs that answered during the current scan
        self._status = "idle"
        self._phase = ""
        self._done = self._total = 0
        self._notes: list[str] = []
        self._error: str | None = None
        self._started = self._finished = None

    # --- public API ---------------------------------------------------------------

    def start(self, info: NetworkInfo) -> bool:
        with self._lock:
            if self._status == "scanning":
                return False
            key = (info.cidr, info.gateway_mac or info.gateway)  # a different client site = fresh list
            self._reset(keep_devices=key == self._network_key)
            self._network_key = key
            self._status, self._started = "scanning", time.time()
        self._cancel.clear()
        self._thread = threading.Thread(target=self._run, args=(info,), name="scanner", daemon=True)
        self._thread.start()
        return True

    def cancel(self) -> None:
        self._cancel.set()

    def snapshot(self) -> dict:
        with self._lock:
            devices = sorted(self._devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))
            end = self._finished or time.time()
            return {
                "status": self._status,
                "phase": self._phase,
                "done": self._done,
                "total": self._total,
                "note": " ".join(self._notes) or None,
                "error": self._error,
                "elapsed": round(end - self._started, 1) if self._started else 0,
                "devices": [d.to_dict() for d in devices],
            }

    # --- pipeline -------------------------------------------------------------------

    def _run(self, info: NetworkInfo) -> None:
        try:
            hosts, note = plan_targets(info.ip, info.netmask or "255.255.255.0")
            self._gateway = info.gateway
            if note:
                self._notes.append(note)
            self._upsert(Device(ip=info.ip, mac=info.mac or None, hostname=info.hostname, is_self=True,
                                found_by=["self"]))
            silent = self._discover([h for h in hosts if h != info.ip], info.ip)
            if not self._cancel.is_set():
                with self._lock:
                    found = [ip for ip in self._seen if not self._devices[ip].is_self]
                late = self._enrich(found, retry=silent)
                if late and not self._cancel.is_set():
                    self._enrich(late, retry=[])
            if not self._cancel.is_set() and not self._vendors.wait(timeout=0):
                self._set_phase("Looking up vendors", 0)  # first run may still be downloading the list
                self._vendors.wait(timeout=8)
            with self._lock:
                for dev in self._devices.values():
                    if not self._cancel.is_set():
                        dev.online = dev.ip in self._seen
                    self._identify(dev)
                if not any(not d.is_self and not d.is_gateway for d in self._devices.values()):
                    self._notes.append(ISOLATION_NOTE)
            status, error = ("cancelled" if self._cancel.is_set() else "done"), None
        except Exception as exc:
            log.exception("Scan failed")
            status, error = "error", str(exc)
        # One locked update so a new start() can never interleave with this scan's final state.
        with self._lock:
            self._status, self._error, self._finished, self._phase = status, error, time.time(), ""

    def _set_phase(self, phase: str, total: int) -> None:
        with self._lock:
            self._phase, self._done, self._total = phase, 0, total

    def _tick(self) -> None:
        with self._lock:
            self._done += 1

    def _probe(self, ip: str, source: str) -> bool:
        """ARP (authoritative on the local segment, sees firewalled PCs) + ICMP for TTL/latency."""
        if self._cancel.is_set():
            return False
        mac = probes.arp_resolve(ip) if probes.IS_WINDOWS else None
        pong = probes.ping(ip, 700) if mac or not probes.IS_WINDOWS else probes.PingResult(False)
        if not (mac or pong.alive):
            return False
        self._upsert(Device(ip=ip, mac=mac, ttl=pong.ttl, rtt_ms=pong.rtt_ms, found_by=[source]))
        return True

    def _discover(self, hosts: list[str], local_ip: str) -> list[str]:
        """Pass 1 + multicast + neighbour cache. Returns the addresses still silent."""
        self._set_phase("Discovering devices", len(hosts))
        hints: dict[str, discovery.Hint] = {}

        def listen() -> None:
            try:
                hints.update(discovery.broadcast_discover(local_ip, BROADCAST_SECONDS, self._cancel))
            except OSError as exc:
                log.warning("Multicast discovery unavailable: %s", exc)

        listener = threading.Thread(target=listen, name="mdns-ssdp", daemon=True)
        listener.start()
        with ThreadPoolExecutor(max_workers=DISCOVERY_WORKERS) as pool:
            for fut in as_completed([pool.submit(self._probe, ip, "arp") for ip in hosts]):
                fut.result()
                self._tick()
        listener.join()

        wanted = set(hosts)
        for ip, hint in hints.items():
            if ip in wanted:
                self._apply_hint(ip, hint)
        for ip, mac in probes.arp_table().items():
            if ip in wanted:
                self._upsert(Device(ip=ip, mac=mac, found_by=["arp-cache"]))
        with self._lock:
            return [h for h in hosts if h not in self._seen]

    def _apply_hint(self, ip: str, hint: discovery.Hint) -> None:
        with self._lock:
            known_mac = self._devices[ip].mac if ip in self._devices else None
        mac = known_mac or probes.arp_resolve(ip)
        sources = (["mdns"] if hint.services or hint.mdns_name else []) + (["ssdp"] if hint.upnp_server else [])
        self._upsert(Device(ip=ip, mac=mac, found_by=sources or ["multicast"]))
        self._update(ip, mdns_name=hint.mdns_name, friendly=hint.friendly, model=hint.model,
                     upnp_server=hint.upnp_server, upnp_location=hint.upnp_location,
                     bonjour=sorted(hint.services))

    def _enrich(self, targets: list[str], retry: list[str]) -> list[str]:
        """Names, ports and UPnP details for ``targets``; second ARP pass over ``retry``.
        Returns hosts newly found by the retry pass."""
        with self._lock:
            upnp = [(d.ip, d.upnp_location) for d in self._devices.values() if d.ip in targets and d.upnp_location]
        jobs: list[tuple] = [("names", ip) for ip in targets]
        jobs += [("port", ip, p) for ip in targets for p in PORTS]
        jobs += [("upnp", ip, loc) for ip, loc in upnp]
        jobs += [("retry", ip) for ip in retry]
        self._set_phase("Identifying devices", len(jobs))
        late: list[str] = []

        def work(job: tuple) -> None:
            if self._cancel.is_set():
                return
            kind, ip = job[0], job[1]
            if kind == "names":
                nb_name, workgroup = probes.netbios_name(ip)
                self._update(ip, netbios=nb_name, workgroup=workgroup, hostname=probes.reverse_dns(ip))
            elif kind == "port":
                if probes.tcp_open(ip, job[2]):
                    with self._lock:
                        dev = self._devices[ip]
                        if job[2] not in dev.ports:
                            dev.ports.append(job[2])
                        self._identify(dev)
            elif kind == "upnp":
                url = urllib.parse.urlsplit(job[2])
                if url.scheme == "http" and url.hostname == ip:  # only ask the device about itself
                    desc = discovery.upnp_describe(job[2])
                    self._update(ip, upnp_name=desc.get("friendlyName"), upnp_maker=desc.get("manufacturer"),
                                 upnp_model=desc.get("modelName"))
            elif kind == "retry" and self._probe(ip, "arp-retry"):
                with self._lock:
                    late.append(ip)

        with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as pool:
            for fut in as_completed([pool.submit(work, j) for j in jobs]):
                fut.result()
                self._tick()
        return late

    # --- state helpers (callers must not hold the lock unless stated) ---------------

    def _upsert(self, dev: Device) -> None:
        """Record evidence that ``dev`` is on the network right now."""
        now = time.time()
        with self._lock:
            existing = self._devices.get(dev.ip)
            if existing and dev.mac and existing.mac and dev.mac != existing.mac:
                existing = None  # the IP was handed to a different device (new DHCP lease)
            if existing:
                existing.mac = existing.mac or dev.mac
                existing.ttl = existing.ttl or dev.ttl
                existing.rtt_ms = existing.rtt_ms if existing.rtt_ms is not None else dev.rtt_ms
                existing.found_by += [s for s in dev.found_by if s not in existing.found_by]
                dev = existing
            dev.is_gateway = dev.is_gateway or dev.ip == self._gateway
            dev.online, dev.last_seen = True, now
            dev.first_seen = dev.first_seen or now
            self._seen.add(dev.ip)
            self._devices[dev.ip] = dev
            self._identify(dev)

    def _update(self, ip: str, **fields) -> None:
        with self._lock:
            dev = self._devices[ip]
            for k, v in fields.items():
                if v:
                    setattr(dev, k, v)
            self._identify(dev)

    def _identify(self, dev: Device) -> None:
        """Recompute vendor and OS guess. Caller holds the lock."""
        dev.randomized_mac = is_randomized_mac(dev.mac)
        if not dev.vendor:
            dev.vendor = self._vendors.lookup(dev.mac)
        upnp = " ".join(filter(None, (dev.upnp_server, dev.upnp_name, dev.upnp_maker, dev.upnp_model)))
        g = guess_device(
            ttl=dev.ttl, ports=dev.ports, vendor=dev.vendor or dev.upnp_maker,
            name=dev.netbios or dev.friendly or dev.mdns_name or dev.hostname,
            netbios=bool(dev.netbios), is_gateway=dev.is_gateway, is_self=dev.is_self,
            randomized=dev.randomized_mac, bonjour=dev.bonjour, model=dev.model, upnp=upnp,
        )
        dev.os, dev.kind, dev.confidence = g.os, g.kind, g.confidence
