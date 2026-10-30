"""Engineer's toolbox: ping, port check (telnet), traceroute, DNS lookup, port scan, Wake-on-LAN, speed test.

Each tool is a generator ``tool(params, stop) -> Iterator[Event]`` run by :class:`JobManager` in a
background thread. The UI polls a job for new events, so long-running tools stream live and can be stopped.
An event is ``{"text": str, "level": "info|ok|warn|bad|dim"}`` and/or ``{"stats": {...}}``.
"""

from __future__ import annotations

import ipaddress
import itertools
import logging
import re
import socket
import statistics
import subprocess
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import dnswire, netinfo, probes
from .scanner import PORTS

log = logging.getLogger(__name__)

Event = dict
Tool = Callable[[dict, threading.Event], Iterator[Event]]

EXTRA_PORTS = {25: "SMTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 465: "SMTPS", 587: "Submission",
               636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
               3306: "MySQL", 5060: "SIP", 5432: "PostgreSQL", 5985: "WinRM", 6379: "Redis", 7547: "TR-069",
               8000: "HTTP-alt", 8081: "HTTP-alt", 8291: "Winbox", 8888: "HTTP-alt", 9000: "HTTP-alt",
               10000: "Webmin", 27017: "MongoDB", 37777: "Dahua", 34567: "DVR"}
SERVICE_NAMES = {**EXTRA_PORTS, **PORTS}


def line(text: str, level: str = "info") -> Event:
    return {"text": text, "level": level}


def resolve(host: str) -> str:
    host = (host or "").strip()
    if not host:
        raise ValueError("Enter a host name or IP address")
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except OSError as exc:
        raise ValueError(f"Cannot resolve {host!r}: {exc}") from None


def _int(params: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(params.get(key) or default)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a number") from None
    return max(lo, min(hi, value))


def _sleep(stop: threading.Event, seconds: float) -> bool:
    """Interruptible sleep; returns True if a stop was requested."""
    return stop.wait(seconds)


# --- ping ------------------------------------------------------------------------------

def ping_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    ip = resolve(p.get("host"))
    count = _int(p, "count", 4, 0, 100_000)  # 0 = continuous (ping -t)
    size = _int(p, "size", 32, 0, 65500)
    interval = max(0.2, float(p.get("interval") or 1))
    df = bool(p.get("df"))
    yield line(f"Pinging {p['host'].strip()} [{ip}] with {size} bytes of data{' (DF set)' if df else ''}:", "dim")
    rtts: list[float] = []
    sent = 0
    while not stop.is_set() and (count == 0 or sent < count):
        sent += 1
        r = probes.icmp_echo(ip, 2000, size=size, dont_fragment=df)
        if r.status == "ok":
            rtts.append(r.rtt_ms or 0.0)
            ms = "<1ms" if not r.rtt_ms else f"={r.rtt_ms:.0f}ms"
            yield line(f"Reply from {r.address}: bytes={size} time{ms} TTL={r.ttl}", "ok")
        elif r.status == "too_big":
            yield line(f"Packet needs to be fragmented but DF set (from {r.address or ip}).", "warn")
        elif r.status == "unreachable":
            yield line(f"Reply from {r.address or ip}: Destination host unreachable.", "bad")
        else:
            yield line("Request timed out." if r.status == "timeout" else f"Error: {r.status}", "bad")
        loss = round(100 * (sent - len(rtts)) / sent)
        stats = {"Sent": sent, "Received": len(rtts), "Loss": f"{loss}%"}
        if rtts:
            jitter = statistics.mean(abs(a - b) for a, b in itertools.pairwise(rtts)) if len(rtts) > 1 else 0
            stats |= {"Min": f"{min(rtts):.0f} ms", "Avg": f"{statistics.mean(rtts):.1f} ms",
                      "Max": f"{max(rtts):.0f} ms", "Jitter": f"{jitter:.1f} ms"}
        yield {"stats": stats}
        if count == 0 or sent < count:
            _sleep(stop, interval)
    yield line(f"Done: {sent} sent, {len(rtts)} received, {round(100 * (sent - len(rtts)) / max(sent, 1))}% loss.",
               "ok" if rtts and len(rtts) == sent else "warn")


# --- port check (telnet) ------------------------------------------------------------------

def _banner(sock: socket.socket, port: int, host: str) -> str:
    sock.settimeout(1.5)
    try:
        if port in (80, 8080, 8000, 8008, 8081, 8888):
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(512)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    server = re.search(r"^Server:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    return first + (f"  ({server.group(1).strip()})" if server else "")


def tcp_check_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    host = (p.get("host") or "").strip()
    ip = resolve(host)
    port = _int(p, "port", 23, 1, 65535)
    count = _int(p, "count", 3, 1, 1000)
    name = SERVICE_NAMES.get(port, "")
    yield line(f"Connecting to {host} [{ip}] port {port}{f' ({name})' if name else ''}…", "dim")
    times: list[float] = []
    for i in range(count):
        if stop.is_set():
            break
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                ms = (time.perf_counter() - start) * 1000
                times.append(ms)
                banner = _banner(sock, port, host) if i == 0 else ""
            yield line(f"[{i + 1}] OPEN — connected in {ms:.0f} ms", "ok")
            if banner:
                yield line(f"    banner: {banner}", "info")
        except ConnectionRefusedError:
            yield line(f"[{i + 1}] CLOSED — connection refused (host is up, nothing listening on {port})", "bad")
        except TimeoutError:
            yield line(f"[{i + 1}] FILTERED — no response in 3 s (firewall drop, or host down)", "warn")
        except OSError as exc:
            yield line(f"[{i + 1}] ERROR — {exc.strerror or exc}", "bad")
        stats = {"Attempts": i + 1, "Open": len(times)}
        if times:
            stats |= {"Avg connect": f"{statistics.mean(times):.0f} ms"}
        yield {"stats": stats}
        if i + 1 < count:
            _sleep(stop, 1)
    verdict = "reachable" if times else "NOT reachable"
    yield line(f"Port {port} on {host} is {verdict}.", "ok" if times else "bad")


# --- traceroute -----------------------------------------------------------------------------

def traceroute_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    host = (p.get("host") or "").strip()
    ip = resolve(host)
    max_hops = _int(p, "max_hops", 30, 1, 64)
    yield line(f"Tracing route to {host} [{ip}] over a maximum of {max_hops} hops:", "dim")
    if not probes.IS_WINDOWS:
        yield from _traceroute_subprocess(ip, max_hops, stop)
        return

    for ttl in range(1, max_hops + 1):
        if stop.is_set():
            break
        replies = [probes.icmp_echo(ip, 1500, ttl=ttl) for _ in range(3)]
        hop = next((r.address for r in replies if r.address), None)
        times = "  ".join(f"{r.rtt_ms:>4.0f} ms" if r.address and r.rtt_ms is not None else "     *"
                          for r in replies)
        if hop:
            name = probes.reverse_dns(hop, 1.0)
            yield line(f"{ttl:>3}  {times}  {f'{name} [{hop}]' if name else hop}", "ok" if hop == ip else "info")
        else:
            yield line(f"{ttl:>3}  {times}  Request timed out.", "warn")
        yield {"stats": {"Hops": ttl}}
        if hop == ip:
            yield line("Trace complete.", "ok")
            return
    yield line("Destination not reached.", "warn")


def _traceroute_subprocess(ip: str, max_hops: int, stop: threading.Event) -> Iterator[Event]:
    proc = subprocess.Popen(["traceroute", "-n", "-q", "3", "-w", "2", "-m", str(max_hops), ip],
                            stdout=subprocess.PIPE, text=True)
    try:
        for raw in proc.stdout:
            if stop.is_set():
                break
            yield line(raw.rstrip())
    finally:
        proc.kill()


# --- DNS lookup ------------------------------------------------------------------------------

def dns_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    name = (p.get("name") or "").strip()
    if not name:
        raise ValueError("Enter a domain name (or an IP for PTR)")
    rtype = (p.get("type") or "A").upper()
    if rtype not in dnswire.TYPES:
        raise ValueError(f"Unsupported record type {rtype}")
    servers = [s.strip() for s in re.split(r"[,\s]+", p.get("servers") or "system") if s.strip()]
    system = netinfo.get_network_info().dns
    asked: set[str] = set()
    for server in servers:
        if stop.is_set():
            return
        targets = system if server.lower() == "system" else [server]
        if not targets:
            yield line("No system DNS server configured.", "bad")
            continue
        for target in targets[:2] if server.lower() == "system" else targets:
            if target in asked:
                continue
            asked.add(target)
            label = f"{target} (system)" if server.lower() == "system" else target
            try:
                msg, ms = dnswire.query(name, rtype, resolve(target))
            except TimeoutError:
                yield line(f"● {label}: no answer in 2.5 s — server down or blocked", "bad")
                continue
            except (OSError, ValueError) as exc:
                yield line(f"● {label}: {exc}", "bad")
                continue
            level = "ok" if msg.rcode == "NOERROR" and msg.answers else "warn"
            yield line(f"● {label}: {msg.rcode}, {len(msg.answers)} answer(s) in {ms:.0f} ms"
                       f"{' (truncated)' if msg.truncated else ''}", level)
            for r in msg.answers:
                yield line(f"    {r.type:<5} {r.value}   (TTL {r.ttl}s)  {r.name}", "info")
            yield {"stats": {f"{label}": f"{ms:.0f} ms"}}


# --- port scan ---------------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    spec = (spec or "common").strip().lower()
    if spec == "common":
        return sorted(SERVICE_NAMES)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in re.split(r"[,\s]+", spec):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        a, b = int(lo), int(hi or lo)
        if not (1 <= a <= b <= 65535):
            raise ValueError(f"Bad port range {part!r}")
        ports.update(range(a, b + 1))
    return sorted(ports)


def port_scan_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    host = (p.get("host") or "").strip()
    ip = resolve(host)
    ports = parse_ports(p.get("ports"))
    yield line(f"Scanning {len(ports)} TCP port(s) on {host} [{ip}]…", "dim")
    start, done, found = time.monotonic(), 0, []

    def check(port: int) -> int | None:
        return port if not stop.is_set() and probes.tcp_open(ip, port, 0.6) else None

    with ThreadPoolExecutor(max_workers=min(400, len(ports))) as pool:
        futures = [pool.submit(check, port) for port in ports]
        for fut in as_completed(futures):
            done += 1
            port = fut.result()
            if port:
                found.append(port)
                yield line(f"  {port:>5}/tcp  open   {SERVICE_NAMES.get(port, '')}", "ok")
            if done % 50 == 0 or done == len(ports):
                yield {"stats": {"Scanned": f"{done}/{len(ports)}", "Open": len(found),
                                 "Time": f"{time.monotonic() - start:.1f} s"}}
            if stop.is_set():
                for f in futures:
                    f.cancel()
                break
    yield line(f"Done: {len(found)} open port(s): {', '.join(map(str, sorted(found))) or 'none'}",
               "ok" if found else "warn")


# --- Wake-on-LAN -----------------------------------------------------------------------------------

def wol_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    mac = re.sub(r"[^0-9a-fA-F]", "", p.get("mac") or "")
    if len(mac) != 12:
        raise ValueError("Enter a MAC address like AA:BB:CC:DD:EE:FF")
    packet = b"\xff" * 6 + bytes.fromhex(mac) * 16
    net = netinfo.get_network_info()
    targets = {"255.255.255.255"}
    if net.cidr:
        targets.add(str(ipaddress.IPv4Network(net.cidr).broadcast_address))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if net.ip:
            sock.bind((net.ip, 0))
        for target in sorted(targets):
            for port in (9, 7):
                sock.sendto(packet, (target, port))
                yield line(f"Magic packet → {target}:{port}", "ok")
    yield line(f"Sent to {probes.normalize_mac(':'.join(mac[i:i + 2] for i in range(0, 12, 2)))}. "
               "The PC must have WoL enabled in BIOS/NIC and be on wired Ethernet (usually).", "dim")


# --- speed test (Cloudflare) ----------------------------------------------------------------------

SPEED_HOST = "https://speed.cloudflare.com"


def _http_ms(url: str) -> float:
    start = time.perf_counter()
    req = urllib.request.Request(url, headers={"User-Agent": "NetEasy"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()
    return (time.perf_counter() - start) * 1000


def _transfer(direction: str, seconds: float, stop: threading.Event) -> Iterator[Event]:
    total, lock, deadline = [0], threading.Lock(), time.monotonic() + seconds
    chunk = b"0" * 1_000_000

    def worker() -> None:
        while time.monotonic() < deadline and not stop.is_set():
            try:
                if direction == "down":
                    req = urllib.request.Request(f"{SPEED_HOST}/__down?bytes=25000000",
                                                 headers={"User-Agent": "NetEasy"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        while (block := resp.read(65536)) and time.monotonic() < deadline and not stop.is_set():
                            with lock:
                                total[0] += len(block)
                else:
                    req = urllib.request.Request(f"{SPEED_HOST}/__up", data=chunk, method="POST",
                                                 headers={"User-Agent": "NetEasy", "Content-Type": "text/plain"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        resp.read()
                    with lock:
                        total[0] += len(chunk)
            except OSError as exc:
                log.debug("speed test %s worker: %s", direction, exc)
                time.sleep(0.2)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
    start = time.monotonic()
    for t in threads:
        t.start()
    label = "Download" if direction == "down" else "Upload"
    while any(t.is_alive() for t in threads):
        if _sleep(stop, 0.5):
            break
        mbps = total[0] * 8 / 1e6 / max(time.monotonic() - start, 0.001)
        yield {"stats": {label: f"{mbps:.1f} Mbps"}}
    mbps = total[0] * 8 / 1e6 / max(time.monotonic() - start, 0.001)
    yield {"stats": {label: f"{mbps:.1f} Mbps"}}
    yield line(f"{label}: {mbps:.1f} Mbps ({total[0] / 1e6:.0f} MB in {time.monotonic() - start:.1f} s)", "ok")


def speed_tool(p: dict, stop: threading.Event) -> Iterator[Event]:
    yield line("Speed test via speed.cloudflare.com (4 parallel connections)…", "dim")
    try:
        pings = [_http_ms(f"{SPEED_HOST}/__down?bytes=0") for _ in range(5)]
    except OSError as exc:
        raise ValueError(f"Cannot reach speed.cloudflare.com: {exc}") from None
    latency = statistics.median(pings[1:])  # first request pays for TLS setup
    yield {"stats": {"Latency": f"{latency:.0f} ms"}}
    yield line(f"Latency: {latency:.0f} ms (HTTP round-trip)", "ok")
    yield from _transfer("down", 10, stop)
    if not stop.is_set():
        yield from _transfer("up", 8, stop)


TOOLS: dict[str, Tool] = {
    "ping": ping_tool, "tcp": tcp_check_tool, "trace": traceroute_tool, "dns": dns_tool,
    "portscan": port_scan_tool, "wol": wol_tool, "speed": speed_tool,
}


# --- job runner ----------------------------------------------------------------------------------

@dataclass
class Job:
    id: str
    tool: str
    events: list[Event] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    base: int = 0  # number of old events trimmed from the front; keeps poll offsets monotonic
    done: bool = False
    stop: threading.Event = field(default_factory=threading.Event)


class JobManager:
    MAX_JOBS = 20
    MAX_EVENTS = 5000  # continuous ping: keep memory bounded

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, tool: str, params: dict) -> str:
        fn = TOOLS.get(tool)
        if not fn:
            raise ValueError(f"Unknown tool {tool!r}")
        job = Job(uuid.uuid4().hex[:10], tool)
        with self._lock:
            finished = [j.id for j in self._jobs.values() if j.done]
            for old in finished[: max(0, len(self._jobs) - self.MAX_JOBS)]:
                del self._jobs[old]
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, fn, params or {}), name=f"tool-{tool}", daemon=True).start()
        return job.id

    def _run(self, job: Job, fn: Tool, params: dict) -> None:
        try:
            for event in fn(params, job.stop):
                self._emit(job, event)
        except ValueError as exc:
            self._emit(job, line(str(exc), "bad"))
        except Exception as exc:
            log.exception("Tool %s failed", job.tool)
            self._emit(job, line(f"Error: {exc}", "bad"))
        finally:
            if job.stop.is_set():
                self._emit(job, line("Stopped.", "dim"))
            with self._lock:
                job.done = True

    def _emit(self, job: Job, event: Event) -> None:
        with self._lock:
            if "stats" in event:
                job.stats.update(event["stats"])
            if event.get("text") is not None:
                job.events.append({"text": event["text"], "level": event.get("level", "info")})
                overflow = len(job.events) - self.MAX_EVENTS
                if overflow > 0:
                    del job.events[:overflow]
                    job.base += overflow

    def poll(self, job_id: str, since: int) -> dict:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                raise ValueError("Unknown job")
            return {"events": job.events[max(0, since - job.base):], "next": job.base + len(job.events),
                    "stats": dict(job.stats), "done": job.done}

    def stop(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job:
            job.stop.set()
