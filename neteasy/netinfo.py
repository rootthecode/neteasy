"""Facts about the network this machine is attached to: adapter, gateway, DNS, Wi-Fi, ISP."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import statistics
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import asdict, dataclass, field

import psutil

from . import probes

log = logging.getLogger(__name__)


@dataclass
class NetworkInfo:
    hostname: str = ""
    adapter: str = ""
    ip: str = ""
    netmask: str = ""
    cidr: str = ""
    mac: str = ""
    speed_mbps: int = 0
    gateway: str = ""
    gateway_mac: str = ""
    dns: list[str] = field(default_factory=list)
    dhcp_enabled: bool | None = None
    dhcp_server: str = ""
    lease_expires: float | None = None
    domain: str = ""
    wifi: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def primary_ip() -> str:
    """IP of the adapter that holds the default route (UDP connect sends no packets)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 53))
            return sock.getsockname()[0]
    except OSError:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                    return a.address
    return "127.0.0.1"


def default_gateway() -> str:
    if probes.IS_WINDOWS:
        import ctypes
        from ctypes import wintypes

        class _Row(ctypes.Structure):
            _fields_ = [(n, wintypes.DWORD) for n in (
                "dest", "mask", "policy", "next_hop", "if_index", "type", "proto", "age",
                "next_hop_as", "metric1", "metric2", "metric3", "metric4", "metric5")]

        row = _Row()
        probes.iphlpapi.GetBestRoute.argtypes = [wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(_Row)]
        if probes.iphlpapi.GetBestRoute(probes.ip_to_ulong("8.8.8.8"), 0, ctypes.byref(row)) == 0:
            gw = probes.ulong_to_ip(row.next_hop)
            return "" if gw == "0.0.0.0" else gw
        return ""
    args = ["route", "-n", "get", "default"] if sys.platform == "darwin" else ["ip", "route", "show", "default"]
    m = re.search(r"(?:gateway:|via)\s+(\d+\.\d+\.\d+\.\d+)", probes.run_quiet(args))
    return m.group(1) if m else ""


def _windows_tcpip_params(ip: str) -> dict:
    """DNS / DHCP details for the adapter owning ``ip`` straight from the registry (fast, no shell)."""
    import winreg

    base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"

    def val(key, name, default=None):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return default

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
        for i in range(winreg.QueryInfoKey(root)[0]):
            with winreg.OpenKey(root, winreg.EnumKey(root, i)) as key:
                addrs = [val(key, "DhcpIPAddress", "")] + list(val(key, "IPAddress", []) or [])
                if ip not in addrs:
                    continue
                dns = val(key, "NameServer", "") or val(key, "DhcpNameServer", "")
                return {
                    "dns": [d for d in re.split(r"[,\s]+", dns) if d],
                    "dhcp_enabled": bool(val(key, "EnableDHCP", 0)),
                    "dhcp_server": val(key, "DhcpServer", "") or "",
                    "lease_expires": val(key, "LeaseTerminatesTime"),
                    "domain": val(key, "DhcpDomain", "") or val(key, "Domain", "") or "",
                }
    return {}


def _posix_dns() -> list[str]:
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            return re.findall(r"^nameserver\s+(\S+)", fh.read(), re.MULTILINE)
    except OSError:
        return []


def wifi_details() -> dict[str, str]:
    """Connected Wi-Fi details from ``netsh wlan show interfaces`` (Windows only)."""
    if not probes.IS_WINDOWS:
        return {}
    wanted = {"name": "interface", "ssid": "ssid", "bssid": "bssid", "radio type": "radio",
              "authentication": "auth", "channel": "channel", "band": "band", "signal": "signal",
              "receive rate (mbps)": "rx_mbps", "transmit rate (mbps)": "tx_mbps", "state": "state"}
    blocks, current = [], {}
    for line in probes.run_quiet(["netsh", "wlan", "show", "interfaces"]).splitlines():
        key, sep, value = line.partition(" : ")
        key = key.strip().lower()
        if not sep:
            continue
        if key == "name" and current:
            blocks.append(current)
            current = {}
        if key in wanted:
            current[wanted[key]] = value.strip()
    if current:
        blocks.append(current)
    connected = [b for b in blocks if b.get("state", "").lower() == "connected"]
    return connected[0] if connected else {}


def get_network_info() -> NetworkInfo:
    info = NetworkInfo(hostname=socket.gethostname(), ip=primary_ip())
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if not any(a.family == socket.AF_INET and a.address == info.ip for a in addrs):
            continue
        info.adapter = name
        info.speed_mbps = stats[name].speed if name in stats else 0
        for a in addrs:
            if a.family == socket.AF_INET and a.address == info.ip:
                info.netmask = a.netmask or "255.255.255.0"
            elif a.family == psutil.AF_LINK and a.address:
                info.mac = probes.normalize_mac(a.address)
        break
    if info.netmask:
        info.cidr = str(ipaddress.IPv4Interface(f"{info.ip}/{info.netmask}").network)

    info.gateway = default_gateway()
    if info.gateway:
        info.gateway_mac = probes.arp_resolve(info.gateway) or ""

    if probes.IS_WINDOWS:
        try:
            for k, v in _windows_tcpip_params(info.ip).items():
                setattr(info, k, v)
        except OSError:
            log.exception("Registry lookup failed")
        wifi = wifi_details()
        if wifi and wifi.get("interface", "").lower() == info.adapter.lower():
            info.wifi = wifi
    else:
        info.dns = _posix_dns()
    return info


def get_public_info(timeout: float = 5.0) -> dict:
    """Public IP and ISP. Tries two free services so one being down doesn't matter."""
    sources = (
        ("http://ip-api.com/json/?fields=status,query,isp,org,as,city,regionName,country,timezone",
         lambda d: {"ip": d["query"], "isp": d.get("isp", ""), "org": d.get("org", ""),
                    "asn": d.get("as", ""), "city": d.get("city", ""),
                    "region": d.get("regionName", ""), "country": d.get("country", ""),
                    "timezone": d.get("timezone", "")}),
        ("https://ipinfo.io/json",
         lambda d: {"ip": d["ip"], "isp": d.get("org", ""), "org": d.get("org", ""),
                    "asn": d.get("org", "").split(" ")[0], "city": d.get("city", ""),
                    "region": d.get("region", ""), "country": d.get("country", ""),
                    "timezone": d.get("timezone", "")}),
    )
    for url, mapper in sources:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NetEasy"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return mapper(json.loads(resp.read().decode()))
        except (OSError, ValueError, KeyError) as exc:
            log.warning("Public IP lookup via %s failed: %s", url, exc)
    return {"error": "No internet access (public IP lookup failed)"}


def _ping_series(ip: str, count: int = 4) -> dict:
    results = [probes.ping(ip, 1000) for _ in range(count)]
    rtts = [r.rtt_ms for r in results if r.alive and r.rtt_ms is not None]
    return {
        "target": ip,
        "avg_ms": round(statistics.mean(rtts), 1) if rtts else None,
        "max_ms": max(rtts) if rtts else None,
        "loss_pct": round(100 * (count - len(rtts)) / count),
    }


def _dns_lookup_ms(host: str = "www.google.com") -> float | None:
    start = time.perf_counter()
    try:
        socket.getaddrinfo(host, 443)
    except OSError:
        return None
    return round((time.perf_counter() - start) * 1000, 1)


def connectivity_check(gateway: str) -> dict:
    """Latency/loss to the router and the internet, plus DNS resolution time."""
    pool = ThreadPoolExecutor(max_workers=4)
    try:
        gw = pool.submit(_ping_series, gateway) if gateway else None
        cf = pool.submit(_ping_series, "1.1.1.1")
        gg = pool.submit(_ping_series, "8.8.8.8")
        dns = pool.submit(_dns_lookup_ms)
        try:
            dns_ms = dns.result(timeout=6)  # getaddrinfo has no timeout of its own
        except FuturesTimeout:
            dns_ms = None
        return {
            "gateway": gw.result() if gw else None,
            "internet": [cf.result(), gg.result()],
            "dns_ms": dns_ms,
        }
    finally:
        pool.shutdown(wait=False)
