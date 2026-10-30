"""Low-level network probes: ICMP echo, ARP resolution, NetBIOS name query, TCP connect.

On Windows the probes call iphlpapi.dll directly (no admin rights, no child processes,
locale-independent). Other platforms fall back to the system ``ping`` / ``arp`` tools.
"""

from __future__ import annotations

import contextlib
import re
import socket
import struct
import subprocess
import sys
import threading
from dataclasses import dataclass

IS_WINDOWS = sys.platform == "win32"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0

_MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


@dataclass(frozen=True)
class PingResult:
    alive: bool
    rtt_ms: float | None = None
    ttl: int | None = None


@dataclass(frozen=True)
class EchoReply:
    status: str  # ok | ttl_expired | timeout | unreachable | too_big | error N
    address: str | None = None  # who answered (a router hop when ttl_expired)
    rtt_ms: float | None = None
    ttl: int | None = None


def ip_to_ulong(ip: str) -> int:
    """IPv4 string -> ULONG holding the address in network byte order (what Win32 expects)."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def ulong_to_ip(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value))


def normalize_mac(mac: str) -> str:
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(p.zfill(2) for p in parts).upper()


def run_quiet(args: list[str], timeout: float = 5.0) -> str:
    """Run a command without flashing a console window; return stdout ('' on failure)."""
    try:
        out = subprocess.run(
            args, capture_output=True, timeout=timeout, creationflags=NO_WINDOW, check=False
        )
        return out.stdout.decode(errors="replace")
    except (OSError, subprocess.SubprocessError):
        return ""


if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

    iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    _INVALID_HANDLE = ctypes.c_void_p(-1).value

    class _IpOptionInformation(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_void_p),
        ]

    class _IcmpEchoReply(ctypes.Structure):
        _fields_ = [
            ("Address", ctypes.c_ulong),
            ("Status", ctypes.c_ulong),
            ("RoundTripTime", ctypes.c_ulong),
            ("DataSize", ctypes.c_ushort),
            ("Reserved", ctypes.c_ushort),
            ("Data", ctypes.c_void_p),
            ("Options", _IpOptionInformation),
        ]

    iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
    iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    iphlpapi.IcmpSendEcho.argtypes = [
        wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ]
    iphlpapi.IcmpSendEcho.restype = wintypes.DWORD
    iphlpapi.SendARP.argtypes = [
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)
    ]
    iphlpapi.SendARP.restype = wintypes.DWORD

    _PATTERN = b"abcdefghijklmnopqrstuvwabcdefghi"  # same payload as Windows ping.exe
    _STATUS = {0: "ok", 11013: "ttl_expired", 11010: "timeout", 11002: "unreachable", 11003: "unreachable",
               11004: "unreachable", 11005: "unreachable", 11009: "too_big"}

    def icmp_echo(ip: str, timeout_ms: int = 1000, ttl: int | None = None, size: int = 32,
                  dont_fragment: bool = False) -> EchoReply:
        handle = iphlpapi.IcmpCreateFile()
        if not handle or handle == _INVALID_HANDLE:
            return _echo_subprocess(ip, timeout_ms)
        try:
            payload = (_PATTERN * (size // len(_PATTERN) + 1))[:size]
            options = None
            if ttl or dont_fragment:
                options = ctypes.byref(_IpOptionInformation(Ttl=ttl or 128, Flags=0x02 if dont_fragment else 0))
            buf = ctypes.create_string_buffer(ctypes.sizeof(_IcmpEchoReply) + size + 256)
            count = iphlpapi.IcmpSendEcho(handle, ip_to_ulong(ip), payload, size, options, buf, len(buf), timeout_ms)
            if count == 0:
                return EchoReply(_STATUS.get(ctypes.get_last_error(), "timeout"))
            reply = _IcmpEchoReply.from_buffer(buf)
            status = _STATUS.get(reply.Status, f"error {reply.Status}")
            return EchoReply(status, ulong_to_ip(reply.Address), float(reply.RoundTripTime), int(reply.Options.Ttl))
        finally:
            iphlpapi.IcmpCloseHandle(handle)

    def arp_resolve(ip: str) -> str | None:
        """Ask the OS to ARP for ``ip``. Finds hosts even when their firewall drops ping."""
        mac = (ctypes.c_ubyte * 8)()
        length = ctypes.c_ulong(8)
        if iphlpapi.SendARP(ip_to_ulong(ip), 0, mac, ctypes.byref(length)) != 0:
            return None
        if length.value != 6 or not any(mac[:6]):
            return None
        return ":".join(f"{b:02X}" for b in mac[:6])

else:

    def icmp_echo(ip: str, timeout_ms: int = 1000, ttl: int | None = None, size: int = 32,
                  dont_fragment: bool = False) -> EchoReply:
        return _echo_subprocess(ip, timeout_ms)

    def arp_resolve(ip: str) -> str | None:
        return arp_table().get(ip)


def ping(ip: str, timeout_ms: int = 800) -> PingResult:
    reply = icmp_echo(ip, timeout_ms)
    if reply.status != "ok" or reply.address != ip:
        return PingResult(False)
    return PingResult(True, reply.rtt_ms, reply.ttl)


def _echo_subprocess(ip: str, timeout_ms: int) -> EchoReply:
    r = _ping_subprocess(ip, timeout_ms)
    return EchoReply("ok", ip, r.rtt_ms, r.ttl) if r.alive else EchoReply("timeout")


def _ping_subprocess(ip: str, timeout_ms: int) -> PingResult:
    if IS_WINDOWS:
        args = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif sys.platform == "darwin":
        args = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    out = run_quiet(args, timeout=timeout_ms / 1000 + 2)
    ttl = re.search(r"ttl[=:](\d+)", out, re.IGNORECASE)
    if not ttl:
        return PingResult(False)
    rtt = re.search(r"time[=<]\s*([\d.]+)", out, re.IGNORECASE)
    return PingResult(True, float(rtt.group(1)) if rtt else None, int(ttl.group(1)))


def arp_table() -> dict[str, str]:
    """Parse the OS neighbour cache (``arp -a``) into {ip: MAC}."""
    table: dict[str, str] = {}
    for line in run_quiet(["arp", "-a"] if IS_WINDOWS else ["arp", "-an"]).splitlines():
        ip, mac = _IP_RE.search(line), _MAC_RE.search(line)
        if ip and mac:
            mac_norm = normalize_mac(mac.group(1))
            if mac_norm not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                table[ip.group(1)] = mac_norm
    return table


# --- NetBIOS node-status query (UDP/137): returns the Windows computer name & workgroup ---

_NBSTAT_QUERY = (
    b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # header: id, flags, 1 question
    b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"  # encoded wildcard name "*"
    b"\x00\x21\x00\x01"  # type NBSTAT, class IN
)


def parse_nbstat(data: bytes) -> tuple[str | None, str | None]:
    """Extract (computer_name, workgroup) from a NetBIOS node-status response."""
    offset = 56  # 12 header + 34 name + type/class/ttl/rdlength
    if len(data) <= offset:
        return None, None
    count = data[offset]
    name = group = None
    for i in range(count):
        start = offset + 1 + i * 18
        entry = data[start:start + 18]
        if len(entry) < 18:
            break
        label = entry[:15].decode("ascii", errors="replace").strip()
        suffix, flags = entry[15], struct.unpack(">H", entry[16:18])[0]
        if suffix != 0x00 or not label:
            continue
        if flags & 0x8000:
            group = group or label
        else:
            name = name or label
    return name, group


def netbios_name(ip: str, timeout: float = 0.8) -> tuple[str | None, str | None]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(_NBSTAT_QUERY, (ip, 137))
            data, _ = sock.recvfrom(2048)
            return parse_nbstat(data)
    except OSError:
        return None, None


def reverse_dns(ip: str, timeout: float = 1.5) -> str | None:
    """PTR / LLMNR lookup. gethostbyaddr can block for seconds, so it runs in a daemon
    thread and is abandoned after ``timeout``."""
    result: list[str] = []

    def lookup() -> None:
        with contextlib.suppress(OSError, UnicodeError):
            result.append(socket.gethostbyaddr(ip)[0])

    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    name = result[0] if result else None
    return None if name == ip else name


def tcp_open(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False
