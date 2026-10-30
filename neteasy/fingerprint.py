"""Device identification: MAC vendor lookup and OS / device-type heuristics."""

from __future__ import annotations

import logging
import os
import platform
import re
import threading
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

CACHE_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".cache") / "NetEasy"
MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
MANUF_MAX_AGE = 60 * 24 * 3600  # refresh the vendor list every 60 days


def is_randomized_mac(mac: str | None) -> bool:
    """Locally administered bit set -> private/random MAC (modern phones, Windows 'random HW address')."""
    if not mac:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


class VendorDB:
    """OUI -> manufacturer table built from Wireshark's ``manuf`` file, cached on disk."""

    def __init__(self, path: Path = CACHE_DIR / "manuf.txt") -> None:
        self._path = path
        self._tables: dict[int, dict[int, str]] = {}
        self._ready = threading.Event()

    def load_async(self) -> None:
        threading.Thread(target=self._load, name="vendor-db", daemon=True).start()

    def wait(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def lookup(self, mac: str | None) -> str | None:
        if not mac or not self._tables:
            return None
        try:
            value = int(mac.replace(":", "").replace("-", ""), 16)
        except ValueError:
            return None
        for bits in sorted(self._tables, reverse=True):  # most specific block first
            name = self._tables[bits].get(value >> (48 - bits))
            if name:
                return name
        return None

    def _load(self) -> None:
        try:
            stale = not self._path.exists() or time.time() - self._path.stat().st_mtime > MANUF_MAX_AGE
            if stale:
                self._download()
            if self._path.exists():
                self._tables = self.parse(self._path.read_text(encoding="utf-8", errors="replace"))
                log.info("Vendor DB loaded: %d entries", sum(map(len, self._tables.values())))
        except Exception:  # vendor names are a nice-to-have; never break the app
            log.exception("Vendor DB unavailable")
        finally:
            self._ready.set()

    def _download(self) -> None:
        try:
            req = urllib.request.Request(MANUF_URL, headers={"User-Agent": "NetEasy"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = resp.read()
            # A captive portal can answer 200 with an HTML page: never overwrite a good cache with junk.
            if sum(map(len, self.parse(data.decode("utf-8", errors="replace")).values())) < 1000:
                log.warning("Vendor list download looked invalid; keeping the cached copy")
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(self._path)
        except Exception as exc:  # offline/blocked: fall back to the cached copy
            log.warning("Could not download vendor list: %s", exc)

    @staticmethod
    def parse(text: str) -> dict[int, dict[int, str]]:
        tables: dict[int, dict[int, str]] = {}
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            prefix, _, bits_s = parts[0].strip().partition("/")
            bits = int(bits_s) if bits_s.isdigit() else 24
            hexdigits = prefix.replace(":", "").replace("-", "").replace(".", "")
            try:
                key = int(hexdigits.ljust(12, "0")[:12], 16) >> (48 - bits)
            except ValueError:
                continue
            name = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
            tables.setdefault(bits, {})[key] = name
        return tables


# --- OS / device-type heuristics -------------------------------------------------------

PHONE_VENDORS = ("samsung", "xiaomi", "oppo", "vivo", "huawei", "honor", "oneplus", "realme",
                 "motorola", "nokia", "google", "infinix", "tecno", "itel", "nothing")
NETWORK_VENDORS = ("tp-link", "ubiquiti", "cisco", "mikrotik", "routerboard", "netgear", "d-link",
                   "tenda", "zyxel", "aruba", "juniper", "ruckus", "mercusys", "linksys",
                   "fortinet", "zte", "h3c", "cambium", "grandstream")
CAMERA_VENDORS = ("hikvision", "dahua", "uniview", "ezviz", "axis comm", "hanwha", "reolink", "imou")
PRINTER_VENDORS = ("canon", "seiko epson", "brother", "kyocera", "ricoh", "xerox", "lexmark",
                   "konica", "sharp corp")
TV_VENDORS = ("lg electronics", "sony", "tcl", "hisense", "roku", "amazon", "vizio", "skyworth")
PC_VENDORS = ("intel", "dell", "lenovo", "hewlett", "asustek", "micro-star", "gigabyte", "realtek",
              "liteon", "azurewave", "acer", "microsoft", "giga-byte")

WINDOWS_PORTS = {135, 139, 445, 3389}
PRINTER_PORTS = {515, 631, 9100}
CAST_PORTS = {8008, 8009}


@dataclass(frozen=True)
class Guess:
    os: str
    kind: str  # router | computer | phone | printer | camera | tv | network | server | device | unknown
    confidence: str  # high | medium | low


def _has(text: str, needles: tuple[str, ...]) -> bool:
    return any(n in text for n in needles)


def ttl_family(ttl: int | None) -> str | None:
    """Initial TTL is OS-specific: 64 Linux/macOS/iOS/Android, 128 Windows, 255 network gear."""
    if ttl is None:
        return None
    if ttl <= 64:
        return "unix"
    if ttl <= 128:
        return "windows"
    return "network"


def local_os() -> str:
    system = platform.system()
    if system == "Windows":
        build = int(platform.version().split(".")[-1] or 0)
        return f"Windows {'11' if build >= 22000 else platform.release()} (build {build})"
    if system == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    return f"{system} {platform.release()}"


def guess_device(
    *,
    ttl: int | None,
    ports: set[int] | list[int],
    vendor: str | None,
    name: str | None,
    netbios: bool = False,
    is_gateway: bool = False,
    is_self: bool = False,
    randomized: bool = False,
    bonjour: list[str] | tuple[str, ...] = (),
    model: str | None = None,
    upnp: str | None = None,
) -> Guess:
    v, n, p = (vendor or "").lower(), (name or "").lower(), set(ports)
    m, u, svc = (model or "").lower(), (upnp or "").lower(), set(bonjour)
    family = ttl_family(ttl)

    if is_self:
        return Guess(local_os(), "computer", "high")
    if is_gateway:
        return Guess("Router / gateway firmware", "router", "high")
    # Self-descriptions (mDNS model / services, UPnP) beat every heuristic below.
    if m.startswith("iphone") or _has(n, ("iphone",)):
        return Guess("iOS", "phone", "high")
    if m.startswith("ipad") or _has(n, ("ipad",)):
        return Guess("iPadOS", "phone", "high")
    if m.startswith(("mac", "imac")) or "macbook" in n:
        return Guess("macOS", "computer", "high")
    if m.startswith("appletv") or ("_airplay._tcp" in svc and "apple" in v and not p & {22, 548}):
        return Guess("Apple TV / AirPlay", "tv", "medium")
    if svc & {"_googlecast._tcp", "_androidtvremote2._tcp", "_amzn-wplay._tcp"}:
        return Guess("Android TV / Chromecast", "tv", "high")
    if svc & {"_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp"}:
        return Guess("Printer firmware", "printer", "high")
    if "_adb-tls-connect._tcp" in svc:
        return Guess("Android", "phone", "high")
    if svc & {"_companion-link._tcp", "_apple-mobdev2._tcp", "_rdlink._tcp"}:
        return Guess("Apple iOS / iPadOS", "phone", "high")
    if "_hap._tcp" in svc or "_sonos._tcp" in svc:
        return Guess("Smart-home device", "device", "medium")
    if "windows" in u:
        return Guess("Windows", "computer", "high")
    if re.search(r"\btv\b|bravia|webos|tizen|roku", u):
        return Guess("Smart TV", "tv", "high")
    if "internetgatewaydevice" in u or "wfadevice" in u:
        return Guess("Router / access point", "network", "high")
    if 62078 in p:
        return Guess("iOS / iPadOS", "phone", "high")
    if p & PRINTER_PORTS or _has(v, PRINTER_VENDORS):
        return Guess("Printer firmware", "printer", "high" if p & PRINTER_PORTS else "medium")
    if 554 in p or _has(v, CAMERA_VENDORS):
        return Guess("IP camera / NVR", "camera", "medium")
    if p & CAST_PORTS or _has(v, TV_VENDORS):
        return Guess("Smart TV / Cast device", "tv", "medium")
    if p & WINDOWS_PORTS or (netbios and family != "unix") or family == "windows" \
            or n.startswith(("desktop-", "laptop-")):
        return Guess("Windows", "computer", "high" if p & WINDOWS_PORTS or netbios else "medium")
    if "apple" in v:
        if p & {22, 548, 5900}:
            return Guess("macOS", "computer", "high")
        return Guess("Apple iOS / macOS", "phone", "medium")
    if 5555 in p or "android" in n or (_has(v, PHONE_VENDORS) and family != "network"):
        return Guess("Android", "phone", "medium")
    if randomized:
        return Guess("Android / iOS (private MAC)", "phone", "low")
    if family == "network" or _has(v, NETWORK_VENDORS):
        return Guess("Network device (switch / AP)", "network", "medium")
    if svc & {"_smb._tcp", "_workstation._tcp"} and family != "windows":
        return Guess("Linux / NAS", "server", "medium")
    if 22 in p and family == "unix":
        return Guess("Linux / Unix", "server", "medium")
    if family == "unix":
        return Guess("Linux / embedded", "device", "low")
    if _has(v, PC_VENDORS):
        return Guess("PC (OS hidden by firewall)", "computer", "low")
    return Guess("Unknown", "unknown", "low")
