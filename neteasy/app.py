"""Desktop shell: a pywebview window whose JavaScript talks to :class:`Api`."""

from __future__ import annotations

import argparse
import csv
import functools
import io
import ipaddress
import logging
import os
import subprocess
import webbrowser
from pathlib import Path

import webview

from . import __version__, netinfo
from .fingerprint import VendorDB
from .scanner import Scanner
from .tools import JobManager

log = logging.getLogger(__name__)
UI_DIR = Path(__file__).parent / "ui"


def _safe(fn):
    """Never let a Python exception escape to the JS bridge; return it as data instead."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            log.exception("API call %s failed", fn.__name__)
            return {"error": str(exc)}

    return wrapper


SYSTEM_ROOT = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))


def _csv_safe(value):
    """Neutralise spreadsheet formulas: hostnames/vendors come from the network."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


class Api:
    """Methods exposed to the UI as ``window.pywebview.api.<name>()``."""

    def __init__(self) -> None:
        self._window: webview.Window | None = None
        self._vendors = VendorDB()
        self._vendors.load_async()
        self._scanner = Scanner(self._vendors)
        self._jobs = JobManager()
        self._net: netinfo.NetworkInfo | None = None

    def _bind(self, window: webview.Window) -> None:
        self._window = window

    def _lan_ip(self, value: str) -> str:
        """Only act on addresses that belong to this LAN (our subnet or a scanned device)."""
        ip = ipaddress.IPv4Address(value)  # raises on anything that is not a plain IPv4 address
        in_subnet = bool(self._net and self._net.cidr) and ip in ipaddress.IPv4Network(self._net.cidr)
        if not in_subnet and str(ip) not in {d["ip"] for d in self._scanner.snapshot()["devices"]}:
            raise ValueError(f"{value} is not on this network")
        return str(ip)

    @_safe
    def version(self) -> str:
        return __version__

    # --- toolbox (ping, telnet, traceroute, …) — see tools.py ---

    @_safe
    def run_tool(self, tool: str, params: dict) -> dict:
        return {"job": self._jobs.start(str(tool), dict(params or {}))}

    @_safe
    def poll_tool(self, job_id: str, since: int = 0) -> dict:
        return self._jobs.poll(str(job_id), int(since))

    @_safe
    def stop_tool(self, job_id: str) -> dict:
        self._jobs.stop(str(job_id))
        return {"ok": True}

    @_safe
    def get_network(self) -> dict:
        self._net = netinfo.get_network_info()
        return self._net.to_dict()

    @_safe
    def get_public(self) -> dict:
        return netinfo.get_public_info()

    @_safe
    def connectivity(self) -> dict:
        net = self._net or netinfo.get_network_info()
        return netinfo.connectivity_check(net.gateway)

    @_safe
    def start_scan(self) -> dict:
        self._net = netinfo.get_network_info()
        return {"started": self._scanner.start(self._net)}

    @_safe
    def cancel_scan(self) -> dict:
        self._scanner.cancel()
        return {"ok": True}

    @_safe
    def get_scan(self) -> dict:
        return self._scanner.snapshot()

    @_safe
    def open_web(self, ip: str, port: int = 80) -> dict:
        ip, port = self._lan_ip(ip), int(port)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid port {port}")
        scheme = "https" if port in (443, 8443) else "http"
        webbrowser.open(f"{scheme}://{ip}" + ("" if port in (80, 443) else f":{port}"))
        return {"ok": True}

    @_safe
    def open_rdp(self, ip: str) -> dict:
        subprocess.Popen([str(SYSTEM_ROOT / "System32" / "mstsc.exe"), f"/v:{self._lan_ip(ip)}"])
        return {"ok": True}

    @_safe
    def open_share(self, ip: str) -> dict:
        subprocess.Popen([str(SYSTEM_ROOT / "explorer.exe"), f"\\\\{self._lan_ip(ip)}"])
        return {"ok": True}

    @_safe
    def export_csv(self) -> dict:
        rows = self._scanner.snapshot()["devices"]
        if not rows:
            return {"error": "Nothing to export yet — run a scan first."}
        cols = ["ip", "name", "mac", "vendor", "os", "kind", "hostname", "netbios", "workgroup", "mdns_name",
                "model", "upnp_maker", "upnp_model", "ttl", "rtt_ms", "ports", "bonjour", "found_by",
                "randomized_mac", "is_gateway"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            row = {k: _csv_safe(" ".join(map(str, v)) if isinstance(v, list) and k != "services" else v)
                   for k, v in r.items()}
            writer.writerow(row)

        dialog = getattr(getattr(webview, "FileDialog", None), "SAVE", None) or webview.SAVE_DIALOG
        target = self._window.create_file_dialog(dialog, save_filename="neteasy-scan.csv")
        if not target:
            return {"cancelled": True}
        path = Path(target if isinstance(target, str) else target[0])
        path.write_text(buf.getvalue(), encoding="utf-8-sig", newline="")
        return {"path": str(path)}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="neteasy", description="NetEasy LAN inspector")
    parser.add_argument("--debug", action="store_true", help="verbose logs + web inspector")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    api = Api()
    window = webview.create_window(
        f"NetEasy {__version__}",
        str(UI_DIR / "index.html"),
        js_api=api,
        width=1280,
        height=820,
        min_size=(960, 640),
        maximized=True,
        background_color="#070b18",
    )
    api._bind(window)
    webview.start(debug=args.debug)
