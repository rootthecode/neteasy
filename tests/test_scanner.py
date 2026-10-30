import time

import pytest

from neteasy import discovery, probes, scanner
from neteasy.fingerprint import VendorDB
from neteasy.netinfo import NetworkInfo


@pytest.fixture
def lan(monkeypatch):
    """A fake /29 LAN; tests set ``lan["up"]`` to the IPs that answer ARP."""
    state = {"up": {}}
    monkeypatch.setattr(probes, "IS_WINDOWS", True)
    monkeypatch.setattr(probes, "arp_resolve", lambda ip: state["up"].get(ip))
    monkeypatch.setattr(probes, "ping", lambda ip, timeout_ms=800: probes.PingResult(ip in state["up"], 1.0, 64))
    monkeypatch.setattr(probes, "arp_table", dict)
    monkeypatch.setattr(probes, "netbios_name", lambda ip: (None, None))
    monkeypatch.setattr(probes, "reverse_dns", lambda ip, timeout=1.5: None)
    monkeypatch.setattr(probes, "tcp_open", lambda ip, port, timeout=0.4: False)
    monkeypatch.setattr(discovery, "broadcast_discover", lambda *a: {})
    return state


def _scan(s: scanner.Scanner, info: NetworkInfo) -> dict:
    assert s.start(info)
    deadline = time.time() + 10
    while s.snapshot()["status"] == "scanning" and time.time() < deadline:
        time.sleep(0.05)
    return {d["ip"]: d for d in s.snapshot()["devices"]}


def _info(gateway_mac: str = "AA:00:00:00:00:01") -> NetworkInfo:
    return NetworkInfo(ip="10.0.0.2", netmask="255.255.255.248", cidr="10.0.0.0/29", mac="AA:00:00:00:00:02",
                       gateway="10.0.0.1", gateway_mac=gateway_mac, hostname="me")


def test_devices_persist_across_rescans_and_go_offline(lan):
    vendors = VendorDB()
    vendors._ready.set()
    s = scanner.Scanner(vendors)

    lan["up"] = {"10.0.0.1": "AA:00:00:00:00:01", "10.0.0.5": "DA:11:22:33:44:55"}
    first = _scan(s, _info())
    assert set(first) == {"10.0.0.1", "10.0.0.2", "10.0.0.5"}
    assert first["10.0.0.5"]["online"] and first["10.0.0.5"]["randomized_mac"]

    lan["up"] = {"10.0.0.1": "AA:00:00:00:00:01", "10.0.0.3": "AA:00:00:00:00:03"}  # phone dozes, PC joins
    second = _scan(s, _info())
    assert second["10.0.0.5"]["online"] is False  # kept, marked offline
    assert second["10.0.0.3"]["online"] is True
    assert second["10.0.0.5"]["last_seen"] <= second["10.0.0.3"]["last_seen"]

    third = _scan(s, _info(gateway_mac="BB:00:00:00:00:01"))  # different site: fresh list
    assert "10.0.0.5" not in third
