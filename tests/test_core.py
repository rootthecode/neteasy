import struct

from neteasy.fingerprint import VendorDB, guess_device, is_randomized_mac, ttl_family
from neteasy.probes import normalize_mac, parse_nbstat
from neteasy.scanner import plan_targets

MANUF_SAMPLE = (
    "# comment\n"
    "0C:0E:76         \tDLinkInterna\tD-Link International\n"
    "00:1B:C5:00:00:00/36\tConvergi\tConverging Systems Inc.\n"
    "00:1B:C5\tIEEERegi\tIEEE Registration Authority\n"
)


def test_vendor_parse_and_longest_prefix():
    db = VendorDB()
    db._tables = VendorDB.parse(MANUF_SAMPLE)
    assert db.lookup("0C:0E:76:12:34:56") == "D-Link International"
    assert db.lookup("00:1B:C5:00:00:12") == "Converging Systems Inc."
    assert db.lookup("00:1B:C5:FF:00:12") == "IEEE Registration Authority"
    assert db.lookup("AA:BB:CC:00:00:00") is None


def test_randomized_mac():
    assert is_randomized_mac("DA:A1:19:00:00:01")
    assert not is_randomized_mac("0C:0E:76:12:34:56")
    assert not is_randomized_mac(None)


def test_ttl_family():
    assert ttl_family(64) == "unix"
    assert ttl_family(127) == "windows"
    assert ttl_family(254) == "network"
    assert ttl_family(None) is None


def test_guess_rules():
    assert guess_device(ttl=64, ports=[53, 80], vendor=None, name=None, is_gateway=True).kind == "router"
    assert guess_device(ttl=128, ports=[445], vendor="Intel", name=None).os == "Windows"
    assert guess_device(ttl=None, ports=[], vendor=None, name="DESKTOP-AB12").os == "Windows"
    assert guess_device(ttl=64, ports=[62078], vendor="Apple, Inc.", name=None).kind == "phone"
    assert guess_device(ttl=64, ports=[9100], vendor="HP", name=None).kind == "printer"
    assert guess_device(ttl=64, ports=[], vendor=None, name=None, randomized=True).kind == "phone"
    assert guess_device(ttl=64, ports=[22], vendor=None, name=None).kind == "server"


def test_parse_nbstat():
    header = b"\x00" * 56
    names = [
        (b"FRONTDESK-PC   ", 0x00, 0x0400),  # unique computer name
        (b"WORKGROUP      ", 0x00, 0x8400),  # group flag set
        (b"FRONTDESK-PC   ", 0x20, 0x0400),  # file-server suffix, ignored
    ]
    body = bytes([len(names)]) + b"".join(n + bytes([s]) + struct.pack(">H", f) for n, s, f in names)
    assert parse_nbstat(header + body) == ("FRONTDESK-PC", "WORKGROUP")
    assert parse_nbstat(b"short") == (None, None)


def test_plan_targets_caps_large_subnets():
    hosts, note = plan_targets("192.168.0.106", "255.255.255.0")
    assert len(hosts) == 254 and note is None
    hosts, note = plan_targets("10.20.30.40", "255.255.0.0")
    assert len(hosts) == 254 and hosts[0] == "10.20.30.1" and note


def test_normalize_mac():
    assert normalize_mac("0c-e-76-12-34-56") == "0C:0E:76:12:34:56"


def test_csv_export_neutralises_formulas():
    from neteasy.app import _csv_safe

    assert _csv_safe("=HYPERLINK(\"x\")") == "'=HYPERLINK(\"x\")"
    assert _csv_safe("@SUM(A1)") == "'@SUM(A1)"
    assert _csv_safe("DESKTOP-AB12") == "DESKTOP-AB12"
    assert _csv_safe(64) == 64
