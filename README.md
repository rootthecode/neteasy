# NetEasy

A fast, good-looking desktop LAN inspector for field support engineers.
Plug your laptop into a client's network, open NetEasy, and in a few seconds you see:

| Panel | What you get |
|---|---|
| **This computer** | Local IP, hostname, MAC, subnet (CIDR), adapter |
| **Router** | Gateway IP + MAC + vendor, DHCP server, lease expiry, one-click **Admin** page |
| **Internet / ISP** | Public IP, ISP, ASN, city/country, DNS servers in use |
| **Wi-Fi** | SSID, signal %, channel/band, 802.11 standard, link rate, security |
| **Connection health** | Latency + packet loss to router, 1.1.1.1, 8.8.8.8, and DNS lookup time |
| **Devices** | Every host on the subnet: name, IP, MAC, vendor, OS/type guess, open services, latency |

**Live monitoring** is on by default. NetEasy rescans every 45 s and announces new devices as they join. Devices that go quiet,
like a dozing phone, stay in the list greyed out as "offline · seen 3 min ago". Moving to another network starts a fresh list.

Click a device for details and actions: copy IP/MAC, open its web UI, Remote Desktop, browse SMB shares,
or jump straight into a troubleshooting tool for that device.
Filter by type (computers, phones, network gear, printers & cameras), search anything, export to CSV.

### Tools tab

| Tool | Use it for |
|---|---|
| **Ping** | Latency, loss and jitter live. Count `0` keeps pinging (like `ping -t`). Set packet size and Don't Fragment to test MTU |
| **Telnet / port check** | `telnet host port` style check: OPEN, CLOSED or FILTERED, connect time and the service banner (SSH, HTTP server…) |
| **Traceroute** | Hop-by-hop path with reverse names, to see where latency or loss starts |
| **DNS lookup** | A/AAAA/MX/TXT/NS/CNAME/PTR/SOA/SRV. Ask several servers at once (`system, 8.8.8.8, 1.1.1.1`) and compare |
| **Port scan** | `common`, ranges (`1-1024`), lists (`22,80,443`) or `all` |
| **Wake-on-LAN** | Magic packet to a scanned PC's MAC |
| **Speed test** | Download and upload throughput via Cloudflare |

## Run it

Double-click **`run.bat`**. The first run creates `.venv` and installs dependencies, and later runs start instantly.

Or manually:

```powershell
python -m venv .venv
.venv\Scripts\pip install -e .[dev]
.venv\Scripts\python -m neteasy          # add --debug for logs + web inspector
```

Requirements: Windows 10/11, Python 3.10+, Microsoft Edge WebView2 (preinstalled on Windows 10/11).
**No admin rights and no Npcap needed.**

## How it works

1. **Discovery.** It uses several signals, so quiet devices aren't missed:
   - It sends an ARP request to every address in the subnet through the Win32 `SendARP` API, 256 in parallel. ARP finds Windows PCs even when their firewall blocks ping. Live hosts then get an ICMP echo through `IcmpSendEcho` for latency and TTL.
   - At the same time it sends mDNS/Bonjour and SSDP/UPnP queries. Phones, Apple and Cast devices, smart TVs and printers answer with names like *"Sara's iPhone"*, model IDs and the services they offer.
   - It reads the OS neighbour cache.
   - It makes a second ARP pass over silent addresses while hosts are being identified. Phones in Wi-Fi power-save often miss the first request.
2. **Identification.** For each host it runs a NetBIOS name query (Windows name + workgroup), a reverse DNS lookup and a TCP connect to
   about 20 common ports (SMB, RDP, SSH, HTTP, printer, RTSP, iPhone sync, Cast…). UPnP devices are asked for their maker and model.
3. **Fingerprinting.** It combines the MAC vendor (Wireshark OUI list, cached in `%LOCALAPPDATA%\NetEasy`), the TTL family
   (64 = Linux/Apple/Android, 128 = Windows, 255 = network gear), open ports and the hostname into an OS and device-type guess.
   mDNS services and models and the UPnP description take priority over these guesses. Randomized (private) phone MACs are flagged.

Large subnets (more than 1024 hosts) are narrowed to the local /24 so a scan stays around 10–15 s.
If only the router answers, NetEasy warns that the Wi-Fi probably has client (AP) isolation turned on.

## Project layout

```
neteasy/
  probes.py       raw probes: ARP, ICMP (with TTL/size/DF), NetBIOS, TCP (ctypes on Windows, CLI fallback elsewhere)
  dnswire.py      tiny DNS wire-format codec (used by DNS lookup and mDNS)
  discovery.py    mDNS/Bonjour + SSDP/UPnP multicast discovery
  netinfo.py      adapter / gateway / DNS / DHCP / Wi-Fi / public IP / connectivity test
  fingerprint.py  MAC vendor DB + OS & device-type heuristics
  scanner.py      threaded scan pipeline, progressive snapshots for the UI
  tools.py        the toolbox (ping, port check, traceroute, DNS, port scan, WoL, speed) + streaming job runner
  app.py          pywebview window + JS bridge (Api)
  ui/             index.html, style.css, app.js, tools.js (vanilla, no build step, works offline)
tests/            unit tests for parsing, heuristics and the job runner
```

Layering is one-way: `probes/dnswire → discovery/netinfo/fingerprint → scanner → tools → app → ui`.

## Development

```powershell
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m ruff check neteasy tests
```

## Limits

- OS detection is a best-effort guess. A fully firewalled PC with a randomized MAC can only be shown as "present".
- Devices on another VLAN, a guest SSID or behind Wi-Fi client isolation are invisible to any LAN scanner. Use the router's client list instead.
- The public IP and ISP lookup uses ip-api.com, with ipinfo.io as the fallback.
