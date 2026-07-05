# SOC Vulnerability Dashboard — Backend Implementation Plan

## Project Overview

This is the **backend half** of a two-repo portfolio project:

- **This repo (owned by [Friend's Name])**: Python + FastAPI backend that performs local network/port scanning using `nmap`, classifies findings by risk level, and exposes the results as a JSON API. This is the CompTIA Security+ portfolio piece.
- **Separate repo (owned by me, the Flutter dev)**: A Flutter app that consumes this API and renders the results as a security dashboard (charts, risk cards, etc). Not part of this repo.

The two projects communicate purely over HTTP using a JSON contract defined below. They are built and versioned independently.

## Why This Project Exists

[Friend's Name] is studying for CompTIA Security+. The goal is a portfolio piece that demonstrably maps to real exam domains, rather than a generic tutorial clone. Each part of the backend should trace back to a specific domain:

| Security+ Domain | How this project demonstrates it |
|---|---|
| Domain 2: Threats, Vulnerabilities, and Mitigation | The scanner identifies open ports/services and flags known risky configurations (e.g. Telnet, unencrypted HTTP, RDP exposure) |
| Domain 4: Security Operations | Scan results are structured, logged, and classified into Critical/High/Medium/Low — mirroring how a SOC analyst triages findings |
| Domain 3: Security Architecture | The API itself is protected with a simple API key auth layer, and only scans pre-approved targets — a basic access-control pattern |
| Domain 1 & 5: General Concepts & Program Management | Covered in the README via a written domain-mapping section, not in code |

## Scope Boundaries (Important)

- **Local/owned targets only.** The API only permits scanning targets in an explicit allow-list (default: `127.0.0.1`, `localhost`, and the user's own LAN). It must never be positioned as a tool for scanning arbitrary external IPs. This is both a legal/ethical boundary and a deliberate design decision worth calling out in the README as "responsible scope."
- **This is a portfolio demo, not a production security tool.** No need to over-engineer; the priority is: (1) working end-to-end, (2) clean/readable code, (3) a README that clearly narrates the security reasoning.

## Architecture

```
Flutter App  --HTTP POST + X-API-Key-->  FastAPI Backend  -->  nmap (via python-nmap)
                                                |
                                                v
                                        Risk Classification Engine
                                                |
                                                v
                                        JSON Response  <-- back to Flutter
```

## JSON Contract (the interface between the two repos — treat as stable/versioned)

There are two endpoints. `/discover` finds devices on the network; `/scan` inspects one specific device in detail. The typical Flutter flow is: call `/discover` first to show a device list, then call `/scan` on whichever device the user taps.

### Endpoint 1 — Network Discovery

Request:
```json
POST /api/v1/discover
Headers: { "X-API-Key": "<key>", "Content-Type": "application/json" }
Body: { "subnet": "192.168.1.0/24" }
```

Response:
```json
{
  "subnet": "192.168.1.0/24",
  "status": "completed",
  "scan_duration_seconds": 2.8,
  "devices_found": [
    { "ip": "192.168.1.1",  "hostname": "router.local", "status": "online" },
    { "ip": "192.168.1.15", "hostname": "unknown",       "status": "online" }
  ]
}
```

### Endpoint 2 — Port/Vulnerability Scan (per device)

Request:
```json
POST /api/v1/scan
Headers: { "X-API-Key": "<key>", "Content-Type": "application/json" }
Body: { "target": "192.168.1.15" }
```

Response:
```json
{
  "target_ip": "192.168.1.15",
  "status": "completed",
  "scan_duration_seconds": 4.2,
  "vulnerabilities_found": [
    {
      "port": 22,
      "service": "SSH",
      "status": "Open",
      "risk_level": "Medium",
      "description": "Outdated OpenSSH version detected. Vulnerable to potential exploit CVE-2024-6387."
    }
  ]
}
```

Any change to either schema should be a deliberate, communicated decision since the Flutter app is built against it independently.

### Backend implementation sketch — discovery

This is simpler than the port scanner: no service/version parsing, just "who responds." Add to `services/scanner.py` (or a new `services/discovery.py`):

```python
import nmap
import time

def run_discovery(subnet: str) -> dict:
    start = time.time()
    scanner = nmap.PortScanner()
    scanner.scan(hosts=subnet, arguments="-sn")  # -sn = ping sweep, no port scan

    devices = []
    for host in scanner.all_hosts():
        hostname = scanner[host].hostname() or "unknown"
        devices.append({
            "ip": host,
            "hostname": hostname,
            "status": "online",
        })

    return {
        "subnet": subnet,
        "status": "completed",
        "scan_duration_seconds": round(time.time() - start, 2),
        "devices_found": devices,
    }
```

Then a matching route in `routers/scan.py` (or a new `routers/discover.py`):

```python
@router.post("/discover", dependencies=[Depends(verify_api_key)])
def discover(request: DiscoverRequest):
    return run_discovery(request.subnet)
```

Add a `DiscoverRequest` Pydantic model to `models/schemas.py` (just `subnet: str = "192.168.1.0/24"`), and `Device` / `DiscoverResponse` models mirroring the response shape above.

Note: finding your own subnet to pass in (e.g. via `ipconfig`/`ifconfig`) is a manual step for now — auto-detecting the local subnet is a nice stretch goal but not required for v1.

## Folder Structure

```
soc-dashboard-backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI app entrypoint
│   ├── config.py            # Settings, API key, allowed targets
│   ├── models/
│   │   └── schemas.py        # Pydantic request/response models
│   ├── services/
│   │   ├── scanner.py         # nmap wrapper logic
│   │   └── risk_engine.py     # port -> risk classification rules
│   ├── routers/
│   │   └── scan.py            # /api/v1/scan route
│   └── auth.py                # API key dependency
├── tests/
│   └── test_scan.py
├── .env                        # API_KEY=xxxx (gitignored, never committed)
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Expected Frontend Flow (for context — actual Flutter code lives in a separate repo)

Although this repo only contains the backend, it's useful to know how the two endpoints above are expected to be consumed, since it explains *why* both exist:

```
[Home Screen]
   "Scan Network" button
        |
        v
[Device List Screen]        <-- populated from /api/v1/discover
   Router  192.168.1.1
   Unknown 192.168.1.15
   Laptop  192.168.1.20
        |  (user taps one device)
        v
[Vulnerability Dashboard]    <-- populated from /api/v1/scan on that device's IP
   Risk breakdown chart (Critical/High/Medium/Low)
   Per-port cards with risk level + description
```

In short: `/discover` answers "what's on the network," `/scan` answers "what's risky about this one device." The frontend calls them in sequence, not in parallel — a scan always targets a specific IP that came from a prior discovery (or a manually entered IP, if that option gets added later).

A possible future addition (undecided for now): letting the user type in a manual target IP on the home screen, to skip discovery and jump straight to scanning a known device (e.g. their own laptop at `127.0.0.1`).

## Build Order (Phases)

1. **Phase 1 — Static mock endpoint.** `/api/v1/scan` returns hardcoded fake JSON matching the contract above. No nmap yet. Purpose: unblock the Flutter side immediately and validate the API shape.
2. **Phase 2 — Real scanning logic.** Wire up `python-nmap` in `services/scanner.py` against `127.0.0.1`. Confirm real port/service data flows through.
3. **Phase 3 — Risk classification engine.** Build out `risk_engine.py` with a meaningful rule set (not just 5–6 ports — aim for a reasonably comprehensive common-ports table with real CVE-style reasoning in the descriptions).
4. **Phase 4 — Auth layer.** Add the `X-API-Key` header check and the target allow-list restriction.
5. **Phase 5 — Local network discovery.** Add the `/api/v1/discover` endpoint (ping-sweep via `nmap -sn`) to list live devices on the LAN before scanning any one of them. This is the "wow, it can see devices on the network" feature, and the intended entry point of the whole app: discover devices first, then let the user pick one to scan.
6. **Phase 6 — Tests.** Basic pytest coverage for the risk engine and the auth dependency at minimum.
7. **Phase 7 — README & documentation.** Domain-mapping write-up, architecture diagram, setup instructions, and an explicit "Responsible Use" section explaining the scope boundary (local/owned targets only).

## Tech Stack

- Python 3.10+
- FastAPI + Uvicorn
- `python-nmap` (wraps the system `nmap` binary — must be installed separately, plus Npcap on Windows)
- Pydantic / `pydantic-settings` for config and schemas
- pytest for testing

## Open Questions / Decisions Still to Make

- Exact list of ports/services to cover in the risk engine (currently have a starter set: FTP, SSH, Telnet, HTTP, HTTPS, RDP)
- Whether to add a `/api/v1/discover` endpoint for LAN device discovery (Phase 5) as a stretch goal
- How deep to go on "outdated version" detection — real CVE matching is a stretch goal, not a requirement for v1
- Rate limiting / scan cooldown to avoid hammering a target repeatedly (nice-to-have, not required for portfolio purposes)

## Notes for Whoever Picks This Up

The person building this backend is new to cybersecurity (studying for Security+) but comfortable following structured guidance. Prioritize:
- Clear, well-commented code over cleverness
- Getting each phase fully working before moving to the next
- Keeping the JSON contract stable once the Flutter side starts consuming it
- Explaining *why* a risk classification exists (not just hardcoding it) since the reasoning is the actual portfolio value, not just the working scanner
