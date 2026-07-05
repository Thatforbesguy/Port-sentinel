# 🛡️ PortSentinel

**A local network vulnerability scanner and risk assessment API.**

PortSentinel discovers devices on your network, probes them for open ports and running services, and classifies each finding by risk severity — giving you a clear, prioritized view of your network's attack surface.

Built with Python, FastAPI, and Nmap.

---

## How It Works

```
             ┌─────────────┐
             │   Client /  │
             │   Frontend  │
             └──────┬──────┘
                    │  HTTP + API Key
                    ▼
          ┌─────────────────────┐
          │   PortSentinel API  │
          │      (FastAPI)      │
          └────┬──────────┬─────┘
               │          │
               ▼          ▼
        ┌──────────┐ ┌──────────────────┐
        │ Discovery │ │  Vulnerability   │
        │  Service  │ │     Scanner      │
        │ (ARP/ICMP)│ │  (Service Detect)│
        └──────────┘ └────────┬─────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Risk Engine     │
                    │  (~30 rules)     │
                    │  Critical → Info │
                    └──────────────────┘
```

**Step 1 — Discover.** Sweep the local subnet with ARP, ICMP, and TCP probes to find every live device, even those hiding behind host firewalls.

**Step 2 — Scan.** Run Nmap service-version detection (`-sV`) against a specific device to identify exactly what software is listening on each open port.

**Step 3 — Classify.** Each open port is evaluated against a built-in risk engine containing ~30 rules that map common services to risk levels (Critical, High, Medium, Low) with plain-English explanations of *why* they are dangerous.

---

## Features

| Feature | Description |
|---------|-------------|
| **Network Discovery** | Multi-protocol host detection (ARP + ICMP + TCP ACK) with automatic local subnet detection. No manual network configuration required. |
| **Port Scanning** | Nmap service-version fingerprinting across the 1,000 most common TCP ports. |
| **Risk Classification** | ~30 rule engine covering Telnet, SMB, RDP, FTP, exposed databases (MySQL, PostgreSQL, MongoDB, Redis), SNMP, VNC, and more. Each rule includes real-world context (CVEs, known exploits, remediation advice). |
| **Access Control** | API key authentication (`X-API-Key` header) and automatic rejection of any scan target outside private network ranges. |
| **Auto-Detection** | The API automatically detects the local subnet — works out of the box on any machine without editing config files. |
| **REST API** | Clean JSON API with interactive Swagger documentation at `/docs`. Designed to be consumed by any frontend or automation tool. |

---

## API Endpoints

### `POST /api/v1/discover` — Find devices on the network

```json
// Request
{ "subnet": "auto" }

// Response
{
  "subnet": "192.168.1.0/24",
  "status": "completed",
  "scan_duration_seconds": 4.05,
  "devices_found": [
    { "ip": "192.168.1.1",   "hostname": "router.local", "status": "online" },
    { "ip": "192.168.1.42",  "hostname": "workstation",  "status": "online" }
  ]
}
```

### `POST /api/v1/scan` — Scan a device for vulnerabilities

```json
// Request
{ "target": "192.168.1.1" }

// Response
{
  "target_ip": "192.168.1.1",
  "status": "completed",
  "scan_duration_seconds": 22.4,
  "vulnerabilities_found": [
    {
      "port": 445,
      "service": "SMB",
      "status": "Open",
      "risk_level": "Critical",
      "description": "SMB has been the target of multiple devastating exploits, including EternalBlue (CVE-2017-0144) which powered the WannaCry ransomware outbreak..."
    },
    {
      "port": 443,
      "service": "HTTPS",
      "status": "Open",
      "risk_level": "Low",
      "description": "HTTPS provides encrypted web communication. Verify that the TLS configuration uses modern protocols (TLS 1.2+)..."
    }
  ]
}
```

> All endpoints require the `X-API-Key` header. All scan targets must be private/local IPs.

---

## Quick Start

### Prerequisites
- Python 3.10+
- [Nmap](https://nmap.org/download) installed and on your system PATH
- Npcap (Windows only — included in the Nmap installer)

### Installation

```bash
# Clone the repo
git clone <repo-url>
cd portsentinel

# Create virtual environment and install dependencies
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
pip install -r requirements.txt

# Configure
cp .env.example .env            # Edit .env to set your API key
```

### Run

```bash
# For best results (ARP scanning), run as Administrator/root
uvicorn app.main:app --reload
```

The API is now live at `http://127.0.0.1:8000`. Open `http://127.0.0.1:8000/docs` for the interactive Swagger UI.

### Test

```bash
pytest tests/
```

---

## Project Structure

```
portsentinel/
├── app/
│   ├── main.py                  # FastAPI entrypoint, CORS, router registration
│   ├── config.py                # Settings loaded from .env
│   ├── auth.py                  # API key authentication
│   ├── models/
│   │   └── schemas.py           # Pydantic request/response models
│   ├── services/
│   │   ├── scanner.py           # Nmap port scanning wrapper
│   │   ├── discovery.py         # Network discovery + subnet auto-detection
│   │   └── risk_engine.py       # Port → risk classification rules
│   └── routers/
│       ├── scan.py              # POST /api/v1/scan
│       └── discover.py          # POST /api/v1/discover
├── tests/
│   └── test_api.py              # Risk engine + auth + access control tests
├── .env.example
├── requirements.txt
└── README.md
```

---

## Security+ Domain Coverage

This project maps directly to CompTIA Security+ exam domains:

| Domain | Implementation |
|--------|---------------|
| **Domain 2 — Threats, Vulnerabilities & Mitigation** | The risk engine identifies open ports/services and flags known risky configurations (Telnet, exposed databases, unpatched services) with CVE-level context. |
| **Domain 3 — Security Architecture** | API key authentication, target allow-listing, and automatic rejection of public IP scan requests enforce access control principles. |
| **Domain 4 — Security Operations** | The discover → scan → classify workflow models a real SOC asset discovery and vulnerability triage pipeline. |

---

## Responsible Use

PortSentinel is designed exclusively for scanning **local, owned networks**. The API automatically rejects any target outside private IP ranges (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, `127.0.0.1`). Scanning networks you do not own or have explicit authorization to test is illegal in most jurisdictions.

---

## Integration

This API is designed to be consumed by any HTTP client or frontend application. A companion web frontend is under development to visualize scan results as an interactive security dashboard.

---

## Tech Stack

- **Python 3.10+** — Core language
- **FastAPI** — High-performance async API framework
- **Nmap** (via `python-nmap`) — Industry-standard network scanner
- **Pydantic** — Request/response validation
- **pytest** — Test framework
