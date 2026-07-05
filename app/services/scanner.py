"""
Nmap scanner wrapper.

This module uses python-nmap to perform real port scans and then feeds the
results through the risk classification engine.

Security+ Domain 4 — Security Operations:
    This is the "collection" step of the SOC workflow.  We gather raw data
    (open ports, running services) and then enrich it with risk context
    before presenting it to the analyst (the frontend dashboard).
"""

from __future__ import annotations

import time

import nmap

from app.services.risk_engine import classify_port, RISK_RULES

# Common ports NOT already in RISK_RULES, added purely for general coverage
# (things worth seeing even if we don't have a specific risk write-up for them yet)
EXTRA_COMMON_PORTS = [25, 53, 110, 143, 445, 3306, 5432, 8080, 8443]


def _scan_port_list() -> str:
    """
    Builds a focused port list instead of scanning a generic top-N range.

    Why: Scanning ports we have no risk classification for wastes scan
    time -- an open port outside our RISK_RULES table just falls back to
    an unhelpful "Unknown/Low" result anyway. Instead we scan exactly the
    ports our risk engine understands, plus a handful of other very common
    ports for general visibility. This is both faster than a top-1000
    scan and more meaningful than a blind top-100 scan.
    """
    ports = set(RISK_RULES.keys()) | set(EXTRA_COMMON_PORTS)
    return ",".join(str(p) for p in sorted(ports))


def run_scan(target: str) -> dict:
    """
    Perform a port scan against a single target IP using nmap.

    Steps:
        1. Run nmap with service-version detection (-sV) and a specific port list.
        2. For each open port found, pass it through the risk engine
           to get a classification and description.
        3. Package everything into the JSON shape the frontend expects.
    """
    start = time.time()

    scanner = nmap.PortScanner()
    port_list = _scan_port_list()

    # -sV enables service/version detection so nmap tells us *what* is
    # running on each port, not just that the port is open.
    scanner.scan(target, arguments=f"-sV -p {port_list}")

    vulnerabilities = []

    # nmap results are organized by host → protocol → port.
    # We iterate through all of them and classify each open port.
    if target in scanner.all_hosts():
        # Get all TCP port results for this host.
        tcp_ports = scanner[target].get("tcp", {})

        for port, port_info in tcp_ports.items():
            # Only report ports that nmap confirmed as "open".
            # Filtered/closed ports are not actionable findings.
            if port_info.get("state") == "open":
                service_name = port_info.get("name", "unknown")
                vulnerability = classify_port(port, service_name)
                vulnerabilities.append(vulnerability)

    # Sort by severity: Critical first, then High, Medium, Low, Info.
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulnerabilities.sort(key=lambda v: severity_order.get(v["risk_level"], 5))

    elapsed = round(time.time() - start, 2)

    return {
        "target_ip": target,
        "status": "completed",
        "scan_duration_seconds": elapsed,
        "vulnerabilities_found": vulnerabilities,
    }
