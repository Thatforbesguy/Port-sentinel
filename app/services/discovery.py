"""
Network discovery service.

Uses nmap's ping sweep (-sn) to find live devices on a local subnet.
This is the "what's on the network?" step that feeds the frontend device
list screen before the user picks a device to scan in detail.

Also provides automatic local subnet detection so the user doesn't need
to manually figure out their network range.

Security+ Domain 4 — Security Operations:
    Asset discovery is a foundational SOC task. You can't protect what
    you don't know exists. This module identifies all active hosts on
    a network segment — the first step in any vulnerability assessment.
"""

from __future__ import annotations

import ipaddress
import socket
import time

import nmap


def detect_local_subnet() -> str:
    """
    Auto-detect the local machine's subnet in CIDR notation.

    How it works:
        1. Opens a UDP socket aimed at a public DNS server (8.8.8.8).
           No data is actually sent — this just forces the OS to pick
           the network interface that *would* be used for internet traffic.
        2. Reads the local IP address from that socket.
        3. Assumes a /24 subnet mask (the most common home/small-office
           configuration) and returns the network address.

    Returns
    -------
    str
        A CIDR subnet string like "192.168.1.0/24".

    Raises
    ------
    RuntimeError
        If the local IP cannot be determined (e.g. no network connection).
    """
    try:
        # Create a UDP socket — we never actually send anything.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        # Build a /24 network from the detected IP.
        # Example: 192.168.1.42 → 192.168.1.0/24
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)

    except Exception as e:
        raise RuntimeError(
            f"Could not auto-detect local subnet: {e}. "
            f"Please provide the subnet manually in the request body."
        ) from e


def _is_subnet_allowed(subnet: str) -> bool:
    """
    Safety check: only allow discovery on private/local subnets.

    This prevents the scanner from being used to sweep public IP ranges,
    which would be both unethical and likely illegal.
    """
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        return network.is_private
    except ValueError:
        return False


def run_discovery(subnet: str) -> dict:
    """
    Runs the network discovery ping-sweep TWICE and merges the results.

    Why: A single -sn pass can miss devices that are slow to respond or
    in WiFi power-saving mode (phones, IoT devices commonly do this).
    Running two quick passes a moment apart and merging unique IPs found
    catches devices that were asleep during the first pass. This trades
    a few extra seconds of scan time for much more consistent results.
    """
    start = time.time()
    scanner = nmap.PortScanner()

    found_devices = {}  # keyed by IP to naturally dedupe across passes

    for pass_num in range(2):
        # -sn = ping sweep only (no port scan)
        # -PR = ARP ping (highly reliable for local networks)
        # -PE = ICMP echo
        # -PA80,443,445 = TCP ACK ping on common ports
        scanner.scan(hosts=subnet, arguments="-sn -PR -PE -PA80,443,445")
        for host in scanner.all_hosts():
            if host not in found_devices:
                hostname = scanner[host].hostname() or "unknown"
                found_devices[host] = {
                    "ip": host,
                    "hostname": hostname,
                    "status": "online",
                }
        if pass_num == 0:
            time.sleep(1)  # brief pause before second pass

    return {
        "subnet": subnet,
        "status": "completed",
        "scan_duration_seconds": round(time.time() - start, 2),
        "devices_found": list(found_devices.values()),
    }
