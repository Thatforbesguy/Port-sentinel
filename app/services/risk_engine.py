"""
Risk Classification Engine.

This module is the "brain" of the vulnerability scanner.  It takes raw nmap
output (open port + service name) and assigns a risk level with a human-
readable explanation of *why* that finding matters.

Why this matters for Security+ (Domain 2 — Threats, Vulnerabilities, and
Mitigation):
    A real SOC analyst doesn't just list open ports — they explain the risk.
    "Port 23 is open" means nothing to a manager; "Telnet transmits
    credentials in plaintext and should be replaced with SSH" is actionable.
    Every entry in RISK_RULES is written to demonstrate that reasoning.

How it works:
    1.  The scanner finds open ports and identifies the service via nmap.
    2.  This engine looks up each port in RISK_RULES.
    3.  If a rule exists, it returns that rule's risk level and description.
    4.  If no rule exists, it returns a generic "Info" level finding — because
        an open port we don't recognize isn't necessarily dangerous, but it
        should still be reported.
"""

from __future__ import annotations

import yaml
from pathlib import Path

# ---------------------------------------------------------------------------
# Risk rule definitions
# ---------------------------------------------------------------------------
# Rules are loaded from rules.yml in this directory.
# Each key is a TCP port number.
# Each value is a dict with:
#   - service:     Canonical service name
#   - risk_level:  "Critical" | "High" | "Medium" | "Low" | "Info"
#   - description: Plain-English security reasoning.
# ---------------------------------------------------------------------------

_RULES_FILE = Path(__file__).parent / "rules.yml"

try:
    with open(_RULES_FILE, "r", encoding="utf-8") as f:
        RISK_RULES: dict[int, dict] = yaml.safe_load(f) or {}
except FileNotFoundError:
    RISK_RULES = {}


def classify_port(port: int, service_name: str) -> dict:
    """
    Classify a single open port and return a risk assessment.

    Parameters
    ----------
    port : int
        The TCP port number found open by nmap.
    service_name : str
        The service name reported by nmap (e.g. "ssh", "http").
        Used as a fallback display name if the port isn't in our rules.

    Returns
    -------
    dict
        A dictionary with keys: port, service, status, risk_level,
        description — matching the Vulnerability schema.
    """
    if port in RISK_RULES:
        rule = RISK_RULES[port]
        return {
            "port": port,
            "service": rule["service"],
            "status": "Open",
            "risk_level": rule["risk_level"],
            "description": rule["description"],
        }

    # Unknown port — still report it, but at "Info" level.
    # An open port we don't have a rule for isn't necessarily dangerous,
    # but a SOC analyst would still want to see it for visibility.
    return {
        "port": port,
        "service": service_name.upper() if service_name else f"UNKNOWN ({port})",
        "status": "Open",
        "risk_level": "Info",
        "description": (
            f"Port {port} ({service_name or 'unknown service'}) is open. "
            f"No specific risk rule is defined for this port. Review "
            f"whether this service is expected and necessary."
        ),
    }
