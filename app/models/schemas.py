"""
Pydantic models (schemas) for API request validation and response formatting.

These models define the JSON contract between this backend and the frontend.
Any change here should be coordinated with the frontend repo since
the app is built against this exact shape.
"""

from pydantic import BaseModel, Field

# Scan endpoint models
class ScanRequest(BaseModel):
    """
    Body of POST /api/v1/scan.
    The frontend sends the IP address of the device the user tapped.
    """
    target: str = Field(
        ...,
        description="IP address of the device to scan (e.g. '192.168.1.15').",
        examples=["127.0.0.1", "192.168.1.15"],
    )


class Vulnerability(BaseModel):
    """
    A single finding from the scan.

    Each open port discovered by nmap becomes one Vulnerability object after
    the risk engine classifies it.  The frontend renders these as individual
    cards on the dashboard.

    Fields
    ------
    port : int
        The TCP port number (e.g. 22, 80, 443).
    service : str
        The service name reported by nmap (e.g. "SSH", "HTTP").
    status : str
        Whether the port is "Open", "Closed", or "Filtered".
    risk_level : str
        One of "Critical", "High", "Medium", "Low", or "Info".
        Determined by the risk_engine module.
    description : str
        A human-readable explanation of *why* this is risky.
        This is the most important field for the portfolio — it shows
        the builder understands the security implications, not just that
        the scanner found an open port.
    """
    port: int
    service: str
    status: str
    risk_level: str
    description: str


class ScanResponse(BaseModel):
    """
    Response body of POST /api/v1/scan.

    Mirrors the JSON contract defined in IMPLEMENTATION_PLAN.md.
    """
    target_ip: str
    status: str
    scan_duration_seconds: float
    vulnerabilities_found: list[Vulnerability]


# ---------------------------------------------------------------------------
# Discover endpoint models (Phase 5 — defined now so the contract is clear)
# ---------------------------------------------------------------------------

class DiscoverRequest(BaseModel):
    """
    Body of POST /api/v1/discover.
    The subnet to ping-sweep for live devices.
    Send "auto" (or omit the field) to let the backend auto-detect
    the local network — no manual configuration needed.
    """
    subnet: str = Field(
        default="auto",
        description=(
            "CIDR subnet to scan for live devices. "
            "Use 'auto' to let the backend detect your local network automatically."
        ),
        examples=["auto", "192.168.1.0/24", "10.0.0.0/24"],
    )


class Device(BaseModel):
    """A single device found on the network during discovery."""
    ip: str
    hostname: str
    status: str


class DiscoverResponse(BaseModel):
    """Response body of POST /api/v1/discover."""
    subnet: str
    status: str
    scan_duration_seconds: float
    devices_found: list[Device]
