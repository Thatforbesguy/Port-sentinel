"""
Scan router — defines the POST /api/v1/scan endpoint.

This is the main entry point the frontend calls after the user taps a
device on the discovery list.  It validates the target against the allow-
list, runs the nmap scan, and returns classified results.
"""

import ipaddress
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from app.auth import verify_api_key
from app.config import settings
from app.models.schemas import ScanRequest, ScanResponse
from app.services.scanner import run_scan

router = APIRouter()


def _is_target_allowed(target: str) -> bool:
    """
    Check whether the requested scan target is in the allow-list
    or if it is a safe local/private network IP.

    This is a deliberate safety boundary (Security+ Domain 3):
    the scanner must only operate against pre-approved targets to
    prevent misuse against external systems.
    """
    # 1. Check if the target is explicitly in the .env allow-list
    allowed = [t.strip() for t in settings.allowed_targets.split(",")]
    if target in allowed:
        return True
        
    # 2. Automatically allow any private local IP (e.g., 192.168.x.x, 10.x.x.x, 127.0.0.1)
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback:
            return True
    except ValueError:
        pass
        
    return False


@router.post(
    "/scan",
    response_model=ScanResponse,
    dependencies=[Depends(verify_api_key)],
    summary="Scan a target for open ports and vulnerabilities",
    description=(
        "Runs an nmap service-version scan (-sV) against the specified "
        "target IP and classifies each open port by risk level."
    ),
)
async def scan(request: ScanRequest):
    """
    1. Verify the target IP is in the allow-list.
    2. Run the nmap scan via services/scanner.py.
    3. Return the classified results as JSON.
    """
    # --- Access control check ---
    if not _is_target_allowed(request.target):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Target '{request.target}' is not in the allowed targets "
                f"list. This scanner is restricted to local/owned networks "
                f"only. Update ALLOWED_TARGETS in your .env to add it."
            ),
        )

    # --- Execute scan ---
    result = await run_in_threadpool(run_scan, request.target)
    return result
