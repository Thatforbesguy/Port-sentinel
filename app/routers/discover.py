"""
Discovery router — defines the POST /api/v1/discover endpoint.

This is the first endpoint the frontend calls. It sweeps the local
network to find live devices, which are then displayed as a list for
the user to pick from and scan individually via /api/v1/scan.

If no subnet is provided in the request body, the backend automatically
detects the local network — so it works out of the box on any machine
without manual configuration.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.concurrency import run_in_threadpool

from app.auth import verify_api_key
from app.models.schemas import DiscoverRequest, DiscoverResponse
from app.services.discovery import (
    detect_local_subnet,
    run_discovery,
    _is_subnet_allowed,
)

router = APIRouter()


@router.post(
    "/discover",
    response_model=DiscoverResponse,
    dependencies=[Depends(verify_api_key)],
    summary="Discover live devices on the local network",
    description=(
        "Performs an nmap ping sweep (-sn) on the specified subnet to "
        "find all online devices. If no subnet is provided, the backend "
        "automatically detects the local network."
    ),
)
async def discover(request: DiscoverRequest):
    """
    1. Determine the subnet (auto-detect if not provided).
    2. Validate that the subnet is a private/local range.
    3. Run the ping sweep via services/discovery.py.
    4. Return the list of discovered devices.
    """
    subnet = request.subnet

    # --- Auto-detect subnet if the client sent the default/empty value ---
    if not subnet or subnet == "auto":
        try:
            subnet = detect_local_subnet()
        except RuntimeError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(e),
            )

    # --- Safety check: only allow private subnets ---
    if not _is_subnet_allowed(subnet):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Subnet '{subnet}' is not a private network range. "
                f"This scanner is restricted to local/owned networks only."
            ),
        )

    # --- Execute discovery ---
    result = await run_in_threadpool(run_discovery, subnet)
    return result
