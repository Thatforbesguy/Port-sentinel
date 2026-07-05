"""
API key authentication dependency.

Security+ Domain 3 — Security Architecture:
    Even a simple API key check demonstrates the principle of access
    control.  Without this header, no scan can be triggered. 
"""

from fastapi import Header, HTTPException, status

from app.config import settings


def verify_api_key(x_api_key: str = Header(...)) -> str:
    """
    FastAPI dependency that checks the X-API-Key header.

    Raises 401 Unauthorized if the key is missing or wrong.
    Returns the key string if valid (not used downstream, but available).
    """
    if x_api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return x_api_key
