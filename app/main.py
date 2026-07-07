"""
FastAPI application entrypoint.

Start the server with:
    uvicorn app.main:app --reload

The API will be available at http://127.0.0.1:8000
Interactive docs (Swagger UI) at http://127.0.0.1:8000/docs
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import discover, scan

app = FastAPI(
    title="PortSentinel — Network Vulnerability Scanner API",
    description=(
        "Discovers devices on local networks, scans them for open ports "
        "and running services, and classifies each finding by risk level "
        "(Critical / High / Medium / Low)."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
# Allow the frontend (running on a different port/origin) to call this API.
# In production you would restrict origins; for local development we allow all.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(scan.router, prefix="/api/v1", tags=["Scanning"])
app.include_router(discover.router, prefix="/api/v1", tags=["Discovery"])


# ---------------------------------------------------------------------------
# Health check — useful for verifying the server is up
# ---------------------------------------------------------------------------
@app.get("/", tags=["Health"])
def health_check():
    """Simple health check endpoint."""
    return {"status": "online", "service": "PortSentinel"}
