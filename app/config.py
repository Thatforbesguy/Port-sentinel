"""
Application configuration.

Loads settings from environment variables (via a .env file).
- API_KEY: The secret key required in the X-API-Key header to access endpoints.
- ALLOWED_TARGETS: A comma-separated list of IPs/subnets that are permitted
  scan targets. This is a deliberate security boundary — the scanner must
  never be usable against arbitrary external hosts.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Central config loaded from environment variables.
    Uses pydantic-settings to automatically read from a .env file.
    """

    # The API key that clients must send in the X-API-Key header.
    # In a real SOC tool this would be rotated and stored in a vault;
    # for this portfolio project a simple env-var is appropriate.
    api_key: str

    # Comma-separated allow-list of scan targets.
    # Only IPs or subnets in this list can be scanned.
    # Default: localhost only. Expand to your LAN range if needed
    # (e.g. "127.0.0.1,192.168.1.0/24").
    allowed_targets: str = "127.0.0.1,localhost"

    class Config:
        env_file = ".env"


# Singleton instance — import this wherever settings are needed.
settings = Settings()
