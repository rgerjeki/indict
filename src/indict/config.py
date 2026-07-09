"""Configuration: API keys and behavior, loaded from the environment / .env.

Everything is optional. The tool runs with zero keys; each key present lights up
more sources. Keys are read once at startup and passed to sources, which decide
whether they are `available`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass
class Config:
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    shodan_api_key: str | None = None  # reserved for a later version

    cache_dir: Path = Path(".cache")
    cache_ttl: int = 86_400  # 24 hours
    http_timeout: float = 20.0

    use_cache: bool = True

    def has(self, key_name: str) -> bool:
        return bool(getattr(self, key_name, None))


def _clean(value: str | None) -> str | None:
    """Treat blank/placeholder values (as in .env.example) as absent."""
    if value is None:
        return None
    value = value.strip()
    return value or None


def load_config(env_file: str | os.PathLike[str] | None = ".env") -> Config:
    """Load configuration from a .env file (if present) and the environment.

    Real environment variables take precedence over the .env file, matching the
    usual twelve-factor expectation.
    """
    if env_file and Path(env_file).exists():
        load_dotenv(env_file, override=False)

    cache_dir = _clean(os.getenv("INDICT_CACHE_DIR")) or ".cache"
    return Config(
        virustotal_api_key=_clean(os.getenv("VIRUSTOTAL_API_KEY")),
        abuseipdb_api_key=_clean(os.getenv("ABUSEIPDB_API_KEY")),
        shodan_api_key=_clean(os.getenv("SHODAN_API_KEY")),
        cache_dir=Path(cache_dir),
        cache_ttl=int(_clean(os.getenv("INDICT_CACHE_TTL")) or 86_400),
        http_timeout=float(_clean(os.getenv("INDICT_HTTP_TIMEOUT")) or 20.0),
    )
