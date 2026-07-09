"""Shared pytest fixtures.

Every test runs against mocked or canned data. No test makes a live network
call: HTTP is intercepted with respx, and the DNS source is exercised through its
pure result-building helpers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from indict.cache import Cache
from indict.config import Config
from indict.feeds import FeedCache
from indict.http import Http
from indict.sources.base import Context

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def config(tmp_path) -> Config:
    return Config(
        virustotal_api_key="test-vt-key",
        abuseipdb_api_key="test-abuse-key",
        cache_dir=tmp_path / "cache",
        use_cache=False,
    )


@pytest.fixture
def ctx(config) -> Context:
    http = Http(timeout=5.0)
    context = Context(
        config=config,
        http=http,
        cache=Cache(config.cache_dir, config.cache_ttl, enabled=False),
        feeds=FeedCache(config.cache_dir / "feeds", http, ttl=0),
    )
    yield context
    http.close()
