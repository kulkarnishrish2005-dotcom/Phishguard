"""Shared fixtures for the PhishGuard test suite."""

from __future__ import annotations

import pytest

from phishguard.config import PhishGuardConfig


@pytest.fixture()
def config() -> PhishGuardConfig:
    """Return a default configuration (no .env file side-effects)."""
    return PhishGuardConfig(
        log_level="DEBUG",
        data_dir="./data",
        model_dir="./ml/models/saved",
        _env_file=None,
    )
