"""Tests for phishguard.config."""

from __future__ import annotations

from pathlib import Path

from phishguard.config import PhishGuardConfig, get_config


class TestPhishGuardConfig:
    """Configuration loading and path resolution."""

    def test_defaults(self, config: PhishGuardConfig) -> None:
        assert config.log_level == "DEBUG"
        assert config.data_dir == Path("./data")

    def test_resolve_paths(self, config: PhishGuardConfig) -> None:
        base = Path("/tmp/project")
        resolved = config.resolve_paths(base)
        assert resolved.data_dir == (base / "data").resolve()
        assert resolved.model_dir == (base / "ml/models/saved").resolve()

    def test_get_config_returns_instance(self) -> None:
        cfg = get_config()
        assert isinstance(cfg, PhishGuardConfig)
