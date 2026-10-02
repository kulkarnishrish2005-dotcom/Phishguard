"""Centralised configuration loaded from environment variables."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class PhishGuardConfig(BaseSettings):
    """Application-wide settings.

    Values are read from environment variables prefixed with ``PHISHGUARD_``.
    A ``.env`` file in the project root is loaded automatically when present.
    """

    model_config = {"env_prefix": "PHISHGUARD_", "env_file": ".env", "extra": "ignore"}

    # Logging
    log_level: str = Field(default="INFO", description="Python logging level name")

    # Paths
    data_dir: Path = Field(default=Path("./data"), description="Root data directory")
    model_dir: Path = Field(
        default=Path("./ml/models/saved"), description="Trained-model storage"
    )

    def resolve_paths(self, base: Path | None = None) -> "PhishGuardConfig":
        """Return a copy with *data_dir* and *model_dir* resolved against *base*."""
        base = base or Path.cwd()
        return self.model_copy(
            update={
                "data_dir": (base / self.data_dir).resolve(),
                "model_dir": (base / self.model_dir).resolve(),
            }
        )


def get_config() -> PhishGuardConfig:
    """Build and return the current configuration."""
    return PhishGuardConfig()
