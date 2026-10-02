"""Schema definitions for PhishGuard dataset samples and manifests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from phishguard.types import InputType


class SplitType(Enum):
    """Dataset split types."""

    TRAIN = "train"
    VAL = "val"
    TEST = "test"
    ARCHIVE = "archive"


@dataclass
class Sample:
    """Canonical representation of a single dataset sample."""

    # Identity
    sample_id: str  # Globally unique ID (UUID4)
    source: str  # Source name (e.g., "phishtank", "tranco")
    source_id: str  # Original ID from source

    # Input
    input_type: InputType  # URL | EMAIL | TEXT | SCREENSHOT | QR_CODE
    raw_input: str  # Original URL/email body/text
    normalized_input: str  # Normalized form

    # Label
    label: str  # "phishing" | "benign"
    label_confidence: float  # 0.0 (low) – 1.0 (high)

    # Provenance
    timestamp: datetime | None  # When sample was collected/verified (if available)
    ingestion_time: datetime  # When we ingested it

    # Domain (for URLs)
    registrable_domain: str | None = None  # Extracted registrable domain

    # Dataset split
    split: str | None = None  # "train" | "val" | "test" | "archive" | None

    # Features (computed during preprocessing)
    features: dict[str, Any] = field(default_factory=dict)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        # Convert enums and datetimes to strings
        d["input_type"] = self.input_type.value
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        d["ingestion_time"] = self.ingestion_time.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Sample:
        """Create Sample from dictionary."""
        d = d.copy()
        d["input_type"] = InputType(d["input_type"])
        if d["timestamp"]:
            d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        d["ingestion_time"] = datetime.fromisoformat(d["ingestion_time"])
        return cls(**d)

    def compute_hash(self) -> str:
        """Compute SHA256 hash of normalized input for deduplication."""
        return hashlib.sha256(self.normalized_input.encode("utf-8")).hexdigest()


@dataclass
class SourceMetadata:
    """Metadata about a dataset source."""

    source_name: str
    source_type: str  # e.g., "phishing_urls", "benign_urls"
    retrieval_timestamp: datetime
    source_url: str
    version_id: str | None
    format: str  # e.g., "csv", "json"
    license: str
    usage_terms: str
    label_definition: str
    raw_file_path: str
    raw_file_hash_sha256: str | None
    samples_ingested: int
    samples_after_validation: int
    samples_after_deduplication: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = asdict(self)
        d["retrieval_timestamp"] = self.retrieval_timestamp.isoformat()
        return d


@dataclass
class SplitMetadata:
    """Metadata about a dataset split."""

    total_samples: int
    phishing_samples: int
    benign_samples: int
    class_ratio: str  # e.g., "1:4.0"
    unique_domains: int
    temporal_range: tuple[str | None, str | None]  # (earliest, latest) timestamps
    sources: dict[str, int]  # source_name -> count
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)


@dataclass
class DatasetManifest:
    """Complete dataset manifest for reproducibility."""

    manifest_version: str = "1.0"
    created_at: datetime = field(default_factory=lambda: datetime.now())
    pipeline_version: str = "0.1.0"
    random_seed: int = 42

    sources: list[SourceMetadata] = field(default_factory=list)

    preprocessing: dict[str, Any] = field(default_factory=dict)

    splits: dict[str, Any] = field(default_factory=dict)

    leakage_validation: dict[str, Any] = field(default_factory=dict)

    class_balance: dict[str, Any] = field(default_factory=dict)

    quality_checks: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        d["sources"] = [s.to_dict() if isinstance(s, SourceMetadata) else s for s in self.sources]
        return d

    def save(self, path: Path) -> None:
        """Save manifest to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Path) -> DatasetManifest:
        """Load manifest from JSON file."""
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        d["created_at"] = datetime.fromisoformat(d["created_at"])
        # Note: sources remain as dicts for simplicity
        return cls(**d)


def compute_file_hash(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
