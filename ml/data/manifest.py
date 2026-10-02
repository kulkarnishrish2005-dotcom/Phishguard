"""Manifest generation and serialization for dataset provenance."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from .schema import DatasetManifest, SourceMetadata, SplitMetadata

logger = logging.getLogger(__name__)


class ManifestGenerator:
    """Generate comprehensive dataset manifests for reproducibility."""

    def __init__(self, pipeline_version: str = "0.1.0", random_seed: int = 42) -> None:
        """Initialize manifest generator.

        Parameters
        ----------
        pipeline_version : str
            Version of the ingestion pipeline
        random_seed : int
            Random seed used for splitting
        """
        self.pipeline_version = pipeline_version
        self.random_seed = random_seed

    def generate(
        self,
        sources: list[SourceMetadata],
        preprocessing_stats: dict[str, Any],
        split_metadata: dict[str, SplitMetadata],
        leakage_results: dict[str, Any],
        class_balance_info: dict[str, Any],
        quality_check_stats: dict[str, Any],
    ) -> DatasetManifest:
        """Generate complete dataset manifest.

        Parameters
        ----------
        sources : list[SourceMetadata]
            Metadata for each source
        preprocessing_stats : dict[str, Any]
            Deduplication and normalization statistics
        split_metadata : dict[str, SplitMetadata]
            Metadata for each split (train, val, test, archive)
        leakage_results : dict[str, Any]
            Results of leakage validation checks
        class_balance_info : dict[str, Any]
            Class balance configuration and counts
        quality_check_stats : dict[str, Any]
            Validation error counts and quality metrics

        Returns
        -------
        DatasetManifest
            Complete manifest object
        """
        logger.info("Generating dataset manifest")

        # Convert split metadata to dicts
        splits_dict: dict[str, Any] = {
            "strategy": "temporal_domain_aware",
            "train_ratio": 0.70,
            "val_ratio": 0.15,
            "test_ratio": 0.15,
            "domain_isolation": True,
            "temporal_ordering": True,
        }

        for split_name, metadata in split_metadata.items():
            splits_dict[split_name] = metadata.to_dict()

        manifest = DatasetManifest(
            manifest_version="1.0",
            created_at=datetime.now(UTC),
            pipeline_version=self.pipeline_version,
            random_seed=self.random_seed,
            sources=sources,
            preprocessing=preprocessing_stats,
            splits=splits_dict,
            leakage_validation=leakage_results,
            class_balance=class_balance_info,
            quality_checks=quality_check_stats,
        )

        logger.info("Manifest generated successfully")
        return manifest
