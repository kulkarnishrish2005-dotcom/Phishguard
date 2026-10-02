"""End-to-end dataset ingestion pipeline orchestration."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phishguard.config import PhishGuardConfig

from .balance import ClassBalancer
from .deduplicate import Deduplicator
from .ingest import PhishTankIngester, TrancoIngester
from .manifest import ManifestGenerator
from .schema import Sample, SourceMetadata, SplitType
from .split import DatasetSplitter
from .validate import SampleValidator

logger = logging.getLogger(__name__)


class DatasetPipeline:
    """End-to-end dataset ingestion pipeline.

    Pipeline stages:
    1. Ingestion: Read PhishTank and Tranco data
    2. Validation: Check required fields and formats
    3. Normalization: Already done during ingestion
    4. Merge: Combine sources
    5. Deduplication: Exact and near-duplicate removal
    6. Split: Domain-aware temporal split
    7. Balance: Undersample training set, archive unused benign
    8. Export: Save splits and manifest
    """

    def __init__(self, config: PhishGuardConfig | None = None) -> None:
        """Initialize pipeline.

        Parameters
        ----------
        config : PhishGuardConfig | None
            Configuration (uses default if None)
        """
        from phishguard.config import get_config

        self.config = config or get_config()

        # Initialize components
        self.validator = SampleValidator()
        self.deduplicator = Deduplicator(campaign_threshold=100, campaign_sample_size=15)
        self.splitter = DatasetSplitter(
            train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42
        )
        self.balancer = ClassBalancer(target_ratio=0.20, random_seed=42)
        self.manifest_generator = ManifestGenerator(pipeline_version="0.1.0", random_seed=42)

        # Statistics
        self.source_metadata: list[SourceMetadata] = []

    def run(
        self,
        phishtank_file: Path,
        tranco_file: Path,
        phishtank_retrieval_time: datetime | None = None,
        phishtank_version: str | None = None,
        tranco_retrieval_time: datetime | None = None,
        tranco_list_id: str | None = None,
        tranco_list_date: datetime | None = None,
        output_dir: Path | None = None,
    ) -> Path:
        """Run complete ingestion pipeline.

        Parameters
        ----------
        phishtank_file : Path
            Path to PhishTank CSV file
        tranco_file : Path
            Path to Tranco CSV file
        phishtank_retrieval_time : datetime | None
            When PhishTank file was retrieved
        phishtank_version : str | None
            PhishTank version ID
        tranco_retrieval_time : datetime | None
            When Tranco file was retrieved
        tranco_list_id : str | None
            Tranco list ID
        tranco_list_date : datetime | None
            Tranco list publication date
        output_dir : Path | None
            Output directory (uses config default if None)

        Returns
        -------
        Path
            Path to generated manifest file
        """
        logger.info("=" * 60)
        logger.info("Starting PhishGuard dataset ingestion pipeline")
        logger.info("=" * 60)

        # Set defaults
        if phishtank_retrieval_time is None:
            phishtank_retrieval_time = datetime.now(UTC)
        if tranco_retrieval_time is None:
            tranco_retrieval_time = datetime.now(UTC)

        if output_dir is None:
            output_dir = self.config.data_dir / "processed"

        output_dir.mkdir(parents=True, exist_ok=True)
        metadata_dir = self.config.data_dir / "metadata"
        metadata_dir.mkdir(parents=True, exist_ok=True)

        # Stage 1: Ingestion
        logger.info("Stage 1: Ingestion")
        all_samples = self._ingest_sources(
            phishtank_file,
            tranco_file,
            phishtank_retrieval_time,
            phishtank_version,
            tranco_retrieval_time,
            tranco_list_id,
            tranco_list_date,
        )
        logger.info("Total samples ingested: %d", len(all_samples))

        # Stage 2: Validation
        logger.info("Stage 2: Validation")
        valid_samples = list(self.validator.validate(iter(all_samples)))
        logger.info(
            "Valid samples: %d (%.1f%%)",
            len(valid_samples),
            100 * len(valid_samples) / len(all_samples) if all_samples else 0,
        )
        logger.info("Validation errors: %d", self.validator.get_error_count())

        # Stage 3: Merge (already done - samples are combined)
        logger.info("Stage 3: Merge (sources combined)")

        # Stage 4: Deduplication
        logger.info("Stage 4: Deduplication")
        deduplicated_samples = self._deduplicate(valid_samples)

        # Stage 5: Split
        logger.info("Stage 5: Split (temporal + domain-aware)")
        splits = self.splitter.split_temporal_domain_aware(deduplicated_samples)

        # Stage 6: Validate leakage
        logger.info("Stage 6: Leakage validation")
        leakage_results = self.splitter.validate_split(splits)

        # Stage 7: Balance training set
        logger.info("Stage 7: Class balance (training set only)")
        balanced_train, archived_benign = self.balancer.balance_training_set(
            splits[SplitType.TRAIN.value]
        )
        splits[SplitType.TRAIN.value] = balanced_train
        splits[SplitType.ARCHIVE.value] = archived_benign

        # Stage 8: Export
        logger.info("Stage 8: Export")
        manifest_path = self._export_all(
            splits, output_dir, metadata_dir, leakage_results
        )

        logger.info("=" * 60)
        logger.info("Pipeline complete!")
        logger.info("Manifest: %s", manifest_path)
        logger.info("=" * 60)

        return manifest_path

    def _ingest_sources(
        self,
        phishtank_file: Path,
        tranco_file: Path,
        phishtank_retrieval_time: datetime,
        phishtank_version: str | None,
        tranco_retrieval_time: datetime,
        tranco_list_id: str | None,
        tranco_list_date: datetime | None,
    ) -> list[Sample]:
        """Ingest all sources."""
        all_samples: list[Sample] = []

        # Ingest PhishTank
        logger.info("Ingesting PhishTank from %s", phishtank_file)
        pt_ingester = PhishTankIngester(verified_only=True, online_only=False)
        pt_samples = list(pt_ingester.ingest(phishtank_file))
        logger.info("PhishTank: %d samples ingested", len(pt_samples))
        all_samples.extend(pt_samples)

        # Ingest Tranco
        logger.info("Ingesting Tranco from %s", tranco_file)
        tranco_ingester = TrancoIngester(top_n=None)  # No limit
        tranco_samples = list(tranco_ingester.ingest(tranco_file, list_date=tranco_list_date))
        logger.info("Tranco: %d samples ingested", len(tranco_samples))
        all_samples.extend(tranco_samples)

        # Store metadata for later (will update after validation/dedup)
        self.pt_ingester = pt_ingester
        self.pt_samples_count = len(pt_samples)
        self.pt_file = phishtank_file
        self.pt_retrieval_time = phishtank_retrieval_time
        self.pt_version = phishtank_version

        self.tranco_ingester = tranco_ingester
        self.tranco_samples_count = len(tranco_samples)
        self.tranco_file = tranco_file
        self.tranco_retrieval_time = tranco_retrieval_time
        self.tranco_list_id = tranco_list_id
        self.tranco_list_date = tranco_list_date

        return all_samples

    def _deduplicate(self, samples: list[Sample]) -> list[Sample]:
        """Apply deduplication."""
        # Tier 1: Exact duplicates
        samples = self.deduplicator.deduplicate_exact(samples)

        # Tier 2: Near-duplicates
        samples = self.deduplicator.deduplicate_near(samples)

        return samples

    def _export_all(
        self,
        splits: dict[str, list[Sample]],
        output_dir: Path,
        metadata_dir: Path,
        leakage_results: dict[str, Any],
    ) -> Path:
        """Export all splits and generate manifest."""
        # Export splits
        for split_name, samples in splits.items():
            output_file = output_dir / f"{split_name}.jsonl"
            self._export_split(samples, output_file)
            logger.info("Exported %s: %d samples to %s", split_name, len(samples), output_file)

        # Generate source metadata
        pt_valid = sum(
            1 for s in splits.get(SplitType.TRAIN.value, []) + splits.get(SplitType.VAL.value, []) + splits.get(SplitType.TEST.value, [])
            if s.source == "phishtank"
        )
        tranco_valid = sum(
            1 for s in splits.get(SplitType.TRAIN.value, []) + splits.get(SplitType.VAL.value, []) + splits.get(SplitType.TEST.value, [])
            if s.source == "tranco"
        )

        pt_metadata = self.pt_ingester.get_metadata(
            self.pt_file,
            self.pt_retrieval_time,
            self.pt_version,
            self.pt_samples_count,
            pt_valid,
            pt_valid,  # After dedup
        )

        tranco_metadata = self.tranco_ingester.get_metadata(
            self.tranco_file,
            self.tranco_retrieval_time,
            self.tranco_list_id,
            self.tranco_list_date,
            self.tranco_samples_count,
            tranco_valid,
            tranco_valid,  # After dedup
        )

        # Compute split metadata
        split_metadata = {}
        for split_name, samples in splits.items():
            if samples:
                split_metadata[split_name] = self.splitter.compute_split_metadata(
                    split_name, samples
                )

        # Class balance info
        train_samples = splits.get(SplitType.TRAIN.value, [])
        archive_samples = splits.get(SplitType.ARCHIVE.value, [])

        train_phishing = sum(1 for s in train_samples if s.label == "phishing")
        train_benign = sum(1 for s in train_samples if s.label == "benign")

        class_balance_info = {
            "training_target_ratio": "1:4.0",
            "training_undersampling_applied": len(archive_samples) > 0,
            "test_set_balanced": False,
            "test_set_note": "Natural distribution preserved",
            "training_phishing_count": train_phishing,
            "training_benign_count": train_benign,
            "archived_benign_count": len(archive_samples),
        }

        # Quality checks
        quality_checks = {
            "validation_errors": self.validator.get_error_count(),
            "validation_errors_by_type": self.validator.get_errors_by_type(),
        }

        # Generate manifest
        manifest = self.manifest_generator.generate(
            sources=[pt_metadata, tranco_metadata],
            preprocessing_stats=self.deduplicator.get_stats(),
            split_metadata=split_metadata,
            leakage_results=leakage_results,
            class_balance_info=class_balance_info,
            quality_check_stats=quality_checks,
        )

        # Save manifest
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        manifest_path = metadata_dir / f"dataset_manifest_{timestamp}.json"
        manifest.save(manifest_path)

        return manifest_path

    def _export_split(self, samples: list[Sample], output_file: Path) -> None:
        """Export samples to JSONL file."""
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            for sample in samples:
                json.dump(sample.to_dict(), f, ensure_ascii=False)
                f.write("\n")
