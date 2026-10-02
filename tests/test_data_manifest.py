"""Tests for dataset manifest generation and serialization."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from ml.data.manifest import ManifestGenerator
from ml.data.schema import DatasetManifest, SourceMetadata, SplitMetadata


class TestManifestGenerator:
    """Tests for manifest generation."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.generator = ManifestGenerator(pipeline_version="0.1.0", random_seed=42)

    def _create_source_metadata(self, name: str) -> SourceMetadata:
        """Helper to create source metadata."""
        return SourceMetadata(
            source_name=name,
            source_type="phishing_urls" if name == "phishtank" else "benign_urls",
            retrieval_timestamp=datetime.now(UTC),
            source_url="https://example.com",
            version_id="2026-08-29",
            format="csv",
            license="Test License",
            usage_terms="Test Terms",
            label_definition="Binary label definition",
            raw_file_path=f"data/raw/{name}.csv",
            raw_file_hash_sha256="abc123hash",
            samples_ingested=1000,
            samples_after_validation=950,
            samples_after_deduplication=900,
        )

    def _create_split_metadata(self, name: str) -> SplitMetadata:
        """Helper to create split metadata."""
        return SplitMetadata(
            total_samples=100,
            phishing_samples=20,
            benign_samples=80,
            class_ratio="1:4.0",
            unique_domains=15,
            temporal_range=("2026-01-01T00:00:00", "2026-06-30T00:00:00"),
            sources={"phishtank": 20, "tranco": 80},
        )

    def test_generate_manifest(self) -> None:
        """Test complete manifest generation."""
        sources = [
            self._create_source_metadata("phishtank"),
            self._create_source_metadata("tranco"),
        ]

        preprocessing_stats = {
            "tier1_exact_duplicates_removed": 100,
            "tier2_near_duplicates_removed": 50,
            "label_conflicts_discarded": 5,
        }

        split_metadata = {
            "train": self._create_split_metadata("train"),
            "val": self._create_split_metadata("val"),
            "test": self._create_split_metadata("test"),
        }

        leakage_results = {
            "exact_duplicate_check": "passed",
            "domain_isolation_check": "passed",
            "temporal_isolation_check": "passed",
            "notes": "All checks passed",
        }

        class_balance_info = {
            "training_target_ratio": "1:4.0",
            "training_undersampling_applied": True,
            "test_set_balanced": False,
        }

        quality_checks = {
            "validation_errors": 50,
            "validation_errors_by_type": {"invalid_url": 30, "missing_field": 20},
        }

        manifest = self.generator.generate(
            sources=sources,
            preprocessing_stats=preprocessing_stats,
            split_metadata=split_metadata,
            leakage_results=leakage_results,
            class_balance_info=class_balance_info,
            quality_check_stats=quality_checks,
        )

        assert manifest.manifest_version == "1.0"
        assert manifest.pipeline_version == "0.1.0"
        assert manifest.random_seed == 42
        assert len(manifest.sources) == 2
        assert manifest.preprocessing["tier1_exact_duplicates_removed"] == 100
        assert manifest.leakage_validation["exact_duplicate_check"] == "passed"

    def test_save_and_load_manifest(self) -> None:
        """Test saving and loading manifest JSON."""
        sources = [self._create_source_metadata("phishtank")]
        split_metadata = {"train": self._create_split_metadata("train")}

        manifest = self.generator.generate(
            sources=sources,
            preprocessing_stats={},
            split_metadata=split_metadata,
            leakage_results={},
            class_balance_info={},
            quality_check_stats={},
        )

        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "manifest.json"
            manifest.save(path)

            assert path.exists()

            # Verify it's valid JSON
            with open(path) as f:
                data = json.load(f)

            assert data["manifest_version"] == "1.0"
            assert data["random_seed"] == 42
            assert len(data["sources"]) == 1

            # Load back
            loaded = DatasetManifest.load(path)
            assert loaded.manifest_version == "1.0"
            assert loaded.random_seed == 42

    def test_manifest_contains_required_fields(self) -> None:
        """Test that manifest contains all mandatory reproducibility fields."""
        sources = [self._create_source_metadata("phishtank")]
        manifest = self.generator.generate(
            sources=sources,
            preprocessing_stats={"tier1_exact_duplicates_removed": 10},
            split_metadata={"train": self._create_split_metadata("train")},
            leakage_results={"exact_duplicate_check": "passed"},
            class_balance_info={"training_target_ratio": "1:4.0"},
            quality_check_stats={"validation_errors": 0},
        )

        manifest_dict = manifest.to_dict()

        # Check top-level required fields
        required_top_level = [
            "manifest_version",
            "created_at",
            "pipeline_version",
            "random_seed",
            "sources",
            "preprocessing",
            "splits",
            "leakage_validation",
            "class_balance",
            "quality_checks",
        ]

        for field in required_top_level:
            assert field in manifest_dict, f"Missing required field: {field}"

        # Check source required fields
        source = manifest_dict["sources"][0]
        required_source_fields = [
            "source_name",
            "retrieval_timestamp",
            "source_url",
            "license",
            "usage_terms",
            "label_definition",
            "samples_ingested",
        ]

        for field in required_source_fields:
            assert field in source, f"Missing source field: {field}"
