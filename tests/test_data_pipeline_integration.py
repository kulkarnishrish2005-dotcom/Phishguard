"""Integration test for full dataset ingestion pipeline."""

from __future__ import annotations

import csv
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from ml.data.pipeline import DatasetPipeline
from ml.data.schema import DatasetManifest
from phishguard.config import PhishGuardConfig


class TestDatasetPipelineIntegration:
    """Integration test for complete pipeline using synthetic data."""

    def _create_synthetic_phishtank_csv(self, path: Path, num_samples: int = 50) -> None:
        """Create synthetic PhishTank CSV file for testing."""
        path.parent.mkdir(parents=True, exist_ok=True)

        base_time = datetime(2026, 1, 1, tzinfo=UTC)

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "phish_id",
                "url",
                "phish_detail_url",
                "submission_time",
                "verified",
                "verification_time",
                "online",
                "target",
            ])

            for i in range(num_samples):
                # Create domains with some duplicate domains to test clustering
                domain_idx = i % 10
                domain = f"phish-target{domain_idx}.com"
                url = f"https://{domain}/login/verify?id={i}"
                time = base_time + timedelta(days=i)

                writer.writerow([
                    str(1000 + i),
                    url,
                    f"https://phishtank.com/phish_detail.php?phish_id={1000 + i}",
                    time.isoformat(),
                    "yes",
                    time.isoformat(),
                    "yes",
                    "Test Brand",
                ])

    def _create_synthetic_tranco_csv(self, path: Path, num_samples: int = 200) -> None:
        """Create synthetic Tranco CSV file for testing."""
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            for i in range(1, num_samples + 1):
                writer.writerow([str(i), f"benign-site{i}.org"])

    def test_full_pipeline_run(self) -> None:
        """Test full pipeline run from end to end."""
        with TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Create synthetic raw files
            pt_file = tmp_path / "raw" / "phishtank.csv"
            tranco_file = tmp_path / "raw" / "tranco.csv"

            self._create_synthetic_phishtank_csv(pt_file, num_samples=30)
            self._create_synthetic_tranco_csv(tranco_file, num_samples=150)

            # Setup config
            config = PhishGuardConfig(
                data_dir=tmp_path,
                log_level="DEBUG",
            )

            # Run pipeline
            pipeline = DatasetPipeline(config)
            manifest_path = pipeline.run(
                phishtank_file=pt_file,
                tranco_file=tranco_file,
                phishtank_version="2026-08-29",
                tranco_list_id="TEST123",
                tranco_list_date=datetime(2026, 8, 28, tzinfo=UTC),
                output_dir=tmp_path / "processed",
            )

            # Verify manifest exists and is valid
            assert manifest_path.exists()
            manifest = DatasetManifest.load(manifest_path)
            assert manifest.manifest_version == "1.0"
            assert len(manifest.sources) == 2

            # Verify split files exist
            processed_dir = tmp_path / "processed"
            assert (processed_dir / "train.jsonl").exists()
            assert (processed_dir / "val.jsonl").exists()
            assert (processed_dir / "test.jsonl").exists()
            assert (processed_dir / "archive.jsonl").exists()

            # Verify training set class balance (approximately 1:4)
            train_lines = (processed_dir / "train.jsonl").read_text().strip().split("\n")
            assert len(train_lines) > 0

            # Verify archive contains unused benign samples
            archive_lines = (processed_dir / "archive.jsonl").read_text().strip().split("\n")
            assert len(archive_lines) > 0
