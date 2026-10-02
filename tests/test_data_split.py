"""Tests for dataset splitting and leakage prevention."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ml.data.schema import Sample
from ml.data.split import DatasetSplitter
from phishguard.types import InputType


class TestDatasetSplitter:
    """Tests for domain-aware and temporal splitting."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.splitter = DatasetSplitter(
            train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42
        )

    def _create_sample(
        self,
        domain: str,
        timestamp: datetime,
        label: str = "phishing",
    ) -> Sample:
        """Helper to create a sample."""
        url = f"https://{domain}/page"
        return Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id=f"test_{uuid4()}",
            input_type=InputType.URL,
            raw_input=url,
            normalized_input=url,
            label=label,
            label_confidence=1.0,
            timestamp=timestamp,
            ingestion_time=datetime.now(UTC),
            registrable_domain=domain,
        )

    def test_split_ratios(self) -> None:
        """Test that split ratios are approximately correct."""
        # Create 100 samples across 10 domains
        samples = []
        base_time = datetime(2026, 1, 1, tzinfo=UTC)

        for i in range(10):
            domain = f"domain{i}.com"
            for j in range(10):
                timestamp = base_time + timedelta(days=i * 10 + j)
                samples.append(self._create_sample(domain, timestamp))

        splits = self.splitter.split_temporal_domain_aware(samples)

        total = sum(len(samples) for samples in splits.values())
        assert total == 100

        # Check approximate ratios (allow some variance due to domain clustering)
        train_ratio = len(splits["train"]) / total
        val_ratio = len(splits["val"]) / total
        test_ratio = len(splits["test"]) / total

        assert 0.60 <= train_ratio <= 0.80
        assert 0.10 <= val_ratio <= 0.25
        assert 0.10 <= test_ratio <= 0.25

    def test_domain_isolation(self) -> None:
        """Test that samples from same domain are in same split."""
        samples = []
        base_time = datetime(2026, 1, 1, tzinfo=UTC)

        # Create 3 domains with 10 samples each
        for i in range(3):
            domain = f"domain{i}.com"
            for j in range(10):
                timestamp = base_time + timedelta(days=i * 10 + j)
                samples.append(self._create_sample(domain, timestamp))

        splits = self.splitter.split_temporal_domain_aware(samples)

        # Check each domain appears in only one split
        domain_splits: dict[str, str] = {}
        for split_name, split_samples in splits.items():
            for sample in split_samples:
                domain = sample.registrable_domain
                if domain:
                    if domain in domain_splits:
                        # Domain should not appear in multiple splits
                        assert domain_splits[domain] == split_name
                    else:
                        domain_splits[domain] = split_name

    def test_temporal_ordering(self) -> None:
        """Test that test set is temporally newer than train set."""
        samples = []
        base_time = datetime(2026, 1, 1, tzinfo=UTC)

        # Create domains with clear temporal progression
        for i in range(10):
            domain = f"domain{i}.com"
            timestamp = base_time + timedelta(days=i * 30)  # Monthly progression
            samples.append(self._create_sample(domain, timestamp))

        splits = self.splitter.split_temporal_domain_aware(samples)

        # Get timestamp ranges
        train_timestamps = [
            s.timestamp for s in splits["train"] if s.timestamp
        ]
        test_timestamps = [
            s.timestamp for s in splits["test"] if s.timestamp
        ]

        if train_timestamps and test_timestamps:
            train_max = max(train_timestamps)
            test_min = min(test_timestamps)

            # Test should generally be newer (may overlap at boundaries)
            # For this test with clear progression, should be strictly newer
            assert test_min >= train_max

    def test_deterministic_splitting(self) -> None:
        """Test that splitting is deterministic with same seed."""
        samples = []
        base_time = datetime(2026, 1, 1, tzinfo=UTC)

        for i in range(10):
            domain = f"domain{i}.com"
            timestamp = base_time + timedelta(days=i)
            samples.append(self._create_sample(domain, timestamp))

        # Split twice with same seed
        splitter1 = DatasetSplitter(random_seed=42)
        splits1 = splitter1.split_temporal_domain_aware(samples)

        splitter2 = DatasetSplitter(random_seed=42)
        splits2 = splitter2.split_temporal_domain_aware(samples)

        # Should produce identical splits
        assert len(splits1["train"]) == len(splits2["train"])
        assert len(splits1["val"]) == len(splits2["val"])
        assert len(splits1["test"]) == len(splits2["test"])

        # Check sample IDs match (same samples in same splits)
        train_ids1 = {s.sample_id for s in splits1["train"]}
        train_ids2 = {s.sample_id for s in splits2["train"]}
        assert train_ids1 == train_ids2

    def test_validate_split_no_leakage(self) -> None:
        """Test leakage validation on clean split."""
        samples = []
        base_time = datetime(2026, 1, 1, tzinfo=UTC)

        for i in range(5):
            domain = f"domain{i}.com"
            timestamp = base_time + timedelta(days=i * 10)
            samples.append(self._create_sample(domain, timestamp))

        splits = self.splitter.split_temporal_domain_aware(samples)
        results = self.splitter.validate_split(splits)

        assert results["exact_duplicate_check"] == "passed"
        assert results["domain_isolation_check"] == "passed"

    def test_validate_split_detects_domain_leakage(self) -> None:
        """Test leakage validation detects domain spanning splits."""
        # Manually create a split with domain leakage
        sample1 = self._create_sample("example.com", datetime.now(UTC))
        sample2 = self._create_sample("example.com", datetime.now(UTC))

        sample1.split = "train"
        sample2.split = "test"

        splits = {
            "train": [sample1],
            "test": [sample2],
        }

        results = self.splitter.validate_split(splits)
        assert results["domain_isolation_check"] == "failed"

    def test_compute_split_metadata(self) -> None:
        """Test split metadata computation."""
        base_time = datetime(2026, 1, 1, tzinfo=UTC)
        samples = [
            self._create_sample("domain1.com", base_time, "phishing"),
            self._create_sample("domain1.com", base_time + timedelta(days=1), "phishing"),
            self._create_sample("domain2.com", base_time + timedelta(days=2), "benign"),
        ]

        metadata = self.splitter.compute_split_metadata("train", samples)

        assert metadata.total_samples == 3
        assert metadata.phishing_samples == 2
        assert metadata.benign_samples == 1
        assert metadata.unique_domains == 2
        assert metadata.class_ratio == "1:0.5"  # 2 phishing, 1 benign
