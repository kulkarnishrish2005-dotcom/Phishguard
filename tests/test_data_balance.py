"""Tests for class balancing logic."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from ml.data.balance import ClassBalancer
from ml.data.schema import Sample, SplitType
from phishguard.types import InputType


class TestClassBalancer:
    """Tests for training set class balancing."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.balancer = ClassBalancer(target_ratio=0.20, random_seed=42)

    def _create_sample(self, label: str) -> Sample:
        """Helper to create a sample."""
        return Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id=f"test_{uuid4()}",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label=label,
            label_confidence=1.0,
            timestamp=datetime.now(UTC),
            ingestion_time=datetime.now(UTC),
            registrable_domain="example.com",
            split=SplitType.TRAIN.value,
        )

    def test_balance_to_1_4_ratio(self) -> None:
        """Test balancing to 1:4 phishing:benign ratio."""
        # Create imbalanced dataset: 10 phishing, 100 benign
        samples = []
        for _ in range(10):
            samples.append(self._create_sample("phishing"))
        for _ in range(100):
            samples.append(self._create_sample("benign"))

        balanced, archived = self.balancer.balance_training_set(samples)

        # Should have 10 phishing + 40 benign = 50 total
        phishing_count = sum(1 for s in balanced if s.label == "phishing")
        benign_count = sum(1 for s in balanced if s.label == "benign")

        assert phishing_count == 10
        assert benign_count == 40
        assert len(balanced) == 50

        # 60 benign should be archived
        assert len(archived) == 60
        assert all(s.split == SplitType.ARCHIVE.value for s in archived)

    def test_no_balancing_needed(self) -> None:
        """Test when dataset is already balanced enough."""
        # Create dataset: 10 phishing, 30 benign (already better than 1:4)
        samples = []
        for _ in range(10):
            samples.append(self._create_sample("phishing"))
        for _ in range(30):
            samples.append(self._create_sample("benign"))

        balanced, archived = self.balancer.balance_training_set(samples)

        # No undersampling needed
        assert len(balanced) == 40
        assert len(archived) == 0

    def test_deterministic_balancing(self) -> None:
        """Test that balancing is deterministic with same seed."""
        samples = []
        for _ in range(10):
            samples.append(self._create_sample("phishing"))
        for _ in range(100):
            samples.append(self._create_sample("benign"))

        # Balance twice with same seed
        balancer1 = ClassBalancer(target_ratio=0.20, random_seed=42)
        balanced1, _ = balancer1.balance_training_set(samples.copy())

        balancer2 = ClassBalancer(target_ratio=0.20, random_seed=42)
        balanced2, _ = balancer2.balance_training_set(samples.copy())

        # Should select same samples
        ids1 = {s.sample_id for s in balanced1}
        ids2 = {s.sample_id for s in balanced2}
        assert ids1 == ids2

    def test_compute_class_weights(self) -> None:
        """Test class weight computation."""
        samples = []
        # 10 phishing, 40 benign (total 50)
        for _ in range(10):
            samples.append(self._create_sample("phishing"))
        for _ in range(40):
            samples.append(self._create_sample("benign"))

        weights = self.balancer.compute_class_weights(samples)

        # weight = n_total / (2 * n_class)
        # phishing: 50 / (2 * 10) = 2.5
        # benign: 50 / (2 * 40) = 0.625
        assert abs(weights["phishing"] - 2.5) < 0.01
        assert abs(weights["benign"] - 0.625) < 0.01

    def test_no_phishing_samples(self) -> None:
        """Test behavior with no phishing samples."""
        samples = []
        for _ in range(10):
            samples.append(self._create_sample("benign"))

        balanced, archived = self.balancer.balance_training_set(samples)

        # Should return original samples unchanged
        assert len(balanced) == 10
        assert len(archived) == 0

    def test_archived_samples_marked(self) -> None:
        """Test that archived samples have correct split marker."""
        samples = []
        for _ in range(10):
            samples.append(self._create_sample("phishing"))
        for _ in range(100):
            samples.append(self._create_sample("benign"))

        balanced, archived = self.balancer.balance_training_set(samples)

        # All archived samples should be marked as ARCHIVE
        for sample in archived:
            assert sample.split == SplitType.ARCHIVE.value
            assert sample.label == "benign"
