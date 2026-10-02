"""Tests for deduplication logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ml.data.deduplicate import Deduplicator
from ml.data.schema import Sample
from phishguard.types import InputType


class TestDeduplicator:
    """Tests for exact and near-duplicate detection."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.deduplicator = Deduplicator(campaign_threshold=5, campaign_sample_size=2)

    def _create_sample(
        self,
        url: str,
        label: str = "phishing",
        confidence: float = 1.0,
        timestamp: datetime | None = None,
    ) -> Sample:
        """Helper to create a sample."""
        return Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id=f"test_{uuid4()}",
            input_type=InputType.URL,
            raw_input=url,
            normalized_input=url,
            label=label,
            label_confidence=confidence,
            timestamp=timestamp or datetime.now(UTC),
            ingestion_time=datetime.now(UTC),
            registrable_domain="example.com",
        )

    def test_no_duplicates(self) -> None:
        """Test deduplication with no duplicates."""
        samples = [
            self._create_sample("https://example.com/page1"),
            self._create_sample("https://example.com/page2"),
            self._create_sample("https://example.com/page3"),
        ]

        deduplicated = self.deduplicator.deduplicate_exact(samples)
        assert len(deduplicated) == 3
        assert self.deduplicator.tier1_removed == 0

    def test_exact_duplicates_same_label(self) -> None:
        """Test exact duplicates with same label."""
        url = "https://example.com/page"
        samples = [
            self._create_sample(url, "phishing", 1.0),
            self._create_sample(url, "phishing", 0.9),
            self._create_sample(url, "phishing", 0.8),
        ]

        deduplicated = self.deduplicator.deduplicate_exact(samples)
        assert len(deduplicated) == 1
        assert deduplicated[0].label_confidence == 1.0  # Highest confidence kept
        assert self.deduplicator.tier1_removed == 2

    def test_exact_duplicates_label_conflict(self) -> None:
        """Test exact duplicates with conflicting labels."""
        url = "https://example.com/page"
        samples = [
            self._create_sample(url, "phishing", 1.0),
            self._create_sample(url, "benign", 1.0),
        ]

        deduplicated = self.deduplicator.deduplicate_exact(samples)
        assert len(deduplicated) == 0  # All discarded due to conflict
        assert self.deduplicator.label_conflicts_removed == 2

    def test_exact_duplicates_prefer_earliest(self) -> None:
        """Test exact duplicates prefer earliest when confidence equal."""
        url = "https://example.com/page"
        now = datetime.now(UTC)
        samples = [
            self._create_sample(url, "phishing", 1.0, now + timedelta(days=2)),
            self._create_sample(url, "phishing", 1.0, now),  # Earliest
            self._create_sample(url, "phishing", 1.0, now + timedelta(days=1)),
        ]

        deduplicated = self.deduplicator.deduplicate_exact(samples)
        assert len(deduplicated) == 1
        assert deduplicated[0].timestamp == now

    def test_near_duplicate_campaign_detection(self) -> None:
        """Test near-duplicate detection for phishing campaigns."""
        # Create campaign: many URLs with same domain/structure but different param values
        samples = []
        for i in range(10):
            url = f"https://phish.example.com/login/verify?id={i}&token=abc{i}"
            samples.append(self._create_sample(url, "phishing"))

        deduplicated = self.deduplicator.deduplicate_near(samples)

        # Should subsample to campaign_sample_size (2)
        assert len(deduplicated) == 2
        assert self.deduplicator.tier2_removed == 8

    def test_near_duplicate_benign_not_deduplicated(self) -> None:
        """Test that benign URLs are not aggressively deduplicated."""
        # Create benign URLs with similar structure
        samples = []
        for i in range(10):
            url = f"https://example.com/page?id={i}"
            samples.append(self._create_sample(url, "benign"))

        deduplicated = self.deduplicator.deduplicate_near(samples)

        # Benign samples should not be deduplicated at near-duplicate level
        assert len(deduplicated) == 10

    def test_near_duplicate_below_threshold(self) -> None:
        """Test near-duplicates below campaign threshold are kept."""
        # Create small group (below threshold of 5)
        samples = []
        for i in range(3):
            url = f"https://phish.example.com/login?id={i}"
            samples.append(self._create_sample(url, "phishing"))

        deduplicated = self.deduplicator.deduplicate_near(samples)

        # All should be kept (below threshold)
        assert len(deduplicated) == 3
        assert self.deduplicator.tier2_removed == 0

    def test_get_stats(self) -> None:
        """Test statistics collection."""
        url = "https://example.com/page"
        samples = [
            self._create_sample(url, "phishing"),
            self._create_sample(url, "phishing"),
        ]

        self.deduplicator.deduplicate_exact(samples)
        stats = self.deduplicator.get_stats()

        assert stats["tier1_exact_duplicates_removed"] == 1
        assert stats["label_conflicts_discarded"] == 0
