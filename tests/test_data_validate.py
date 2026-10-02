"""Tests for dataset validation."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from ml.data.schema import Sample
from ml.data.validate import SampleValidator
from phishguard.types import InputType


class TestSampleValidator:
    """Tests for sample validation."""

    def setup_method(self) -> None:
        """Set up test fixtures."""
        self.validator = SampleValidator()

    def test_valid_sample(self) -> None:
        """Test validation of a valid sample."""
        sample = Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="benign",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
            registrable_domain="example.com",
        )

        valid_samples = list(self.validator.validate(iter([sample])))
        assert len(valid_samples) == 1
        assert self.validator.get_error_count() == 0

    def test_missing_sample_id(self) -> None:
        """Test rejection of sample with missing sample_id."""
        sample = Sample(
            sample_id="",
            source="test",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="benign",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        valid_samples = list(self.validator.validate(iter([sample])))
        assert len(valid_samples) == 0
        assert self.validator.get_error_count() == 1

    def test_missing_source(self) -> None:
        """Test rejection of sample with missing source."""
        sample = Sample(
            sample_id=str(uuid4()),
            source="",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="benign",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        valid_samples = list(self.validator.validate(iter([sample])))
        assert len(valid_samples) == 0
        assert self.validator.get_error_count() == 1

    def test_invalid_label(self) -> None:
        """Test rejection of sample with invalid label."""
        sample = Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="spam",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        valid_samples = list(self.validator.validate(iter([sample])))
        assert len(valid_samples) == 0
        assert self.validator.get_error_count() == 1

    def test_invalid_confidence(self) -> None:
        """Test rejection of sample with invalid confidence."""
        sample = Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="benign",
            label_confidence=1.5,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        valid_samples = list(self.validator.validate(iter([sample])))
        assert len(valid_samples) == 0
        assert self.validator.get_error_count() == 1

    def test_invalid_url(self) -> None:
        """Test rejection of sample with invalid URL."""
        sample = Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="not a url",
            normalized_input="not a url",
            label="benign",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        valid_samples = list(self.validator.validate(iter([sample])))
        assert len(valid_samples) == 0
        assert self.validator.get_error_count() == 1

    def test_multiple_samples(self) -> None:
        """Test validation of multiple samples."""
        valid_sample = Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id="test_1",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="benign",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        invalid_sample = Sample(
            sample_id=str(uuid4()),
            source="test",
            source_id="test_2",
            input_type=InputType.URL,
            raw_input="https://example.com",
            normalized_input="https://example.com/",
            label="invalid_label",
            label_confidence=1.0,
            timestamp=None,
            ingestion_time=datetime.now(UTC),
        )

        valid_samples = list(self.validator.validate(iter([valid_sample, invalid_sample])))
        assert len(valid_samples) == 1
        assert self.validator.get_error_count() == 1

    def test_error_statistics(self) -> None:
        """Test error statistics collection."""
        samples = [
            Sample(
                sample_id="",
                source="test",
                source_id="test_1",
                input_type=InputType.URL,
                raw_input="https://example.com",
                normalized_input="https://example.com/",
                label="benign",
                label_confidence=1.0,
                timestamp=None,
                ingestion_time=datetime.now(UTC),
            ),
            Sample(
                sample_id=str(uuid4()),
                source="",
                source_id="test_2",
                input_type=InputType.URL,
                raw_input="https://example.com",
                normalized_input="https://example.com/",
                label="benign",
                label_confidence=1.0,
                timestamp=None,
                ingestion_time=datetime.now(UTC),
            ),
        ]

        list(self.validator.validate(iter(samples)))

        errors_by_type = self.validator.get_errors_by_type()
        assert errors_by_type["missing_sample_id"] == 1
        assert errors_by_type["missing_source"] == 1
