"""Validation and normalization for dataset samples."""

from __future__ import annotations

import logging
from collections.abc import Iterator

from .schema import Sample
from .utils import validate_label, validate_url

logger = logging.getLogger(__name__)


class SampleValidator:
    """Validate dataset samples."""

    def __init__(self) -> None:
        """Initialize validator."""
        self.validation_errors: list[dict[str, str]] = []

    def validate(self, samples: Iterator[Sample]) -> Iterator[Sample]:
        """Validate samples and yield only valid ones.

        Parameters
        ----------
        samples : Iterator[Sample]
            Samples to validate

        Yields
        ------
        Sample
            Valid samples only
        """
        for sample in samples:
            try:
                # Check required fields
                if not sample.sample_id:
                    self._log_error(sample, "missing_sample_id", "sample_id is empty")
                    continue

                if not sample.source:
                    self._log_error(sample, "missing_source", "source is empty")
                    continue

                if not sample.raw_input:
                    self._log_error(sample, "missing_raw_input", "raw_input is empty")
                    continue

                if not sample.normalized_input:
                    self._log_error(
                        sample, "missing_normalized_input", "normalized_input is empty"
                    )
                    continue

                # Validate label
                if not validate_label(sample.label):
                    self._log_error(
                        sample,
                        "invalid_label",
                        f"label '{sample.label}' not in allowed set",
                    )
                    continue

                # Validate label confidence
                if not (0.0 <= sample.label_confidence <= 1.0):
                    self._log_error(
                        sample,
                        "invalid_confidence",
                        f"label_confidence {sample.label_confidence} not in [0, 1]",
                    )
                    continue

                # Type-specific validation
                if sample.input_type.value == "url" and not validate_url(
                    sample.normalized_input
                ):
                    self._log_error(
                        sample,
                        "invalid_url",
                        f"URL validation failed: {sample.normalized_input}",
                    )
                    continue

                # Passed all checks
                yield sample

            except Exception as e:
                self._log_error(sample, "validation_exception", str(e))
                continue

    def _log_error(self, sample: Sample, error_type: str, message: str) -> None:
        """Log validation error.

        Parameters
        ----------
        sample : Sample
            Sample that failed validation
        error_type : str
            Type of validation error
        message : str
            Error message
        """
        error = {
            "sample_id": sample.sample_id,
            "source": sample.source,
            "source_id": sample.source_id,
            "error_type": error_type,
            "message": message,
            "raw_input": sample.raw_input[:100] if sample.raw_input else "",
        }
        self.validation_errors.append(error)
        logger.debug("Validation error: %s - %s", error_type, message)

    def get_error_count(self) -> int:
        """Get total number of validation errors.

        Returns
        -------
        int
            Number of validation errors
        """
        return len(self.validation_errors)

    def get_errors_by_type(self) -> dict[str, int]:
        """Get error counts grouped by type.

        Returns
        -------
        dict[str, int]
            Error type -> count mapping
        """
        error_counts: dict[str, int] = {}
        for error in self.validation_errors:
            error_type = error["error_type"]
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        return error_counts
