"""Base class for all analysis services."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from phishguard.types import AnalysisResult


class AnalysisService(ABC):
    """Contract that every analysis service must satisfy."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"phishguard.{self.__class__.__name__}")

    @abstractmethod
    def analyze(self, input_data: Any) -> AnalysisResult:
        """Run analysis on *input_data* and return a structured result."""

    @abstractmethod
    def validate_input(self, input_data: Any) -> bool:
        """Return ``True`` when *input_data* is acceptable."""

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Human-readable service identifier."""
