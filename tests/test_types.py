"""Tests for phishguard.types."""

from __future__ import annotations

import pytest

from phishguard.types import (
    AnalysisResult,
    Evidence,
    InputType,
    ThreatLevel,
)


class TestEvidence:
    def test_creation(self) -> None:
        e = Evidence(indicator="test", description="A test indicator", weight=0.5)
        assert e.indicator == "test"
        assert e.weight == 0.5

    def test_immutable(self) -> None:
        e = Evidence(indicator="x", description="y")
        with pytest.raises(AttributeError):
            e.indicator = "z"  # type: ignore[misc]


class TestAnalysisResult:
    def test_valid_result(self) -> None:
        result = AnalysisResult(
            input_type=InputType.URL,
            threat_level=ThreatLevel.SAFE,
            risk_score=0.1,
        )
        assert result.risk_score == 0.1
        assert result.evidence == []

    def test_risk_score_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="risk_score"):
            AnalysisResult(
                input_type=InputType.URL,
                threat_level=ThreatLevel.SAFE,
                risk_score=1.5,
            )

    def test_negative_risk_score(self) -> None:
        with pytest.raises(ValueError, match="risk_score"):
            AnalysisResult(
                input_type=InputType.URL,
                threat_level=ThreatLevel.SAFE,
                risk_score=-0.1,
            )
