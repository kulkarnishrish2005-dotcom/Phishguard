"""Shared domain types used across PhishGuard modules."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import UTC, datetime


class ThreatLevel(enum.Enum):
    """Coarse threat classification."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


class InputType(enum.Enum):
    """Kinds of input the platform can analyse."""

    URL = "url"
    EMAIL = "email"
    TEXT = "text"
    SCREENSHOT = "screenshot"
    QR_CODE = "qr_code"


@dataclass(frozen=True)
class Evidence:
    """A single piece of supporting evidence for a detection decision."""

    indicator: str
    description: str
    weight: float = 0.0  # contribution to risk score; 0 = informational


@dataclass
class AnalysisResult:
    """Structured output of any analysis pipeline."""

    input_type: InputType
    threat_level: ThreatLevel
    risk_score: float  # 0.0 (safe) – 1.0 (certain phishing)
    evidence: list[Evidence] = field(default_factory=list)
    raw_input: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError(f"risk_score must be in [0, 1], got {self.risk_score}")
