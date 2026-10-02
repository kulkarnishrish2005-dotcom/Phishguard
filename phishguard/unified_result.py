"""Unified analysis response schema and serializer for PhishGuard.

Provides a unified JSON-serializable dictionary structure across all modalities
(URL, Text, Email, Screenshot, QR Code).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from phishguard.types import Evidence, InputType, ThreatLevel


@dataclass
class UnifiedAnalysisResult:
    """Unified result structure across all PhishGuard analysis modalities."""

    input_type: str  # "url", "text", "email", "screenshot", "qr_code"
    verdict: str  # "SAFE", "SUSPICIOUS", "PHISHING"
    risk_score: int  # 0 to 100
    model_probability: float | None  # 0.0 to 1.0 (or None if heuristic)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    raw_input_summary: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to standard JSON-serializable dict."""
        return asdict(self)

    @classmethod
    def from_url_prediction(
        cls,
        prediction: Any,
        risk: Any,
    ) -> UnifiedAnalysisResult:
        """Create from URL inference prediction and risk evaluation."""
        evidence_dicts = [
            {"indicator": e.indicator, "description": e.description, "weight": e.weight}
            for e in risk.evidence
        ]
        return cls(
            input_type="url",
            verdict=risk.verdict,
            risk_score=risk.risk_score,
            model_probability=prediction.probability,
            evidence=evidence_dicts,
            details={
                "model_name": prediction.model_name,
                "is_phishing": prediction.is_phishing,
                "threat_level": prediction.threat_level.value,
                "feature_count": len(prediction.features),
                "key_features": {
                    k: v for k, v in prediction.features.items()
                    if v and k in [
                        "is_ip_host", "is_punycode", "has_at_sign",
                        "has_suspicious_keyword", "suspicious_keyword_count",
                        "subdomain_count", "hostname_entropy", "url_length",
                        "domain_has_hyphen", "has_shortener_pattern", "has_port"
                    ]
                },
                "summary": risk.summary,
            },
            raw_input_summary=prediction.url[:120],
        )

    @classmethod
    def from_text_result(cls, text_res: Any) -> UnifiedAnalysisResult:
        """Create from NLP text analysis result."""
        evidence_dicts = [
            {"indicator": e.indicator, "description": e.description, "weight": e.weight}
            for e in text_res.evidence
        ]
        return cls(
            input_type="email" if "Subject:" in text_res.text else "text",
            verdict="PHISHING" if text_res.threat_level == ThreatLevel.PHISHING else ("SUSPICIOUS" if text_res.threat_level == ThreatLevel.SUSPICIOUS else "SAFE"),
            risk_score=text_res.risk_score,
            model_probability=text_res.confidence if text_res.is_phishing else None,
            evidence=evidence_dicts,
            details={
                "urgency_score": text_res.urgency_score,
                "credential_harvesting_score": text_res.credential_harvesting_score,
                "financial_lure_score": text_res.financial_lure_score,
                "found_urls": text_res.found_urls,
                "summary": text_res.summary,
            },
            raw_input_summary=text_res.text[:120] + ("..." if len(text_res.text) > 120 else ""),
        )

    @classmethod
    def from_screenshot_result(cls, screen_res: Any) -> UnifiedAnalysisResult:
        """Create from Screenshot OCR analysis result."""
        evidence_dicts = [
            {"indicator": e.indicator, "description": e.description, "weight": e.weight}
            for e in screen_res.evidence
        ]
        return cls(
            input_type="screenshot",
            verdict="PHISHING" if screen_res.threat_level == ThreatLevel.PHISHING else ("SUSPICIOUS" if screen_res.threat_level == ThreatLevel.SUSPICIOUS else "SAFE"),
            risk_score=screen_res.risk_score,
            model_probability=None,
            evidence=evidence_dicts,
            details={
                "ocr_engine": screen_res.ocr_engine_used,
                "extracted_text_preview": screen_res.extracted_text[:200] + ("..." if len(screen_res.extracted_text) > 200 else ""),
                "extracted_urls": screen_res.extracted_urls,
                "url_analyses": screen_res.url_analyses,
                "summary": screen_res.summary,
            },
            raw_input_summary=f"Image source: {screen_res.image_source}",
        )
