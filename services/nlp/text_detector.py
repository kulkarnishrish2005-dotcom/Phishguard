"""Lightweight text and email phishing detector for PhishGuard.

Implements a rule-based + lexical heuristic NLP analysis engine that scores
email/SMS/message text for phishing, social engineering, credential harvesting,
and urgency patterns without calling external APIs or heavy models.

Labelled as: Rule-Based & Lexical Heuristic NLP Baseline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from phishguard.types import Evidence, InputType, ThreatLevel
from services.base import AnalysisService


@dataclass
class TextAnalysisResult:
    """Structured result of email / text analysis."""

    text: str
    is_phishing: bool
    confidence: float  # 0.0 to 1.0
    risk_score: int  # 0 to 100
    threat_level: ThreatLevel
    evidence: list[Evidence] = field(default_factory=list)
    found_urls: list[str] = field(default_factory=list)
    urgency_score: float = 0.0
    credential_harvesting_score: float = 0.0
    financial_lure_score: float = 0.0
    summary: str = ""


# Pre-compiled pattern groups for phishing detection
_URGENCY_PATTERNS = [
    (r"\b(?:immediate(?:ly)?|urgent(?:ly)?|critical|emergency)\b", "Immediate urgency keywords", 0.15),
    (r"\b(?:within\s+\d+\s+(?:hours?|days?|minutes?)|24\s*hours?|48\s*hours?)\b", "Time-pressure deadline specified", 0.20),
    (r"\b(?:account\s+(?:suspended|restricted|disabled|locked|terminated|cancelled))\b", "Account restriction threat", 0.25),
    (r"\b(?:action\s+required|failure\s+to\s+(?:comply|respond)|legal\s+action)\b", "Threat of consequence / action required", 0.20),
    (r"\b(?:unauthorized\s+access|security\s+breach|suspicious\s+activity\s+detected)\b", "False security alert lure", 0.20),
]

_CREDENTIAL_PATTERNS = [
    (r"\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|password|credential|details|pin)\b", "Direct credential / identity verification prompt", 0.25),
    (r"\b(?:password|passcode|secret\s+key|recovery\s+phrase|seed\s+phrase)\s+(?:reset|expired|change|required)\b", "Password/Key reset or expiration prompt", 0.20),
    (r"\b(?:click\s+(?:here|the\s+link|below)|follow\s+this\s+link|log\s*in\s+to\s+(?:your\s+)?account)\b", "Direct call-to-action link click lure", 0.15),
    (r"\b(?:click\s+here)\b", "Direct click-here call to action", 0.15),
    (r"\b(?:enter|provide|submit)\s+(?:your\s+)?(?:ssn|social\s+security|credit\s+card|banking|cvv)\b", "Sensitive PII or financial data request", 0.30),
]

_FINANCIAL_LURE_PATTERNS = [
    (r"\b(?:refund|tax\s+refund|overdue\s+invoice|wire\s+transfer|payment\s+overdue)\b", "Financial / Invoice lure", 0.15),
    (r"\b(?:you\s+(?:have\s+)?won|lottery|crypto|bitcoin|inheritance|claim\s+your\s+prize|won\s+a\s+\$?\d+)\b", "Unsolicited reward / lottery / prize scam pattern", 0.25),
    (r"\b(?:gift\s+card|bonus|exclusive\s+offer|claim\s+\$?\d+|\$?\d+\s+prize)\b", "Prize / Gift card incentive lure", 0.15),
]

_URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?",
    re.IGNORECASE,
)


class TextPhishingDetector(AnalysisService):
    """Rule-based and lexical heuristic text/email phishing detector."""

    @property
    def service_name(self) -> str:
        return "text_nlp_detector"

    def validate_input(self, input_data: Any) -> bool:
        """Accept non-empty text strings."""
        return isinstance(input_data, str) and bool(input_data.strip())

    def analyze(self, input_data: Any) -> Any:
        """Run standard AnalysisResult."""
        result = self.detect(str(input_data))
        from phishguard.types import AnalysisResult

        return AnalysisResult(
            input_type=InputType.EMAIL if "Subject:" in str(input_data) else InputType.TEXT,
            threat_level=result.threat_level,
            risk_score=result.risk_score / 100.0,
            evidence=result.evidence,
            raw_input=str(input_data),
        )

    def detect(self, text: str) -> TextAnalysisResult:
        """Analyse freeform text/email for phishing indicators.

        Parameters
        ----------
        text : str
            Email message, SMS, or plain text to evaluate.

        Returns
        -------
        TextAnalysisResult
            Detailed assessment with risk score, urgency metrics, and extracted URLs.
        """
        if not text or not text.strip():
            return TextAnalysisResult(
                text=text,
                is_phishing=False,
                confidence=0.0,
                risk_score=0,
                threat_level=ThreatLevel.SAFE,
                evidence=[Evidence("empty_input", "No text provided for analysis", 0.0)],
                summary="Empty input text.",
            )

        evidence: list[Evidence] = []
        raw_score = 0.0

        # 1. Extract embedded URLs
        found_urls = _URL_REGEX.findall(text)
        if found_urls:
            raw_score += 15.0
            evidence.append(
                Evidence(
                    indicator="embedded_urls",
                    description=f"Message contains {len(found_urls)} embedded URL(s): {', '.join(found_urls[:3])}",
                    weight=0.15,
                )
            )

        # 2. Check Urgency / Intimidation Patterns
        urgency_points = 0.0
        for pattern, desc, weight in _URGENCY_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                urgency_points += weight
                evidence.append(Evidence(indicator="urgency_pressure", description=desc, weight=weight))

        # 3. Check Credential Harvesting Patterns
        cred_points = 0.0
        for pattern, desc, weight in _CREDENTIAL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                cred_points += weight
                evidence.append(Evidence(indicator="credential_harvesting", description=desc, weight=weight))

        # 4. Check Financial & Social Engineering Lures
        fin_points = 0.0
        for pattern, desc, weight in _FINANCIAL_LURE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                fin_points += weight
                evidence.append(Evidence(indicator="financial_lure", description=desc, weight=weight))

        # Sum contributions into 0-100 risk score
        raw_score += min(urgency_points * 60.0, 35.0)
        raw_score += min(cred_points * 60.0, 35.0)
        raw_score += min(fin_points * 50.0, 25.0)

        # High density penalty: combined urgency + credentials is a classic phishing signature
        if urgency_points > 0 and cred_points > 0:
            raw_score += 15.0
            evidence.append(
                Evidence(
                    indicator="urgency_plus_credential_request",
                    description="Severe threat signature: Message pairs artificial time pressure with credential/login requests",
                    weight=0.25,
                )
            )

        if not evidence:
            evidence.append(
                Evidence(
                    indicator="benign_text_profile",
                    description="No suspicious urgency, credential requests, or financial phishing patterns detected",
                    weight=0.0,
                )
            )

        risk_score = int(min(max(round(raw_score), 0), 100))
        confidence = round(min(risk_score / 100.0 + 0.1, 0.95), 2) if risk_score >= 35 else round(max(1.0 - (risk_score / 100.0), 0.5), 2)

        if risk_score >= 60:
            threat_level = ThreatLevel.PHISHING
            is_phishing = True
            summary = f"High Phishing Threat ({risk_score}/100): Social engineering and credential harvesting indicators detected."
        elif risk_score >= 30:
            threat_level = ThreatLevel.SUSPICIOUS
            is_phishing = False
            summary = f"Suspicious Message ({risk_score}/100): Contains moderate urgency or promotional lures."
        else:
            threat_level = ThreatLevel.SAFE
            is_phishing = False
            summary = f"Safe ({risk_score}/100): Normal conversational or business communication patterns."

        return TextAnalysisResult(
            text=text,
            is_phishing=is_phishing,
            confidence=confidence,
            risk_score=risk_score,
            threat_level=threat_level,
            evidence=evidence,
            found_urls=found_urls,
            urgency_score=round(urgency_points, 2),
            credential_harvesting_score=round(cred_points, 2),
            financial_lure_score=round(fin_points, 2),
            summary=summary,
        )


def analyze_text(text: str) -> TextAnalysisResult:
    """Convenience helper for text phishing analysis."""
    detector = TextPhishingDetector()
    return detector.detect(text)
