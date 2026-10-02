"""Evidence-based risk scoring and explanation engine for PhishGuard.

Takes ML model output, heuristic indicators, and extracted features,
and computes a transparent composite Risk Score (0-100), Risk Level (LOW/MEDIUM/HIGH),
and an ordered list of human-interpretable Evidence items with weights.

NOTE: Risk score is an expert-weighted threat index, NOT a calibrated probability.
Model probability and Risk score are kept strictly distinct.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any

from phishguard.types import Evidence


class RiskLevel(enum.Enum):
    """Categorical risk classification."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment output."""

    risk_score: int  # 0 to 100
    risk_level: RiskLevel
    verdict: str  # "SAFE", "SUSPICIOUS", "PHISHING"
    model_probability: float  # 0.0 to 1.0 (kept separate from risk score)
    evidence: list[Evidence] = field(default_factory=list)
    contributing_factors: dict[str, float] = field(default_factory=dict)
    summary: str = ""


class RiskEngine:
    """Combines statistical ML probability with rule-based security evidence."""

    def evaluate_url(
        self,
        features: dict[str, Any],
        model_probability: float,
        model_name: str = "ML Model",
    ) -> RiskAssessment:
        """Evaluate URL features and model probability into a risk assessment.

        Parameters
        ----------
        features : dict[str, Any]
            The 42 features extracted from the URL.
        model_probability : float
            Phishing probability output by the ML model.
        model_name : str
            Name of the model that generated the probability.

        Returns
        -------
        RiskAssessment
            Structured risk score (0-100), RiskLevel, and supporting Evidence.
        """
        evidence: list[Evidence] = []
        raw_score = 0.0

        # Factor 1: ML Model Output (up to 40 points)
        ml_weight = 40.0
        ml_contrib = model_probability * ml_weight
        raw_score += ml_contrib

        if model_probability >= 0.70:
            evidence.append(
                Evidence(
                    indicator="ml_high_confidence",
                    description=f"{model_name} indicates high phishing probability ({model_probability:.1%})",
                    weight=0.35,
                )
            )
        elif model_probability >= 0.40:
            evidence.append(
                Evidence(
                    indicator="ml_moderate_confidence",
                    description=f"{model_name} indicates suspicious structural patterns ({model_probability:.1%})",
                    weight=0.15,
                )
            )

        # Factor 2: Critical Obfuscation Indicators (up to 30 points)
        if features.get("is_ip_host", False):
            raw_score += 20.0
            evidence.append(
                Evidence(
                    indicator="ip_address_host",
                    description="Hostname uses a raw IP address instead of a registered domain name",
                    weight=0.25,
                )
            )

        if features.get("is_punycode", False):
            raw_score += 15.0
            evidence.append(
                Evidence(
                    indicator="punycode_idn",
                    description="Hostname uses Punycode (xn--) which can be used for homograph deception",
                    weight=0.20,
                )
            )

        if features.get("has_at_sign", False):
            raw_score += 15.0
            evidence.append(
                Evidence(
                    indicator="at_symbol_redirect",
                    description="URL contains '@' symbol; browsers treat preceding text as credentials and route to the following host",
                    weight=0.20,
                )
            )

        if features.get("has_double_slash_redirect", False):
            raw_score += 10.0
            evidence.append(
                Evidence(
                    indicator="double_slash_redirect",
                    description="URL path contains double slash ('//') indicative of open-redirect exploitation",
                    weight=0.15,
                )
            )

        if features.get("has_shortener_pattern", False):
            raw_score += 10.0
            evidence.append(
                Evidence(
                    indicator="url_shortener",
                    description="URL uses a link-shortening service that conceals the true landing page",
                    weight=0.10,
                )
            )

        # Factor 3: Lexical & Keyword Indicators (up to 20 points)
        kw_count = int(features.get("suspicious_keyword_count", 0))
        if kw_count > 0:
            raw_score += min(kw_count * 5.0, 15.0)
            evidence.append(
                Evidence(
                    indicator="suspicious_keywords",
                    description=f"URL contains {kw_count} phishing-associated keyword(s) (e.g. login, verify, account)",
                    weight=min(0.08 * kw_count, 0.20),
                )
            )

        # Factor 4: Structural Indicators (up to 15 points)
        subdomains = int(features.get("subdomain_count", 0))
        if subdomains >= 3:
            raw_score += 10.0
            evidence.append(
                Evidence(
                    indicator="excessive_subdomains",
                    description=f"Deep subdomain nesting detected ({subdomains} levels), common in brand spoofing",
                    weight=0.12,
                )
            )

        entropy = float(features.get("hostname_entropy", 0.0))
        if entropy > 3.8:
            raw_score += 8.0
            evidence.append(
                Evidence(
                    indicator="high_hostname_entropy",
                    description=f"Hostname character randomness is high (entropy: {entropy:.2f} bits), characteristic of DGA domains",
                    weight=0.10,
                )
            )

        if features.get("has_port", False):
            raw_score += 8.0
            evidence.append(
                Evidence(
                    indicator="non_standard_port",
                    description="URL explicitly specifies a non-standard network port",
                    weight=0.08,
                )
            )

        if int(features.get("url_length", 0)) > 100:
            raw_score += 5.0
            evidence.append(
                Evidence(
                    indicator="excessive_length",
                    description=f"URL is unusually long ({features.get('url_length')} characters), often used to hide payloads",
                    weight=0.05,
                )
            )

        if features.get("domain_has_hyphen", False):
            raw_score += 5.0
            evidence.append(
                Evidence(
                    indicator="domain_hyphenation",
                    description="Registrable domain contains hyphens, frequently seen in typosquatting / look-alike domains",
                    weight=0.05,
                )
            )

        # Baseline safe evidence if no strong signals
        if not evidence:
            evidence.append(
                Evidence(
                    indicator="clean_structure",
                    description="No known malicious structural patterns, obfuscation techniques, or suspicious keywords found",
                    weight=0.0,
                )
            )

        # Scale and clamp risk score to integer 0-100
        risk_score = int(min(max(round(raw_score), 0), 100))

        # Determine Risk Level and Verdict
        if risk_score >= 65:
            risk_level = RiskLevel.HIGH
            verdict = "PHISHING"
            summary = f"High threat probability ({risk_score}/100). Strongly recommend blocking this URL."
        elif risk_score >= 35:
            risk_level = RiskLevel.MEDIUM
            verdict = "SUSPICIOUS"
            summary = f"Moderate risk detected ({risk_score}/100). Exercise caution; anomalous attributes present."
        else:
            risk_level = RiskLevel.LOW
            verdict = "SAFE"
            summary = f"Low risk detected ({risk_score}/100). URL structure conforms to benign web patterns."

        return RiskAssessment(
            risk_score=risk_score,
            risk_level=risk_level,
            verdict=verdict,
            model_probability=model_probability,
            evidence=evidence,
            summary=summary,
        )


def evaluate_risk(
    features: dict[str, Any],
    model_probability: float,
    model_name: str = "ML Model",
) -> RiskAssessment:
    """Convenience function to evaluate risk for a URL."""
    engine = RiskEngine()
    return engine.evaluate_url(features, model_probability, model_name)
