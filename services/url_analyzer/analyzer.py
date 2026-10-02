"""URL analyser — rule-based heuristic checks."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from phishguard.types import (
    AnalysisResult,
    Evidence,
    InputType,
    ThreatLevel,
)
from services.base import AnalysisService

logger = logging.getLogger(__name__)

# ---- lightweight heuristic patterns (no ML, no external API) ----

_IP_ADDRESS_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    ".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
})

_PHISHING_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "credential",
})


class URLAnalyzer(AnalysisService):
    """Analyse a URL using lightweight heuristics.

    This does **not** fetch the page or call any external service.
    It examines the URL string itself for known phishing signals.
    """

    @property
    def service_name(self) -> str:
        return "url_analyzer"

    # -- public API --------------------------------------------------

    def validate_input(self, input_data: object) -> bool:
        """Accept any non-empty string that ``urlparse`` can handle."""
        if not isinstance(input_data, str) or not input_data.strip():
            return False
        parsed = urlparse(input_data)
        return parsed.scheme in {"http", "https", ""}

    def analyze(self, input_data: object) -> AnalysisResult:
        """Return an :class:`AnalysisResult` for the given URL string."""
        if not isinstance(input_data, str):
            raise TypeError(f"Expected str, got {type(input_data).__name__}")

        url = input_data.strip()
        evidence: list[Evidence] = []

        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or ""

        self._check_ip_address(hostname, evidence)
        self._check_suspicious_tld(hostname, evidence)
        self._check_excessive_subdomains(hostname, evidence)
        self._check_phishing_keywords(url, evidence)
        self._check_at_symbol(url, evidence)
        self._check_url_length(url, evidence)

        risk_score = self._compute_score(evidence)
        threat_level = self._score_to_threat(risk_score)

        logger.info("URL analysis complete: %s → %s (%.2f)", url, threat_level.value, risk_score)

        return AnalysisResult(
            input_type=InputType.URL,
            threat_level=threat_level,
            risk_score=risk_score,
            evidence=evidence,
            raw_input=url,
        )

    # -- heuristic checks -------------------------------------------

    def _check_ip_address(self, hostname: str, evidence: list[Evidence]) -> None:
        if _IP_ADDRESS_RE.match(hostname):
            evidence.append(Evidence(
                indicator="ip_address_url",
                description="URL uses a raw IP address instead of a domain name",
                weight=0.3,
            ))

    def _check_suspicious_tld(self, hostname: str, evidence: list[Evidence]) -> None:
        for tld in _SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                evidence.append(Evidence(
                    indicator="suspicious_tld",
                    description=f"Domain uses a TLD commonly associated with abuse: {tld}",
                    weight=0.2,
                ))
                break

    def _check_excessive_subdomains(self, hostname: str, evidence: list[Evidence]) -> None:
        if hostname.count(".") > 3:
            evidence.append(Evidence(
                indicator="excessive_subdomains",
                description="URL has an unusually deep subdomain chain",
                weight=0.15,
            ))

    def _check_phishing_keywords(self, url: str, evidence: list[Evidence]) -> None:
        lower = url.lower()
        found = [kw for kw in _PHISHING_KEYWORDS if kw in lower]
        if found:
            evidence.append(Evidence(
                indicator="phishing_keywords",
                description=f"URL contains phishing-related keywords: {', '.join(found)}",
                weight=min(0.1 * len(found), 0.3),
            ))

    def _check_at_symbol(self, url: str, evidence: list[Evidence]) -> None:
        if "@" in url:
            evidence.append(Evidence(
                indicator="at_symbol",
                description="URL contains an '@' symbol, which can disguise the real destination",
                weight=0.25,
            ))

    def _check_url_length(self, url: str, evidence: list[Evidence]) -> None:
        if len(url) > 100:
            evidence.append(Evidence(
                indicator="long_url",
                description=f"URL is unusually long ({len(url)} characters)",
                weight=0.1,
            ))

    # -- scoring -----------------------------------------------------

    @staticmethod
    def _compute_score(evidence: list[Evidence]) -> float:
        total = sum(e.weight for e in evidence)
        return min(total, 1.0)

    @staticmethod
    def _score_to_threat(score: float) -> ThreatLevel:
        if score >= 0.6:
            return ThreatLevel.PHISHING
        if score >= 0.3:
            return ThreatLevel.SUSPICIOUS
        return ThreatLevel.SAFE
