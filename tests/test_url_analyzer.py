"""Tests for the URL analysis service."""

from __future__ import annotations

from phishguard.types import InputType, ThreatLevel
from services.url_analyzer import URLAnalyzer


class TestURLAnalyzerValidation:
    def setup_method(self) -> None:
        self.analyzer = URLAnalyzer()

    def test_valid_url(self) -> None:
        assert self.analyzer.validate_input("https://example.com") is True

    def test_valid_url_no_scheme(self) -> None:
        assert self.analyzer.validate_input("example.com") is True

    def test_empty_string_invalid(self) -> None:
        assert self.analyzer.validate_input("") is False

    def test_non_string_invalid(self) -> None:
        assert self.analyzer.validate_input(42) is False  # type: ignore[arg-type]


class TestURLAnalyzerDetection:
    def setup_method(self) -> None:
        self.analyzer = URLAnalyzer()

    def test_safe_url(self) -> None:
        result = self.analyzer.analyze("https://example.com")
        assert result.input_type == InputType.URL
        assert result.threat_level == ThreatLevel.SAFE
        assert result.risk_score == 0.0

    def test_ip_address_url(self) -> None:
        result = self.analyzer.analyze("http://192.168.1.1/login")
        assert result.risk_score > 0
        indicators = {e.indicator for e in result.evidence}
        assert "ip_address_url" in indicators

    def test_suspicious_tld(self) -> None:
        result = self.analyzer.analyze("https://something.xyz")
        indicators = {e.indicator for e in result.evidence}
        assert "suspicious_tld" in indicators

    def test_phishing_keywords(self) -> None:
        result = self.analyzer.analyze("https://secure-login-verify.example.com")
        indicators = {e.indicator for e in result.evidence}
        assert "phishing_keywords" in indicators

    def test_at_symbol(self) -> None:
        result = self.analyzer.analyze("https://legit.com@evil.com/path")
        indicators = {e.indicator for e in result.evidence}
        assert "at_symbol" in indicators

    def test_combined_signals_raise_score(self) -> None:
        """A URL with multiple red flags should score higher."""
        result = self.analyzer.analyze(
            "http://192.168.1.1/secure-login-verify-account-update"
        )
        assert result.risk_score >= 0.5
        assert result.threat_level in {ThreatLevel.SUSPICIOUS, ThreatLevel.PHISHING}

    def test_analyze_rejects_non_string(self) -> None:
        import pytest
        with pytest.raises(TypeError):
            self.analyzer.analyze(123)  # type: ignore[arg-type]

    def test_result_has_raw_input(self) -> None:
        result = self.analyzer.analyze("https://example.com")
        assert result.raw_input == "https://example.com"
