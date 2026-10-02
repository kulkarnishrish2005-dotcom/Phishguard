"""Tests for text / email NLP phishing detector."""

import pytest
from phishguard.types import ThreatLevel
from services.nlp.text_detector import TextPhishingDetector, analyze_text


class TestTextPhishingDetector:
    @pytest.fixture
    def detector(self):
        return TextPhishingDetector()

    def test_benign_text(self, detector):
        text = "Hi Sarah, please find the quarterly sprint report attached for your review. Thanks!"
        res = detector.detect(text)
        assert res.threat_level == ThreatLevel.SAFE
        assert not res.is_phishing
        assert res.risk_score < 30

    def test_phishing_email_with_urgency_and_credentials(self, detector):
        text = (
            "URGENT: Your account has been temporarily suspended due to suspicious activity. "
            "Action required within 24 hours to prevent permanent deletion. "
            "Please confirm your password and identity here: http://login.evil-verify.com/auth"
        )
        res = detector.detect(text)
        assert res.threat_level == ThreatLevel.PHISHING
        assert res.is_phishing
        assert res.risk_score >= 60
        assert len(res.found_urls) == 1
        assert "http://login.evil-verify.com/auth" in res.found_urls
        assert res.urgency_score > 0
        assert res.credential_harvesting_score > 0

    def test_empty_or_whitespace_text(self, detector):
        res1 = detector.detect("")
        assert res1.risk_score == 0
        assert res1.threat_level == ThreatLevel.SAFE

        res2 = detector.detect("   \n\t   ")
        assert res2.risk_score == 0

    def test_regression_prize_lure_score_above_20(self):
        """Regression: prize-lure text must score >= 20 after pattern fixes."""
        res = analyze_text("Winner! You won a $1000 prize bonus gift card! Click here now.")
        assert res.risk_score >= 20
        assert res.financial_lure_score > 0
        assert res.credential_harvesting_score > 0
        descriptions = [e.description for e in res.evidence]
        assert any("Prize" in d or "lure" in d.lower() for d in descriptions)

    def test_convenience_function(self):
        res = analyze_text("Winner! You won a $1000 prize bonus gift card! Click here now.")
        assert res.risk_score >= 20
        assert res.financial_lure_score > 0
        assert res.risk_score >= 10
