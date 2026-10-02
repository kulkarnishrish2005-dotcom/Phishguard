"""Tests for evidence-based risk scoring engine."""

import pytest
from ml.inference.risk_engine import RiskEngine, RiskLevel, evaluate_risk
from phishguard.types import Evidence


class TestRiskEngine:
    @pytest.fixture
    def engine(self):
        return RiskEngine()

    def test_safe_url_evaluation(self, engine):
        clean_features = {
            "is_ip_host": False,
            "is_punycode": False,
            "has_at_sign": False,
            "has_suspicious_keyword": False,
            "suspicious_keyword_count": 0,
            "subdomain_count": 0,
            "hostname_entropy": 2.5,
            "url_length": 35,
        }
        assessment = engine.evaluate_url(clean_features, model_probability=0.05, model_name="Random Forest")
        assert 0 <= assessment.risk_score <= 100
        assert assessment.risk_level == RiskLevel.LOW
        assert assessment.verdict == "SAFE"
        assert len(assessment.evidence) >= 1

    def test_phishing_url_evaluation(self, engine):
        malicious_features = {
            "is_ip_host": True,
            "is_punycode": True,
            "has_at_sign": True,
            "has_double_slash_redirect": True,
            "has_suspicious_keyword": True,
            "suspicious_keyword_count": 4,
            "subdomain_count": 4,
            "hostname_entropy": 4.5,
            "url_length": 150,
            "domain_has_hyphen": True,
            "has_port": True,
        }
        assessment = engine.evaluate_url(malicious_features, model_probability=0.92, model_name="XGBoost")
        assert assessment.risk_score >= 65
        assert assessment.risk_level == RiskLevel.HIGH
        assert assessment.verdict == "PHISHING"
        assert len(assessment.evidence) >= 4

        # Verify evidence weights and descriptions
        indicators = [e.indicator for e in assessment.evidence]
        assert "ip_address_host" in indicators
        assert "punycode_idn" in indicators
        assert "at_symbol_redirect" in indicators
        assert "ml_high_confidence" in indicators

    def test_convenience_function(self):
        res = evaluate_risk({"is_ip_host": False}, model_probability=0.1)
        assert res.risk_score < 35
        assert res.verdict == "SAFE"
