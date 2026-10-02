"""Tests for URL inference engine."""

import pytest
from ml.inference.url_inference import URLInferenceEngine, analyze_url
from phishguard.types import ThreatLevel


class TestURLInference:
    @pytest.fixture
    def engine(self):
        return URLInferenceEngine()

    def test_engine_initialization(self, engine):
        assert engine.is_model_available("random_forest")
        assert engine.is_model_available("logistic_regression")
        assert engine.is_model_available("xgboost")

    def test_predict_benign_url(self, engine):
        pred = engine.predict("https://www.google.com/search?q=security")
        assert pred.url == "https://www.google.com/search?q=security"
        assert 0.0 <= pred.probability <= 1.0
        assert len(pred.features) == 42
        assert len(pred.feature_vector) == 42
        assert isinstance(pred.threat_level, ThreatLevel)

    def test_predict_phishing_url(self, engine):
        url = "http://login.paypal.account-verify.update.evil.com:8080/signin?token=xyz@bad"
        pred = engine.predict(url, model_name="random_forest")
        assert pred.url == url
        assert len(pred.features) == 42
        assert pred.features["has_suspicious_keyword"] == 1
        assert pred.features["has_port"] == 1
        assert pred.features["has_at_sign"] == 1

    def test_analyze_url_convenience_function(self):
        pred = analyze_url("https://github.com/torvalds/linux")
        assert pred.url == "https://github.com/torvalds/linux"
        assert 0.0 <= pred.probability <= 1.0

    def test_malformed_url_handling(self, engine):
        # Must never raise exception on garbage / malformed input
        pred = engine.predict("not-a-valid-url-at-all!@@#$%^&*()")
        assert pred is not None
        assert 0.0 <= pred.probability <= 1.0
        assert len(pred.features) == 42
