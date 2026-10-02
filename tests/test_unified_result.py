"""Tests for unified analysis result serialization."""

import pytest
from ml.inference.risk_engine import evaluate_risk
from ml.inference.url_inference import analyze_url
from phishguard.unified_result import UnifiedAnalysisResult
from services.nlp.text_detector import analyze_text
from services.ocr.ocr_service import analyze_screenshot
from PIL import Image


def test_unified_result_from_url():
    url = "https://example.com"
    pred = analyze_url(url)
    risk = evaluate_risk(pred.features, pred.probability, pred.model_name)
    unified = UnifiedAnalysisResult.from_url_prediction(pred, risk)

    d = unified.to_dict()
    assert d["input_type"] == "url"
    assert d["verdict"] in ["SAFE", "SUSPICIOUS", "PHISHING"]
    assert 0 <= d["risk_score"] <= 100
    assert d["model_probability"] is not None
    assert isinstance(d["evidence"], list)
    assert "details" in d
    assert "timestamp" in d


def test_unified_result_from_text():
    text_res = analyze_text("Subject: Meeting Notes\n\nLet's meet tomorrow.")
    unified = UnifiedAnalysisResult.from_text_result(text_res)

    d = unified.to_dict()
    assert d["input_type"] == "email"
    assert d["verdict"] == "SAFE"
    assert 0 <= d["risk_score"] <= 100
    assert "details" in d


def test_unified_result_from_screenshot():
    img = Image.new("RGB", (100, 50), color=(200, 200, 200))
    screen_res = analyze_screenshot(img)
    unified = UnifiedAnalysisResult.from_screenshot_result(screen_res)

    d = unified.to_dict()
    assert d["input_type"] == "screenshot"
    assert 0 <= d["risk_score"] <= 100
    assert "details" in d
