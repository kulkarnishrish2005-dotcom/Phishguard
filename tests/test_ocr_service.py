"""Tests for screenshot OCR analysis service."""

from pathlib import Path
from PIL import Image, ImageDraw
import pytest

from phishguard.types import ThreatLevel
from services.ocr.ocr_service import ScreenshotOCRAnalyzer, analyze_screenshot


class TestScreenshotOCR:
    @pytest.fixture
    def analyzer(self):
        return ScreenshotOCRAnalyzer()

    @pytest.fixture
    def sample_image(self):
        img = Image.new("RGB", (300, 100), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.text((10, 10), "Security Alert: Verify your account", fill=(0, 0, 0))
        return img

    def test_analyzer_initialization(self, analyzer):
        assert analyzer.service_name == "screenshot_ocr_service"

    def test_validate_input(self, analyzer, sample_image):
        assert analyzer.validate_input(sample_image) is True
        assert analyzer.validate_input(12345) is False

    def test_analyze_screenshot_pil(self, analyzer, sample_image):
        res = analyzer.analyze_screenshot(sample_image, source_label="test_image")
        assert res.image_source == "test_image"
        assert 0 <= res.risk_score <= 100
        assert isinstance(res.threat_level, ThreatLevel)
        assert len(res.evidence) >= 1

    def test_analyze_screenshot_convenience_function(self, sample_image):
        res = analyze_screenshot(sample_image)
        assert res is not None
        assert res.risk_score >= 0
