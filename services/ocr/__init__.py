"""Screenshot and OCR analysis exports for PhishGuard."""

from .ocr_service import ScreenshotAnalysisResult, ScreenshotOCRAnalyzer, analyze_screenshot

__all__ = [
    "ScreenshotAnalysisResult",
    "ScreenshotOCRAnalyzer",
    "analyze_screenshot",
]
