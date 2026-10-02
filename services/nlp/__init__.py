"""NLP and text phishing analysis exports for PhishGuard."""

from .text_detector import TextAnalysisResult, TextPhishingDetector, analyze_text

__all__ = [
    "TextAnalysisResult",
    "TextPhishingDetector",
    "analyze_text",
]
