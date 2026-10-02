"""Screenshot and image OCR analysis service for PhishGuard.

Extracts text from screenshots using local OCR engines (pytesseract or easyocr if available,
with graceful fallback and diagnostic reporting), then pipes extracted text and any discovered
URLs into the NLP detector and URL inference engine.

Pipeline:
Image → Local OCR → Extracted Text → Text Phishing Analysis (+ URL analysis if URLs found) → Evidence & Verdict
"""

from __future__ import annotations

import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image

from ml.inference.risk_engine import evaluate_risk
from ml.inference.url_inference import analyze_url
from phishguard.types import Evidence, InputType, ThreatLevel
from services.base import AnalysisService
from services.nlp.text_detector import TextAnalysisResult, TextPhishingDetector

logger = logging.getLogger(__name__)


@dataclass
class ScreenshotAnalysisResult:
    """Structured output of screenshot / image OCR analysis."""

    image_source: str
    ocr_engine_used: str
    extracted_text: str
    extracted_urls: list[str] = field(default_factory=list)
    risk_score: int = 0  # 0 to 100
    threat_level: ThreatLevel = ThreatLevel.SAFE
    is_phishing: bool = False
    evidence: list[Evidence] = field(default_factory=list)
    text_analysis: TextAnalysisResult | None = None
    url_analyses: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""


class ScreenshotOCRAnalyzer(AnalysisService):
    """Local OCR screenshot analysis service."""

    def __init__(self) -> None:
        super().__init__()
        self.nlp_detector = TextPhishingDetector()
        self._check_ocr_engines()

    def _check_ocr_engines(self) -> None:
        """Inspect available OCR backends."""
        self.has_pytesseract = False
        self.has_easyocr = False

        try:
            import pytesseract  # noqa: F401
            self.has_pytesseract = True
        except ImportError:
            pass

        try:
            import easyocr  # noqa: F401
            self.has_easyocr = True
        except ImportError:
            pass

    @property
    def service_name(self) -> str:
        return "screenshot_ocr_service"

    def validate_input(self, input_data: Any) -> bool:
        """Accept image paths, bytes, or PIL Images."""
        if isinstance(input_data, (str, Path)):
            return Path(input_data).exists()
        if isinstance(input_data, (bytes, Image.Image)):
            return True
        return False

    def analyze(self, input_data: Any) -> Any:
        """Standard AnalysisService interface."""
        result = self.analyze_screenshot(input_data)
        from phishguard.types import AnalysisResult

        return AnalysisResult(
            input_type=InputType.SCREENSHOT,
            threat_level=result.threat_level,
            risk_score=result.risk_score / 100.0,
            evidence=result.evidence,
            raw_input=str(result.image_source),
        )

    def extract_text_from_image(self, image_input: str | Path | bytes | Image.Image) -> tuple[str, str]:
        """Perform local OCR on an image.

        Returns
        -------
        tuple[str, str]
            (extracted_text, ocr_engine_name)
        """
        # 1. Load PIL Image
        pil_img: Image.Image
        if isinstance(image_input, (str, Path)):
            pil_img = Image.open(str(image_input))
        elif isinstance(image_input, bytes):
            pil_img = Image.open(io.BytesIO(image_input))
        elif isinstance(image_input, Image.Image):
            pil_img = image_input
        else:
            raise TypeError(f"Unsupported image type: {type(image_input)}")

        # 2. Try pytesseract first
        if self.has_pytesseract:
            try:
                import pytesseract
                text = pytesseract.image_to_string(pil_img)
                if text.strip():
                    return text.strip(), "pytesseract"
            except Exception as e:
                logger.debug("pytesseract failed or binary not found: %s", e)

        # 3. Try easyocr next
        if self.has_easyocr:
            try:
                import numpy as np
                import easyocr
                reader = easyocr.Reader(["en"], verbose=False)
                img_array = np.array(pil_img)
                results = reader.readtext(img_array)
                extracted_lines = [res[1] for res in results]
                text = "\n".join(extracted_lines)
                if text.strip():
                    return text.strip(), "easyocr"
            except Exception as e:
                logger.debug("easyocr extraction failed: %s", e)

        # 4. Fallback: Local image metadata and visual property inspection
        width, height = pil_img.size
        mode = pil_img.mode
        return (
            f"[OCR Note: External OCR binary not in PATH. Image properties: {width}x{height}px, Mode: {mode}. "
            "Please paste screenshot text or install Tesseract OCR for automated character extraction.]",
            "metadata_fallback",
        )

    def analyze_screenshot(
        self,
        image_input: str | Path | bytes | Image.Image,
        source_label: str = "uploaded_image",
    ) -> ScreenshotAnalysisResult:
        """Extract text from screenshot and evaluate phishing risk."""
        extracted_text, engine_used = self.extract_text_from_image(image_input)

        evidence: list[Evidence] = []
        evidence.append(
            Evidence(
                indicator="ocr_extraction",
                description=f"Extracted image text using local engine '{engine_used}' ({len(extracted_text)} chars)",
                weight=0.0,
            )
        )

        # Run text NLP analysis
        text_result = self.nlp_detector.detect(extracted_text)
        evidence.extend(text_result.evidence)

        # Extract URLs
        url_regex = re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s]*)?", re.IGNORECASE)
        found_urls = url_regex.findall(extracted_text)

        url_analyses: list[dict[str, Any]] = []
        url_max_risk = 0

        for url in found_urls:
            pred = analyze_url(url)
            risk = evaluate_risk(pred.features, pred.probability, pred.model_name)
            url_analyses.append({
                "url": url,
                "is_phishing": pred.is_phishing,
                "model_prob": pred.probability,
                "risk_score": risk.risk_score,
                "verdict": risk.verdict,
            })
            url_max_risk = max(url_max_risk, risk.risk_score)
            evidence.append(
                Evidence(
                    indicator="embedded_screenshot_url",
                    description=f"URL detected in screenshot: {url} (Risk: {risk.risk_score}/100, Verdict: {risk.verdict})",
                    weight=min(risk.risk_score / 100.0 * 0.35, 0.35),
                )
            )

        # Combined risk: max of text risk and URL risk, plus fusion boost if both are elevated
        composite_risk = max(text_result.risk_score, url_max_risk)
        if text_result.risk_score >= 40 and url_max_risk >= 40:
            composite_risk = min(composite_risk + 15, 100)
            evidence.append(
                Evidence(
                    indicator="multimodal_phishing_correlation",
                    description="Severe threat: Corroborating phishing signals detected across both screenshot text and embedded URLs",
                    weight=0.30,
                )
            )

        if composite_risk >= 60:
            threat_level = ThreatLevel.PHISHING
            is_phishing = True
            summary = f"Phishing Threat Detected ({composite_risk}/100) in screenshot."
        elif composite_risk >= 30:
            threat_level = ThreatLevel.SUSPICIOUS
            is_phishing = False
            summary = f"Suspicious Content Detected ({composite_risk}/100) in screenshot."
        else:
            threat_level = ThreatLevel.SAFE
            is_phishing = False
            summary = f"Safe ({composite_risk}/100): No phishing signatures found in screenshot."

        return ScreenshotAnalysisResult(
            image_source=str(source_label),
            ocr_engine_used=engine_used,
            extracted_text=extracted_text,
            extracted_urls=found_urls,
            risk_score=composite_risk,
            threat_level=threat_level,
            is_phishing=is_phishing,
            evidence=evidence,
            text_analysis=text_result,
            url_analyses=url_analyses,
            summary=summary,
        )


def analyze_screenshot(image_input: str | Path | bytes | Image.Image, source_label: str = "image") -> ScreenshotAnalysisResult:
    """Convenience helper for screenshot OCR analysis."""
    service = ScreenshotOCRAnalyzer()
    return service.analyze_screenshot(image_input, source_label=source_label)
