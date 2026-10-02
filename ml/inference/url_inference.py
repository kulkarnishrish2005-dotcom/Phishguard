"""URL inference module for PhishGuard.

Takes a URL string, extracts 42 deterministic features via Phase 1B extractor,
and runs the specified ML model (Logistic Regression, Random Forest, or XGBoost).
The URL is NEVER fetched, resolved, or connected to over the network.
"""

from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import joblib
import pandas as pd

from ml.features.schema import FEATURE_NAMES
from ml.features.url_features import URLFeatureExtractor
from phishguard.types import ThreatLevel

logger = logging.getLogger(__name__)

DEFAULT_MODEL_DIR = Path(__file__).resolve().parent.parent / "models"


@dataclass
class URLModelPrediction:
    """Output of URL ML inference."""

    url: str
    model_name: str
    is_phishing: bool
    probability: float  # 0.0 to 1.0 probability of phishing
    features: dict[str, Any]
    feature_vector: list[int | float]
    threat_level: ThreatLevel = field(init=False)

    def __post_init__(self) -> None:
        if self.probability >= 0.70:
            self.threat_level = ThreatLevel.PHISHING
        elif self.probability >= 0.40:
            self.threat_level = ThreatLevel.SUSPICIOUS
        else:
            self.threat_level = ThreatLevel.SAFE


class URLInferenceEngine:
    """Offline ML inference engine for URLs using 42-feature extraction."""

    def __init__(
        self,
        model_name: Literal["random_forest", "xgboost", "logistic_regression"] = "random_forest",
        model_dir: Path | str | None = None,
    ) -> None:
        self.model_dir = Path(model_dir) if model_dir else DEFAULT_MODEL_DIR
        self.model_name = model_name
        self.feature_extractor = URLFeatureExtractor()
        self._models: dict[str, Any] = {}
        self._load_models()

    def _load_models(self) -> None:
        """Load available serialized models from disk."""
        model_files = {
            "logistic_regression": self.model_dir / "lr_phishguard.pkl",
            "random_forest": self.model_dir / "rf_phishguard.pkl",
            "xgboost": self.model_dir / "xgb_phishguard.pkl",
        }

        for name, path in model_files.items():
            if path.exists():
                try:
                    self._models[name] = joblib.load(path)
                    logger.info("Loaded model '%s' from %s", name, path)
                except Exception as e:
                    logger.warning("Failed to load model '%s': %s", name, e)
            else:
                logger.warning("Model file not found: %s", path)

    def is_model_available(self, model_name: str | None = None) -> bool:
        """Check if requested model is loaded."""
        target = model_name or self.model_name
        return target in self._models

    def predict(
        self,
        url: str,
        model_name: Literal["random_forest", "xgboost", "logistic_regression"] | None = None,
    ) -> URLModelPrediction:
        """Extract 42 features and predict phishing probability.

        Parameters
        ----------
        url : str
            The raw URL to analyse (never requested over network).
        model_name : str, optional
            Which trained model to use. Defaults to initialised model.

        Returns
        -------
        URLModelPrediction
            Structured prediction containing probability, verdict, and extracted features.
        """
        chosen_model = model_name or self.model_name

        # Extract features deterministically
        record = self.feature_extractor.extract(url)
        vector = record.feature_vector()
        feature_dict = record.features

        if chosen_model not in self._models:
            # Fallback heuristic calculation if model file is missing
            logger.warning("Model '%s' not found. Falling back to heuristic probability.", chosen_model)
            prob = self._heuristic_probability(feature_dict)
            is_phish = prob >= 0.5
            return URLModelPrediction(
                url=url,
                model_name=f"{chosen_model} (fallback-heuristic)",
                is_phishing=is_phish,
                probability=prob,
                features=feature_dict,
                feature_vector=vector,
            )

        model = self._models[chosen_model]
        # Use DataFrame with feature names to ensure alignment and silence scikit-learn warnings
        df_row = pd.DataFrame([[feature_dict.get(col, 0) for col in FEATURE_NAMES]], columns=list(FEATURE_NAMES))

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                if hasattr(model, "predict_proba"):
                    probs = model.predict_proba(df_row)[0]
                    # Class 1 is phishing
                    phish_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
                else:
                    pred = model.predict(df_row)[0]
                    phish_prob = float(pred)
        except Exception as e:
            logger.error("Inference failed for %s: %s", chosen_model, e)
            phish_prob = self._heuristic_probability(feature_dict)

        is_phishing = phish_prob >= 0.5

        return URLModelPrediction(
            url=url,
            model_name=chosen_model,
            is_phishing=is_phishing,
            probability=round(phish_prob, 4),
            features=feature_dict,
            feature_vector=vector,
        )

    def _heuristic_probability(self, features: dict[str, Any]) -> float:
        """Lightweight heuristic score if model is not yet loaded."""
        score = 0.0
        if features.get("is_ip_host", False):
            score += 0.35
        if features.get("is_punycode", False):
            score += 0.30
        if features.get("has_at_sign", False):
            score += 0.25
        if features.get("has_suspicious_keyword", False):
            score += 0.20
        if features.get("has_double_slash_redirect", False):
            score += 0.20
        if features.get("subdomain_count", 0) > 2:
            score += 0.15
        if features.get("hostname_entropy", 0.0) > 3.8:
            score += 0.15
        if features.get("has_shortener_pattern", False):
            score += 0.10
        if features.get("digit_ratio", 0.0) > 0.2:
            score += 0.10
        return min(max(score, 0.05), 0.95)


def analyze_url(
    url: str,
    model_name: Literal["random_forest", "xgboost", "logistic_regression"] = "random_forest",
) -> URLModelPrediction:
    """Convenience functional interface for URL prediction."""
    engine = URLInferenceEngine(model_name=model_name)
    return engine.predict(url)
