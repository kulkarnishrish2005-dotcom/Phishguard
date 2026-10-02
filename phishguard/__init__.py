"""PhishGuard — AI-powered phishing intelligence platform."""

from .config import PhishGuardConfig, get_config
from .logging import setup_logging
from .types import AnalysisResult, Evidence, InputType, ThreatLevel
from .unified_result import UnifiedAnalysisResult

__version__ = "0.1.0"

__all__ = [
    "AnalysisResult",
    "Evidence",
    "InputType",
    "PhishGuardConfig",
    "ThreatLevel",
    "UnifiedAnalysisResult",
    "get_config",
    "setup_logging",
]
