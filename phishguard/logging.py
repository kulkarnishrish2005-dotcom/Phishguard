"""Structured logging setup for PhishGuard."""

import logging
import sys


def setup_logging(level: str = "INFO") -> None:
    """Configure the root ``phishguard`` logger.

    Parameters
    ----------
    level:
        A Python log-level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(formatter)

    logger = logging.getLogger("phishguard")
    logger.setLevel(numeric_level)
    # Avoid duplicate handlers when called more than once.
    if not logger.handlers:
        logger.addHandler(handler)
