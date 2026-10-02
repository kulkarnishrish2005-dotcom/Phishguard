"""Smoke tests — verify all packages are importable."""

from __future__ import annotations

import importlib

import pytest

_PACKAGES = [
    "phishguard",
    "phishguard.config",
    "phishguard.logging",
    "phishguard.types",
    "backend",
    "ml",
    "ml.data",
    "ml.features",
    "ml.models",
    "ml.training",
    "ml.inference",
    "services",
    "services.base",
    "services.url_analyzer",
    "services.url_analyzer.analyzer",
    "services.nlp",
    "services.ocr",
    "services.qr",
    "evaluation",
]


@pytest.mark.parametrize("package", _PACKAGES)
def test_import(package: str) -> None:
    importlib.import_module(package)
