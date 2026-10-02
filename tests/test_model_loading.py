"""Tests for ML model loading and schema consistency."""

import json
from pathlib import Path
import joblib
import pytest


def test_model_files_exist():
    model_dir = Path("ml/models")
    assert (model_dir / "lr_phishguard.pkl").exists()
    assert (model_dir / "rf_phishguard.pkl").exists()
    assert (model_dir / "xgb_phishguard.pkl").exists()
    assert (model_dir / "schema.json").exists()
    assert (model_dir / "class_info.json").exists()


def test_model_loading_and_prediction():
    model_dir = Path("ml/models")
    lr = joblib.load(model_dir / "lr_phishguard.pkl")
    rf = joblib.load(model_dir / "rf_phishguard.pkl")
    xgb = joblib.load(model_dir / "xgb_phishguard.pkl")

    assert hasattr(lr, "predict")
    assert hasattr(rf, "predict")
    assert hasattr(xgb, "predict")


def test_schema_json_contains_42_features():
    schema_path = Path("ml/models/schema.json")
    with open(schema_path, "r") as f:
        schema = json.load(f)

    assert schema["schema_version"] == "1.0.0"
    assert schema["feature_count"] == 42
    assert len(schema["feature_names"]) == 42
    assert schema["categories"]["lexical"] == 14
    assert schema["categories"]["structural"] == 10
    assert schema["categories"]["obfuscation"] == 11
    assert schema["categories"]["domain"] == 7
