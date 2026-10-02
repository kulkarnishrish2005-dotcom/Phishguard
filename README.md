# PhishGuard

**AI-powered phishing intelligence platform.**

PhishGuard is a modular detection engine for identifying phishing threats across URLs, emails, screenshots, and QR codes. It combines rule-based heuristics with machine-learning classification to produce structured risk assessments with supporting evidence.

## Current Status — Phase 1: Foundation

The project is in early development. Phase 1 establishes:

- Repository structure and packaging
- Configuration system (environment-variable-driven)
- Service interfaces for URL analysis, NLP, OCR, and QR extraction
- ML pipeline skeleton (data → features → model → inference)
- Evaluation framework interfaces
- Test infrastructure (pytest, mypy, ruff)

**No models, dashboards, APIs, or external integrations are implemented yet.**

## Project Structure

```
phishguard/          # Core package: config, logging, types
backend/             # API server (future)
ml/                  # ML pipeline: data, features, models, training, inference
services/            # Domain services: url_analyzer, nlp, ocr, qr
evaluation/          # Evaluation framework
tests/               # Test suite
data/                # Dataset directories (raw, cleaned, processed)
docs/                # Documentation
scripts/             # Utility scripts
```

## Requirements

- Python 3.11+
- No paid APIs required — runs fully offline

## Setup

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\\Scripts\\activate   # Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy phishguard/ services/ ml/

# Linting
ruff check .
```

## Configuration

PhishGuard reads configuration from environment variables. Copy the example and adjust:

```bash
cp .env.example .env
```

Key variables:

| Variable | Default | Description |
|---|---|---|
| `PHISHGUARD_LOG_LEVEL` | `INFO` | Logging verbosity |
| `PHISHGUARD_DATA_DIR` | `./data` | Root data directory |
| `PHISHGUARD_MODEL_DIR` | `./ml/models/saved` | Trained model storage |

## License

MIT