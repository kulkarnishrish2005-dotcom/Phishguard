# PhishGuard Dataset Ingestion Pipeline — Usage Guide

**Version:** 1.0  
**Date:** 2026-08-29  
**Status:** Phase 1A Complete

---

## Overview

The PhishGuard dataset ingestion pipeline transforms raw phishing and benign URL datasets into clean, reproducible training/validation/test splits with comprehensive leakage controls and provenance tracking.

**Key Features:**
- Domain-aware splitting (prevents domain leakage across splits)
- Temporal test sets (newer campaigns reserved for evaluation)
- Three-tier deduplication (exact, near-duplicate, domain clustering)
- Class balancing with benign sample archiving
- Comprehensive manifest generation for full reproducibility

---

## Quick Start

### Prerequisites

- Python 3.11+
- PhishGuard installed with dependencies (`pip install -r requirements.txt`)
- Raw dataset files (PhishTank CSV, Tranco CSV)

### Basic Usage

```bash
python -m ml.data.cli_ingest \
    --phishtank data/raw/verified_online.csv \
    --tranco data/raw/top-1m.csv \
    --output data/processed \
    --phishtank-version "2026-08-29" \
    --tranco-list-id "X9QZL"
```

### Output Files

The pipeline generates:
- `train.jsonl` — Training set (1:4 phishing:benign ratio)
- `val.jsonl` — Validation set (natural distribution)
- `test.jsonl` — Test set (natural distribution, temporally newer)
- `archive.jsonl` — Unused benign samples (reserved for future use)
- `manifest.json` — Complete provenance and reproducibility metadata

---

## Dataset Sources

### PhishTank (Phishing URLs)

**Source:** https://www.phishtank.com/developer_info.php  
**License:** Free for research and non-commercial use with attribution  
**Format:** CSV with columns: `phish_id`, `url`, `verified`, `verification_time`, `target`, etc.

**Obtaining the data:**
1. Visit https://www.phishtank.com/developer_info.php
2. Download "verified_online.csv" (no API key required)
3. Place in `data/raw/`

**What we use:**
- Only verified phishing URLs (`verified=yes`)
- Verification timestamp for temporal splitting
- Target brand metadata

### Tranco (Benign Domains)

**Source:** https://tranco-list.eu/  
**License:** Free for research and commercial use  
**Format:** CSV with columns: `rank`, `domain`

**Obtaining the data:**
1. Visit https://tranco-list.eu/
2. Download a recent top-1M list
3. Note the list ID (e.g., "X9QZL") and date
4. Place in `data/raw/`

**What we use:**
- Top-ranked domains (distant supervision: assumed benign)
- List date as timestamp for temporal metadata

---

## URL Normalization Rules

All URLs undergo deterministic normalization while preserving security-relevant signals:

1. **Scheme Addition:** Add `https://` if missing
2. **Case Normalization:** Lowercase scheme and hostname only (preserve path case)
3. **www. Removal:** Strip `www.` prefix from hostname
4. **Default Port Removal:** Remove port 80 (HTTP) and 443 (HTTPS)
5. **Fragment Removal:** Strip `#fragment` identifiers
6. **Query Parameter Sorting:** Alphabetically sort `?key=value` pairs
7. **Trailing Slash Removal:** Remove trailing `/` except for root path

**Example:**
```
Input:  HTTP://WWW.EXAMPLE.COM:80/Path/?z=1&a=2#section
Output: http://example.com/Path?a=2&z=1
```

**What is preserved:**
- Path case (security signal: `Login` vs `login`)
- Non-default ports (common in phishing)
- All query parameters and their values
- Subdomain structure

---

## Leakage Controls

### Three-Tier Deduplication

**Tier 1: Exact Duplicates**
- SHA256 hash of normalized URL
- Conflicting labels (same URL, different labels) are discarded as label noise
- Identical duplicates: keep earliest, most confident sample

**Tier 2: Near-Duplicate Campaign Detection**
- Structural fingerprint: `domain || path_structure || query_param_keys`
- Detects automated phishing campaigns (same pattern, different parameter values)
- Subsample phishing campaigns to 10 representative samples per fingerprint
- Benign URLs are NOT subsampled (preserve ranking diversity)

**Tier 3: Domain Clustering**
- Extract registrable domain (eTLD+1) using public suffix list
- Group subdomains: `login.evil.com` and `secure.evil.com` → `evil.com`
- All URLs from the same domain assigned to the same split

### Domain-Aware Splitting

**Process:**
1. Group all samples by registrable domain
2. Compute median timestamp for each domain cluster
3. Sort domains by median timestamp (oldest → newest)
4. Allocate entire domain clusters to splits in temporal order:
   - Oldest 70% of samples → training
   - Next 15% → validation
   - Newest 15% → test

**Validation Checks:**
- No exact URL duplicates across splits
- No domain spans multiple splits
- Test set temporally newer than training set (when timestamps available)

---

## Dataset Splitting Strategy

### Split Ratios

- **Training:** 70% of total samples
- **Validation:** 15% of total samples
- **Test:** 15% of total samples

### Temporal Ordering

Domain clusters are sorted by their median verification/publication timestamp:
- **Training:** Oldest phishing campaigns and established benign domains
- **Test:** Newest phishing campaigns (simulates zero-day evaluation)

This ensures models are evaluated on future/unseen attack patterns rather than memorizing historical campaigns.

### Determinism

All operations are deterministic:
- Random seed: `42` (configurable)
- Campaign subsampling uses seeded random selection
- Benign undersampling uses seeded shuffling

Running the pipeline twice with the same inputs and seed produces identical outputs.

---

## Class Imbalance Handling

### Training Set Balance (1:4 Ratio)

- **Target:** 20% phishing, 80% benign
- **Method:** Undersample majority (benign) class via random selection (seeded)
- **Rationale:** Reflects realistic phishing prevalence while providing sufficient benign examples

### Validation and Test Sets (Natural Distribution)

- **No artificial balancing applied**
- Preserves natural class imbalance from sources
- Provides realistic performance estimates

### Benign Sample Archiving

Excess benign samples removed during training balancing are saved to `archive.jsonl` with `split="archive"`.

**Use cases for archived samples:**
- Hard negative mining after initial training
- Rebalancing for different ratios
- Augmentation for subsequent training rounds

Nothing is permanently discarded.

---

## Dataset Manifest

Every pipeline run generates `manifest.json` documenting:

### Source Metadata (per source)
- Source name, type, and URL
- Retrieval timestamp
- Version/list ID
- File format and license
- Label definition and usage terms
- Raw file path and SHA256 hash
- Sample counts at each pipeline stage

### Pipeline Metadata
- Manifest version and creation timestamp
- Pipeline version and random seed
- Preprocessing statistics (duplicates removed, conflicts discarded)
- Split metadata (sample counts, class ratios, unique domains, temporal ranges)
- Leakage validation results
- Class balance configuration
- Quality check statistics

### Reproducibility

The manifest enables:
1. **Verification:** Confirm dataset integrity via SHA256 hashes
2. **Attribution:** Track data sources and licenses
3. **Debugging:** Identify sample filtering at each stage
4. **Replication:** Reproduce exact splits using documented seed and configuration

---

## CLI Reference

### Command

```bash
python -m ml.data.cli_ingest [OPTIONS]
```

### Required Arguments

- `--phishtank PATH` — Path to PhishTank CSV file
- `--tranco PATH` — Path to Tranco CSV file

### Optional Arguments

- `--output PATH` — Output directory (default: `data/processed`)
- `--phishtank-version STR` — PhishTank version ID (e.g., "2026-08-29")
- `--tranco-list-id STR` — Tranco list ID (e.g., "X9QZL")
- `--tranco-list-date STR` — Tranco list date (ISO 8601: "2026-08-28")

### Environment Variables

Configure via `.env` or environment:

```bash
PHISHGUARD_DATA_DIR=./data
PHISHGUARD_LOG_LEVEL=INFO
```

### Example

```bash
python -m ml.data.cli_ingest \
    --phishtank data/raw/phishtank_verified_2026-08-29.csv \
    --tranco data/raw/tranco_X9QZL_2026-08-28.csv \
    --output data/processed/run_2026-08-29 \
    --phishtank-version "2026-08-29" \
    --tranco-list-id "X9QZL" \
    --tranco-list-date "2026-08-28"
```

---

## Limitations and Known Issues

### Current Limitations

1. **No automatic dataset download**
   - Datasets must be manually obtained and placed in `data/raw/`
   - Prevents accidental bandwidth usage and ensures license compliance

2. **Benign label distant supervision**
   - Tranco domains are assumed benign based on popularity ranking
   - High-traffic sites can host phishing on compromised subpages
   - Some legitimate subdomains may be weaponized

3. **Temporal test isolation not guaranteed**
   - Domain clusters may contain samples spanning wide time ranges
   - Test set median is newer, but individual samples may overlap training temporally
   - Domain-level grouping takes precedence over sample-level temporal isolation

4. **English-only**
   - No internationalized domain name (IDN) normalization beyond basic RFC handling
   - No language-specific URL pattern detection

5. **Single-machine processing**
   - No distributed/parallel processing support
   - Large datasets (>10M samples) may require significant RAM

### Future Enhancements

- Streaming ingestion for incremental updates
- Configurable split ratios and class balance targets
- Support for additional phishing sources (PhishStats, OpenPhish)
- Email/text dataset ingestion (Phase 1B)
- Hard negative mining integration
- Multi-language support

---

## Troubleshooting

### FileNotFoundError

**Issue:** `PhishTank file not found: data/raw/verified_online.csv`

**Solution:** 
- Verify file exists at the specified path
- Use absolute paths if relative paths fail
- Check file permissions

### Memory Issues

**Issue:** Pipeline crashes with `MemoryError` on large datasets

**Solution:**
- Process datasets incrementally (split PhishTank/Tranco into chunks)
- Reduce Tranco list size (use top 100K instead of top 1M)
- Increase system swap space

### Label Noise

**Issue:** Warning: `Label conflict for hash abc123`

**Explanation:**
- Same normalized URL appears with both "phishing" and "benign" labels
- Could indicate data quality issues or legitimate URL repurposing
- These samples are discarded to prevent training on noisy labels

**Action:** Review source data quality if conflicts exceed 1% of dataset

### Validation Errors

**Issue:** High number of `invalid_url` validation errors

**Solution:**
- Check raw CSV format matches expected schema
- Verify URL column contains actual URLs (not empty/malformed)
- Inspect first 10 rejected samples via debug logging (`PHISHGUARD_LOG_LEVEL=DEBUG`)

---

## References

- [Dataset Pipeline Design](dataset_pipeline_design.md) — Technical specification
- [PhishTank Developer Info](https://www.phishtank.com/developer_info.php)
- [Tranco List](https://tranco-list.eu/)
- [Public Suffix List](https://publicsuffix.org/)

---

**Document Status:** Complete  
**Last Updated:** 2026-08-29  
**Author:** PhishGuard Development Team
