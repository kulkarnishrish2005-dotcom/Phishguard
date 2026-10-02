# Dataset Ingestion and Evaluation Pipeline — Technical Design

**Document Version:** 2.0  
**Date:** 2026-08-29  
**Status:** Revised — Pending Approval

---

## Table of Contents

1. [Overview](#overview)
2. [Approved Initial Dataset Strategy](#approved-initial-dataset-strategy)
3. [Dataset Sources](#dataset-sources)
4. [Dataset Manifest and Reproducibility](#dataset-manifest-and-reproducibility)
5. [Canonical Schema](#canonical-schema)
6. [Preprocessing Pipeline](#preprocessing-pipeline)
7. [Deduplication Strategy](#deduplication-strategy)
8. [Train/Test Split Strategy](#traintest-split-strategy)
9. [Class Imbalance Handling](#class-imbalance-handling)
10. [Implementation Plan](#implementation-plan)

---

## Overview

This document specifies the technical design for PhishGuard's data ingestion and evaluation pipeline. The pipeline must handle multiple input types (URLs, emails, text) from heterogeneous sources, normalize them into a canonical schema, implement leakage controls, and handle class imbalance appropriately.

**Goals:**

- Unified schema across URL and text/email data
- Reproducible dataset splits with leakage controls implemented and validated
- Transparent data provenance tracking via comprehensive manifests
- Realistic test sets that reflect real-world class distributions
- Balanced training sets to support effective learning
- Support for incremental updates

**Non-goals (Phase 1):**

- Real-time streaming ingestion
- Distributed processing (single-machine only)
- Active learning or online updates
- Multi-language NLP (English-only initially)

---

## Approved Initial Dataset Strategy

Based on project requirements and approved decisions, the initial implementation focuses on URL-based phishing detection with the following strategy:

### Phase 1 Scope: URL Data Only

**Training Data Sources:**
- **PhishTank** — verified phishing URLs (positive class)
- **Tranco** — top-ranked domains as benign URLs (negative class)

**Key Decisions:**

1. **Dataset sizes discovered at runtime:** No hardcoded sample counts. All sizes recorded in dataset manifest.

2. **Training set class balance:** 1:4 phishing:benign ratio
   - Undersample benign class to achieve balance
   - Retain unused benign samples in archive (not permanently discarded)

3. **Test set realism:** Use natural class distribution from sources
   - Do not artificially balance test set
   - Reflects real-world deployment scenario

4. **Domain-aware splitting:** Mandatory
   - All samples from the same registrable domain assigned to the same split
   - Prevents domain leakage between train/test

5. **Temporal ordering:** Use when available
   - PhishTank provides timestamps → newest data in test set
   - Tranco list date used as timestamp proxy
   - Simulates "evaluate on future data" scenario

6. **Leakage prevention:** Multi-layer approach
   - Exact duplicate removal (SHA256 hash)
   - Near-duplicate detection (structural fingerprinting)
   - Domain clustering (no domain spans train/test)
   - Temporal validation (test set temporally isolated)
   - Controls implemented and validated, not guaranteed

### Deferred Components

**Email/text data:**
- Nazario phishing corpus — deferred to Phase 1B
- Enron benign emails — deferred to Phase 1B

**External benchmarks:**
- OpenPhish — deferred pending license confirmation and academic access terms
- May be used later as external generalization benchmark

**Excluded sources:**
- SpamAssassin — excluded from initial phishing dataset (spam ≠ phishing)
- Common Crawl — too heavy for local-only pipeline

### Success Criteria

A successful Phase 1 implementation will:
1. Ingest PhishTank and Tranco data without manual intervention
2. Produce deterministic, reproducible splits given a random seed
3. Generate comprehensive dataset manifest documenting all provenance
4. Export training data with 1:4 class balance
5. Export test data with natural class distribution
6. Validate leakage controls via automated checks
7. Archive unused benign samples for future use

---

## Dataset Sources

### 1. PhishTank (Phishing URLs) — APPROVED FOR PHASE 1

**Source Name:** PhishTank  
**URL:** https://www.phishtank.com/  
**What it provides:** Community-verified phishing URLs  
**Label semantics:** Binary — all entries are phishing (positive class)  
**Expected format:** CSV or JSON dump with columns:
- `phish_id` (unique identifier)
- `url` (full URL)
- `phish_detail_url` (PhishTank entry page)
- `submission_time` (ISO 8601 timestamp)
- `verified` (yes/no)
- `verification_time`
- `online` (yes/no — whether site was still live at verification)
- `target` (brand/entity being impersonated)

**Update/freshness:**
- Daily database exports available
- Verified entries only (filter `verified=yes`)
- Historical data available dating back years

**Licensing/usage:**
- Free for research and non-commercial use
- Attribution required
- Commercial use requires approval

**Potential risks:**
- **Duplicates:** Same URL may be submitted multiple times with different `phish_id`. Normalize URLs before deduplication.
- **Temporal leakage:** Phishing campaigns often reuse similar URL patterns. Must use time-based splits, not random splits.
- **Label drift:** A URL marked "online=yes" may be taken down hours later. Use `verification_time` as ground truth timestamp.
- **Domain clustering:** Many URLs share the same compromised domain. Risk of domain leakage between train/test.

**Normalization strategy:**
- Extract: `phish_id` → `source_id`, `url` → `raw_input`, `verification_time` → `timestamp`, `target` → `metadata.target`
- URL normalization: lowercase, strip fragments, sort query params, decode percent-encoding
- Filter: `verified == "yes"` only
- Deduplicate on normalized URL

---

### 2. Tranco List (Benign URLs) — APPROVED FOR PHASE 1

**Source Name:** Tranco  
**URL:** https://tranco-list.eu/  
**What it provides:** Research-oriented top-ranked domain list (aggregates multiple sources)  
**Label semantics:** Binary — assumed benign (negative class)  
**Expected format:** CSV with columns:
- `rank` (integer, typically 1–1,000,000)
- `domain` (e.g., `example.com`)

**Update/freshness:**
- Daily list updates
- Historical lists available with unique list IDs
- More stable than Alexa (now defunct) or single-source rankings

**Licensing/usage:**
- Free for research and commercial use
- Open methodology
- No restrictions

**Potential risks:**
- **Domain-only data:** Tranco provides domains, not full URLs. Must synthesize full URLs (e.g., `https://example.com/`) or use domains as seeds.
- **Assumption risk:** High-ranking domains are _usually_ benign, but:
  - Compromised legitimate sites (e.g., WordPress sites) can host phishing pages
  - Subdomain abuse (e.g., `phishing.example.com` on a legitimate `example.com`)
- **Label noise:** Some fraction of "benign" samples may be mislabeled
- **Temporal drift:** A domain benign today may be compromised tomorrow

**Normalization strategy:**
- Convert domain to canonical URL: `https://{domain}/`
- Assign `source_id` as `tranco_{list_id}_{rank}`
- Use list publication date as `timestamp`
- Mark as `label=benign`, `metadata.rank={rank}`
- Note in manifest that labels are distant supervision (assumed benign based on popularity)

---

### 3. OpenPhish (Phishing URLs) — DEFERRED

**Status:** Deferred pending license confirmation and academic access terms verification.

**Potential future use:** External generalization benchmark after training on PhishTank.

---

### 4. Enron Email Corpus (Benign Emails) — DEFERRED TO PHASE 1B

**Status:** Email data deferred. Initial implementation focuses on URL data only.

---

### 5. Nazario Phishing Corpus (Phishing Emails) — DEFERRED TO PHASE 1B

**Status:** Email data deferred. Initial implementation focuses on URL data only.

---

### 6. SpamAssassin Public Corpus — EXCLUDED

**Status:** Excluded from initial phishing dataset. Spam ≠ phishing; filtering would introduce noise.

---

### 7. Common Crawl — EXCLUDED

**Status:** Too heavy for local-only pipeline. Requires cloud compute and violates offline-first constraint.

---

### Phase 1 Dataset Summary

| Source | Type | Label | Phase | Rationale |
|--------|------|-------|-------|-----------|
| **PhishTank** | URL | Phishing | **Phase 1** | Verified phishing URLs with timestamps |
| **Tranco** | URL | Benign | **Phase 1** | High-quality benign domains |
| OpenPhish | URL | Phishing | Deferred | Pending license/access confirmation |
| Enron | Email | Benign | Phase 1B | Email data deferred |
| Nazario | Email | Phishing | Phase 1B | Email data deferred |
| SpamAssassin | Email | Mixed | Excluded | Spam ≠ phishing |
| Common Crawl | URL | Benign | Excluded | Too heavy for local pipeline |

---

## Dataset Manifest and Reproducibility

Every dataset snapshot must be fully reproducible and auditable. The pipeline generates comprehensive manifests documenting all aspects of data provenance and processing.

### Dataset Manifest Schema

**Location:** `data/metadata/dataset_manifest_{timestamp}.json`

**Required fields:**

```json
{
  "manifest_version": "1.0",
  "created_at": "2026-08-29T12:00:00Z",
  "pipeline_version": "0.1.0",
  "random_seed": 42,
  
  "sources": [
    {
      "source_name": "phishtank",
      "source_type": "phishing_urls",
      "retrieval_timestamp": "2026-08-29T10:30:00Z",
      "source_url": "https://www.phishtank.com/developer_info.php",
      "version_id": "2026-08-29",
      "format": "csv",
      "license": "Free for research and non-commercial use with attribution",
      "usage_terms": "Commercial use requires approval",
      "label_definition": "Binary: phishing (positive class). All entries verified by community.",
      "raw_file_path": "data/raw/phishtank/verified_online_2026-08-29.csv",
      "raw_file_hash_sha256": "abc123...",
      "samples_ingested": 48237,
      "samples_after_validation": 48103,
      "samples_after_deduplication": 47891
    },
    {
      "source_name": "tranco",
      "source_type": "benign_urls",
      "retrieval_timestamp": "2026-08-29T11:00:00Z",
      "source_url": "https://tranco-list.eu/",
      "version_id": "list_id_XYZ123",
      "list_date": "2026-08-28",
      "format": "csv",
      "license": "Free for research and commercial use",
      "usage_terms": "No restrictions",
      "label_definition": "Binary: benign (negative class). Assumed benign based on popularity ranking. Distant supervision.",
      "raw_file_path": "data/raw/tranco/tranco_XYZ123.csv",
      "raw_file_hash_sha256": "def456...",
      "samples_ingested": 1000000,
      "samples_after_validation": 998745,
      "samples_after_deduplication": 997234
    }
  ],
  
  "preprocessing": {
    "deduplication": {
      "tier1_exact_duplicates_removed": 1453,
      "tier2_near_duplicates_removed": 287,
      "tier3_domain_clusters": 23456,
      "label_conflicts_discarded": 12
    },
    "normalization": {
      "url_normalization_applied": true,
      "email_normalization_applied": false
    }
  },
  
  "splits": {
    "strategy": "temporal_domain_aware",
    "train_ratio": 0.70,
    "val_ratio": 0.15,
    "test_ratio": 0.15,
    "domain_isolation": true,
    "temporal_ordering": true,
    
    "train": {
      "total_samples": 52341,
      "phishing_samples": 10468,
      "benign_samples": 41873,
      "class_ratio_phishing_benign": "1:4.0",
      "unique_domains": 8234,
      "temporal_range": ["2025-01-15", "2026-06-30"],
      "sources": {"phishtank": 10468, "tranco": 41873}
    },
    
    "val": {
      "total_samples": 7821,
      "phishing_samples": 1564,
      "benign_samples": 6257,
      "class_ratio_phishing_benign": "1:4.0",
      "unique_domains": 1823,
      "temporal_range": ["2026-07-01", "2026-07-31"],
      "sources": {"phishtank": 1564, "tranco": 6257}
    },
    
    "test": {
      "total_samples": 15643,
      "phishing_samples": 1234,
      "benign_samples": 14409,
      "class_ratio_phishing_benign": "1:11.7",
      "note": "Natural class distribution preserved for realistic evaluation",
      "unique_domains": 2987,
      "temporal_range": ["2026-08-01", "2026-08-29"],
      "sources": {"phishtank": 1234, "tranco": 14409}
    },
    
    "archive": {
      "benign_reserve_samples": 935495,
      "note": "Unused benign samples retained for future use",
      "file_path": "data/processed/benign_reserve.jsonl"
    }
  },
  
  "leakage_validation": {
    "exact_duplicate_check": "passed",
    "domain_isolation_check": "passed",
    "temporal_isolation_check": "passed",
    "near_duplicate_check": "passed",
    "notes": "Leakage controls implemented and validated through exact, near-duplicate, domain and temporal checks."
  },
  
  "class_balance": {
    "original_phishing_count": 47891,
    "original_benign_count": 997234,
    "original_ratio": "1:20.8",
    "training_target_ratio": "1:4.0",
    "training_undersampling_applied": true,
    "test_set_balanced": false,
    "test_set_note": "Natural distribution preserved"
  },
  
  "quality_checks": {
    "validation_errors": 2139,
    "label_conflicts": 12,
    "malformed_urls": 1876,
    "duplicate_source_ids": 251
  }
}
```

### Reproducibility Guarantees

1. **Deterministic splits:** Given the same random seed and input data, splits are identical
2. **Full provenance:** Every sample traces back to source file, line number, and original ID
3. **Immutable snapshots:** Raw data files preserved with SHA256 hashes
4. **Version tracking:** Pipeline version, dataset version, and manifest schema version recorded
5. **Audit trail:** Ingestion log records every processing decision

### Manifest Usage

**During development:**
- Verify pipeline correctness (sample counts, distributions)
- Debug split issues (domain leakage, temporal ordering)
- Track dataset evolution over time

**During evaluation:**
- Report exact dataset composition in papers/documentation
- Enable reproduction of results by external researchers
- Compare model performance across dataset versions

**For compliance:**
- Document license compliance for each source
- Prove no unauthorized commercial use of restricted data
- Demonstrate proper attribution

---

## Canonical Schema

### Sample Record Schema

Each ingested sample is normalized into the following schema:

```python
@dataclass
class Sample:
    """Canonical representation of a single training/evaluation sample."""
    
    # Identity
    sample_id: str              # Globally unique ID (UUID4)
    source: str                 # Source name (e.g., "phishtank", "tranco")
    source_id: str              # Original ID from source (e.g., phish_id, tranco rank)
    
    # Input
    input_type: InputType       # URL | EMAIL | TEXT | SCREENSHOT | QR_CODE
    raw_input: str              # Original URL/email body/text
    normalized_input: str       # Normalized form (lowercased URL, cleaned text)
    
    # Label
    label: str                  # "phishing" | "benign"
    label_confidence: float     # 0.0 (low) – 1.0 (high) — for weak/distant labels
    
    # Provenance
    timestamp: datetime | None  # When sample was collected/verified (if available)
    ingestion_time: datetime    # When we ingested it
    
    # Features (computed during preprocessing)
    features: dict[str, Any]    # Extracted features (URL parsed, email headers, etc.)
    
    # Dataset split
    split: str | None           # "train" | "val" | "test" | None (not yet assigned)
    
    # Metadata
    metadata: dict[str, Any]    # Source-specific fields (e.g., target brand, rank)
```

**Serialization formats:**

- **Intermediate storage (post-ingestion):** JSON Lines (`.jsonl`) — one JSON object per line
- **Processed storage (post-split):** Parquet or CSV for tabular features + separate JSON for metadata
- **Raw data:** Keep original files in `data/raw/{source}/` for reproducibility

**Storage layout:**

```
data/
├── raw/
│   ├── phishtank/
│   │   └── verified_online_{date}.csv
│   └── tranco/
│       └── tranco_{list_id}.csv
├── cleaned/
│   ├── phishtank_cleaned.jsonl
│   └── tranco_cleaned.jsonl
├── processed/
│   ├── merged_deduplicated.jsonl
│   ├── train.jsonl
│   ├── val.jsonl
│   ├── test.jsonl
│   └── benign_reserve.jsonl         # Unused benign samples (archived)
└── metadata/
    ├── ingestion_log_{timestamp}.jsonl
    ├── dataset_manifest_{timestamp}.json
    ├── deduplication_report_{timestamp}.json
    └── leakage_validation_{timestamp}.json
```

---

## Preprocessing Pipeline

### Pipeline Stages

```
┌─────────────┐
│  Ingestion  │  Read raw source files, parse format-specific fields
└──────┬──────┘
       │
       v
┌─────────────┐
│ Validation  │  Check required fields, discard malformed samples
└──────┬──────┘
       │
       v
┌─────────────┐
│Normalization│  Convert to canonical schema, normalize inputs
└──────┬──────┘
       │
       v
┌─────────────┐
│   Merge     │  Combine all sources into single dataset
└──────┬──────┘
       │
       v
┌─────────────┐
│Deduplication│  Remove exact and near-duplicates (see below)
└──────┬──────┘
       │
       v
┌─────────────┐
│    Split    │  Assign train/val/test splits (see below)
└──────┬──────┘
       │
       v
┌─────────────┐
│   Balance   │  Apply undersampling to training set only
└──────┬──────┘
       │
       v
┌─────────────┐
│   Export    │  Write split datasets and manifests to disk
└─────────────┘
```

### Stage Details

#### 1. Ingestion

**Responsibilities:**
- Read source-specific formats (CSV, JSON)
- Parse fields into temporary source-specific structures
- Assign `source`, `source_id`, `ingestion_time`
- Record retrieval metadata for manifest

**Error handling:**
- Log malformed rows/files to `ingestion_log.jsonl`
- Skip and continue (do not crash entire pipeline)
- Report ingestion statistics (total read, skipped, errors)

**Outputs:**
- Source-specific cleaned JSONL files
- Ingestion statistics for manifest

#### 2. Validation

**Checks:**
- Required fields present (`raw_input`, `label`, `source`)
- Input type matches expected type (e.g., URL samples have valid URL format)
- Timestamp parsing (if available)
- Label is in allowed set (`phishing`, `benign`)

**Failure action:**
- Discard invalid samples
- Log to `validation_errors.jsonl` with reason
- Count errors for manifest

#### 3. Normalization

**URL normalization:**
- Lowercase scheme and domain
- Remove URL fragments (`#...`)
- Sort query parameters alphabetically
- Decode percent-encoding (`%20` → ` `)
- Strip trailing `/` from path (unless path is `/`)
- Remove default ports (`:80` for http, `:443` for https)
- Remove `www.` prefix for consistency (configurable)

**Assign:**
- `sample_id` (UUID4)
- `normalized_input`
- `label_confidence` (default 1.0 for PhishTank verified, 0.9 for Tranco distant supervision)

#### 4. Merge

**Action:**
- Concatenate all cleaned source `.jsonl` files into `merged.jsonl`
- Preserve provenance (`source`, `source_id`)
- Discover and record actual dataset sizes (no hardcoded values)

#### 5. Deduplication

See [Deduplication Strategy](#deduplication-strategy) below.

#### 6. Split

See [Train/Test Split Strategy](#traintest-split-strategy) below.

#### 7. Balance

**Training set only:**
- Apply 1:4 undersampling to benign class
- Preserve all phishing samples
- Archive unused benign samples to `benign_reserve.jsonl`

**Validation set:**
- Apply same 1:4 ratio for consistency

**Test set:**
- **No balancing applied** — preserve natural class distribution
- Reflects realistic deployment scenario

#### 8. Export

**Outputs:**
- `train.jsonl`, `val.jsonl`, `test.jsonl`
- `benign_reserve.jsonl` (archived samples)
- `dataset_manifest_{timestamp}.json` with full provenance
- `leakage_validation_{timestamp}.json` with validation results

---

## Deduplication Strategy

### Problem

- **Exact duplicates:** Same URL appears multiple times in same source or across sources
- **Near-duplicates:** URLs differ only in query params or tracking tokens
- **Campaign duplicates:** Phishing campaigns generate many similar URLs (same domain, different paths)

### Strategy

**Three-tier deduplication:**

#### Tier 1: Exact Duplicates (Normalized Input)

**Method:** Hash-based deduplication on `normalized_input`

**Process:**
1. Compute SHA256 hash of `normalized_input`
2. Group by hash
3. **Conflict resolution:** If multiple samples have same hash but different labels:
   - If labels disagree: discard both (label noise detected)
   - If labels agree: keep earliest by `timestamp` (or highest `label_confidence`)
4. Keep one representative per hash

**Rationale:** After normalization, identical inputs should have identical labels. Disagreement indicates mislabeling or temporal shift (site was benign, then compromised).

**Record for manifest:**
- `tier1_exact_duplicates_removed`
- `label_conflicts_discarded`

#### Tier 2: Near-Duplicates (URL Structure)

**Method:** URL fingerprinting for phishing URLs

**Process:**
1. For phishing URLs, extract:
   - Registered domain (e.g., `example.com` from `https://phishing.example.com/path`)
   - Path structure (e.g., `/login/verify` → `/PATH/PATH`)
   - Query parameter keys (ignore values)
2. Compute structural fingerprint: `hash(domain || path_structure || sorted_param_keys)`
3. Group samples by fingerprint
4. **Conflict resolution:**
   - If group size > threshold (e.g., 100): likely a campaign — subsample to 10–20 representatives
   - Preserve diversity: sample across different `timestamp` ranges

**Rationale:** Phishing campaigns generate many URLs on the same compromised domain with similar structure. Keeping all creates artificial correlation and inflates dataset size without adding information.

**For benign URLs:**
- Less aggressive near-duplicate removal (benign sites are more diverse)
- Only deduplicate if domain + path are identical

**Record for manifest:**
- `tier2_near_duplicates_removed`

#### Tier 3: Domain Clustering (for train/test split)

**Method:** Group samples by registered domain, ensure domain clusters do not span train/test

**Rationale:** If `phishing.example.com/page1` is in train and `phishing.example.com/page2` is in test, the model learns the domain is phishing, not the phishing pattern. This is domain leakage.

**Process:**
1. Extract registered domain from each URL (using public suffix list)
2. Group subdomains under their registrable domain (e.g., `sub1.example.com` and `sub2.example.com` → `example.com` cluster)
3. Assign all samples from the same domain cluster to the same split
4. See [Split Strategy](#traintest-split-strategy) below

**Record for manifest:**
- `tier3_domain_clusters` (total number of unique domain clusters)
- Per-split `unique_domains` count

---

## Train/Test Split Strategy

### Requirements

1. **Leakage controls:** Prevent information from test set being visible during training through multiple validation checks
2. **Temporal validity:** When timestamps available, test set is strictly newer than train
3. **Domain isolation:** URL samples from the same registrable domain must not span train/test
4. **Realistic evaluation:** Test set preserves natural class distribution
5. **Reproducibility:** Splits must be deterministic given a random seed

### Approved Strategy: Temporal + Domain-Aware Split

#### For URL Data (PhishTank, Tranco)

**Method:** Time-based split with domain clustering

**Process:**
1. **Group by domain:** Cluster all samples by registrable domain
   - Use public suffix list to extract registrable domain
   - `sub1.example.com` and `sub2.example.com` → both in `example.com` cluster
2. **Sort domain clusters by median timestamp:**
   - Compute median `timestamp` for each domain cluster
   - For PhishTank: use `verification_time`
   - For Tranco: use list publication date
   - Sort clusters from oldest to newest
3. **Cumulative split:**
   - Allocate domains (not individual samples) to splits in temporal order
   - Train: oldest 70% of domains
   - Val: next 15% of domains
   - Test: newest 15% of domains
4. **Balance training set only:**
   - After split, undersample training benign class to 1:4 ratio
   - Archive unused benign samples separately
   - **Do not balance validation or test sets** — preserve natural distribution

**Rationale:**
- Test set contains newer phishing campaigns → evaluates generalization to emerging threats
- Domain isolation prevents leakage
- Temporal ordering simulates real-world deployment (model trained on past, evaluated on future)
- Realistic test set provides honest performance estimates

**Leakage Validation:**
1. **Exact duplicate check:** Verify no `normalized_input` appears in multiple splits
2. **Domain isolation check:** Verify no domain cluster spans multiple splits
3. **Temporal isolation check:** Verify test set timestamps are strictly newer than train
4. **Near-duplicate check:** Verify no structural fingerprint collisions across splits

**Record for manifest:**
- Split strategy name
- Temporal ranges for each split
- Unique domain counts per split
- Natural class distributions (before and after balancing)
- Leakage validation results

---

## Class Imbalance Handling

### Problem

Phishing detection faces severe class imbalance in real-world deployments. Expected distribution:
- PhishTank provides verified phishing URLs (discovered during ingestion)
- Tranco provides top-ranked domains (discovered during ingestion)
- Actual ratio unknown until runtime, but expected to be heavily imbalanced (benign >> phishing)

Severe imbalance leads to:
- Model bias toward majority class (predicts "benign" for everything)
- Poor recall on minority class (phishing)
- Misleading accuracy metrics (high accuracy by always predicting "benign")

### Approved Strategy

#### Training Set: Artificial Balance (1:4 ratio)

**Goal:** Enable effective learning by reducing majority class dominance

**Method:** Undersample benign class to 1:4 phishing:benign ratio

**Process:**
1. After deduplication and split, apply to training set only
2. Discover actual phishing count at runtime
3. Compute target benign count: `n_benign_target = n_phishing * 4`
4. Randomly subsample benign samples (stratified by source if multiple)
5. Archive unused benign samples to `benign_reserve.jsonl` — **do not discard permanently**

**Rationale:**
- 1:4 ratio balances learning effectiveness with data efficiency
- Keeps majority class represented (not 1:1 balance)
- Preserves unused data for future use (hard negative mining, curriculum learning, model updates)

#### Validation Set: Same Balance (1:4 ratio)

**Goal:** Consistent train/val distribution for hyperparameter tuning

**Method:** Apply same 1:4 undersampling as training set

#### Test Set: Natural Distribution

**Goal:** Honest evaluation reflecting real-world deployment

**Method:** **No balancing applied**

**Rationale:**
- Real-world phishing detection sees heavily imbalanced traffic (benign >> phishing)
- Artificially balanced test sets inflate performance metrics
- Natural distribution provides realistic performance estimates
- Forces model to handle imbalance during inference

**Expected test metrics:**
- Lower overall accuracy than artificially balanced test set
- More realistic precision/recall trade-offs
- Honest false positive rate estimates

#### Class Weights in Training

**Method:** Assign higher loss weight to minority class

**Process:**
- Even with 1:4 undersampling, apply class weights during training
- Compute weights: `weight_phishing = n_total / (2 * n_phishing)`, `weight_benign = n_total / (2 * n_benign)`
- Apply in model training (e.g., `class_weight` parameter in scikit-learn)

**Rationale:**
- Standard ML best practice
- Further reduces bias toward majority class
- Compatible with undersampling

#### Evaluation Metrics

**Required metrics (computed for all splits):**
- Precision, Recall, F1-score (per class and macro-average)
- ROC-AUC (threshold-independent)
- Precision-Recall AUC (better than ROC for imbalanced data)
- Confusion matrix

**Prohibited metrics:**
- Accuracy alone (misleading for imbalanced data)

**Rationale:**
- Accuracy is meaningless for imbalanced datasets
- Precision/Recall trade-off critical for security applications
- PR-AUC preferred over ROC-AUC for imbalanced evaluation

### Archived Benign Samples

**Purpose:** Retain for future use

**Potential uses:**
- Curriculum learning (gradually introduce harder negatives)
- Hard negative mining (find benign samples model struggles with)
- Model updates (retrain with different balance ratios)
- External validation (hold-out evaluation set)

**Storage:** `data/processed/benign_reserve.jsonl` with manifest entry documenting count and source distribution

---

## Implementation Plan

### Phased Implementation

**Phase 1A: Core Pipeline (URL data only) — APPROVED**
1. Implement `Ingestion` for PhishTank + Tranco
   - Parse source-specific formats
   - Discover actual dataset sizes at runtime
   - Record retrieval metadata for manifest
2. Implement `Validation` and `Normalization`
   - URL validation and normalization
   - Assign sample IDs and confidence scores
3. Implement Tier 1 (exact) and Tier 2 (near-duplicate) deduplication
   - SHA256-based exact deduplication
   - Structural fingerprinting for phishing campaigns
4. Implement temporal + domain-aware split
   - Domain clustering using public suffix list
   - Temporal ordering by median timestamp
   - Leakage validation checks
5. Implement training set undersampling (1:4 ratio)
   - Archive unused benign samples
   - Apply to training and validation sets only
   - Preserve natural test distribution
6. Export train/val/test splits and manifests
   - Generate comprehensive dataset manifest
   - Generate leakage validation report
   - Export archived benign samples
7. **Validation:** Run automated checks
   - Verify no domain spans multiple splits
   - Verify temporal ordering
   - Verify no exact duplicates across splits
   - Verify class distributions match expected ratios

**Phase 1B: Add Email Data — DEFERRED**
1. Extend `Ingestion` for Nazario + Enron
2. Implement email-specific normalization
3. Reuse deduplication and split logic
4. Update manifest schema for email metadata

**Phase 1C: Evaluation Framework — DEFERRED**
1. Implement evaluation metrics (precision, recall, F1, ROC-AUC, PR-AUC)
2. Implement cross-validation scaffolding

### Code Structure

**Modules to implement (in `ml/data/`):**

```
ml/data/
├── __init__.py
├── ingest.py              # Source-specific ingesters (PhishTank, Tranco)
├── schema.py              # Sample dataclass, manifest schema, serialization
├── normalize.py           # URL normalization functions
├── deduplicate.py         # Tier 1, 2, 3 deduplication
├── split.py               # Train/val/test splitting logic with domain clustering
├── balance.py             # Class imbalance handling (undersampling, archiving)
├── validate.py            # Leakage validation checks
├── manifest.py            # Manifest generation and validation
├── pipeline.py            # End-to-end pipeline orchestration
└── utils.py               # Hashing, domain extraction, logging
```

**Configuration (in `phishguard/config.py`):**

```python
# Data pipeline settings
PHISHGUARD_DATA_RAW_DIR: Path = Path("./data/raw")
PHISHGUARD_DATA_CLEANED_DIR: Path = Path("./data/cleaned")
PHISHGUARD_DATA_PROCESSED_DIR: Path = Path("./data/processed")
PHISHGUARD_DATA_METADATA_DIR: Path = Path("./data/metadata")

# Split configuration
PHISHGUARD_SPLIT_TRAIN_RATIO: float = 0.70
PHISHGUARD_SPLIT_VAL_RATIO: float = 0.15
PHISHGUARD_SPLIT_TEST_RATIO: float = 0.15
PHISHGUARD_RANDOM_SEED: int = 42

# Class balance configuration
PHISHGUARD_TRAIN_BALANCE_RATIO: float = 0.20  # 1:4 phishing:benign
PHISHGUARD_BALANCE_TEST_SET: bool = False     # Never balance test set

# Deduplication configuration
PHISHGUARD_CAMPAIGN_THRESHOLD: int = 100      # Near-duplicate campaign detection
PHISHGUARD_CAMPAIGN_SAMPLE_SIZE: int = 15     # Representatives per campaign
```

**Testing:**
- Unit tests for URL normalization (edge cases: IDN, IPv6, unusual ports)
- Unit tests for domain extraction (public suffix list edge cases)
- Integration test: synthetic mini-dataset through full pipeline
- Deduplication correctness tests (exact, near-duplicate, label conflicts)
- Split reproducibility test (same seed → identical splits)
- Leakage validation test (detect violations)
- Manifest validation test (schema compliance)

---

## References

- Public Suffix List (for domain extraction): https://publicsuffix.org/
- URL normalization RFC 3986: https://tools.ietf.org/html/rfc3986
- PhishTank API documentation: https://www.phishtank.com/developer_info.php
- Tranco list methodology: https://tranco-list.eu/methodology
- Imbalanced learning best practices: He & Garcia, "Learning from Imbalanced Data" (2009)

---

**End of Document**

## Document Revision History

**Version 2.0 (2026-08-29):**
- Added "Approved Initial Dataset Strategy" section with clear Phase 1 scope
- Added "Dataset Manifest and Reproducibility" section with comprehensive manifest schema
- Removed hardcoded dataset size estimates (sizes discovered at runtime)
- Clarified test set is NOT balanced (natural distribution preserved)
- Emphasized benign samples are archived, not permanently discarded
- Replaced "zero leakage guarantee" with "leakage controls implemented and validated"
- Deferred OpenPhish pending license confirmation
- Excluded SpamAssassin from initial dataset
- Removed email sources from Phase 1 (URL-only focus)
- Updated all sections to reflect approved decisions
- Added comprehensive manifest schema and validation requirements

**Version 1.0 (2026-08-29):**
- Initial design document
