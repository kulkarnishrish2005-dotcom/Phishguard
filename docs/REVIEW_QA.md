# PhishGuard — Academic Review Q&A

Answers describe the **actual implemented system** — not aspirational features.

---

### 1. What problem are you solving?

Phishing attacks leverage deceptive URLs, deceptive messages, and deceptive visual content to steal credentials, financial details, and personal data. PhishGuard addresses this with a multi-modal, offline-capable detection pipeline that combines deterministic URL structural feature extraction (42 features, Phase 1B) with transparent evidence-based scoring for URLs, text/email content, and screenshots.

---

### 2. Why phishing detection?

Phishing is one of the most frequent and costly cybersecurity threats to both individuals and organizations. Existing defenses are either black-box (hard to audit) or require external network connections (not allowed in restricted environments). PhishGuard is designed to be fully offline with transparent reasoning for every decision.

---

### 3. What is your novelty?

The prototype demonstrates a **local-first, multi-modal architecture** combining:
- 42 deterministic URL structural features + 3 independent ML classifiers
- Explicit evidence-based risk fusion (not just probability)
- Transparent heuristic NLP baseline clearly labeled (not misrepresented as a transformer)
- Local OCR pipeline with graceful failure diagnostics
- Unified JSON output across all modalities

What it does **not** claim: transformer-based text detection, VLM-based visual fraud detection, real-time streaming, or production-grade accuracy.

---

### 4. Why PhishTank?

PhishTank is a verified, community-curated phishing URL dataset with timestamp metadata — required for domain-aware temporal splitting. It is free for research with attribution. It provides verified positive-class samples with `verified=yes`. The dataset must be manually downloaded (pipeline design choice for licensing/reproducibility).

---

### 5. Why Tranco?

Tranco provides top-ranked domains as benign distant supervision, is open-methodology, and has stable historical list versions with IDs — ideal for temporal splitting and reproducible benchmarks. It is free for commercial/research use.

---

### 6. Why 42 URL features?

Direct match to Phase 1B specification. The 42 features cover lexical (14), structural (10), obfuscation (11), and domain (7) categories using pure URL string analysis — no network access. They are versioned at `1.0.0` for stable downstream model training.

---

### 7. What are the most important features?

The highest security-rationale features (from `docs/feature_engineering.md`) include:
- **`is_ip_host`** (strong phishing indicator — IP hostnames are abnormal)
- **`is_punycode`** (IDN homograph attack)
- **`hostname_entropy`** (DGA / random domain generation)
- **`has_at_sign`** (redirection trick `trusted.com@evil.com`)
- **`has_suspicious_keyword`** (credential harvesting lure patterns)
- **`has_shortener_pattern`** (concealed destinations)
- **`subdomain_count`** (subdomain spoofing of legitimate brands)

---

### 8. Why Logistic Regression?

Provides a linear baseline that is fast to train, interpretable (coefficients indicate feature direction), and allows comparison with non-linear methods. It achieves ~76% ROC-AUC on synthetic demo data — comparable to Random Forest and XGBoost in this small-sample setting.

---

### 9. Why Random Forest?

An ensemble of 100 trees with `max_depth=10`, `class_weight='balanced'`, `n_jobs=-1`. Provides non-linear feature interactions, handles mixed data types well, and is robust out-of-the-box with minimal hyperparameter tuning needed for a prototype.

---

### 10. Why XGBoost?

Gradient-boosted trees (`hist` method, 100 estimators, `max_depth=6`) provide state-of-the-art performance on tabular data with regularization. Included for comparative baseline with LR and RF.

---

### 11. How did you prevent leakage?

- **Domain isolation**: All URLs from the same registrable domain (eTLD+1) assigned to exactly one split.
- **Temporal splitting**: Domain clusters sorted by median timestamp; oldest 70% → train, newest 15% → test.
- **Exact duplicate removal**: SHA256 hash matching with label-conflict discard.
- **No feature leakage**: 42 features computed solely from URL string; labels never used during feature computation.

---

### 12. Why domain-aware splitting?

Without domain isolation, a model could memorize `login.evil.com` is phishing rather than learning structural patterns. This prevents overfitting to domain names.

---

### 13. Why isn't accuracy enough?

Accuracy is misleading with class imbalance (e.g., 95% benign traffic = 95% accuracy by always predicting benign). We report **precision, recall, F1, ROC-AUC, and PR-AUC** — with PR-AUC preferred for imbalanced detection.

---

### 14. What is a false positive?

A false positive is a legitimate URL that is flagged as phishing. This causes user friction and can erode trust. Our evidence-based design allows users to review *why* a URL was flagged (e.g., long subdomain chain + suspicious keyword + high entropy), reducing opaque errors.

---

### 15. What is a false negative?

A false negative is a phishing URL that is not detected. This is more dangerous because the user receives no warning. The prototype includes urgency + credential harvesting + embedded URL fusion for screenshots to reduce false negatives across modalities.

---

### 16. How does the risk score work?

The **Risk Score** (0-100) is a composite expert-weighted index combining:
- **ML model probability** (up to 40 points, scaled)
- **Obfuscation indicators** (IP host, punycode, @ symbol, shorteners — up to 30 pts)
- **Lexical/keyword indicators** (suspicious keywords — up to 20 pts)
- **Structural indicators** (subdomains, entropy, custom ports — up to 15 pts)

The **Model Probability** (0.0-1.0) is kept **separate** — it represents the statistical classifier confidence, not the security assessment.

The Risk Score is **not a calibrated probability**.

---

### 17. Does your system visit URLs?

**No.** The URL is never fetched, resolved via DNS, or connected to over HTTP/HTTPS. All 42 features are computed exclusively from the URL string using `urllib.parse`, regex, and string operations. This is an explicit security design choice documented in Phase 1B.

---

### 18. How does screenshot detection work?

**Pipeline (local only):**
1. Receive image bytes or file path.
2. Load with PIL `Image.open()`.
3. Attempt `pytesseract.image_to_string()` (if binary present).
4. If unavailable, attempt `easyocr.Reader()` (if installed; notes progress if downloading).
5. If both unavailable: graceful metadata fallback reporting image dimensions and mode.
6. Extracted text passed to `TextPhishingDetector`.
7. Embedded URLs extracted via regex and passed to `URLInferenceEngine`.
8. Multi-modal fusion combines text risk and URL risk, with correlation bonus if both elevated.

No VLM is implemented.

---

### 19. What are the limitations?

- **No real dataset** (synthetic only for this prototype).
- **No automatic downloads** (must download PhishTank/Tranco manually).
- **Text detector is heuristic** (not a transformer/LLM).
- **OCR requires external binary** (tesseract) or easyocr model download.
- **Single-machine** (no distributed processing).
- **No QR / advanced VLM detection** (scaffold only).
- **Model accuracy ~70-77%** (prototype-level, not production-grade).

---

### 20. What would you add next?

- Integrate real PhishTank + Tranco datasets into `pipeline.py` for training.
- Add cross-validation across temporal domain clusters.
- Fine-tune lightweight NLP model (with full documentation of method) for text detection.
- Fill `services/qr/` with barcode detection.
- Deploy API server (`backend/`) for remote access.
- Add threat intelligence feeds for domain reputation.
- Build dataset manifest tracking for full reproducibility.

---

*Prepared for academic defense — answers describe actual implemented functionality verified by running code, tests, and documentation.*
