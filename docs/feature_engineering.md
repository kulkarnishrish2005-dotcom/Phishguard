# PhishGuard Phase 1B: URL Feature Engineering Reference

## Overview

This document provides a comprehensive reference for the URL feature engineering module implemented in Phase 1B.

**Schema Version:** 1.0.0  
**Feature Count:** 42 features  
**Categories:** Lexical (14), Structural (10), Obfuscation/Security (11), Domain (7)  

The feature engine operates exclusively on URL strings and metadata already present in the dataset. It does **NOT** perform DNS resolution, WHOIS lookups, HTTP requests, or any other external network access.

---

## Design Principles

1. **Pure String Analysis**: All features are computed solely from the URL text and standard library URL parsing. No external network queries or reputation lookups are performed.
2. **Determinism**: The same URL string always produces the exact same feature vector.
3. **Safety on Malformed Input**: The feature extractor handles malformed, truncated, or garbage input safely without raising exceptions.
4. **Stable Ordering & Schema Versioning**: Feature names, types, and column ordering are defined in `ml.features.schema` with semantic versioning. Downstream ML models depend on a frozen schema.
5. **Separation of Concerns**: Metadata (like labels, sample IDs, dataset splits) is carried through in the `FeatureRecord` structure for provenance and training coordination, but is **strictly excluded** from the feature vector.

---

## Feature Reference

### Group 1: Lexical Features (14 features)

| Feature Name | Type | Description | Security Rationale |
|---|---|---|---|
| `url_length` | `int` | Total character length of the full URL string. | Phishing URLs often use long URLs to embed encoded payloads or obfuscate the real destination. |
| `hostname_length` | `int` | Character length of the hostname portion. | Unusually long hostnames may indicate subdomain abuse or typosquatting. |
| `path_length` | `int` | Character length of the URL path. | Deep or long paths are common in phishing URLs hosting kits. |
| `query_length` | `int` | Character length of the query string (excluding `?`). | Long query strings may carry encoded credentials or redirect parameters. |
| `fragment_length` | `int` | Character length of the URL fragment (excluding `#`). | Fragments can be abused for client-side routing and payload delivery. |
| `digit_count` | `int` | Number of digit characters (0–9) in the URL. | High digit counts often correlate with IP addresses, random hashes, or tracking IDs. |
| `digit_ratio` | `float` | Ratio of digits to total URL length (`digit_count / url_length`). | Elevated digit ratio indicates numeric-heavy, possibly obfuscated URLs. |
| `alpha_count` | `int` | Number of alphabetic characters (a–z, A–Z) in the URL. | Baseline character-profile metric used in ratio calculations. |
| `alpha_ratio` | `float` | Ratio of alphabetic characters to total URL length (`alpha_count / url_length`). | Legitimate URLs typically have higher alphabetic ratios than machine-generated phishing URLs. |
| `special_char_count` | `int` | Number of non-alphanumeric characters in the URL. | Excessive special characters indicate encoding tricks, delimiters, or obfuscation. |
| `special_char_ratio` | `float` | Ratio of special characters to total URL length (`special_char_count / url_length`). | High special-character ratio is a strong indicator of obfuscation. |
| `url_token_count` | `int` | Number of tokens when splitting URL on common delimiters (`/`, `.`, `-`, `_`, `?`, `&`, `=`, `@`). | Phishing URLs tend to have more tokens due to complex parameter structures. |
| `suspicious_keyword_count` | `int` | Number of distinct suspicious keywords found in the URL. | Phishing URLs frequently contain target-luring terms like `login`, `verify`, `account`. |
| `has_suspicious_keyword` | `bool` | Whether any suspicious keyword is present in the URL. | Binary flag for fast pre-filtering and rule-based triggering. |

#### Suspicious Keyword Vocabulary (v1.0.0)

The vocabulary includes 40+ carefully curated terms across several categories:
- **Authentication/Credentials:** `login`, `signin`, `sign-in`, `log-in`, `logon`, `password`, `passwd`, `credential`
- **Verification/Urgency:** `verify`, `verification`, `confirm`, `validate`, `secure`, `security`, `alert`, `urgent`, `suspend`, `restrict`, `locked`, `expired`, `expire`
- **Account Actions:** `account`, `update`, `upgrade`, `billing`, `payment`, `invoice`, `refund`
- **Generic Targets:** `bank`, `wallet`, `webmail`
- **Technical Deception:** `redirect`, `authenticate`, `authorize`, `oauth`, `token`, `session`, `recover`, `reset`
- **Social Engineering:** `free`, `winner`, `prize`, `reward`, `bonus`, `gift`, `offer`, `deal`, `promo`, `click`, `action`, `required`

---

### Group 2: Structural Features (10 features)

| Feature Name | Type | Description | Security Rationale |
|---|---|---|---|
| `subdomain_count` | `int` | Number of subdomain levels beyond the registrable domain. | Deep subdomain nesting is a common tactic to impersonate brands (e.g. `paypal.com.evil.com`). |
| `path_depth` | `int` | Number of path segments (e.g., `/a/b/c` → 3). | Deep paths may indicate phishing kits nested inside compromised site directories. |
| `query_param_count` | `int` | Number of distinct query parameters. | Multiple query parameters often accompany tracking or credential harvesting scripts. |
| `has_fragment` | `bool` | Whether the URL contains a fragment (`#`) component. | Fragments can be used for client-side DOM-based phishing or token extraction. |
| `has_port` | `bool` | Whether the URL specifies an explicit non-standard port. | Legitimate sites rarely expose custom ports (e.g., `:8080`, `:8443`) to general users. |
| `is_ip_host` | `bool` | Whether the hostname is an IPv4 or IPv6 address. | IP-address hostnames are a very strong indicator of malicious intent. |
| `is_https` | `bool` | Whether the scheme is HTTPS. | Historically, lack of HTTPS indicated suspicious sites; modern phishing uses HTTPS, making this a contextual baseline feature. |
| `hostname_token_count` | `int` | Number of dot-separated components in the hostname. | Indicates hostname complexity and potential subdomain stacking. |
| `path_max_segment_length` | `int` | Length of the longest individual path segment. | Very long segments often contain base64 payloads, hashes, or encoded tokens. |
| `query_max_value_length` | `int` | Length of the longest individual query parameter value. | Long query values may carry full encoded landing page contents or serialized state. |

---

### Group 3: Obfuscation & Security Features (11 features)

| Feature Name | Type | Description | Security Rationale |
|---|---|---|---|
| `is_punycode` | `bool` | Whether the hostname contains punycode labels (`xn--`). | Punycode/IDN homograph attacks use look-alike Cyrillic/Greek characters to impersonate legitimate domains. |
| `pct_encoded_count` | `int` | Number of percent-encoded triplets (`%XX`) in the URL. | Percent-encoding is used to bypass naive keyword filters or obfuscate malicious destinations. |
| `pct_encoded_ratio` | `float` | Ratio of percent-encoded triplets to total URL length. | High percent-encoding ratios strongly correlate with deliberate obfuscation. |
| `has_at_sign` | `bool` | Whether the URL contains an `@` character. | The `@` delimiter causes browsers to treat everything before it as userinfo, redirecting to the host after it (e.g., `http://trusted.com@evil.com`). |
| `has_double_slash_redirect` | `bool` | Whether the path contains `//` after the initial scheme separator. | Double slashes in paths can trigger open-redirect vulnerabilities. |
| `has_hex_encoding_in_host` | `bool` | Whether the hostname portion contains percent-encoded characters. | Encoding inside hostnames is extremely rare in benign traffic and indicates evasion attempts. |
| `hostname_entropy` | `float` | Shannon entropy (in bits) of the hostname string. | High-entropy hostnames indicate domain generation algorithms (DGAs) or randomly generated subdomains. |
| `hostname_consonant_ratio` | `float` | Ratio of consonants to total alphabetic characters in the hostname. | DGA domains frequently have unnatural consonant-to-vowel distributions compared to natural words. |
| `hostname_digit_ratio` | `float` | Ratio of digits to total characters in the hostname. | High digit density in hostnames is characteristic of botnet-generated infrastructure. |
| `has_shortener_pattern` | `bool` | Whether the hostname matches known URL shortener domains. | URL shorteners (e.g. `bit.ly`, `tinyurl.com`) hide the real landing page. |
| `has_data_uri` | `bool` | Whether the URL uses the `data:` scheme. | Data URIs can embed entire HTML/JavaScript phishing pages directly in the link. |

---

### Group 4: Domain Features (7 features)

| Feature Name | Type | Description | Security Rationale |
|---|---|---|---|
| `tld` | `int` | Hash-encoded integer representation of the top-level domain. | Certain free or low-cost TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.top`) have disproportionately high phishing rates. |
| `tld_length` | `int` | Character length of the effective TLD. | Correlates with newer/generic TLDs vs. established short ccTLDs/gTLDs. |
| `registrable_domain_length` | `int` | Character length of the registrable domain (eTLD+1). | Very long registrable domains are often generated or designed to include multiple brand names. |
| `domain_token_count` | `int` | Total number of dot-separated labels across the entire hostname. | Structural indicator of domain nesting depth. |
| `domain_has_hyphen` | `bool` | Whether the registrable domain contains a hyphen (`-`). | Hyphens are widely used in typosquatting and brand impersonation (e.g., `paypal-security.com`). |
| `domain_has_digit` | `bool` | Whether the registrable domain contains digit characters. | Digits in the core domain name often indicate disposable or programmatic registration. |
| `subdomain_length` | `int` | Total character length of the subdomain string (all labels preceding eTLD+1). | Long subdomains are commonly used to craft convincing fake URLs (e.g. `login.microsoft.com.account-verify.evil.com`). |

---

## API Usage

### Python API

```python
from ml.features import URLFeatureExtractor, SCHEMA_VERSION

# Initialize extractor
extractor = URLFeatureExtractor()

# Single URL extraction
record = extractor.extract("https://login.example-verify.com/auth?user=test")

# Access features dictionary
features = record.features
print(f"URL Length: {features['url_length']}")
print(f"Suspicious Keywords: {features['suspicious_keyword_count']}")

# Access numeric feature vector (for ML model input)
vector = record.feature_vector()
print(f"Feature vector length: {len(vector)}")

# Serialization
record_dict = record.to_dict()
```

### CLI Batch Extraction

```bash
# Transform a single processed dataset file
python -m ml.features.cli_extract \
    --input data/processed/train.jsonl \
    --output data/features/train_features.jsonl

# Inspect schema information
python -m ml.features.cli_extract --show-schema-info
```

---

## Known Limitations & Future Work

1. **No Content / Page Analysis**: The feature extractor inspects URL strings only. A phishing site hosted on a legitimate domain with a benign-looking URL will not be caught by URL features alone. (Addressed in future phases via content/NLP analysis).
2. **Lightweight PSL**: The public suffix list embedded in the lightweight module covers common multi-level TLDs (`.co.uk`, `.com.au`, etc.) but is not exhaustive. In production, a full `tldextract` or `publicsuffix2` snapshot can be plugged in without changing the feature interface.
3. **No Network Intelligence**: Features like domain age, DNS MX/NS records, SSL certificate details, and IP reputation are excluded by design in Phase 1B to ensure zero latency, zero external dependencies, and complete offline reproducibility.
