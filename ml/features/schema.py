"""Feature schema definitions for URL feature engineering.

This module defines the feature schema used by the URL feature extractor.
It provides:
- A versioned schema so downstream model training can depend on a stable interface
- Feature metadata (name, type, category, description)
- Serialization support for feature records

Schema version follows semantic versioning:
- Major: breaking changes (removed features, renamed features, changed semantics)
- Minor: new features added (backward-compatible)
- Patch: bug fixes in computation (same feature set)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any

# Schema version — bump on any change to the feature set.
SCHEMA_VERSION = "1.0.0"


class FeatureCategory(enum.Enum):
    """Feature category for documentation and grouping."""

    LEXICAL = "lexical"
    STRUCTURAL = "structural"
    OBFUSCATION = "obfuscation"
    DOMAIN = "domain"


FEATURE_CATEGORIES = tuple(cat.value for cat in FeatureCategory)


class FeatureType(enum.Enum):
    """Python type of a feature value."""

    INT = "int"
    FLOAT = "float"
    BOOL = "bool"


@dataclass(frozen=True)
class FeatureMeta:
    """Metadata for a single feature.

    Parameters
    ----------
    name : str
        Stable programmatic name (snake_case). Used as column/key name.
    feature_type : FeatureType
        Python type produced by the extractor.
    category : FeatureCategory
        Which group this feature belongs to.
    description : str
        Human description of what the feature measures.
    security_rationale : str
        Why this feature is relevant to phishing detection.
    """

    name: str
    feature_type: FeatureType
    category: FeatureCategory
    description: str
    security_rationale: str


# ---------------------------------------------------------------------------
# Canonical feature definitions — the single source of truth.
# Order here determines the canonical column / vector order.
# ---------------------------------------------------------------------------

FEATURE_DEFINITIONS: tuple[FeatureMeta, ...] = (
    # ── Lexical features ───────────────────────────────────────────────
    FeatureMeta(
        name="url_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Total character length of the full URL string.",
        security_rationale=(
            "Phishing URLs often use very long URLs to obfuscate the true destination "
            "or to embed encoded payloads."
        ),
    ),
    FeatureMeta(
        name="hostname_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Character length of the hostname portion.",
        security_rationale=(
            "Unusually long hostnames may indicate subdomain abuse or look-alike domains."
        ),
    ),
    FeatureMeta(
        name="path_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Character length of the URL path.",
        security_rationale="Deep or long paths are common in phishing URLs hosting kits.",
    ),
    FeatureMeta(
        name="query_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Character length of the query string (excluding '?').",
        security_rationale=(
            "Long query strings may carry encoded credentials or redirect parameters."
        ),
    ),
    FeatureMeta(
        name="fragment_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Character length of the URL fragment (excluding '#').",
        security_rationale="Fragments can be abused to pass data client-side.",
    ),
    FeatureMeta(
        name="digit_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Number of digit characters (0-9) in the URL.",
        security_rationale="High digit counts suggest IP addresses or random IDs.",
    ),
    FeatureMeta(
        name="digit_ratio",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.LEXICAL,
        description="Ratio of digits to total URL length.",
        security_rationale="Elevated digit ratio indicates numeric-heavy, possibly obfuscated URLs.",
    ),
    FeatureMeta(
        name="alpha_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Number of alphabetic characters in the URL.",
        security_rationale="Used together with digit and special-char counts for character-profile analysis.",
    ),
    FeatureMeta(
        name="alpha_ratio",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.LEXICAL,
        description="Ratio of alphabetic characters to total URL length.",
        security_rationale="Legitimate URLs tend to have higher alphabetic ratios.",
    ),
    FeatureMeta(
        name="special_char_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Number of special (non-alphanumeric, non-scheme-structural) characters.",
        security_rationale="Excessive special characters can indicate obfuscation or encoding tricks.",
    ),
    FeatureMeta(
        name="special_char_ratio",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.LEXICAL,
        description="Ratio of special characters to total URL length.",
        security_rationale="High special-character ratio indicates obfuscation techniques.",
    ),
    FeatureMeta(
        name="url_token_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Number of tokens when splitting URL on common delimiters (/ . - _ ? & = @).",
        security_rationale="Phishing URLs tend to have more tokens from appending parameters.",
    ),
    FeatureMeta(
        name="suspicious_keyword_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.LEXICAL,
        description="Number of distinct suspicious keywords found in the URL.",
        security_rationale="Phishing URLs frequently contain keywords like 'login', 'verify', 'account'.",
    ),
    FeatureMeta(
        name="has_suspicious_keyword",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.LEXICAL,
        description="Whether any suspicious keyword is present in the URL.",
        security_rationale="Binary flag for quick filtering potential phishing URLs.",
    ),
    # ── Structural features ────────────────────────────────────────────
    FeatureMeta(
        name="subdomain_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.STRUCTURAL,
        description="Number of subdomain levels (e.g. a.b.example.com → 2).",
        security_rationale="Deep subdomains are a common phishing tactic to mimic legitimate domains.",
    ),
    FeatureMeta(
        name="path_depth",
        feature_type=FeatureType.INT,
        category=FeatureCategory.STRUCTURAL,
        description="Number of path segments (e.g. /a/b/c → 3).",
        security_rationale="Deep paths may indicate hidden phishing kit directories.",
    ),
    FeatureMeta(
        name="query_param_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.STRUCTURAL,
        description="Number of query parameters.",
        security_rationale="Many parameters may indicate tracking or credential harvesting.",
    ),
    FeatureMeta(
        name="has_fragment",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.STRUCTURAL,
        description="Whether the URL has a fragment (#) component.",
        security_rationale="Fragments can be abused for client-side data passing.",
    ),
    FeatureMeta(
        name="has_port",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.STRUCTURAL,
        description="Whether the URL specifies an explicit port number.",
        security_rationale="Non-standard ports are unusual for legitimate sites.",
    ),
    FeatureMeta(
        name="is_ip_host",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.STRUCTURAL,
        description="Whether the hostname is an IP address (v4 or v6).",
        security_rationale="IP-address hostnames are a strong phishing indicator.",
    ),
    FeatureMeta(
        name="is_https",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.STRUCTURAL,
        description="Whether the scheme is HTTPS.",
        security_rationale="HTTP-only sites are increasingly suspicious; but phishing also uses HTTPS.",
    ),
    FeatureMeta(
        name="hostname_token_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.STRUCTURAL,
        description="Number of dot-separated components in the hostname.",
        security_rationale="More hostname components may indicate subdomain abuse.",
    ),
    FeatureMeta(
        name="path_max_segment_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.STRUCTURAL,
        description="Length of the longest path segment.",
        security_rationale="Very long segments often contain encoded data or hashes.",
    ),
    FeatureMeta(
        name="query_max_value_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.STRUCTURAL,
        description="Length of the longest query parameter value.",
        security_rationale="Long parameter values may contain encoded payloads.",
    ),
    # ── Obfuscation / security features ────────────────────────────────
    FeatureMeta(
        name="is_punycode",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.OBFUSCATION,
        description="Whether the hostname contains punycode (xn--) labels.",
        security_rationale=(
            "Punycode/IDN homograph attacks use look-alike Unicode characters "
            "to impersonate legitimate domains."
        ),
    ),
    FeatureMeta(
        name="pct_encoded_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.OBFUSCATION,
        description="Number of percent-encoded triplets (%XX) in the URL.",
        security_rationale="Excessive percent-encoding obfuscates URL content.",
    ),
    FeatureMeta(
        name="pct_encoded_ratio",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.OBFUSCATION,
        description="Ratio of percent-encoded triplets to total URL length.",
        security_rationale="High percent-encoding ratio suggests deliberate obfuscation.",
    ),
    FeatureMeta(
        name="has_at_sign",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.OBFUSCATION,
        description="Whether the URL contains an '@' character.",
        security_rationale=(
            "The @ in a URL can trick users: http://legitimate@evil.com goes to evil.com."
        ),
    ),
    FeatureMeta(
        name="has_double_slash_redirect",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.OBFUSCATION,
        description="Whether the path contains '//' which may indicate a redirect.",
        security_rationale="Double-slash in path can be used for open-redirect attacks.",
    ),
    FeatureMeta(
        name="has_hex_encoding_in_host",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.OBFUSCATION,
        description="Whether the hostname contains percent-encoded characters.",
        security_rationale="Encoding in hostnames is unusual and may indicate obfuscation.",
    ),
    FeatureMeta(
        name="hostname_entropy",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.OBFUSCATION,
        description="Shannon entropy of the hostname string.",
        security_rationale=(
            "Randomly generated hostnames (DGA-style) have high entropy, "
            "while legitimate domains tend to be lower-entropy words."
        ),
    ),
    FeatureMeta(
        name="hostname_consonant_ratio",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.OBFUSCATION,
        description="Ratio of consonants to total alphabetic characters in hostname.",
        security_rationale=(
            "Random/DGA hostnames have atypical consonant-to-vowel ratios "
            "compared to pronounceable domain names."
        ),
    ),
    FeatureMeta(
        name="hostname_digit_ratio",
        feature_type=FeatureType.FLOAT,
        category=FeatureCategory.OBFUSCATION,
        description="Ratio of digits to total characters in hostname.",
        security_rationale="Digit-heavy hostnames are rarer for legitimate domains.",
    ),
    FeatureMeta(
        name="has_shortener_pattern",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.OBFUSCATION,
        description="Whether the URL structure matches known URL shortener patterns.",
        security_rationale="URL shorteners hide the real destination.",
    ),
    FeatureMeta(
        name="has_data_uri",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.OBFUSCATION,
        description="Whether the URL references a data: URI scheme.",
        security_rationale="Data URIs can embed executable content or phishing pages.",
    ),
    # ── Domain features ────────────────────────────────────────────────
    FeatureMeta(
        name="tld",
        feature_type=FeatureType.INT,
        category=FeatureCategory.DOMAIN,
        description="Hash-encoded top-level domain (for categorical use).",
        security_rationale=(
            "Certain TLDs (.tk, .ml, .ga, .cf) are disproportionately used for phishing."
        ),
    ),
    FeatureMeta(
        name="tld_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.DOMAIN,
        description="Character length of the TLD.",
        security_rationale="Unusual TLD lengths may correlate with newer or less-trusted TLDs.",
    ),
    FeatureMeta(
        name="registrable_domain_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.DOMAIN,
        description="Character length of the registrable domain (eTLD+1).",
        security_rationale="Very long registrable domains may be generated or look-alike domains.",
    ),
    FeatureMeta(
        name="domain_token_count",
        feature_type=FeatureType.INT,
        category=FeatureCategory.DOMAIN,
        description="Number of dot-separated labels in the full hostname.",
        security_rationale="More domain labels indicate deeper subdomain nesting.",
    ),
    FeatureMeta(
        name="domain_has_hyphen",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.DOMAIN,
        description="Whether the registrable domain contains a hyphen.",
        security_rationale="Hyphens are often used in look-alike domains (e.g. paypa-l.com).",
    ),
    FeatureMeta(
        name="domain_has_digit",
        feature_type=FeatureType.BOOL,
        category=FeatureCategory.DOMAIN,
        description="Whether the registrable domain contains digits.",
        security_rationale="Digits in domain names can indicate generated or suspicious domains.",
    ),
    FeatureMeta(
        name="subdomain_length",
        feature_type=FeatureType.INT,
        category=FeatureCategory.DOMAIN,
        description="Total character length of the subdomain portion.",
        security_rationale="Long subdomains are used to impersonate legitimate brands.",
    ),
)

# Ordered list of feature names — the canonical column order.
FEATURE_NAMES: tuple[str, ...] = tuple(f.name for f in FEATURE_DEFINITIONS)

# Fast lookup by name.
FEATURE_MAP: dict[str, FeatureMeta] = {f.name: f for f in FEATURE_DEFINITIONS}


# ---------------------------------------------------------------------------
# Suspicious keyword vocabulary — versioned so model retraining picks up changes.
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS_VERSION = "1.0.0"

SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset({
    # Authentication / credentials
    "login", "signin", "sign-in", "log-in", "logon",
    "password", "passwd", "credential",
    # Verification / urgency
    "verify", "verification", "confirm", "validate",
    "secure", "security", "alert", "urgent", "suspend",
    "restrict", "locked", "expired", "expire",
    # Account actions
    "account", "update", "upgrade", "billing",
    "payment", "invoice", "refund",
    # Popular impersonation targets (generic, not brand-specific)
    "bank", "wallet", "webmail",
    # Technical deception
    "redirect", "authenticate", "authorize", "oauth",
    "token", "session", "recover", "reset",
    # Social engineering
    "free", "winner", "prize", "reward", "bonus",
    "gift", "offer", "deal", "promo",
    "click", "action", "required",
})

# Known URL shortener domains (hostname-only, lowercase).
URL_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "v.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "bl.ink",
})


@dataclass
class FeatureRecord:
    """A single feature extraction result.

    Contains the feature vector alongside metadata that must be preserved
    but is NOT part of the feature vector.

    Parameters
    ----------
    sample_id : str
        The globally unique sample ID from Phase 1A.
    url : str
        The URL that was analysed.
    features : dict[str, int | float | bool]
        Computed feature values keyed by canonical feature names.
    schema_version : str
        The schema version used to produce these features.
    split : str | None
        Dataset split (train/val/test/archive) if known.
    label : str | None
        Ground-truth label — preserved for training but NOT a feature.
    """

    sample_id: str
    url: str
    features: dict[str, int | float | bool]
    schema_version: str = SCHEMA_VERSION
    split: str | None = None
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a flat dictionary suitable for JSON export.

        The output keeps metadata keys separate from feature keys.
        Feature keys are prefixed with ``feat_`` in the flat form
        to prevent name collisions.
        """
        d: dict[str, Any] = {
            "sample_id": self.sample_id,
            "url": self.url,
            "schema_version": self.schema_version,
        }
        if self.split is not None:
            d["split"] = self.split
        if self.label is not None:
            d["label"] = self.label
        # Features go in a nested key so they don't collide with metadata.
        d["features"] = dict(self.features)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FeatureRecord:
        """Deserialize from a flat dictionary."""
        return cls(
            sample_id=d["sample_id"],
            url=d["url"],
            features=d.get("features", {}),
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            split=d.get("split"),
            label=d.get("label"),
        )

    def feature_vector(self) -> list[int | float]:
        """Return a list of feature values in canonical order.

        Boolean features are cast to int (0/1) for numeric compatibility.
        Missing features are filled with 0.
        """
        vec: list[int | float] = []
        for name in FEATURE_NAMES:
            val = self.features.get(name, 0)
            if isinstance(val, bool):
                val = int(val)
            vec.append(val)
        return vec


def get_schema_info() -> dict[str, Any]:
    """Return a JSON-serializable description of the current feature schema."""
    return {
        "schema_version": SCHEMA_VERSION,
        "suspicious_keywords_version": SUSPICIOUS_KEYWORDS_VERSION,
        "feature_count": len(FEATURE_DEFINITIONS),
        "categories": {
            cat.value: sum(1 for f in FEATURE_DEFINITIONS if f.category == cat)
            for cat in FeatureCategory
        },
        "features": [
            {
                "name": f.name,
                "type": f.feature_type.value,
                "category": f.category.value,
                "description": f.description,
                "security_rationale": f.security_rationale,
            }
            for f in FEATURE_DEFINITIONS
        ],
    }
