"""URL feature extraction for phishing detection.

This module implements a deterministic, network-free feature extractor that
operates exclusively on URL strings.  It produces a stable feature record
conforming to the schema defined in :mod:`ml.features.schema`.

Design constraints
------------------
* **No network access** — no DNS resolution, WHOIS, HTTP requests, or
  external reputation lookups.
* **Deterministic** — the same URL always produces the same feature record.
* **Safe on malformed input** — never raises; returns a zero-filled record
  on garbage input.
* **Stable ordering** — feature names and order are dictated by
  :data:`ml.features.schema.FEATURE_NAMES`.

Usage
-----
::

    extractor = URLFeatureExtractor()
    record = extractor.extract("https://example.com/login?user=1")
    print(record.features)
    print(record.feature_vector())
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from urllib.parse import ParseResult, parse_qsl, urlparse

from ml.data.utils import extract_registrable_domain

from .schema import (
    FEATURE_NAMES,
    SCHEMA_VERSION,
    SUSPICIOUS_KEYWORDS,
    URL_SHORTENER_DOMAINS,
    FeatureRecord,
)

logger = logging.getLogger(__name__)

# Pre-compiled patterns (module-level for performance).
_RE_PCT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")
_RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_IPV6_BRACKET = re.compile(r"^\[.*\]$")
_RE_DOUBLE_SLASH_PATH = re.compile(r"(?<!:)//")
_RE_TOKEN_SPLIT = re.compile(r"[/.\-_?&=@]+")
_VOWELS = frozenset("aeiouAEIOU")
_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")

# Public Suffix List — reuse the same lightweight list from Phase 1A utils.
from ml.data.utils import _PUBLIC_SUFFIXES  # noqa: E402


class URLFeatureExtractor:
    """Extract numeric/boolean features from a URL string.

    All methods are pure functions of the URL text — no I/O, no statefulness
    between calls.

    Parameters
    ----------
    schema_version : str
        Recorded in each :class:`FeatureRecord` for provenance.
    """

    def __init__(self, schema_version: str = SCHEMA_VERSION) -> None:
        self._schema_version = schema_version

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        url: str,
        *,
        sample_id: str = "",
        split: str | None = None,
        label: str | None = None,
    ) -> FeatureRecord:
        """Extract all features from *url*.

        Parameters
        ----------
        url : str
            The URL string to analyse.  May be malformed.
        sample_id : str
            Opaque ID carried through for traceability.
        split : str | None
            Dataset split tag (train / val / test / archive).
        label : str | None
            Ground-truth label — preserved but NOT included in features.

        Returns
        -------
        FeatureRecord
            A record with stable feature ordering.
        """
        features: dict[str, int | float | bool] = {}

        # Parse — tolerant of garbage input.
        try:
            parsed = self._safe_parse(url)
        except Exception:
            # Truly unparseable: return zero-filled record.
            features = {name: _zero(name) for name in FEATURE_NAMES}
            return FeatureRecord(
                sample_id=sample_id,
                url=url,
                features=features,
                schema_version=self._schema_version,
                split=split,
                label=label,
            )

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        scheme = (parsed.scheme or "").lower()

        # ── Lexical ────────────────────────────────────────────────────
        features["url_length"] = len(url)
        features["hostname_length"] = len(hostname)
        features["path_length"] = len(path)
        features["query_length"] = len(query)
        features["fragment_length"] = len(fragment)

        digit_count = sum(c.isdigit() for c in url)
        features["digit_count"] = digit_count
        features["digit_ratio"] = digit_count / max(len(url), 1)

        alpha_count = sum(c.isalpha() for c in url)
        features["alpha_count"] = alpha_count
        features["alpha_ratio"] = alpha_count / max(len(url), 1)

        special = sum(1 for c in url if not c.isalnum())
        features["special_char_count"] = special
        features["special_char_ratio"] = special / max(len(url), 1)

        tokens = [t for t in _RE_TOKEN_SPLIT.split(url) if t]
        features["url_token_count"] = len(tokens)

        url_lower = url.lower()
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        features["suspicious_keyword_count"] = len(found_keywords)
        features["has_suspicious_keyword"] = len(found_keywords) > 0

        # ── Structural ─────────────────────────────────────────────────
        features["subdomain_count"] = self._subdomain_count(hostname)
        path_segments = [s for s in path.split("/") if s]
        features["path_depth"] = len(path_segments)

        query_params = parse_qsl(query, keep_blank_values=True) if query else []
        features["query_param_count"] = len(query_params)

        features["has_fragment"] = len(fragment) > 0
        try:
            features["has_port"] = parsed.port is not None
        except (ValueError, TypeError):
            # e.g. data: URIs where urlparse can't extract a port
            features["has_port"] = False
        features["is_ip_host"] = self._is_ip(hostname)
        features["is_https"] = scheme == "https"

        hostname_parts = hostname.split(".") if hostname else []
        features["hostname_token_count"] = len(hostname_parts)

        features["path_max_segment_length"] = (
            max((len(s) for s in path_segments), default=0)
        )
        features["query_max_value_length"] = (
            max((len(v) for _, v in query_params), default=0)
        )

        # ── Obfuscation ────────────────────────────────────────────────
        features["is_punycode"] = any(
            label.startswith("xn--") for label in hostname.lower().split(".")
        ) if hostname else False

        pct_triplets = _RE_PCT_ENCODED.findall(url)
        features["pct_encoded_count"] = len(pct_triplets)
        features["pct_encoded_ratio"] = len(pct_triplets) / max(len(url), 1)

        features["has_at_sign"] = "@" in url
        features["has_double_slash_redirect"] = bool(
            _RE_DOUBLE_SLASH_PATH.search(path)
        )
        features["has_hex_encoding_in_host"] = "%" in (parsed.netloc or "")

        features["hostname_entropy"] = self._shannon_entropy(hostname)
        features["hostname_consonant_ratio"] = self._consonant_ratio(hostname)

        host_digits = sum(c.isdigit() for c in hostname)
        features["hostname_digit_ratio"] = host_digits / max(len(hostname), 1)

        features["has_shortener_pattern"] = self._is_shortener(hostname)
        features["has_data_uri"] = url.strip().lower().startswith("data:")

        # ── Domain ─────────────────────────────────────────────────────
        tld = self._extract_tld(hostname)
        features["tld"] = hash(tld) % (2**31)  # stable int encoding
        features["tld_length"] = len(tld)

        reg_domain = extract_registrable_domain(url) or ""
        features["registrable_domain_length"] = len(reg_domain)
        features["domain_token_count"] = len(hostname_parts)
        features["domain_has_hyphen"] = "-" in reg_domain
        features["domain_has_digit"] = any(c.isdigit() for c in reg_domain)

        subdomain_str = self._subdomain_string(hostname)
        features["subdomain_length"] = len(subdomain_str)

        return FeatureRecord(
            sample_id=sample_id,
            url=url,
            features=features,
            schema_version=self._schema_version,
            split=split,
            label=label,
        )

    def extract_batch(
        self,
        urls: list[str],
        *,
        sample_ids: list[str] | None = None,
        splits: list[str | None] | None = None,
        labels: list[str | None] | None = None,
    ) -> list[FeatureRecord]:
        """Extract features for a batch of URLs.

        Parameters
        ----------
        urls : list[str]
            URL strings.
        sample_ids : list[str] | None
            Parallel list of sample IDs.
        splits : list[str | None] | None
            Parallel list of split tags.
        labels : list[str | None] | None
            Parallel list of labels.

        Returns
        -------
        list[FeatureRecord]
        """
        n = len(urls)
        ids = sample_ids or [""] * n
        sp = splits or [None] * n
        lb = labels or [None] * n
        return [
            self.extract(u, sample_id=sid, split=s, label=la)
            for u, sid, s, la in zip(urls, ids, sp, lb, strict=True)
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_parse(url: str) -> ParseResult:
        """Parse *url* tolerantly, adding a scheme when missing."""
        if not url or not url.strip():
            return urlparse("https://")
        # urlparse needs a scheme to parse netloc correctly.
        test_url = url if "://" in url else f"https://{url}"
        return urlparse(test_url)

    @staticmethod
    def _is_ip(hostname: str) -> bool:
        """Check if *hostname* is an IPv4 or IPv6 address."""
        if not hostname:
            return False
        if _RE_IPV4.match(hostname):
            return True
        return bool(_RE_IPV6_BRACKET.match(hostname) or ":" in hostname)

    @staticmethod
    def _subdomain_count(hostname: str) -> int:
        """Count subdomain levels, aware of multi-level TLDs."""
        if not hostname:
            return 0
        parts = hostname.lower().split(".")
        if len(parts) <= 2:
            return 0
        # Check for two-level public suffix.
        if len(parts) >= 3:
            two_level = f"{parts[-2]}.{parts[-1]}"
            if two_level in _PUBLIC_SUFFIXES:
                # eTLD is 2 labels → registrable domain is parts[-3].two_level
                return max(len(parts) - 3, 0)
        # Single-level TLD → registrable domain is parts[-2].parts[-1]
        return max(len(parts) - 2, 0)

    @staticmethod
    def _subdomain_string(hostname: str) -> str:
        """Return the subdomain portion (everything left of the registrable domain)."""
        if not hostname:
            return ""
        parts = hostname.lower().split(".")
        if len(parts) <= 2:
            return ""
        # Check for two-level public suffix.
        if len(parts) >= 3:
            two_level = f"{parts[-2]}.{parts[-1]}"
            if two_level in _PUBLIC_SUFFIXES:
                return ".".join(parts[:-3])
        return ".".join(parts[:-2])

    @staticmethod
    def _extract_tld(hostname: str) -> str:
        """Extract the effective TLD from *hostname*."""
        if not hostname:
            return ""
        parts = hostname.lower().split(".")
        if len(parts) < 2:
            return hostname.lower()
        # Check for two-level TLD.
        two_level = f"{parts[-2]}.{parts[-1]}"
        if two_level in _PUBLIC_SUFFIXES:
            return two_level
        return parts[-1]

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Compute Shannon entropy (bits) of string *s*."""
        if not s:
            return 0.0
        counts = Counter(s.lower())
        length = len(s)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 6)

    @staticmethod
    def _consonant_ratio(hostname: str) -> float:
        """Ratio of consonants to total alphabetic characters in *hostname*."""
        alpha_chars = [c for c in hostname if c.isalpha()]
        if not alpha_chars:
            return 0.0
        consonants = sum(1 for c in alpha_chars if c in _CONSONANTS)
        return consonants / len(alpha_chars)

    @staticmethod
    def _is_shortener(hostname: str) -> bool:
        """Check if *hostname* matches a known URL shortener domain."""
        if not hostname:
            return False
        hl = hostname.lower()
        return hl in URL_SHORTENER_DOMAINS or (
            hl.startswith("www.") and hl[4:] in URL_SHORTENER_DOMAINS
        )


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _zero(name: str) -> int | float | bool:
    """Return the zero/default value for the feature named *name*."""
    from .schema import FEATURE_MAP, FeatureType

    meta = FEATURE_MAP.get(name)
    if meta is None:
        return 0
    if meta.feature_type == FeatureType.BOOL:
        return False
    if meta.feature_type == FeatureType.FLOAT:
        return 0.0
    return 0
