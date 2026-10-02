"""Utility functions for dataset processing."""

from __future__ import annotations

import hashlib
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Public Suffix List - minimal embedded version for common TLDs
# In production, use the full list from https://publicsuffix.org/
_PUBLIC_SUFFIXES = {
    # Common TLDs
    "com", "org", "net", "edu", "gov", "mil", "int",
    # Country codes (sample)
    "uk", "us", "ca", "au", "de", "fr", "jp", "cn", "in", "br",
    # Special cases
    "co.uk", "ac.uk", "gov.uk",
    "co.jp", "ac.jp", "go.jp",
    "com.au", "gov.au", "edu.au",
    "co.in", "ac.in", "gov.in",
}

logger = logging.getLogger(__name__)


def normalize_url(url: str) -> str:
    """Normalize a URL for deduplication.

    Normalization rules:
    - Lowercase scheme and domain
    - Remove URL fragments (#...)
    - Sort query parameters alphabetically
    - Remove default ports (:80 for http, :443 for https)
    - Strip trailing / from path (unless path is /)
    - Decode percent-encoding where safe
    - Remove www. prefix (configurable, currently enabled)

    Does NOT:
    - Remove all query parameters (they may be meaningful)
    - Decode all percent-encoding (some is semantic)
    - Change path structure (semantic)

    Parameters
    ----------
    url : str
        URL to normalize

    Returns
    -------
    str
        Normalized URL
    """
    # Add scheme if missing
    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)

    # Lowercase scheme and domain
    scheme = parsed.scheme.lower()
    netloc = parsed.hostname.lower() if parsed.hostname else ""

    # Add port if non-default
    if (
        parsed.port
        and not (scheme == "http" and parsed.port == 80)
        and not (scheme == "https" and parsed.port == 443)
    ):
        netloc = f"{netloc}:{parsed.port}"

    # Remove www. prefix
    if netloc.startswith("www."):
        netloc = netloc[4:]

    # Normalize path: strip trailing / unless it's the only character
    path = parsed.path
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    if not path:
        path = "/"

    # Sort query parameters alphabetically
    query = ""
    if parsed.query:
        params = sorted(parse_qsl(parsed.query, keep_blank_values=True))
        query = urlencode(params)

    # Reconstruct URL (no fragment)
    normalized = urlunparse((scheme, netloc, path, parsed.params, query, ""))

    return normalized


def extract_registrable_domain(url: str) -> str | None:
    """Extract registrable (eTLD+1) domain from URL.

    Examples:
    - https://sub.example.com/path → example.com
    - https://phishing.co.uk/page → phishing.co.uk
    - https://192.168.1.1/page → 192.168.1.1 (IP, no domain)

    Uses a minimal embedded public suffix list. For production use,
    consider the `publicsuffix2` or `tldextract` library.

    Parameters
    ----------
    url : str
        URL to extract domain from

    Returns
    -------
    str | None
        Registrable domain, or None if extraction fails or IP address
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname = parsed.hostname

    if not hostname:
        return None

    # Check if it's an IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        return hostname  # Return IP as-is (no registrable domain concept)

    # Check for IPv6
    if ":" in hostname:
        return hostname  # Return IPv6 as-is

    # Split into parts
    parts = hostname.lower().split(".")

    if len(parts) < 2:
        return hostname  # Single-label domain (unusual)

    # Check for two-level suffix (e.g., co.uk)
    if len(parts) >= 3:
        two_level = f"{parts[-2]}.{parts[-1]}"
        if two_level in _PUBLIC_SUFFIXES:
            return f"{parts[-3]}.{two_level}"

    # Check for single-level suffix (e.g., com)
    if parts[-1] in _PUBLIC_SUFFIXES:
        return f"{parts[-2]}.{parts[-1]}"

    # Unknown suffix, assume last two parts
    return f"{parts[-2]}.{parts[-1]}"


def validate_url(url: str) -> bool:
    """Validate that a string is a well-formed URL.

    Parameters
    ----------
    url : str
        URL to validate

    Returns
    -------
    bool
        True if valid, False otherwise
    """
    if not url or not url.strip():
        return False

    try:
        # Add scheme if missing for parsing
        test_url = url if "://" in url else f"https://{url}"
        parsed = urlparse(test_url)

        # Must have scheme and netloc
        if not parsed.scheme or parsed.scheme not in {"http", "https"}:
            return False

        if not parsed.netloc:
            return False

        # Check that netloc doesn't contain spaces or other invalid characters
        if " " in parsed.netloc or "\t" in parsed.netloc:
            return False

        # Must have valid hostname (not just whitespace)
        return bool(parsed.hostname and parsed.hostname.strip())
    except Exception:
        return False


def compute_structural_fingerprint(url: str) -> str:
    """Compute structural fingerprint for near-duplicate detection.

    Extracts:
    - Registrable domain
    - Path structure (replace path segments with /PATH/)
    - Query parameter keys (ignore values)

    Example:
    - https://phish.example.com/login/verify?id=123&token=xyz
      → hash(example.com || /PATH/PATH || id,token)

    Parameters
    ----------
    url : str
        URL to fingerprint

    Returns
    -------
    str
        SHA256 hash of structural components
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")

    # Extract domain
    domain = extract_registrable_domain(url) or parsed.netloc or ""

    # Extract path structure
    path = parsed.path
    if path and path != "/":
        # Replace each path segment with PATH
        segments = [seg for seg in path.split("/") if seg]
        path_structure = "/" + "/".join(["PATH"] * len(segments))
    else:
        path_structure = "/"

    # Extract query parameter keys
    query_keys = ""
    if parsed.query:
        keys = sorted([k for k, v in parse_qsl(parsed.query, keep_blank_values=True)])
        query_keys = ",".join(keys)

    # Compute fingerprint
    fingerprint_str = f"{domain}||{path_structure}||{query_keys}"
    return hashlib.sha256(fingerprint_str.encode("utf-8")).hexdigest()


def validate_label(label: str) -> bool:
    """Validate that a label is in the allowed set.

    Parameters
    ----------
    label : str
        Label to validate

    Returns
    -------
    bool
        True if valid, False otherwise
    """
    return label in {"phishing", "benign"}
