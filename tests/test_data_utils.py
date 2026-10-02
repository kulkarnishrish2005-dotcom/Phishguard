"""Tests for URL normalization and utility functions."""

from __future__ import annotations

from ml.data.utils import (
    compute_structural_fingerprint,
    extract_registrable_domain,
    normalize_url,
    validate_label,
    validate_url,
)


class TestNormalizeURL:
    """Tests for URL normalization."""

    def test_basic_normalization(self) -> None:
        """Test basic URL normalization."""
        url = "HTTPS://EXAMPLE.COM/PATH"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/PATH"

    def test_remove_www(self) -> None:
        """Test www. prefix removal."""
        url = "https://www.example.com/path"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/path"

    def test_remove_fragment(self) -> None:
        """Test fragment removal."""
        url = "https://example.com/path#section"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/path"

    def test_sort_query_params(self) -> None:
        """Test query parameter sorting."""
        url = "https://example.com/path?z=1&a=2&m=3"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/path?a=2&m=3&z=1"

    def test_remove_default_port_http(self) -> None:
        """Test default port removal for HTTP."""
        url = "http://example.com:80/path"
        normalized = normalize_url(url)
        assert normalized == "http://example.com/path"

    def test_remove_default_port_https(self) -> None:
        """Test default port removal for HTTPS."""
        url = "https://example.com:443/path"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/path"

    def test_keep_non_default_port(self) -> None:
        """Test that non-default ports are preserved."""
        url = "https://example.com:8443/path"
        normalized = normalize_url(url)
        assert normalized == "https://example.com:8443/path"

    def test_strip_trailing_slash(self) -> None:
        """Test trailing slash removal."""
        url = "https://example.com/path/"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/path"

    def test_keep_root_slash(self) -> None:
        """Test that root slash is preserved."""
        url = "https://example.com/"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/"

    def test_add_scheme_if_missing(self) -> None:
        """Test scheme addition."""
        url = "example.com/path"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/path"

    def test_empty_path(self) -> None:
        """Test URL with no path."""
        url = "https://example.com"
        normalized = normalize_url(url)
        assert normalized == "https://example.com/"

    def test_complex_url(self) -> None:
        """Test complex URL with multiple transformations."""
        url = "HTTP://WWW.EXAMPLE.COM:80/Path/?z=1&a=2#fragment"
        normalized = normalize_url(url)
        assert normalized == "http://example.com/Path?a=2&z=1"


class TestExtractRegistrableDomain:
    """Tests for registrable domain extraction."""

    def test_simple_domain(self) -> None:
        """Test simple domain extraction."""
        domain = extract_registrable_domain("https://example.com/path")
        assert domain == "example.com"

    def test_subdomain(self) -> None:
        """Test subdomain extraction."""
        domain = extract_registrable_domain("https://sub.example.com/path")
        assert domain == "example.com"

    def test_deep_subdomain(self) -> None:
        """Test deep subdomain extraction."""
        domain = extract_registrable_domain("https://a.b.c.example.com/path")
        assert domain == "example.com"

    def test_two_level_suffix(self) -> None:
        """Test two-level suffix (e.g., co.uk)."""
        domain = extract_registrable_domain("https://example.co.uk/path")
        assert domain == "example.co.uk"

    def test_subdomain_with_two_level_suffix(self) -> None:
        """Test subdomain with two-level suffix."""
        domain = extract_registrable_domain("https://sub.example.co.uk/path")
        assert domain == "example.co.uk"

    def test_ip_address(self) -> None:
        """Test IP address (no registrable domain concept)."""
        domain = extract_registrable_domain("https://192.168.1.1/path")
        assert domain == "192.168.1.1"

    def test_ipv6(self) -> None:
        """Test IPv6 address."""
        domain = extract_registrable_domain("https://[2001:db8::1]/path")
        # urlparse strips brackets from IPv6 hostname
        assert domain == "2001:db8::1"

    def test_no_scheme(self) -> None:
        """Test domain extraction without scheme."""
        domain = extract_registrable_domain("example.com/path")
        assert domain == "example.com"


class TestValidateURL:
    """Tests for URL validation."""

    def test_valid_https_url(self) -> None:
        """Test valid HTTPS URL."""
        assert validate_url("https://example.com/path") is True

    def test_valid_http_url(self) -> None:
        """Test valid HTTP URL."""
        assert validate_url("http://example.com/path") is True

    def test_valid_domain_only(self) -> None:
        """Test valid domain without scheme."""
        assert validate_url("example.com") is True

    def test_empty_string(self) -> None:
        """Test empty string."""
        assert validate_url("") is False

    def test_whitespace_only(self) -> None:
        """Test whitespace only."""
        assert validate_url("   ") is False

    def test_no_netloc(self) -> None:
        """Test URL without netloc."""
        assert validate_url("https://") is False

    def test_invalid_scheme(self) -> None:
        """Test invalid scheme."""
        assert validate_url("ftp://example.com") is False


class TestComputeStructuralFingerprint:
    """Tests for structural fingerprinting."""

    def test_same_structure_different_values(self) -> None:
        """Test URLs with same structure but different parameter values."""
        url1 = "https://phish.example.com/login/verify?id=123&token=abc"
        url2 = "https://phish.example.com/login/verify?id=456&token=xyz"

        fp1 = compute_structural_fingerprint(url1)
        fp2 = compute_structural_fingerprint(url2)

        assert fp1 == fp2

    def test_different_structure(self) -> None:
        """Test URLs with different structure."""
        url1 = "https://example.com/login/verify?id=123"
        url2 = "https://example.com/admin/panel?session=456"

        fp1 = compute_structural_fingerprint(url1)
        fp2 = compute_structural_fingerprint(url2)

        assert fp1 != fp2

    def test_different_domains(self) -> None:
        """Test URLs with different domains."""
        url1 = "https://example1.com/path"
        url2 = "https://example2.com/path"

        fp1 = compute_structural_fingerprint(url1)
        fp2 = compute_structural_fingerprint(url2)

        assert fp1 != fp2

    def test_different_path_length(self) -> None:
        """Test URLs with different path lengths."""
        url1 = "https://example.com/a/b/c"
        url2 = "https://example.com/x/y"

        fp1 = compute_structural_fingerprint(url1)
        fp2 = compute_structural_fingerprint(url2)

        # Different number of path segments
        assert fp1 != fp2


class TestValidateLabel:
    """Tests for label validation."""

    def test_valid_phishing(self) -> None:
        """Test valid phishing label."""
        assert validate_label("phishing") is True

    def test_valid_benign(self) -> None:
        """Test valid benign label."""
        assert validate_label("benign") is True

    def test_invalid_label(self) -> None:
        """Test invalid label."""
        assert validate_label("spam") is False
        assert validate_label("malware") is False
        assert validate_label("") is False
