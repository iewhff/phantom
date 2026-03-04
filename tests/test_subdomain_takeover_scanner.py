"""Tests for scanning/modules/subdomain_takeover_scanner.py."""

from __future__ import annotations

import pytest

from scanning.modules.subdomain_takeover_scanner import (
    TAKEOVER_SCANNER_VERSION,
    ServiceFingerprints,
    TakeoverCandidate,
)


class TestTakeoverScannerVersion:
    """Tests for the TAKEOVER_SCANNER_VERSION constant."""

    def test_version_value(self):
        assert TAKEOVER_SCANNER_VERSION == "1.0.0"

    def test_version_is_string(self):
        assert isinstance(TAKEOVER_SCANNER_VERSION, str)


class TestTakeoverCandidate:
    """Tests for the TakeoverCandidate dataclass."""

    def test_defaults(self):
        candidate = TakeoverCandidate(
            subdomain="sub.example.com",
            cname="sub.example.com.s3.amazonaws.com",
            service="aws_s3",
            confidence=80,
        )
        assert candidate.subdomain == "sub.example.com"
        assert candidate.cname == "sub.example.com.s3.amazonaws.com"
        assert candidate.service == "aws_s3"
        assert candidate.confidence == 80
        assert candidate.evidence == []
        assert candidate.fingerprint_matched is False
        assert candidate.dns_vulnerable is False

    def test_full_creation(self):
        candidate = TakeoverCandidate(
            subdomain="app.target.com",
            cname="app.target.com.herokuapp.com",
            service="heroku",
            confidence=95,
            evidence=["No such app", "NXDOMAIN response"],
            fingerprint_matched=True,
            dns_vulnerable=True,
        )
        assert candidate.subdomain == "app.target.com"
        assert candidate.cname == "app.target.com.herokuapp.com"
        assert candidate.service == "heroku"
        assert candidate.confidence == 95
        assert candidate.evidence == ["No such app", "NXDOMAIN response"]
        assert candidate.fingerprint_matched is True
        assert candidate.dns_vulnerable is True

    def test_evidence_default_is_independent_per_instance(self):
        """Each instance should get its own empty list, not a shared one."""
        c1 = TakeoverCandidate(
            subdomain="a.example.com", cname="a.cdn.com", service="fastly", confidence=50
        )
        c2 = TakeoverCandidate(
            subdomain="b.example.com", cname="b.cdn.com", service="fastly", confidence=50
        )
        c1.evidence.append("test")
        assert c2.evidence == []


class TestServiceFingerprints:
    """Tests for the ServiceFingerprints.SERVICES dictionary."""

    VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW", "CRITICAL"}
    REQUIRED_KEYS = {"cname_patterns", "fingerprints", "nxdomain", "severity"}

    EXPECTED_SERVICE_KEYS = [
        "aws_s3",
        "aws_cloudfront",
        "aws_elasticbeanstalk",
        "aws_elb",
        "azure_blob",
        "azure_websites",
        "azure_cloudapp",
        "azure_trafficmanager",
        "github_pages",
        "heroku",
        "shopify",
        "zendesk",
        "fastly",
        "pantheon",
        "tumblr",
        "wordpress",
        "surge",
    ]

    def test_services_count_minimum(self):
        assert len(ServiceFingerprints.SERVICES) >= 12

    def test_services_is_dict(self):
        assert isinstance(ServiceFingerprints.SERVICES, dict)

    @pytest.mark.parametrize("key", EXPECTED_SERVICE_KEYS)
    def test_expected_service_exists(self, key: str):
        assert key in ServiceFingerprints.SERVICES, (
            f"Expected service '{key}' not found in SERVICES"
        )

    @pytest.mark.parametrize(
        "service_name",
        list(ServiceFingerprints.SERVICES.keys()),
    )
    def test_service_has_required_keys(self, service_name: str):
        entry = ServiceFingerprints.SERVICES[service_name]
        missing = self.REQUIRED_KEYS - set(entry.keys())
        assert not missing, (
            f"Service '{service_name}' missing keys: {missing}"
        )

    @pytest.mark.parametrize(
        "service_name",
        list(ServiceFingerprints.SERVICES.keys()),
    )
    def test_cname_patterns_are_nonempty_list_of_strings(self, service_name: str):
        patterns = ServiceFingerprints.SERVICES[service_name]["cname_patterns"]
        assert isinstance(patterns, list), (
            f"'{service_name}' cname_patterns should be a list"
        )
        assert len(patterns) > 0, (
            f"'{service_name}' cname_patterns should not be empty"
        )
        for pat in patterns:
            assert isinstance(pat, str), (
                f"'{service_name}' cname_pattern entry {pat!r} should be a string"
            )

    @pytest.mark.parametrize(
        "service_name",
        list(ServiceFingerprints.SERVICES.keys()),
    )
    def test_fingerprints_is_list_of_strings(self, service_name: str):
        fps = ServiceFingerprints.SERVICES[service_name]["fingerprints"]
        assert isinstance(fps, list), (
            f"'{service_name}' fingerprints should be a list"
        )
        for fp in fps:
            assert isinstance(fp, str), (
                f"'{service_name}' fingerprint entry {fp!r} should be a string"
            )

    @pytest.mark.parametrize(
        "service_name",
        list(ServiceFingerprints.SERVICES.keys()),
    )
    def test_nxdomain_is_bool(self, service_name: str):
        val = ServiceFingerprints.SERVICES[service_name]["nxdomain"]
        assert isinstance(val, bool), (
            f"'{service_name}' nxdomain should be a bool, got {type(val)}"
        )

    @pytest.mark.parametrize(
        "service_name",
        list(ServiceFingerprints.SERVICES.keys()),
    )
    def test_severity_is_valid(self, service_name: str):
        sev = ServiceFingerprints.SERVICES[service_name]["severity"]
        assert sev in self.VALID_SEVERITIES, (
            f"'{service_name}' severity '{sev}' not in {self.VALID_SEVERITIES}"
        )

    # ------------------------------------------------------------------
    # Specific fingerprint checks for key services
    # ------------------------------------------------------------------
    def test_s3_fingerprint_nosuchbucket(self):
        fps = ServiceFingerprints.SERVICES["aws_s3"]["fingerprints"]
        assert "NoSuchBucket" in fps

    def test_heroku_fingerprint_no_such_app(self):
        fps = ServiceFingerprints.SERVICES["heroku"]["fingerprints"]
        assert "No such app" in fps

    def test_github_pages_fingerprint(self):
        fps = ServiceFingerprints.SERVICES["github_pages"]["fingerprints"]
        assert "There isn't a GitHub Pages site here" in fps

    def test_fastly_fingerprint_unknown_domain(self):
        fps = ServiceFingerprints.SERVICES["fastly"]["fingerprints"]
        assert "Fastly error: unknown domain" in fps

    def test_azure_blob_fingerprint_blobnotfound(self):
        fps = ServiceFingerprints.SERVICES["azure_blob"]["fingerprints"]
        assert "BlobNotFound" in fps

    def test_azure_websites_fingerprint(self):
        fps = ServiceFingerprints.SERVICES["azure_websites"]["fingerprints"]
        assert "404 Web Site not found" in fps

    # ------------------------------------------------------------------
    # Specific cname pattern checks
    # ------------------------------------------------------------------
    def test_s3_cname_pattern(self):
        patterns = ServiceFingerprints.SERVICES["aws_s3"]["cname_patterns"]
        assert ".s3.amazonaws.com" in patterns

    def test_cloudfront_cname_pattern(self):
        patterns = ServiceFingerprints.SERVICES["aws_cloudfront"]["cname_patterns"]
        assert ".cloudfront.net" in patterns

    def test_heroku_cname_pattern(self):
        patterns = ServiceFingerprints.SERVICES["heroku"]["cname_patterns"]
        assert ".herokuapp.com" in patterns

    def test_github_pages_cname_pattern(self):
        patterns = ServiceFingerprints.SERVICES["github_pages"]["cname_patterns"]
        assert ".github.io" in patterns

    # ------------------------------------------------------------------
    # Specific nxdomain and severity checks
    # ------------------------------------------------------------------
    def test_s3_nxdomain_true(self):
        assert ServiceFingerprints.SERVICES["aws_s3"]["nxdomain"] is True

    def test_cloudfront_nxdomain_false(self):
        assert ServiceFingerprints.SERVICES["aws_cloudfront"]["nxdomain"] is False

    def test_s3_severity_high(self):
        assert ServiceFingerprints.SERVICES["aws_s3"]["severity"] == "HIGH"

    def test_cloudfront_severity_medium(self):
        assert ServiceFingerprints.SERVICES["aws_cloudfront"]["severity"] == "MEDIUM"

    def test_heroku_severity_high(self):
        assert ServiceFingerprints.SERVICES["heroku"]["severity"] == "HIGH"

    def test_github_pages_severity_medium(self):
        assert ServiceFingerprints.SERVICES["github_pages"]["severity"] == "MEDIUM"
