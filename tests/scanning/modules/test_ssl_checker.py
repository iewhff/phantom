"""
Tests for scanning/modules/ssl_checker.py - SSL/TLS Security Scanner.

Covers:
- TLSVulnerability enum
- CipherStrength enum
- CipherInfo dataclass
- CertificateInfo dataclass
- TLSVulnResult dataclass
"""

import pytest
from datetime import datetime

from scanning.modules.ssl_checker import (
    TLSVulnerability,
    CipherStrength,
    CipherInfo,
    CertificateInfo,
    TLSVulnResult,
)


# =============================================================================
# TLS VULNERABILITY ENUM TESTS
# =============================================================================

class TestTLSVulnerability:
    """Tests for TLSVulnerability enum."""

    def test_heartbleed_exists(self):
        """Test Heartbleed vulnerability is defined."""
        assert TLSVulnerability.HEARTBLEED
        assert TLSVulnerability.HEARTBLEED.value == "heartbleed"

    def test_poodle_exists(self):
        """Test POODLE vulnerability is defined."""
        assert TLSVulnerability.POODLE
        assert TLSVulnerability.POODLE.value == "poodle"

    def test_beast_exists(self):
        """Test BEAST vulnerability is defined."""
        assert TLSVulnerability.BEAST
        assert TLSVulnerability.BEAST.value == "beast"

    def test_crime_exists(self):
        """Test CRIME vulnerability is defined."""
        assert TLSVulnerability.CRIME
        assert TLSVulnerability.CRIME.value == "crime"

    def test_breach_exists(self):
        """Test BREACH vulnerability is defined."""
        assert TLSVulnerability.BREACH
        assert TLSVulnerability.BREACH.value == "breach"

    def test_robot_exists(self):
        """Test ROBOT vulnerability is defined."""
        assert TLSVulnerability.ROBOT
        assert TLSVulnerability.ROBOT.value == "robot"

    def test_drown_exists(self):
        """Test DROWN vulnerability is defined."""
        assert TLSVulnerability.DROWN
        assert TLSVulnerability.DROWN.value == "drown"

    def test_freak_exists(self):
        """Test FREAK vulnerability is defined."""
        assert TLSVulnerability.FREAK
        assert TLSVulnerability.FREAK.value == "freak"

    def test_logjam_exists(self):
        """Test Logjam vulnerability is defined."""
        assert TLSVulnerability.LOGJAM
        assert TLSVulnerability.LOGJAM.value == "logjam"

    def test_lucky13_exists(self):
        """Test Lucky13 vulnerability is defined."""
        assert TLSVulnerability.LUCKY13
        assert TLSVulnerability.LUCKY13.value == "lucky13"

    def test_sweet32_exists(self):
        """Test Sweet32 vulnerability is defined."""
        assert TLSVulnerability.SWEET32
        assert TLSVulnerability.SWEET32.value == "sweet32"

    def test_ticketbleed_exists(self):
        """Test Ticketbleed vulnerability is defined."""
        assert TLSVulnerability.TICKETBLEED
        assert TLSVulnerability.TICKETBLEED.value == "ticketbleed"

    def test_roca_exists(self):
        """Test ROCA vulnerability is defined."""
        assert TLSVulnerability.ROCA
        assert TLSVulnerability.ROCA.value == "roca"

    def test_goldendoodle_exists(self):
        """Test Goldendoodle vulnerability is defined."""
        assert TLSVulnerability.GOLDENDOODLE
        assert TLSVulnerability.GOLDENDOODLE.value == "goldendoodle"

    def test_zombie_poodle_exists(self):
        """Test Zombie POODLE vulnerability is defined."""
        assert TLSVulnerability.ZOMBIE_POODLE
        assert TLSVulnerability.ZOMBIE_POODLE.value == "zombie_poodle"

    def test_raccoon_exists(self):
        """Test Raccoon vulnerability is defined."""
        assert TLSVulnerability.RACCOON
        assert TLSVulnerability.RACCOON.value == "raccoon"

    def test_all_vulnerabilities_count(self):
        """Test total number of known vulnerabilities."""
        # Should have at least 15 known vulnerabilities
        assert len(TLSVulnerability) >= 15


# =============================================================================
# CIPHER STRENGTH ENUM TESTS
# =============================================================================

class TestCipherStrength:
    """Tests for CipherStrength enum."""

    def test_insecure_exists(self):
        """Test INSECURE strength is defined."""
        assert CipherStrength.INSECURE
        assert CipherStrength.INSECURE.value == "insecure"

    def test_weak_exists(self):
        """Test WEAK strength is defined."""
        assert CipherStrength.WEAK
        assert CipherStrength.WEAK.value == "weak"

    def test_acceptable_exists(self):
        """Test ACCEPTABLE strength is defined."""
        assert CipherStrength.ACCEPTABLE
        assert CipherStrength.ACCEPTABLE.value == "acceptable"

    def test_strong_exists(self):
        """Test STRONG strength is defined."""
        assert CipherStrength.STRONG
        assert CipherStrength.STRONG.value == "strong"

    def test_recommended_exists(self):
        """Test RECOMMENDED strength is defined."""
        assert CipherStrength.RECOMMENDED
        assert CipherStrength.RECOMMENDED.value == "recommended"

    def test_all_strengths_count(self):
        """Test total number of strength levels."""
        assert len(CipherStrength) == 5


# =============================================================================
# CIPHER INFO DATACLASS TESTS
# =============================================================================

class TestCipherInfo:
    """Tests for CipherInfo dataclass."""

    def test_creation_modern_cipher(self):
        """Test creating CipherInfo for modern cipher."""
        cipher = CipherInfo(
            name="TLS_AES_256_GCM_SHA384",
            protocol="TLSv1.3",
            key_exchange="ECDHE",
            authentication="ECDSA",
            encryption="AES-256-GCM",
            mac="AEAD",
            key_size=256,
            strength=CipherStrength.RECOMMENDED,
            pfs=True,
            aead=True,
        )

        assert cipher.name == "TLS_AES_256_GCM_SHA384"
        assert cipher.protocol == "TLSv1.3"
        assert cipher.key_size == 256
        assert cipher.strength == CipherStrength.RECOMMENDED
        assert cipher.pfs is True
        assert cipher.aead is True

    def test_creation_weak_cipher(self):
        """Test creating CipherInfo for weak cipher."""
        cipher = CipherInfo(
            name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            protocol="TLSv1.0",
            key_exchange="RSA",
            authentication="RSA",
            encryption="3DES",
            mac="SHA1",
            key_size=112,
            strength=CipherStrength.WEAK,
            pfs=False,
            aead=False,
        )

        assert cipher.name == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
        assert cipher.key_size == 112
        assert cipher.strength == CipherStrength.WEAK
        assert cipher.pfs is False
        assert cipher.aead is False

    def test_creation_insecure_cipher(self):
        """Test creating CipherInfo for insecure cipher."""
        cipher = CipherInfo(
            name="SSL_RSA_WITH_NULL_MD5",
            protocol="SSLv3",
            key_exchange="RSA",
            authentication="RSA",
            encryption="NULL",
            mac="MD5",
            key_size=0,
            strength=CipherStrength.INSECURE,
            pfs=False,
            aead=False,
        )

        assert cipher.encryption == "NULL"
        assert cipher.mac == "MD5"
        assert cipher.key_size == 0
        assert cipher.strength == CipherStrength.INSECURE


# =============================================================================
# CERTIFICATE INFO DATACLASS TESTS
# =============================================================================

class TestCertificateInfo:
    """Tests for CertificateInfo dataclass."""

    def test_creation_valid_cert(self):
        """Test creating CertificateInfo for valid certificate."""
        cert = CertificateInfo(
            subject={"CN": "example.com", "O": "Example Inc"},
            issuer={"CN": "DigiCert", "O": "DigiCert Inc"},
            serial_number="0123456789ABCDEF",
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            san=["example.com", "www.example.com", "api.example.com"],
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size=2048,
            fingerprint_sha256="AB:CD:EF:12:34:56",
            chain_valid=True,
            self_signed=False,
            ct_enabled=True,
        )

        assert cert.subject["CN"] == "example.com"
        assert cert.issuer["CN"] == "DigiCert"
        assert cert.public_key_size == 2048
        assert cert.chain_valid is True
        assert cert.self_signed is False
        assert cert.ct_enabled is True
        assert len(cert.san) == 3

    def test_creation_self_signed_cert(self):
        """Test creating CertificateInfo for self-signed certificate."""
        cert = CertificateInfo(
            subject={"CN": "localhost"},
            issuer={"CN": "localhost"},
            serial_number="1234567890",
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            san=["localhost", "127.0.0.1"],
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size=2048,
            fingerprint_sha256="AA:BB:CC:DD",
            chain_valid=False,
            self_signed=True,
            ct_enabled=False,
        )

        assert cert.self_signed is True
        assert cert.chain_valid is False
        assert cert.ct_enabled is False

    def test_creation_expired_cert(self):
        """Test creating CertificateInfo for expired certificate."""
        cert = CertificateInfo(
            subject={"CN": "expired.example.com"},
            issuer={"CN": "CA"},
            serial_number="EXPIRED",
            not_before=datetime(2020, 1, 1),
            not_after=datetime(2021, 1, 1),  # Expired
            san=["expired.example.com"],
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size=2048,
            fingerprint_sha256="EX:PI:RE:D",
            chain_valid=True,
            self_signed=False,
            ct_enabled=False,
        )

        # Check expiration
        assert cert.not_after < datetime.now()

    def test_san_list(self):
        """Test SAN (Subject Alternative Name) list."""
        cert = CertificateInfo(
            subject={"CN": "example.com"},
            issuer={"CN": "CA"},
            serial_number="123",
            not_before=datetime.now(),
            not_after=datetime.now(),
            san=["example.com", "*.example.com", "api.example.com"],
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size=2048,
            fingerprint_sha256="FP",
            chain_valid=True,
            self_signed=False,
            ct_enabled=True,
        )

        assert "*.example.com" in cert.san  # Wildcard
        assert len(cert.san) == 3

    def test_ecdsa_key_type(self):
        """Test ECDSA key type certificate."""
        cert = CertificateInfo(
            subject={"CN": "ecdsa.example.com"},
            issuer={"CN": "CA"},
            serial_number="ECDSA123",
            not_before=datetime.now(),
            not_after=datetime.now(),
            san=["ecdsa.example.com"],
            signature_algorithm="ecdsa-with-SHA256",
            public_key_type="EC",
            public_key_size=256,  # P-256 curve
            fingerprint_sha256="EC:DS:A",
            chain_valid=True,
            self_signed=False,
            ct_enabled=True,
        )

        assert cert.public_key_type == "EC"
        assert cert.public_key_size == 256


# =============================================================================
# TLS VULN RESULT DATACLASS TESTS
# =============================================================================

class TestTLSVulnResult:
    """Tests for TLSVulnResult dataclass."""

    def test_creation_vulnerable(self):
        """Test creating result for vulnerable target."""
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.HEARTBLEED,
            vulnerable=True,
            evidence=["Server responded to malformed heartbeat", "Memory leak detected"],
            cve="CVE-2014-0160",
            cvss=9.8,
        )

        assert result.vulnerability == TLSVulnerability.HEARTBLEED
        assert result.vulnerable is True
        assert len(result.evidence) == 2
        assert result.cve == "CVE-2014-0160"
        assert result.cvss == 9.8

    def test_creation_not_vulnerable(self):
        """Test creating result for non-vulnerable target."""
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.POODLE,
            vulnerable=False,
            evidence=["SSLv3 not supported"],
        )

        assert result.vulnerability == TLSVulnerability.POODLE
        assert result.vulnerable is False
        assert result.cve is None
        assert result.cvss == 0.0

    def test_default_values(self):
        """Test default values for optional fields."""
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.BEAST,
            vulnerable=False,
            evidence=[],
        )

        assert result.cve is None
        assert result.cvss == 0.0

    def test_various_vulnerabilities(self):
        """Test creating results for various vulnerabilities."""
        vulnerabilities = [
            (TLSVulnerability.DROWN, "CVE-2016-0800", 5.9),
            (TLSVulnerability.FREAK, "CVE-2015-0204", 5.9),
            (TLSVulnerability.LOGJAM, "CVE-2015-4000", 4.3),
            (TLSVulnerability.SWEET32, "CVE-2016-2183", 7.5),
            (TLSVulnerability.ROBOT, "CVE-2017-13099", 7.4),
        ]

        for vuln, cve, cvss in vulnerabilities:
            result = TLSVulnResult(
                vulnerability=vuln,
                vulnerable=True,
                evidence=["Test evidence"],
                cve=cve,
                cvss=cvss,
            )

            assert result.vulnerability == vuln
            assert result.cve == cve
            assert result.cvss == cvss


# =============================================================================
# VULNERABILITY COVERAGE TESTS
# =============================================================================

class TestVulnerabilityCoverage:
    """Tests for comprehensive vulnerability coverage."""

    def test_all_major_vulns_have_values(self):
        """Test all major vulnerabilities have string values."""
        major_vulns = [
            TLSVulnerability.HEARTBLEED,
            TLSVulnerability.POODLE,
            TLSVulnerability.BEAST,
            TLSVulnerability.CRIME,
            TLSVulnerability.DROWN,
            TLSVulnerability.FREAK,
            TLSVulnerability.LOGJAM,
        ]

        for vuln in major_vulns:
            assert isinstance(vuln.value, str)
            assert len(vuln.value) > 0

    def test_vuln_values_lowercase(self):
        """Test vulnerability values are lowercase."""
        for vuln in TLSVulnerability:
            assert vuln.value == vuln.value.lower()

    def test_cipher_strength_ordered(self):
        """Test cipher strength has logical ordering."""
        strengths = [
            CipherStrength.INSECURE,
            CipherStrength.WEAK,
            CipherStrength.ACCEPTABLE,
            CipherStrength.STRONG,
            CipherStrength.RECOMMENDED,
        ]

        # Verify all exist and are distinct
        values = [s.value for s in strengths]
        assert len(set(values)) == 5


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_san_list(self):
        """Test certificate with empty SAN list."""
        cert = CertificateInfo(
            subject={"CN": "old.example.com"},
            issuer={"CN": "CA"},
            serial_number="OLD",
            not_before=datetime.now(),
            not_after=datetime.now(),
            san=[],  # Empty SAN (old certificates)
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size=2048,
            fingerprint_sha256="OLD",
            chain_valid=True,
            self_signed=False,
            ct_enabled=False,
        )

        assert cert.san == []

    def test_empty_evidence_list(self):
        """Test vulnerability result with empty evidence."""
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.CRIME,
            vulnerable=False,
            evidence=[],
        )

        assert result.evidence == []

    def test_large_key_size(self):
        """Test cipher with large key size."""
        cipher = CipherInfo(
            name="TLS_AES_256_GCM_SHA384",
            protocol="TLSv1.3",
            key_exchange="ECDHE",
            authentication="ECDSA",
            encryption="AES-256-GCM",
            mac="AEAD",
            key_size=256,
            strength=CipherStrength.RECOMMENDED,
            pfs=True,
            aead=True,
        )

        assert cipher.key_size == 256

    def test_small_rsa_key(self):
        """Test certificate with small RSA key (insecure)."""
        cert = CertificateInfo(
            subject={"CN": "weak.example.com"},
            issuer={"CN": "CA"},
            serial_number="WEAK",
            not_before=datetime.now(),
            not_after=datetime.now(),
            san=["weak.example.com"],
            signature_algorithm="sha1WithRSAEncryption",  # Weak
            public_key_type="RSA",
            public_key_size=1024,  # Too small
            fingerprint_sha256="WEAK",
            chain_valid=True,
            self_signed=False,
            ct_enabled=False,
        )

        assert cert.public_key_size == 1024
        assert "sha1" in cert.signature_algorithm.lower()
