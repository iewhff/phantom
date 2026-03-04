"""
Tests for scanning/modules/ssl_checker.py

Covers:
- TLSVulnerability enum (16 types)
- CipherStrength enum (5 levels)
- CipherInfo dataclass
- CertificateInfo dataclass
- TLSVulnResult dataclass
- SSLChecker class attributes (INSECURE_CIPHERS, WEAK_CIPHERS, STRONG_CIPHERS)
- CVE_DATABASE constant
- PROTOCOL_VERSIONS constant
- MIN_KEY_SIZES constant
"""

import pytest
import re
from datetime import datetime
from scanning.modules.ssl_checker import (
    TLSVulnerability,
    CipherStrength,
    CipherInfo,
    CertificateInfo,
    TLSVulnResult,
    SSLChecker,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestTLSVulnerability:
    def test_count(self):
        assert len(TLSVulnerability) == 16

    def test_heartbleed(self):
        assert TLSVulnerability.HEARTBLEED.value == "heartbleed"

    def test_poodle(self):
        assert TLSVulnerability.POODLE.value == "poodle"

    def test_beast(self):
        assert TLSVulnerability.BEAST.value == "beast"

    def test_crime(self):
        assert TLSVulnerability.CRIME.value == "crime"

    def test_breach(self):
        assert TLSVulnerability.BREACH.value == "breach"

    def test_robot(self):
        assert TLSVulnerability.ROBOT.value == "robot"

    def test_drown(self):
        assert TLSVulnerability.DROWN.value == "drown"

    def test_freak(self):
        assert TLSVulnerability.FREAK.value == "freak"

    def test_logjam(self):
        assert TLSVulnerability.LOGJAM.value == "logjam"

    def test_lucky13(self):
        assert TLSVulnerability.LUCKY13.value == "lucky13"

    def test_sweet32(self):
        assert TLSVulnerability.SWEET32.value == "sweet32"

    def test_ticketbleed(self):
        assert TLSVulnerability.TICKETBLEED.value == "ticketbleed"

    def test_roca(self):
        assert TLSVulnerability.ROCA.value == "roca"

    def test_goldendoodle(self):
        assert TLSVulnerability.GOLDENDOODLE.value == "goldendoodle"

    def test_zombie_poodle(self):
        assert TLSVulnerability.ZOMBIE_POODLE.value == "zombie_poodle"

    def test_raccoon(self):
        assert TLSVulnerability.RACCOON.value == "raccoon"


class TestCipherStrength:
    def test_count(self):
        assert len(CipherStrength) == 5

    def test_insecure(self):
        assert CipherStrength.INSECURE.value == "insecure"

    def test_weak(self):
        assert CipherStrength.WEAK.value == "weak"

    def test_acceptable(self):
        assert CipherStrength.ACCEPTABLE.value == "acceptable"

    def test_strong(self):
        assert CipherStrength.STRONG.value == "strong"

    def test_recommended(self):
        assert CipherStrength.RECOMMENDED.value == "recommended"


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestCipherInfo:
    def test_creation(self):
        cipher = CipherInfo(
            name="ECDHE-RSA-AES256-GCM-SHA384",
            protocol="TLSv1.2",
            key_exchange="ECDHE",
            authentication="RSA",
            encryption="AES256-GCM",
            mac="SHA384",
            key_size=256,
            strength=CipherStrength.RECOMMENDED,
            pfs=True,
            aead=True,
        )
        assert cipher.name == "ECDHE-RSA-AES256-GCM-SHA384"
        assert cipher.pfs is True
        assert cipher.aead is True
        assert cipher.strength == CipherStrength.RECOMMENDED

    def test_weak_cipher(self):
        cipher = CipherInfo(
            name="DES-CBC3-SHA",
            protocol="TLSv1.0",
            key_exchange="RSA",
            authentication="RSA",
            encryption="3DES",
            mac="SHA",
            key_size=112,
            strength=CipherStrength.INSECURE,
            pfs=False,
            aead=False,
        )
        assert cipher.strength == CipherStrength.INSECURE
        assert cipher.pfs is False


class TestCertificateInfo:
    def test_creation(self):
        cert = CertificateInfo(
            subject={"CN": "example.com"},
            issuer={"O": "Let's Encrypt", "CN": "R3"},
            serial_number="0A1B2C3D4E",
            not_before=datetime(2024, 1, 1),
            not_after=datetime(2025, 1, 1),
            san=["example.com", "*.example.com"],
            signature_algorithm="sha256WithRSAEncryption",
            public_key_type="RSA",
            public_key_size=2048,
            fingerprint_sha256="AB:CD:EF:12",
            chain_valid=True,
            self_signed=False,
            ct_enabled=True,
        )
        assert cert.public_key_size == 2048
        assert cert.chain_valid is True
        assert cert.self_signed is False
        assert len(cert.san) == 2


class TestTLSVulnResult:
    def test_basic_creation(self):
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.HEARTBLEED,
            vulnerable=True,
            evidence=["OpenSSL version 1.0.1f detected"],
        )
        assert result.vulnerable is True
        assert result.cve is None
        assert result.cvss == 0.0

    def test_full_creation(self):
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.POODLE,
            vulnerable=True,
            evidence=["SSLv3 enabled", "CBC cipher accepted"],
            cve="CVE-2014-3566",
            cvss=3.4,
        )
        assert result.cve == "CVE-2014-3566"
        assert result.cvss == 3.4

    def test_not_vulnerable(self):
        result = TLSVulnResult(
            vulnerability=TLSVulnerability.DROWN,
            vulnerable=False,
            evidence=[],
        )
        assert result.vulnerable is False


# =============================================================================
# SSL CHECKER CLASS ATTRIBUTES
# =============================================================================

class TestSSLCheckerClass:
    def test_name(self):
        assert SSLChecker.name == "ssl"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(SSLChecker, ScanModule)


class TestInsecureCiphers:
    def test_not_empty(self):
        assert len(SSLChecker.INSECURE_CIPHERS) > 0

    def test_has_null(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("NULL" in p for p in patterns)

    def test_has_export(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("EXPORT" in p or "EXP" in p for p in patterns)

    def test_has_des(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("DES" in p for p in patterns)

    def test_has_rc4(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("RC4" in p for p in patterns)

    def test_has_rc2(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("RC2" in p for p in patterns)

    def test_has_md5(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("MD5" in p for p in patterns)

    def test_has_anonymous(self):
        patterns = [p for p, d in SSLChecker.INSECURE_CIPHERS]
        assert any("ADH" in p or "AECDH" in p or "anon" in p for p in patterns)

    def test_all_have_description(self):
        for pattern, desc in SSLChecker.INSECURE_CIPHERS:
            assert len(desc) > 0

    def test_all_patterns_compile(self):
        for pattern, desc in SSLChecker.INSECURE_CIPHERS:
            re.compile(pattern)


class TestWeakCiphers:
    def test_not_empty(self):
        assert len(SSLChecker.WEAK_CIPHERS) > 0

    def test_has_cbc(self):
        patterns = [p for p, d in SSLChecker.WEAK_CIPHERS]
        assert any("CBC" in p for p in patterns)

    def test_has_sha1(self):
        patterns = [p for p, d in SSLChecker.WEAK_CIPHERS]
        assert any("SHA" in p for p in patterns)

    def test_has_rsa_kex(self):
        patterns = [p for p, d in SSLChecker.WEAK_CIPHERS]
        assert any("RSA" in p for p in patterns)

    def test_all_have_description(self):
        for pattern, desc in SSLChecker.WEAK_CIPHERS:
            assert len(desc) > 0

    def test_all_patterns_compile(self):
        for pattern, desc in SSLChecker.WEAK_CIPHERS:
            re.compile(pattern)


class TestStrongCiphers:
    def test_not_empty(self):
        assert len(SSLChecker.STRONG_CIPHERS) > 0

    def test_has_ecdhe_gcm(self):
        patterns = [p for p, d in SSLChecker.STRONG_CIPHERS]
        assert any("ECDHE" in p and "GCM" in p for p in patterns)

    def test_has_chacha20(self):
        patterns = [p for p, d in SSLChecker.STRONG_CIPHERS]
        assert any("CHACHA20" in p for p in patterns)

    def test_has_tls13(self):
        patterns = [p for p, d in SSLChecker.STRONG_CIPHERS]
        assert any("TLS_AES" in p or "TLS_CHACHA" in p for p in patterns)

    def test_all_have_description(self):
        for pattern, desc in SSLChecker.STRONG_CIPHERS:
            assert len(desc) > 0

    def test_all_patterns_compile(self):
        for pattern, desc in SSLChecker.STRONG_CIPHERS:
            re.compile(pattern)


# =============================================================================
# CVE DATABASE
# =============================================================================

class TestCVEDatabase:
    def test_not_empty(self):
        assert len(SSLChecker.CVE_DATABASE) > 0

    def test_has_heartbleed(self):
        assert TLSVulnerability.HEARTBLEED in SSLChecker.CVE_DATABASE
        hb = SSLChecker.CVE_DATABASE[TLSVulnerability.HEARTBLEED]
        assert hb["cve"] == "CVE-2014-0160"
        assert hb["cvss"] == 9.8
        assert hb["severity"] == "CRITICAL"

    def test_has_poodle(self):
        assert TLSVulnerability.POODLE in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.POODLE]["cve"] == "CVE-2014-3566"

    def test_has_beast(self):
        assert TLSVulnerability.BEAST in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.BEAST]["cve"] == "CVE-2011-3389"

    def test_has_crime(self):
        assert TLSVulnerability.CRIME in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.CRIME]["cve"] == "CVE-2012-4929"

    def test_has_robot(self):
        assert TLSVulnerability.ROBOT in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.ROBOT]["cvss"] == 7.4

    def test_has_drown(self):
        assert TLSVulnerability.DROWN in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.DROWN]["cve"] == "CVE-2016-0800"

    def test_has_freak(self):
        assert TLSVulnerability.FREAK in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.FREAK]["cve"] == "CVE-2015-0204"

    def test_has_logjam(self):
        assert TLSVulnerability.LOGJAM in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.LOGJAM]["cve"] == "CVE-2015-4000"

    def test_has_sweet32(self):
        assert TLSVulnerability.SWEET32 in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.SWEET32]["cve"] == "CVE-2016-2183"
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.SWEET32]["severity"] == "HIGH"

    def test_has_lucky13(self):
        assert TLSVulnerability.LUCKY13 in SSLChecker.CVE_DATABASE

    def test_has_ticketbleed(self):
        assert TLSVulnerability.TICKETBLEED in SSLChecker.CVE_DATABASE

    def test_has_raccoon(self):
        assert TLSVulnerability.RACCOON in SSLChecker.CVE_DATABASE
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.RACCOON]["cve"] == "CVE-2020-1968"

    def test_all_have_cve(self):
        for vuln, data in SSLChecker.CVE_DATABASE.items():
            assert "cve" in data, f"Missing CVE for {vuln}"
            assert data["cve"].startswith("CVE-")

    def test_all_have_cvss(self):
        for vuln, data in SSLChecker.CVE_DATABASE.items():
            assert "cvss" in data, f"Missing CVSS for {vuln}"
            assert 0 <= data["cvss"] <= 10

    def test_all_have_severity(self):
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for vuln, data in SSLChecker.CVE_DATABASE.items():
            assert "severity" in data, f"Missing severity for {vuln}"
            assert data["severity"] in valid_severities

    def test_all_have_name(self):
        for vuln, data in SSLChecker.CVE_DATABASE.items():
            assert "name" in data
            assert len(data["name"]) > 0

    def test_all_have_description(self):
        for vuln, data in SSLChecker.CVE_DATABASE.items():
            assert "description" in data
            assert len(data["description"]) > 10


# =============================================================================
# PROTOCOL VERSIONS
# =============================================================================

class TestProtocolVersions:
    def test_has_6_versions(self):
        assert len(SSLChecker.PROTOCOL_VERSIONS) == 6

    def test_sslv2_deprecated(self):
        assert SSLChecker.PROTOCOL_VERSIONS["SSLv2"]["deprecated"] is True
        assert SSLChecker.PROTOCOL_VERSIONS["SSLv2"]["secure"] is False

    def test_sslv3_deprecated(self):
        assert SSLChecker.PROTOCOL_VERSIONS["SSLv3"]["deprecated"] is True
        assert SSLChecker.PROTOCOL_VERSIONS["SSLv3"]["secure"] is False

    def test_tls10_deprecated(self):
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.0"]["deprecated"] is True
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.0"]["secure"] is False

    def test_tls11_deprecated(self):
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.1"]["deprecated"] is True
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.1"]["secure"] is False

    def test_tls12_secure(self):
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.2"]["secure"] is True
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.2"]["deprecated"] is False

    def test_tls13_secure(self):
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.3"]["secure"] is True
        assert SSLChecker.PROTOCOL_VERSIONS["TLSv1.3"]["deprecated"] is False

    def test_all_have_version_number(self):
        for name, data in SSLChecker.PROTOCOL_VERSIONS.items():
            assert "version" in data
            assert isinstance(data["version"], int)


# =============================================================================
# MIN KEY SIZES
# =============================================================================

class TestMinKeySizes:
    def test_has_rsa(self):
        assert SSLChecker.MIN_KEY_SIZES["RSA"] == 2048

    def test_has_dsa(self):
        assert SSLChecker.MIN_KEY_SIZES["DSA"] == 2048

    def test_has_ecdsa(self):
        assert SSLChecker.MIN_KEY_SIZES["ECDSA"] == 256

    def test_has_dh(self):
        assert SSLChecker.MIN_KEY_SIZES["DH"] == 2048

    def test_has_ecdh(self):
        assert SSLChecker.MIN_KEY_SIZES["ECDH"] == 256


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    def test_all_vulns_unique(self):
        values = [v.value for v in TLSVulnerability]
        assert len(values) == len(set(values))

    def test_all_cipher_strengths_unique(self):
        values = [s.value for s in CipherStrength]
        assert len(values) == len(set(values))

    def test_heartbleed_is_most_critical(self):
        max_cvss = max(d["cvss"] for d in SSLChecker.CVE_DATABASE.values())
        assert SSLChecker.CVE_DATABASE[TLSVulnerability.HEARTBLEED]["cvss"] == max_cvss
