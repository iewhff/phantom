"""
Tests for scanning/modules/saml_scanner.py

Covers:
1. SAMLScanner identity and class hierarchy
2. SAML_ENDPOINTS completeness (17 items) and specific entries
3. METADATA_ENDPOINTS completeness (7 items) and specific entries
4. IDP_DISCOVERY completeness (4 items)
5. No empty strings in any endpoint list
6. All endpoints start with /
7. scan method exists and is async

Run with: pytest tests/test_saml_scanner.py -v
"""

import asyncio

import pytest
from unittest.mock import MagicMock


class TestSAMLScannerIdentity:
    """Test scanner name and class hierarchy."""

    def test_name_is_saml_scanner(self):
        """SAMLScanner.name must be 'saml_scanner'."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert SAMLScanner.name == "saml_scanner"

    def test_is_scan_module_subclass(self):
        """SAMLScanner must inherit from ScanModule."""
        from scanning.modules.saml_scanner import SAMLScanner
        from scanning.vuln_scanner import ScanModule

        assert issubclass(SAMLScanner, ScanModule)

    def test_instance_is_scan_module(self):
        """Instantiated SAMLScanner should be a ScanModule instance."""
        from scanning.modules.saml_scanner import SAMLScanner
        from scanning.vuln_scanner import ScanModule

        scanner = SAMLScanner(MagicMock())
        assert isinstance(scanner, ScanModule)

    def test_has_scan_method(self):
        """SAMLScanner must have a scan method."""
        from scanning.modules.saml_scanner import SAMLScanner

        scanner = SAMLScanner(MagicMock())
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)

    def test_scan_method_is_async(self):
        """SAMLScanner.scan must be an async coroutine function."""
        from scanning.modules.saml_scanner import SAMLScanner

        scanner = SAMLScanner(MagicMock())
        assert asyncio.iscoroutinefunction(scanner.scan)


class TestSAMLEndpoints:
    """Test SAML_ENDPOINTS list completeness and specific entries."""

    def test_endpoints_count(self):
        """SAML_ENDPOINTS must have exactly 17 items."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert len(SAMLScanner.SAML_ENDPOINTS) == 17

    def test_has_saml_acs(self):
        """Must include /saml/acs."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/acs" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml_consume(self):
        """Must include /saml/consume."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/consume" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml_callback(self):
        """Must include /saml/callback."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/callback" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml_sso(self):
        """Must include /saml/sso."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/sso" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml_login(self):
        """Must include /saml/login."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/login" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml_auth(self):
        """Must include /saml/auth."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/auth" in SAMLScanner.SAML_ENDPOINTS

    def test_has_sso_saml(self):
        """Must include /sso/saml."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/sso/saml" in SAMLScanner.SAML_ENDPOINTS

    def test_has_sso_callback(self):
        """Must include /sso/callback."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/sso/callback" in SAMLScanner.SAML_ENDPOINTS

    def test_has_auth_saml_callback(self):
        """Must include /auth/saml/callback."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/auth/saml/callback" in SAMLScanner.SAML_ENDPOINTS

    def test_has_api_saml_acs(self):
        """Must include /api/saml/acs."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/api/saml/acs" in SAMLScanner.SAML_ENDPOINTS

    def test_has_api_auth_saml(self):
        """Must include /api/auth/saml."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/api/auth/saml" in SAMLScanner.SAML_ENDPOINTS

    def test_has_simplesaml_acs(self):
        """Must include the SimpleSAMLphp ACS path."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/simplesaml/module.php/saml/sp/saml2-acs.php" in SAMLScanner.SAML_ENDPOINTS

    def test_has_adfs_ls(self):
        """Must include /adfs/ls."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/adfs/ls" in SAMLScanner.SAML_ENDPOINTS

    def test_has_adfs_ls_trailing_slash(self):
        """Must include /adfs/ls/ (trailing slash variant)."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/adfs/ls/" in SAMLScanner.SAML_ENDPOINTS

    def test_has_underscore_saml(self):
        """Must include /_saml."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/_saml" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml2_acs(self):
        """Must include /saml2/acs."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml2/acs" in SAMLScanner.SAML_ENDPOINTS

    def test_has_saml2(self):
        """Must include /saml2."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml2" in SAMLScanner.SAML_ENDPOINTS

    def test_no_empty_strings(self):
        """No endpoint in SAML_ENDPOINTS should be an empty string."""
        from scanning.modules.saml_scanner import SAMLScanner

        for endpoint in SAMLScanner.SAML_ENDPOINTS:
            assert endpoint != "", f"Found empty string in SAML_ENDPOINTS"

    def test_all_start_with_slash(self):
        """Every endpoint in SAML_ENDPOINTS must start with /."""
        from scanning.modules.saml_scanner import SAMLScanner

        for endpoint in SAMLScanner.SAML_ENDPOINTS:
            assert endpoint.startswith("/"), f"Endpoint {endpoint!r} does not start with /"

    def test_no_duplicates(self):
        """SAML_ENDPOINTS must not contain duplicate entries."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert len(SAMLScanner.SAML_ENDPOINTS) == len(set(SAMLScanner.SAML_ENDPOINTS))


class TestMetadataEndpoints:
    """Test METADATA_ENDPOINTS list completeness and specific entries."""

    def test_metadata_count(self):
        """METADATA_ENDPOINTS must have exactly 7 items."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert len(SAMLScanner.METADATA_ENDPOINTS) == 7

    def test_has_saml_metadata(self):
        """Must include /saml/metadata."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/metadata" in SAMLScanner.METADATA_ENDPOINTS

    def test_has_saml_metadata_xml(self):
        """Must include /saml/metadata.xml."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/metadata.xml" in SAMLScanner.METADATA_ENDPOINTS

    def test_has_saml_sp_metadata(self):
        """Must include /saml/sp/metadata."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/sp/metadata" in SAMLScanner.METADATA_ENDPOINTS

    def test_has_sso_metadata(self):
        """Must include /sso/metadata."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/sso/metadata" in SAMLScanner.METADATA_ENDPOINTS

    def test_has_api_saml_metadata(self):
        """Must include /api/saml/metadata."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/api/saml/metadata" in SAMLScanner.METADATA_ENDPOINTS

    def test_has_simplesaml_metadata(self):
        """Must include the SimpleSAMLphp metadata path."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/simplesaml/module.php/saml/sp/metadata.php" in SAMLScanner.METADATA_ENDPOINTS

    def test_has_federation_metadata(self):
        """Must include the ADFS FederationMetadata XML path."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/FederationMetadata/2007-06/FederationMetadata.xml" in SAMLScanner.METADATA_ENDPOINTS

    def test_no_empty_strings(self):
        """No endpoint in METADATA_ENDPOINTS should be an empty string."""
        from scanning.modules.saml_scanner import SAMLScanner

        for endpoint in SAMLScanner.METADATA_ENDPOINTS:
            assert endpoint != "", f"Found empty string in METADATA_ENDPOINTS"

    def test_all_start_with_slash(self):
        """Every endpoint in METADATA_ENDPOINTS must start with /."""
        from scanning.modules.saml_scanner import SAMLScanner

        for endpoint in SAMLScanner.METADATA_ENDPOINTS:
            assert endpoint.startswith("/"), f"Endpoint {endpoint!r} does not start with /"

    def test_no_duplicates(self):
        """METADATA_ENDPOINTS must not contain duplicate entries."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert len(SAMLScanner.METADATA_ENDPOINTS) == len(set(SAMLScanner.METADATA_ENDPOINTS))


class TestIDPDiscovery:
    """Test IDP_DISCOVERY list completeness and specific entries."""

    def test_idp_discovery_count(self):
        """IDP_DISCOVERY must have exactly 4 items."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert len(SAMLScanner.IDP_DISCOVERY) == 4

    def test_has_saml_discovery(self):
        """Must include /saml/discovery."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/discovery" in SAMLScanner.IDP_DISCOVERY

    def test_has_saml_idp_discovery(self):
        """Must include /saml/idp-discovery."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/saml/idp-discovery" in SAMLScanner.IDP_DISCOVERY

    def test_has_discovery(self):
        """Must include /discovery."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/discovery" in SAMLScanner.IDP_DISCOVERY

    def test_has_sso_discovery(self):
        """Must include /sso/discovery."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert "/sso/discovery" in SAMLScanner.IDP_DISCOVERY

    def test_no_empty_strings(self):
        """No endpoint in IDP_DISCOVERY should be an empty string."""
        from scanning.modules.saml_scanner import SAMLScanner

        for endpoint in SAMLScanner.IDP_DISCOVERY:
            assert endpoint != "", f"Found empty string in IDP_DISCOVERY"

    def test_all_start_with_slash(self):
        """Every endpoint in IDP_DISCOVERY must start with /."""
        from scanning.modules.saml_scanner import SAMLScanner

        for endpoint in SAMLScanner.IDP_DISCOVERY:
            assert endpoint.startswith("/"), f"Endpoint {endpoint!r} does not start with /"

    def test_no_duplicates(self):
        """IDP_DISCOVERY must not contain duplicate entries."""
        from scanning.modules.saml_scanner import SAMLScanner

        assert len(SAMLScanner.IDP_DISCOVERY) == len(set(SAMLScanner.IDP_DISCOVERY))


class TestAllEndpointListsStructure:
    """Cross-cutting structural tests across all endpoint lists."""

    def test_no_overlap_saml_and_metadata(self):
        """SAML_ENDPOINTS and METADATA_ENDPOINTS should not overlap."""
        from scanning.modules.saml_scanner import SAMLScanner

        overlap = set(SAMLScanner.SAML_ENDPOINTS) & set(SAMLScanner.METADATA_ENDPOINTS)
        assert len(overlap) == 0, f"Overlap between SAML and METADATA: {overlap}"

    def test_no_overlap_saml_and_idp(self):
        """SAML_ENDPOINTS and IDP_DISCOVERY should not overlap."""
        from scanning.modules.saml_scanner import SAMLScanner

        overlap = set(SAMLScanner.SAML_ENDPOINTS) & set(SAMLScanner.IDP_DISCOVERY)
        assert len(overlap) == 0, f"Overlap between SAML and IDP: {overlap}"

    def test_no_overlap_metadata_and_idp(self):
        """METADATA_ENDPOINTS and IDP_DISCOVERY should not overlap."""
        from scanning.modules.saml_scanner import SAMLScanner

        overlap = set(SAMLScanner.METADATA_ENDPOINTS) & set(SAMLScanner.IDP_DISCOVERY)
        assert len(overlap) == 0, f"Overlap between METADATA and IDP: {overlap}"

    def test_all_endpoints_are_strings(self):
        """Every item in all endpoint lists must be a string."""
        from scanning.modules.saml_scanner import SAMLScanner

        for lst_name in ("SAML_ENDPOINTS", "METADATA_ENDPOINTS", "IDP_DISCOVERY"):
            for item in getattr(SAMLScanner, lst_name):
                assert isinstance(item, str), f"Non-string in {lst_name}: {item!r}"

    def test_total_endpoint_count(self):
        """Total endpoint count across all three lists should be 28 (17+7+4)."""
        from scanning.modules.saml_scanner import SAMLScanner

        total = (
            len(SAMLScanner.SAML_ENDPOINTS)
            + len(SAMLScanner.METADATA_ENDPOINTS)
            + len(SAMLScanner.IDP_DISCOVERY)
        )
        assert total == 28
