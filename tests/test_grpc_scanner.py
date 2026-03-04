"""
Tests for scanning/modules/grpc_scanner.py

Covers:
- GRPCScanner class attributes (name, ports, content types)
- Class hierarchy (ScanModule subclass)
- GRPC_PORTS: exact list and validation
- GRPC_WEB_CONTENT_TYPES: exact list and validation
- scan method existence
"""

import pytest

from scanning.modules.grpc_scanner import GRPCScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# GRPCScanner CLASS — Identity & Hierarchy
# =============================================================================

class TestGRPCScannerIdentity:
    def test_name_is_grpc_scanner(self):
        assert GRPCScanner.name == "grpc_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(GRPCScanner, ScanModule)

    def test_scan_method_exists(self):
        assert hasattr(GRPCScanner, "scan")
        assert callable(getattr(GRPCScanner, "scan"))


# =============================================================================
# GRPC_PORTS
# =============================================================================

class TestGRPCPorts:
    def test_exact_list(self):
        assert GRPCScanner.GRPC_PORTS == [50051, 50052, 9090, 443, 8443]

    def test_count(self):
        assert len(GRPCScanner.GRPC_PORTS) == 5

    def test_contains_default_grpc_port(self):
        assert 50051 in GRPCScanner.GRPC_PORTS

    def test_contains_secondary_grpc_port(self):
        assert 50052 in GRPCScanner.GRPC_PORTS

    def test_contains_9090(self):
        assert 9090 in GRPCScanner.GRPC_PORTS

    def test_contains_443(self):
        assert 443 in GRPCScanner.GRPC_PORTS

    def test_contains_8443(self):
        assert 8443 in GRPCScanner.GRPC_PORTS

    def test_all_ports_are_integers(self):
        for port in GRPCScanner.GRPC_PORTS:
            assert isinstance(port, int), f"Port {port!r} is not an integer"

    def test_all_ports_are_positive(self):
        for port in GRPCScanner.GRPC_PORTS:
            assert port > 0, f"Port {port} is not positive"


# =============================================================================
# GRPC_WEB_CONTENT_TYPES
# =============================================================================

class TestGRPCWebContentTypes:
    def test_count(self):
        assert len(GRPCScanner.GRPC_WEB_CONTENT_TYPES) == 4

    def test_exact_list(self):
        expected = [
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpc-web-text",
            "application/grpc-web-text+proto",
        ]
        assert GRPCScanner.GRPC_WEB_CONTENT_TYPES == expected

    def test_all_start_with_application_grpc_web(self):
        for ct in GRPCScanner.GRPC_WEB_CONTENT_TYPES:
            assert ct.startswith("application/grpc-web"), (
                f"Content type {ct!r} does not start with 'application/grpc-web'"
            )

    def test_no_empty_strings(self):
        for ct in GRPCScanner.GRPC_WEB_CONTENT_TYPES:
            assert ct != "", "Found empty string in GRPC_WEB_CONTENT_TYPES"
            assert len(ct.strip()) > 0, f"Content type {ct!r} is blank"
