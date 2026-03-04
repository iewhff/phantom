"""
Tests for DNS Rebinding Scanner v2.0.

Covers:
- RebindingVectorType enum (9 members)
- InternalServiceType enum (12 members)
- RebindingVector dataclass
- InternalService dataclass
- RebindingVulnerability dataclass
- DNSRebindingScanner class attributes

"""

import pytest
from dataclasses import fields, asdict

from scanning.modules.dns_rebinding_scanner import (
    RebindingVectorType,
    InternalServiceType,
    RebindingVector,
    InternalService,
    RebindingVulnerability,
    DNSRebindingScanner,
)
from scanning.findings import Severity


# ============================================================================
# TESTS: RebindingVectorType Enum
# ============================================================================

class TestRebindingVectorType:
    """Tests for RebindingVectorType enum."""

    def test_member_count(self):
        """Should have exactly 9 members."""
        assert len(RebindingVectorType) == 9

    def test_has_host_header_bypass(self):
        """Should have HOST_HEADER_BYPASS type."""
        assert RebindingVectorType.HOST_HEADER_BYPASS is not None
        assert RebindingVectorType.HOST_HEADER_BYPASS.value == "host_header_bypass"

    def test_has_ssrf_rebinding(self):
        """Should have SSRF_REBINDING type."""
        assert RebindingVectorType.SSRF_REBINDING is not None
        assert RebindingVectorType.SSRF_REBINDING.value == "ssrf_rebinding"

    def test_has_websocket_origin(self):
        """Should have WEBSOCKET_ORIGIN type."""
        assert RebindingVectorType.WEBSOCKET_ORIGIN is not None
        assert RebindingVectorType.WEBSOCKET_ORIGIN.value == "websocket_origin"

    def test_has_cors_bypass(self):
        """Should have CORS_BYPASS type."""
        assert RebindingVectorType.CORS_BYPASS is not None
        assert RebindingVectorType.CORS_BYPASS.value == "cors_bypass"

    def test_has_redirect_rebinding(self):
        """Should have REDIRECT_REBINDING type."""
        assert RebindingVectorType.REDIRECT_REBINDING is not None
        assert RebindingVectorType.REDIRECT_REBINDING.value == "redirect_rebinding"

    def test_has_dns_manipulation(self):
        """Should have DNS_MANIPULATION type."""
        assert RebindingVectorType.DNS_MANIPULATION is not None
        assert RebindingVectorType.DNS_MANIPULATION.value == "dns_manipulation"

    def test_has_iframe_sandbox(self):
        """Should have IFRAME_SANDBOX type."""
        assert RebindingVectorType.IFRAME_SANDBOX is not None
        assert RebindingVectorType.IFRAME_SANDBOX.value == "iframe_sandbox"

    def test_has_service_worker(self):
        """Should have SERVICE_WORKER type."""
        assert RebindingVectorType.SERVICE_WORKER is not None
        assert RebindingVectorType.SERVICE_WORKER.value == "service_worker"

    def test_has_ttl_rebinding(self):
        """Should have TTL_REBINDING type."""
        assert RebindingVectorType.TTL_REBINDING is not None
        assert RebindingVectorType.TTL_REBINDING.value == "ttl_rebinding"

    def test_all_values_are_unique(self):
        """All vector type values should be unique."""
        values = [v.value for v in RebindingVectorType]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        """All vector type values should be strings."""
        for member in RebindingVectorType:
            assert isinstance(member.value, str)


# ============================================================================
# TESTS: InternalServiceType Enum
# ============================================================================

class TestInternalServiceType:
    """Tests for InternalServiceType enum."""

    def test_member_count(self):
        """Should have exactly 12 members."""
        assert len(InternalServiceType) == 12

    def test_has_aws_metadata(self):
        """Should have AWS_METADATA type."""
        assert InternalServiceType.AWS_METADATA is not None
        assert InternalServiceType.AWS_METADATA.value == "aws_metadata"

    def test_has_gcp_metadata(self):
        """Should have GCP_METADATA type."""
        assert InternalServiceType.GCP_METADATA is not None
        assert InternalServiceType.GCP_METADATA.value == "gcp_metadata"

    def test_has_azure_metadata(self):
        """Should have AZURE_METADATA type."""
        assert InternalServiceType.AZURE_METADATA is not None
        assert InternalServiceType.AZURE_METADATA.value == "azure_metadata"

    def test_has_kubernetes_api(self):
        """Should have KUBERNETES_API type."""
        assert InternalServiceType.KUBERNETES_API is not None
        assert InternalServiceType.KUBERNETES_API.value == "kubernetes_api"

    def test_has_docker_api(self):
        """Should have DOCKER_API type."""
        assert InternalServiceType.DOCKER_API is not None
        assert InternalServiceType.DOCKER_API.value == "docker_api"

    def test_has_redis(self):
        """Should have REDIS type."""
        assert InternalServiceType.REDIS is not None
        assert InternalServiceType.REDIS.value == "redis"

    def test_has_elasticsearch(self):
        """Should have ELASTICSEARCH type."""
        assert InternalServiceType.ELASTICSEARCH is not None
        assert InternalServiceType.ELASTICSEARCH.value == "elasticsearch"

    def test_has_mongodb(self):
        """Should have MONGODB type."""
        assert InternalServiceType.MONGODB is not None
        assert InternalServiceType.MONGODB.value == "mongodb"

    def test_has_consul(self):
        """Should have CONSUL type."""
        assert InternalServiceType.CONSUL is not None
        assert InternalServiceType.CONSUL.value == "consul"

    def test_has_etcd(self):
        """Should have ETCD type."""
        assert InternalServiceType.ETCD is not None
        assert InternalServiceType.ETCD.value == "etcd"

    def test_has_prometheus(self):
        """Should have PROMETHEUS type."""
        assert InternalServiceType.PROMETHEUS is not None
        assert InternalServiceType.PROMETHEUS.value == "prometheus"

    def test_has_grafana(self):
        """Should have GRAFANA type."""
        assert InternalServiceType.GRAFANA is not None
        assert InternalServiceType.GRAFANA.value == "grafana"

    def test_all_values_are_unique(self):
        """All service type values should be unique."""
        values = [v.value for v in InternalServiceType]
        assert len(values) == len(set(values))

    def test_all_values_are_strings(self):
        """All service type values should be strings."""
        for member in InternalServiceType:
            assert isinstance(member.value, str)

    def test_cloud_metadata_types_present(self):
        """Should have all 3 major cloud metadata types."""
        cloud_types = {
            InternalServiceType.AWS_METADATA,
            InternalServiceType.GCP_METADATA,
            InternalServiceType.AZURE_METADATA,
        }
        assert len(cloud_types) == 3


# ============================================================================
# TESTS: RebindingVector Dataclass
# ============================================================================

class TestRebindingVector:
    """Tests for RebindingVector dataclass."""

    def test_create_with_required_fields(self):
        """Should create with required fields only."""
        vector = RebindingVector(
            payload="127.0.0.1",
            vector_type=RebindingVectorType.HOST_HEADER_BYPASS,
            description="Localhost bypass",
        )
        assert vector.payload == "127.0.0.1"
        assert vector.vector_type == RebindingVectorType.HOST_HEADER_BYPASS
        assert vector.description == "Localhost bypass"

    def test_default_target_ip_is_none(self):
        """Default target_ip should be None."""
        vector = RebindingVector(
            payload="test",
            vector_type=RebindingVectorType.SSRF_REBINDING,
            description="test",
        )
        assert vector.target_ip is None

    def test_default_header_based_is_false(self):
        """Default header_based should be False."""
        vector = RebindingVector(
            payload="test",
            vector_type=RebindingVectorType.SSRF_REBINDING,
            description="test",
        )
        assert vector.header_based is False

    def test_default_requires_dns_is_false(self):
        """Default requires_dns should be False."""
        vector = RebindingVector(
            payload="test",
            vector_type=RebindingVectorType.DNS_MANIPULATION,
            description="test",
        )
        assert vector.requires_dns is False

    def test_create_with_all_fields(self):
        """Should create with all fields specified."""
        vector = RebindingVector(
            payload="evil.com.127.0.0.1.nip.io",
            vector_type=RebindingVectorType.DNS_MANIPULATION,
            description="DNS rebinding via nip.io",
            target_ip="127.0.0.1",
            header_based=True,
            requires_dns=True,
        )
        assert vector.payload == "evil.com.127.0.0.1.nip.io"
        assert vector.target_ip == "127.0.0.1"
        assert vector.header_based is True
        assert vector.requires_dns is True

    def test_has_correct_field_names(self):
        """Should have exactly the expected fields."""
        field_names = {f.name for f in fields(RebindingVector)}
        expected = {"payload", "vector_type", "description", "target_ip", "header_based", "requires_dns"}
        assert field_names == expected

    def test_is_dataclass(self):
        """Should be a proper dataclass."""
        from dataclasses import is_dataclass
        assert is_dataclass(RebindingVector)


# ============================================================================
# TESTS: InternalService Dataclass
# ============================================================================

class TestInternalService:
    """Tests for InternalService dataclass."""

    def test_create_with_required_fields(self):
        """Should create with required fields and default severity."""
        svc = InternalService(
            service_type=InternalServiceType.REDIS,
            host="127.0.0.1",
            port=6379,
            path="/",
            indicators=["redis_version", "PONG"],
            description="Redis Database",
        )
        assert svc.service_type == InternalServiceType.REDIS
        assert svc.host == "127.0.0.1"
        assert svc.port == 6379
        assert svc.path == "/"
        assert svc.indicators == ["redis_version", "PONG"]
        assert svc.description == "Redis Database"

    def test_default_severity_is_critical(self):
        """Default severity should be 'CRITICAL' string."""
        svc = InternalService(
            service_type=InternalServiceType.REDIS,
            host="127.0.0.1",
            port=6379,
            path="/",
            indicators=["test"],
            description="Test",
        )
        assert svc.severity == "CRITICAL"

    def test_create_with_custom_severity(self):
        """Should accept custom severity."""
        svc = InternalService(
            service_type=InternalServiceType.GRAFANA,
            host="127.0.0.1",
            port=3000,
            path="/api/admin/settings",
            indicators=["DEFAULT"],
            description="Grafana Dashboard",
            severity=Severity.MEDIUM,
        )
        assert svc.severity == Severity.MEDIUM

    def test_has_correct_field_names(self):
        """Should have exactly the expected fields."""
        field_names = {f.name for f in fields(InternalService)}
        expected = {"service_type", "host", "port", "path", "indicators", "description", "severity"}
        assert field_names == expected

    def test_indicators_is_list(self):
        """Indicators field should be a list."""
        svc = InternalService(
            service_type=InternalServiceType.ELASTICSEARCH,
            host="127.0.0.1",
            port=9200,
            path="/",
            indicators=["cluster_name", "version"],
            description="ES",
        )
        assert isinstance(svc.indicators, list)

    def test_is_dataclass(self):
        """Should be a proper dataclass."""
        from dataclasses import is_dataclass
        assert is_dataclass(InternalService)


# ============================================================================
# TESTS: RebindingVulnerability Dataclass
# ============================================================================

class TestRebindingVulnerability:
    """Tests for RebindingVulnerability dataclass."""

    def test_create_with_required_fields(self):
        """Should create with required fields only."""
        vuln = RebindingVulnerability(
            vector_type=RebindingVectorType.HOST_HEADER_BYPASS,
            payload="127.0.0.1",
            target="https://example.com",
            evidence=["Host header accepted"],
            severity="HIGH",
            confidence="HIGH",
        )
        assert vuln.vector_type == RebindingVectorType.HOST_HEADER_BYPASS
        assert vuln.payload == "127.0.0.1"
        assert vuln.target == "https://example.com"
        assert vuln.evidence == ["Host header accepted"]
        assert vuln.severity == "HIGH"
        assert vuln.confidence == "HIGH"

    def test_default_internal_access_is_false(self):
        """Default internal_access should be False."""
        vuln = RebindingVulnerability(
            vector_type=RebindingVectorType.CORS_BYPASS,
            payload="null",
            target="https://example.com",
            evidence=[],
            severity="MEDIUM",
            confidence="MEDIUM",
        )
        assert vuln.internal_access is False

    def test_default_service_exposed_is_none(self):
        """Default service_exposed should be None."""
        vuln = RebindingVulnerability(
            vector_type=RebindingVectorType.CORS_BYPASS,
            payload="null",
            target="https://example.com",
            evidence=[],
            severity="MEDIUM",
            confidence="MEDIUM",
        )
        assert vuln.service_exposed is None

    def test_create_with_all_fields(self):
        """Should create with all fields specified."""
        vuln = RebindingVulnerability(
            vector_type=RebindingVectorType.SSRF_REBINDING,
            payload="http://evil.com.169.254.169.254.nip.io/latest/meta-data/",
            target="https://example.com/fetch?url=",
            evidence=["AWS metadata leaked", "ami-id found in response"],
            severity="CRITICAL",
            confidence="HIGH",
            internal_access=True,
            service_exposed="AWS EC2 Instance Metadata Service",
        )
        assert vuln.internal_access is True
        assert vuln.service_exposed == "AWS EC2 Instance Metadata Service"

    def test_has_correct_field_names(self):
        """Should have exactly the expected fields."""
        field_names = {f.name for f in fields(RebindingVulnerability)}
        expected = {
            "vector_type", "payload", "target", "evidence",
            "severity", "confidence", "internal_access", "service_exposed",
        }
        assert field_names == expected

    def test_evidence_is_list(self):
        """Evidence field should be a list."""
        vuln = RebindingVulnerability(
            vector_type=RebindingVectorType.TTL_REBINDING,
            payload="rebind.example.com",
            target="https://example.com",
            evidence=["TTL=0 observed", "IP changed between requests"],
            severity="HIGH",
            confidence="MEDIUM",
        )
        assert isinstance(vuln.evidence, list)
        assert len(vuln.evidence) == 2

    def test_is_dataclass(self):
        """Should be a proper dataclass."""
        from dataclasses import is_dataclass
        assert is_dataclass(RebindingVulnerability)


# ============================================================================
# TESTS: DNSRebindingScanner Class Attributes
# ============================================================================

class TestDNSRebindingScannerName:
    """Tests for DNSRebindingScanner name attribute."""

    def test_name_is_dns_rebinding_scanner(self):
        """Scanner name should be 'dns_rebinding_scanner'."""
        assert DNSRebindingScanner.name == "dns_rebinding_scanner"


class TestDNSRebindingScannerMaxDuration:
    """Tests for MAX_SCAN_DURATION."""

    def test_max_scan_duration_value(self):
        """MAX_SCAN_DURATION should be 90.0 seconds."""
        assert DNSRebindingScanner.MAX_SCAN_DURATION == 90.0

    def test_max_scan_duration_is_float(self):
        """MAX_SCAN_DURATION should be a float."""
        assert isinstance(DNSRebindingScanner.MAX_SCAN_DURATION, float)


# ============================================================================
# TESTS: INTERNAL_IP_TARGETS
# ============================================================================

class TestInternalIPTargets:
    """Tests for INTERNAL_IP_TARGETS class attribute."""

    def test_count(self):
        """Should have exactly 22 internal IP targets."""
        assert len(DNSRebindingScanner.INTERNAL_IP_TARGETS) == 22

    def test_all_are_tuples(self):
        """Each entry should be a (ip, description) tuple."""
        for entry in DNSRebindingScanner.INTERNAL_IP_TARGETS:
            assert isinstance(entry, tuple)
            assert len(entry) == 2

    def test_all_have_string_ip(self):
        """Each entry should have a string IP address."""
        for ip, desc in DNSRebindingScanner.INTERNAL_IP_TARGETS:
            assert isinstance(ip, str)
            assert len(ip) > 0

    def test_all_have_string_description(self):
        """Each entry should have a string description."""
        for ip, desc in DNSRebindingScanner.INTERNAL_IP_TARGETS:
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_has_ipv4_localhost(self):
        """Should include IPv4 localhost (127.0.0.1)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "127.0.0.1" in ips

    def test_has_hostname_localhost(self):
        """Should include hostname 'localhost'."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "localhost" in ips

    def test_has_ipv6_localhost(self):
        """Should include IPv6 localhost [::1]."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "[::1]" in ips

    def test_has_aws_metadata_ip(self):
        """Should include AWS/Cloud metadata IP 169.254.169.254."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "169.254.169.254" in ips

    def test_has_private_class_a(self):
        """Should include 10.0.0.1 (Private Class A)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "10.0.0.1" in ips

    def test_has_private_class_b(self):
        """Should include 172.16.0.1 (Private Class B)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "172.16.0.1" in ips

    def test_has_private_class_c(self):
        """Should include 192.168.0.1 (Private Class C)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "192.168.0.1" in ips

    def test_has_octal_encoding(self):
        """Should include octal localhost encoding (0177.0.0.1)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "0177.0.0.1" in ips

    def test_has_decimal_encoding(self):
        """Should include decimal localhost encoding (2130706433)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "2130706433" in ips

    def test_has_hex_encoding(self):
        """Should include hex localhost encoding (0x7f000001)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "0x7f000001" in ips

    def test_has_any_address(self):
        """Should include 0.0.0.0 (any interface)."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "0.0.0.0" in ips

    def test_has_ipv4_mapped_ipv6(self):
        """Should include IPv4-mapped IPv6 address."""
        ips = [ip for ip, _ in DNSRebindingScanner.INTERNAL_IP_TARGETS]
        assert "[::ffff:127.0.0.1]" in ips


# ============================================================================
# TESTS: HOST_BYPASS_TECHNIQUES
# ============================================================================

class TestHostBypassTechniques:
    """Tests for HOST_BYPASS_TECHNIQUES class attribute."""

    def test_count(self):
        """Should have exactly 34 bypass techniques."""
        assert len(DNSRebindingScanner.HOST_BYPASS_TECHNIQUES) == 34

    def test_all_are_strings(self):
        """Each technique should be a string."""
        for technique in DNSRebindingScanner.HOST_BYPASS_TECHNIQUES:
            assert isinstance(technique, str)

    def test_has_basic_injection(self):
        """Should include basic internal injection '{internal}'."""
        assert "{internal}" in DNSRebindingScanner.HOST_BYPASS_TECHNIQUES

    def test_has_nip_io_service(self):
        """Should include nip.io DNS rebinding service."""
        techniques = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES
        assert any("nip.io" in t for t in techniques)

    def test_has_xip_io_service(self):
        """Should include xip.io DNS rebinding service."""
        techniques = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES
        assert any("xip.io" in t for t in techniques)

    def test_has_sslip_io_service(self):
        """Should include sslip.io DNS rebinding service."""
        techniques = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES
        assert any("sslip.io" in t for t in techniques)

    def test_has_null_byte_technique(self):
        """Should include null byte injection technique."""
        techniques = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES
        assert any("%00" in t for t in techniques)

    def test_has_unicode_bypass(self):
        """Should include unicode bypass techniques."""
        techniques = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES
        # Circled letters or fullwidth characters
        assert any(ord(c) > 127 for t in techniques for c in t)

    def test_has_case_manipulation(self):
        """Should include case manipulation like LOCALHOST."""
        assert "LOCALHOST" in DNSRebindingScanner.HOST_BYPASS_TECHNIQUES

    def test_has_at_sign_authority_trick(self):
        """Should include @ authority tricks."""
        techniques = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES
        assert any("@" in t for t in techniques)

    def test_first_technique_is_basic(self):
        """First technique should be basic '{internal}'."""
        assert DNSRebindingScanner.HOST_BYPASS_TECHNIQUES[0] == "{internal}"

    def test_last_technique_is_rebind_nip_io(self):
        """Last technique should use nip.io rebind pattern."""
        last = DNSRebindingScanner.HOST_BYPASS_TECHNIQUES[-1]
        assert "rebind" in last and "nip.io" in last


# ============================================================================
# TESTS: INTERNAL_SERVICES
# ============================================================================

class TestInternalServices:
    """Tests for INTERNAL_SERVICES class attribute."""

    def test_count(self):
        """Should have exactly 16 internal service definitions."""
        assert len(DNSRebindingScanner.INTERNAL_SERVICES) == 16

    def test_all_are_internal_service_instances(self):
        """Each entry should be an InternalService dataclass instance."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc, InternalService)

    def test_all_have_valid_service_type(self):
        """Each service should have a valid InternalServiceType."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc.service_type, InternalServiceType)

    def test_all_have_string_host(self):
        """Each service should have a non-empty string host."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc.host, str)
            assert len(svc.host) > 0

    def test_all_have_positive_port(self):
        """Each service should have a positive integer port."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc.port, int)
            assert svc.port > 0

    def test_all_have_string_path(self):
        """Each service should have a non-empty string path."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc.path, str)
            assert len(svc.path) > 0

    def test_all_have_nonempty_indicators(self):
        """Each service should have at least one indicator."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc.indicators, list)
            assert len(svc.indicators) >= 1
            for indicator in svc.indicators:
                assert isinstance(indicator, str)
                assert len(indicator) > 0

    def test_all_have_string_description(self):
        """Each service should have a non-empty description."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert isinstance(svc.description, str)
            assert len(svc.description) > 0

    def test_all_have_severity(self):
        """Each service should have a severity value."""
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            assert svc.severity is not None

    def test_covers_all_service_types(self):
        """INTERNAL_SERVICES should cover all 12 InternalServiceType members."""
        covered_types = {svc.service_type for svc in DNSRebindingScanner.INTERNAL_SERVICES}
        for service_type in InternalServiceType:
            assert service_type in covered_types, f"{service_type.name} not covered"

    # --- Cloud Metadata Services ---

    def test_has_aws_metadata_imds(self):
        """Should include AWS IMDS metadata service."""
        aws_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.AWS_METADATA
        ]
        assert len(aws_services) >= 1
        hosts = [s.host for s in aws_services]
        assert "169.254.169.254" in hosts

    def test_has_aws_iam_credentials(self):
        """Should include AWS IAM credentials path."""
        aws_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.AWS_METADATA
        ]
        paths = [s.path for s in aws_services]
        assert any("iam/security-credentials" in p for p in paths)

    def test_has_gcp_metadata(self):
        """Should include GCP metadata service."""
        gcp_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.GCP_METADATA
        ]
        assert len(gcp_services) >= 1
        # GCP uses both metadata.google.internal and 169.254.169.254
        hosts = [s.host for s in gcp_services]
        assert "metadata.google.internal" in hosts

    def test_has_azure_metadata(self):
        """Should include Azure IMDS."""
        azure_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.AZURE_METADATA
        ]
        assert len(azure_services) >= 1
        paths = [s.path for s in azure_services]
        assert any("metadata/instance" in p for p in paths)

    # --- Container/Orchestration ---

    def test_has_kubernetes_api(self):
        """Should include Kubernetes API service."""
        k8s_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.KUBERNETES_API
        ]
        assert len(k8s_services) >= 1
        hosts = [s.host for s in k8s_services]
        assert "kubernetes.default" in hosts

    def test_has_docker_api(self):
        """Should include Docker Remote API (unauthenticated port 2375)."""
        docker_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.DOCKER_API
        ]
        assert len(docker_services) >= 1
        ports = [s.port for s in docker_services]
        assert 2375 in ports

    def test_has_docker_tls_api(self):
        """Should include Docker TLS API on port 2376."""
        docker_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.DOCKER_API
        ]
        ports = [s.port for s in docker_services]
        assert 2376 in ports

    # --- Database Services ---

    def test_has_redis(self):
        """Should include Redis on port 6379."""
        redis_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.REDIS
        ]
        assert len(redis_services) >= 1
        assert redis_services[0].port == 6379

    def test_has_elasticsearch(self):
        """Should include Elasticsearch on port 9200."""
        es_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.ELASTICSEARCH
        ]
        assert len(es_services) >= 1
        assert es_services[0].port == 9200

    def test_has_mongodb(self):
        """Should include MongoDB on port 27017."""
        mongo_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.MONGODB
        ]
        assert len(mongo_services) >= 1
        assert mongo_services[0].port == 27017

    # --- Service Discovery ---

    def test_has_consul(self):
        """Should include Consul on port 8500."""
        consul_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.CONSUL
        ]
        assert len(consul_services) >= 1
        assert consul_services[0].port == 8500

    def test_has_etcd(self):
        """Should include etcd on port 2379."""
        etcd_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.ETCD
        ]
        assert len(etcd_services) >= 1
        assert etcd_services[0].port == 2379

    # --- Monitoring ---

    def test_has_prometheus(self):
        """Should include Prometheus on port 9090."""
        prom_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.PROMETHEUS
        ]
        assert len(prom_services) >= 1
        assert prom_services[0].port == 9090

    def test_has_grafana(self):
        """Should include Grafana on port 3000."""
        grafana_services = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.GRAFANA
        ]
        assert len(grafana_services) >= 1
        assert grafana_services[0].port == 3000

    # --- Severity Distribution ---

    def test_cloud_metadata_services_are_critical(self):
        """Cloud metadata services should have CRITICAL severity."""
        cloud_types = {
            InternalServiceType.AWS_METADATA,
            InternalServiceType.GCP_METADATA,
            InternalServiceType.AZURE_METADATA,
        }
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            if svc.service_type in cloud_types:
                assert svc.severity == Severity.CRITICAL, (
                    f"{svc.description} should be CRITICAL, got {svc.severity}"
                )

    def test_container_services_are_critical(self):
        """Kubernetes and Docker API services should have CRITICAL severity."""
        container_types = {
            InternalServiceType.KUBERNETES_API,
            InternalServiceType.DOCKER_API,
        }
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            if svc.service_type in container_types:
                assert svc.severity == Severity.CRITICAL, (
                    f"{svc.description} should be CRITICAL, got {svc.severity}"
                )

    def test_database_services_are_high(self):
        """Database services should have HIGH severity."""
        db_types = {
            InternalServiceType.REDIS,
            InternalServiceType.ELASTICSEARCH,
            InternalServiceType.MONGODB,
        }
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            if svc.service_type in db_types:
                assert svc.severity == Severity.HIGH, (
                    f"{svc.description} should be HIGH, got {svc.severity}"
                )

    def test_monitoring_services_are_medium(self):
        """Monitoring services should have MEDIUM severity."""
        monitoring_types = {
            InternalServiceType.PROMETHEUS,
            InternalServiceType.GRAFANA,
        }
        for svc in DNSRebindingScanner.INTERNAL_SERVICES:
            if svc.service_type in monitoring_types:
                assert svc.severity == Severity.MEDIUM, (
                    f"{svc.description} should be MEDIUM, got {svc.severity}"
                )

    # --- Docker Indicator Specificity (FP fix) ---

    def test_docker_version_indicators_are_json_specific(self):
        """Docker /version indicators should require JSON keys (FP fix 2026-02-12)."""
        docker_version = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.DOCKER_API and s.path == "/version"
        ]
        assert len(docker_version) == 1
        indicators = docker_version[0].indicators
        # Should use JSON-specific patterns, not generic words like "Os"
        assert all('"' in ind for ind in indicators), (
            "Docker /version indicators should be JSON key patterns"
        )

    def test_docker_containers_indicators_are_json_specific(self):
        """Docker /containers/json indicators should require JSON keys (FP fix 2026-02-12)."""
        docker_containers = [
            s for s in DNSRebindingScanner.INTERNAL_SERVICES
            if s.service_type == InternalServiceType.DOCKER_API and s.path == "/containers/json"
        ]
        assert len(docker_containers) == 1
        indicators = docker_containers[0].indicators
        assert all('"' in ind for ind in indicators), (
            "Docker /containers/json indicators should be JSON key patterns"
        )


# ============================================================================
# TESTS: SSRF_PARAMETERS
# ============================================================================

class TestSSRFParameters:
    """Tests for SSRF_PARAMETERS class attribute."""

    def test_count(self):
        """Should have exactly 72 SSRF parameter names."""
        assert len(DNSRebindingScanner.SSRF_PARAMETERS) == 72

    def test_all_are_strings(self):
        """Each parameter should be a string."""
        for param in DNSRebindingScanner.SSRF_PARAMETERS:
            assert isinstance(param, str)
            assert len(param) > 0

    def test_has_url_parameter(self):
        """Should include 'url' parameter."""
        assert "url" in DNSRebindingScanner.SSRF_PARAMETERS

    def test_has_callback_parameter(self):
        """Should include 'callback' parameter."""
        assert "callback" in DNSRebindingScanner.SSRF_PARAMETERS

    def test_has_redirect_parameter(self):
        """Should include 'redirect' parameter."""
        assert "redirect" in DNSRebindingScanner.SSRF_PARAMETERS

    def test_has_webhook_parameter(self):
        """Should include 'webhook' parameter."""
        assert "webhook" in DNSRebindingScanner.SSRF_PARAMETERS

    def test_has_proxy_parameter(self):
        """Should include 'proxy' parameter."""
        assert "proxy" in DNSRebindingScanner.SSRF_PARAMETERS

    def test_has_image_parameters(self):
        """Should include image-related parameters (img, image, avatar)."""
        params = DNSRebindingScanner.SSRF_PARAMETERS
        assert "img" in params
        assert "image" in params
        assert "avatar" in params

    def test_has_xml_parameters(self):
        """Should include XML-related parameters."""
        params = DNSRebindingScanner.SSRF_PARAMETERS
        assert "xml" in params

    def test_has_pdf_parameter(self):
        """Should include PDF-related parameter."""
        assert "pdf" in DNSRebindingScanner.SSRF_PARAMETERS

    def test_no_duplicates(self):
        """Should have no duplicate parameter names."""
        params = DNSRebindingScanner.SSRF_PARAMETERS
        assert len(params) == len(set(params))


# ============================================================================
# TESTS: WEBSOCKET_PATHS
# ============================================================================

class TestWebSocketPaths:
    """Tests for WEBSOCKET_PATHS class attribute."""

    def test_count(self):
        """Should have exactly 16 WebSocket paths."""
        assert len(DNSRebindingScanner.WEBSOCKET_PATHS) == 16

    def test_all_are_strings(self):
        """Each path should be a string."""
        for path in DNSRebindingScanner.WEBSOCKET_PATHS:
            assert isinstance(path, str)

    def test_all_start_with_slash(self):
        """Each path should start with /."""
        for path in DNSRebindingScanner.WEBSOCKET_PATHS:
            assert path.startswith("/"), f"Path '{path}' does not start with /"

    def test_has_ws_path(self):
        """Should include /ws path."""
        assert "/ws" in DNSRebindingScanner.WEBSOCKET_PATHS

    def test_has_websocket_path(self):
        """Should include /websocket path."""
        assert "/websocket" in DNSRebindingScanner.WEBSOCKET_PATHS

    def test_has_socket_io(self):
        """Should include /socket.io/ path."""
        assert "/socket.io/" in DNSRebindingScanner.WEBSOCKET_PATHS

    def test_has_signalr(self):
        """Should include /signalr path."""
        assert "/signalr" in DNSRebindingScanner.WEBSOCKET_PATHS

    def test_has_graphql_ws(self):
        """Should include /graphql-ws path."""
        assert "/graphql-ws" in DNSRebindingScanner.WEBSOCKET_PATHS

    def test_has_sockjs(self):
        """Should include /sockjs/ path."""
        assert "/sockjs/" in DNSRebindingScanner.WEBSOCKET_PATHS


# ============================================================================
# TESTS: SPA_INDICATORS
# ============================================================================

class TestSPAIndicators:
    """Tests for SPA_INDICATORS class attribute."""

    def test_count(self):
        """Should have exactly 24 SPA indicators."""
        assert len(DNSRebindingScanner.SPA_INDICATORS) == 24

    def test_all_are_strings(self):
        """Each indicator should be a string."""
        for indicator in DNSRebindingScanner.SPA_INDICATORS:
            assert isinstance(indicator, str)
            assert len(indicator) > 0

    def test_has_angular(self):
        """Should include Angular indicators."""
        indicators = DNSRebindingScanner.SPA_INDICATORS
        assert "angular" in indicators

    def test_has_react(self):
        """Should include React indicators."""
        indicators = DNSRebindingScanner.SPA_INDICATORS
        assert "react" in indicators

    def test_has_vue(self):
        """Should include Vue indicators."""
        indicators = DNSRebindingScanner.SPA_INDICATORS
        assert "vue" in indicators

    def test_has_svelte(self):
        """Should include Svelte indicators."""
        indicators = DNSRebindingScanner.SPA_INDICATORS
        assert "svelte" in indicators

    def test_has_next_data(self):
        """Should include Next.js __NEXT_DATA__ indicator."""
        assert "__NEXT_DATA__" in DNSRebindingScanner.SPA_INDICATORS

    def test_has_nuxt(self):
        """Should include Nuxt.js __NUXT__ indicator."""
        assert "__NUXT__" in DNSRebindingScanner.SPA_INDICATORS

    def test_has_bundle_pattern(self):
        """Should include bundle.js pattern."""
        assert "bundle.js" in DNSRebindingScanner.SPA_INDICATORS

    def test_has_redux_state(self):
        """Should include Redux state indicator."""
        assert "__REDUX__" in DNSRebindingScanner.SPA_INDICATORS

    def test_no_duplicates(self):
        """Should have no duplicate indicators."""
        indicators = DNSRebindingScanner.SPA_INDICATORS
        assert len(indicators) == len(set(indicators))


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_rebinding_vector_with_empty_payload(self):
        """Should handle empty payload."""
        vector = RebindingVector(
            payload="",
            vector_type=RebindingVectorType.HOST_HEADER_BYPASS,
            description="Empty test",
        )
        assert vector.payload == ""

    def test_rebinding_vulnerability_with_empty_evidence(self):
        """Should handle empty evidence list."""
        vuln = RebindingVulnerability(
            vector_type=RebindingVectorType.CORS_BYPASS,
            payload="null",
            target="https://example.com",
            evidence=[],
            severity="LOW",
            confidence="LOW",
        )
        assert vuln.evidence == []

    def test_internal_service_with_long_path(self):
        """Should handle long paths."""
        svc = InternalService(
            service_type=InternalServiceType.AWS_METADATA,
            host="169.254.169.254",
            port=80,
            path="/latest/meta-data/iam/security-credentials/very-long-role-name-" + "x" * 200,
            indicators=["AccessKeyId"],
            description="Long path test",
        )
        assert len(svc.path) > 200

    def test_rebinding_vector_all_types_constructible(self):
        """Should be able to create a vector for each RebindingVectorType."""
        for vtype in RebindingVectorType:
            vector = RebindingVector(
                payload=f"test_{vtype.value}",
                vector_type=vtype,
                description=f"Test for {vtype.name}",
            )
            assert vector.vector_type == vtype

    def test_internal_service_all_types_constructible(self):
        """Should be able to create a service for each InternalServiceType."""
        for stype in InternalServiceType:
            svc = InternalService(
                service_type=stype,
                host="127.0.0.1",
                port=80,
                path="/test",
                indicators=["test"],
                description=f"Test {stype.name}",
            )
            assert svc.service_type == stype

    def test_vulnerability_with_all_vector_types(self):
        """Should be able to create a vulnerability for each vector type."""
        for vtype in RebindingVectorType:
            vuln = RebindingVulnerability(
                vector_type=vtype,
                payload="test",
                target="https://example.com",
                evidence=["test evidence"],
                severity="MEDIUM",
                confidence="LOW",
            )
            assert vuln.vector_type == vtype
