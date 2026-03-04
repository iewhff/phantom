"""
Tests for scanning/modules/kubernetes_scanner.py

Covers:
- KubernetesContainerScanner.name attribute
- ScanModule subclass verification
- K8S_API_PATHS (18 items)
- KUBELET_PATHS (11 items)
- ETCD_PATHS (6 items)
- REGISTRY_PATHS (4 items)
- Port lists: K8S_PORTS, KUBELET_PORTS, ETCD_PORTS, DASHBOARD_PORTS, REGISTRY_PORTS
- All paths start with /
"""

import pytest

from scanning.modules.kubernetes_scanner import KubernetesContainerScanner
from scanning.vuln_scanner import ScanModule


# =============================================================================
# CLASS IDENTITY
# =============================================================================

class TestKubernetesContainerScannerIdentity:
    def test_name(self):
        assert KubernetesContainerScanner.name == "kubernetes_container_scanner"

    def test_is_scan_module_subclass(self):
        assert issubclass(KubernetesContainerScanner, ScanModule)


# =============================================================================
# K8S_API_PATHS
# =============================================================================

class TestK8sApiPaths:
    def test_count(self):
        assert len(KubernetesContainerScanner.K8S_API_PATHS) == 19

    def test_all_start_with_slash(self):
        for path in KubernetesContainerScanner.K8S_API_PATHS:
            assert path.startswith("/"), f"Path does not start with /: {path}"

    def test_contains_api(self):
        assert "/api" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_api_v1(self):
        assert "/api/v1" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_api_v1_namespaces(self):
        assert "/api/v1/namespaces" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_api_v1_pods(self):
        assert "/api/v1/pods" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_api_v1_secrets(self):
        assert "/api/v1/secrets" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_healthz(self):
        assert "/healthz" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_version(self):
        assert "/version" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_metrics(self):
        assert "/metrics" in KubernetesContainerScanner.K8S_API_PATHS

    def test_contains_swagger_json(self):
        assert "/swagger.json" in KubernetesContainerScanner.K8S_API_PATHS


# =============================================================================
# KUBELET_PATHS
# =============================================================================

class TestKubeletPaths:
    def test_count(self):
        assert len(KubernetesContainerScanner.KUBELET_PATHS) == 11

    def test_all_start_with_slash(self):
        for path in KubernetesContainerScanner.KUBELET_PATHS:
            assert path.startswith("/"), f"Path does not start with /: {path}"

    def test_contains_pods(self):
        assert "/pods" in KubernetesContainerScanner.KUBELET_PATHS

    def test_contains_spec(self):
        assert "/spec" in KubernetesContainerScanner.KUBELET_PATHS

    def test_contains_metrics(self):
        assert "/metrics" in KubernetesContainerScanner.KUBELET_PATHS

    def test_contains_exec(self):
        assert "/exec" in KubernetesContainerScanner.KUBELET_PATHS

    def test_contains_runningpods(self):
        assert "/runningpods" in KubernetesContainerScanner.KUBELET_PATHS


# =============================================================================
# ETCD_PATHS
# =============================================================================

class TestEtcdPaths:
    def test_count(self):
        assert len(KubernetesContainerScanner.ETCD_PATHS) == 6

    def test_all_start_with_slash(self):
        for path in KubernetesContainerScanner.ETCD_PATHS:
            assert path.startswith("/"), f"Path does not start with /: {path}"


# =============================================================================
# REGISTRY_PATHS
# =============================================================================

class TestRegistryPaths:
    def test_count(self):
        assert len(KubernetesContainerScanner.REGISTRY_PATHS) == 4

    def test_all_start_with_slash(self):
        for path in KubernetesContainerScanner.REGISTRY_PATHS:
            assert path.startswith("/"), f"Path does not start with /: {path}"

    def test_contains_v2_root(self):
        assert "/v2/" in KubernetesContainerScanner.REGISTRY_PATHS

    def test_contains_v2_catalog(self):
        assert "/v2/_catalog" in KubernetesContainerScanner.REGISTRY_PATHS


# =============================================================================
# PORT LISTS
# =============================================================================

class TestK8sPorts:
    def test_values(self):
        assert KubernetesContainerScanner.K8S_PORTS == [6443, 8443, 443]


class TestKubeletPorts:
    def test_values(self):
        assert KubernetesContainerScanner.KUBELET_PORTS == [10250, 10255]


class TestEtcdPorts:
    def test_values(self):
        assert KubernetesContainerScanner.ETCD_PORTS == [2379, 2380]


class TestDashboardPorts:
    def test_values(self):
        assert KubernetesContainerScanner.DASHBOARD_PORTS == [8001, 30000, 443]


class TestRegistryPorts:
    def test_values(self):
        assert KubernetesContainerScanner.REGISTRY_PORTS == [5000, 5001]
