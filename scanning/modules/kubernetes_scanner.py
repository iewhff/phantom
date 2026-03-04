"""
Kubernetes and Container Security Scanner.
Tests for Kubernetes misconfigurations and container security issues.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class KubernetesContainerScanner(ScanModule):
    """
    Kubernetes and Container Security Scanner.
    
    Tests for:
    - Exposed Kubernetes API
    - Kubernetes Dashboard exposure
    - etcd exposure
    - Kubelet API access
    - Service account token leakage
    - Namespace escapes
    - Pod security policy bypass
    - Container escape vectors
    - Registry misconfigurations
    - Helm Tiller exposure
    - Metrics endpoint exposure
    - Debug endpoints
    """
    
    name = "kubernetes_container_scanner"
    
    # Kubernetes API paths
    K8S_API_PATHS = [
        "/api",
        "/api/v1",
        "/apis",
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/nodes",
        "/api/v1/secrets",
        "/api/v1/configmaps",
        "/api/v1/serviceaccounts",
        "/apis/apps/v1/deployments",
        "/healthz",
        "/livez",
        "/readyz",
        "/version",
        "/metrics",
        "/debug/pprof",
        "/openapi/v2",
        "/swagger.json",
        "/swaggerapi",
    ]
    
    # Kubelet paths
    KUBELET_PATHS = [
        "/pods",
        "/spec",
        "/metrics",
        "/stats/summary",
        "/logs",
        "/run",
        "/exec",
        "/attach",
        "/portForward",
        "/containerLogs",
        "/runningpods",
    ]
    
    # etcd paths
    ETCD_PATHS = [
        "/v2/keys",
        "/v2/keys/",
        "/v3/kv/range",
        "/health",
        "/version",
        "/metrics",
    ]
    
    # Container registry paths
    REGISTRY_PATHS = [
        "/v2/",
        "/v2/_catalog",
        "/v1/_ping",
        "/v1/search",
    ]
    
    # Common ports
    K8S_PORTS = [6443, 8443, 443]  # API Server
    KUBELET_PORTS = [10250, 10255]
    ETCD_PORTS = [2379, 2380]
    DASHBOARD_PORTS = [8001, 30000, 443]
    REGISTRY_PORTS = [5000, 5001]
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for Kubernetes and container vulnerabilities."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        
        # Clean host for testing
        clean_host = host.replace("https://", "").replace("http://", "").split("/")[0]
        
        async with get_scan_client(verify_ssl=False, timeout=self.timeout) as client:
            # Test Kubernetes API
            k8s_findings = await self._test_kubernetes_api(
                client, clean_host, rate_limiter
            )
            findings.extend(k8s_findings)
            
            # Test Kubelet
            kubelet_findings = await self._test_kubelet(
                client, clean_host, rate_limiter
            )
            findings.extend(kubelet_findings)
            
            # Test etcd
            etcd_findings = await self._test_etcd(
                client, clean_host, rate_limiter
            )
            findings.extend(etcd_findings)
            
            # Test Kubernetes Dashboard
            dashboard_findings = await self._test_dashboard(
                client, clean_host, rate_limiter
            )
            findings.extend(dashboard_findings)
            
            # Test Container Registry
            registry_findings = await self._test_container_registry(
                client, clean_host, rate_limiter
            )
            findings.extend(registry_findings)
            
            # Test Helm Tiller
            tiller_findings = await self._test_helm_tiller(
                client, clean_host, rate_limiter
            )
            findings.extend(tiller_findings)
            
            # Test for container escape indicators
            escape_findings = await self._test_container_escape(
                client, clean_host, rate_limiter
            )
            findings.extend(escape_findings)
            
            # Test metrics and debug endpoints
            metrics_findings = await self._test_metrics_endpoints(
                client, clean_host, rate_limiter
            )
            findings.extend(metrics_findings)

        return {"findings": [f.to_dict() for f in findings], "info": []}
    
    async def _test_kubernetes_api(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed Kubernetes API."""
        findings = []
        
        for port in self.K8S_PORTS:
            for path in self.K8S_API_PATHS:
                await rate_limiter.acquire()
                
                try:
                    url = f"https://{host}:{port}{path}"
                    response = await client.get(url, timeout=5.0)
                    
                    if response.status_code in [200, 401, 403]:
                        try:
                            data = response.json()
                            
                            # Successful access
                            if response.status_code == 200:
                                if path == "/api/v1/secrets":
                                    findings.append(Finding(
                                        name="Kubernetes Secrets Exposed",
                                        severity=Severity.CRITICAL,
                                        confidence_score=85.0,
                                        description="Kubernetes secrets API accessible without authentication",
                                        endpoint=url,
                                        evidence=[f"Secrets accessible: {len(data.get('items', []))} items"] if isinstance(data, dict) else [],
                                        cwe_id="CWE-200",
                                        cvss_score=9.8,
                                        remediation="Enable RBAC. Restrict API access. Use network policies.",
                                    ))
                                elif path == "/api/v1/pods":
                                    findings.append(Finding(
                                        name="Kubernetes Pods Exposed",
                                        severity=Severity.HIGH,
                                        confidence_score=85.0,
                                        description="Kubernetes pods API accessible",
                                        endpoint=url,
                                        evidence=[f"Pods visible: {len(data.get('items', []))} items"] if isinstance(data, dict) else [],
                                        cwe_id="CWE-200",
                                        cvss_score=7.5,
                                        remediation="Restrict API server access.",
                                    ))
                                elif path == "/api" or path == "/version":
                                    findings.append(Finding(
                                        name="Kubernetes API Server Exposed",
                                        severity=Severity.HIGH,
                                        confidence_score=85.0,
                                        description="Kubernetes API server publicly accessible",
                                        endpoint=url,
                                        evidence=[
                                            f"API accessible",
                                            f"Version info: {data.get('gitVersion', 'unknown')}" if isinstance(data, dict) else "Version info: unknown",
                                        ],
                                        cwe_id="CWE-200",
                                        cvss_score=7.5,
                                        remediation="Restrict API server to internal network. Use firewall rules.",
                                    ))
                                elif path == "/metrics":
                                    findings.append(Finding(
                                        name="Kubernetes Metrics Exposed",
                                        severity=Severity.MEDIUM,
                                        confidence_score=85.0,
                                        description="Kubernetes metrics endpoint accessible",
                                        endpoint=url,
                                        evidence=["Prometheus metrics exposed"],
                                        cwe_id="CWE-200",
                                        cvss_score=5.3,
                                        remediation="Protect metrics endpoint with authentication.",
                                    ))
                            
                            # 401 with version info still reveals K8s presence
                            elif response.status_code == 401:
                                findings.append(Finding(
                                    name="Kubernetes API Server Detected",
                                    severity=Severity.INFO,
                                    confidence_score=85.0,
                                    description="Kubernetes API server detected (requires auth)",
                                    endpoint=url,
                                    evidence=["API server responds but requires authentication"],
                                    cwe_id="CWE-200",
                                    remediation="Ensure API server not publicly accessible.",
                                ))
                                break
                                
                        except json.JSONDecodeError:
                            pass
                            
                except Exception as e:
                    logger.debug(f"Error testing K8s API {path}: {e}")
        
        return findings
    
    async def _test_kubelet(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed Kubelet API."""
        findings = []
        
        for port in self.KUBELET_PORTS:
            for path in self.KUBELET_PATHS:
                await rate_limiter.acquire()
                
                try:
                    url = f"https://{host}:{port}{path}"
                    response = await client.get(url, timeout=5.0)
                    
                    if response.status_code == 200:
                        if path == "/pods" or path == "/runningpods":
                            try:
                                data = response.json()
                                findings.append(Finding(
                                    name="Kubelet API Exposed (Pods)",
                                    severity=Severity.CRITICAL,
                                    confidence_score=85.0,
                                    description="Kubelet API allows listing pods - can lead to RCE",
                                    endpoint=url,
                                    evidence=[f"Running pods visible"],
                                    cwe_id="CWE-284",
                                    cvss_score=9.8,
                                    remediation="Disable anonymous kubelet access. "
                                               "Set --anonymous-auth=false.",
                                ))
                            except json.JSONDecodeError:
                                pass
                                
                        elif path in ["/exec", "/run"]:
                            findings.append(Finding(
                                name="Kubelet Exec/Run API Exposed",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="Kubelet exec API allows command execution in containers",
                                endpoint=url,
                                evidence=["Exec endpoint accessible"],
                                cwe_id="CWE-78",
                                cvss_score=10.0,
                                remediation="Disable anonymous kubelet access immediately.",
                            ))
                            
                        elif path == "/metrics":
                            findings.append(Finding(
                                name="Kubelet Metrics Exposed",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="Kubelet metrics reveal node information",
                                endpoint=url,
                                evidence=["Kubelet Prometheus metrics accessible"],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                                remediation="Protect kubelet metrics with authentication.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing kubelet {path}: {e}")
        
        return findings
    
    async def _test_etcd(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed etcd."""
        findings = []
        
        for port in self.ETCD_PORTS:
            for path in self.ETCD_PATHS:
                await rate_limiter.acquire()
                
                try:
                    url = f"http://{host}:{port}{path}"
                    response = await client.get(url, timeout=5.0)
                    
                    if response.status_code == 200:
                        if path == "/v2/keys" or path == "/v2/keys/":
                            findings.append(Finding(
                                name="etcd Database Exposed",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="etcd database publicly accessible - contains all K8s secrets",
                                endpoint=url,
                                evidence=["etcd keys endpoint accessible"],
                                cwe_id="CWE-200",
                                cvss_score=10.0,
                                remediation="Never expose etcd publicly. "
                                           "Use TLS client certificates. "
                                           "Restrict to localhost/internal.",
                            ))
                        elif path == "/health" or path == "/version":
                            findings.append(Finding(
                                name="etcd Endpoint Detected",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description="etcd endpoint publicly reachable",
                                endpoint=url,
                                evidence=[f"etcd health/version endpoint accessible"],
                                cwe_id="CWE-200",
                                cvss_score=7.5,
                                remediation="Restrict etcd access to internal network.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing etcd: {e}")
        
        return findings
    
    async def _test_dashboard(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed Kubernetes Dashboard."""
        findings = []
        
        dashboard_paths = [
            "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/",
            "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/",
            "/ui",
            "/dashboard",
        ]
        
        for port in self.DASHBOARD_PORTS:
            for path in dashboard_paths:
                await rate_limiter.acquire()
                
                try:
                    url = f"https://{host}:{port}{path}"
                    response = await client.get(url, timeout=5.0, follow_redirects=True)
                    
                    if response.status_code == 200:
                        if "kubernetes dashboard" in response.text.lower() or "kube-dashboard" in response.text.lower():
                            # Check if auth is required
                            if "login" not in response.text.lower():
                                findings.append(Finding(
                                    name="Kubernetes Dashboard Exposed (No Auth)",
                                    severity=Severity.CRITICAL,
                                    confidence_score=85.0,
                                    description="Kubernetes Dashboard accessible without authentication",
                                    endpoint=url,
                                    evidence=["Dashboard accessible without login"],
                                    cwe_id="CWE-306",
                                    cvss_score=9.8,
                                    remediation="Enable authentication for dashboard. "
                                               "Consider removing dashboard in production.",
                                ))
                            else:
                                findings.append(Finding(
                                    name="Kubernetes Dashboard Exposed",
                                    severity=Severity.HIGH,
                                    confidence_score=85.0,
                                    description="Kubernetes Dashboard publicly accessible (requires login)",
                                    endpoint=url,
                                    evidence=["Dashboard login page exposed"],
                                    cwe_id="CWE-200",
                                    cvss_score=6.5,
                                    remediation="Restrict dashboard to internal access only. "
                                               "Use kubectl proxy or VPN.",
                                ))
                                
                except Exception as e:
                    logger.debug(f"Error testing dashboard: {e}")
        
        return findings
    
    async def _test_container_registry(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed container registries."""
        findings = []
        
        for port in self.REGISTRY_PORTS:
            for path in self.REGISTRY_PATHS:
                await rate_limiter.acquire()
                
                try:
                    url = f"https://{host}:{port}{path}"
                    response = await client.get(url, timeout=5.0)
                    
                    if response.status_code == 200:
                        if path == "/v2/_catalog":
                            try:
                                data = response.json()
                                repos = []
                                if isinstance(asset_data, dict):
                                    repos = data.get("repositories", [])
                                
                                findings.append(Finding(
                                    name="Container Registry Catalog Exposed",
                                    severity=Severity.HIGH,
                                    confidence_score=85.0,
                                    description="Container registry allows listing all repositories",
                                    endpoint=url,
                                    evidence=[
                                        f"Repositories: {len(repos)}",
                                        f"Sample: {repos[:5] if repos else 'empty'}",
                                    ],
                                    cwe_id="CWE-200",
                                    cvss_score=7.5,
                                    remediation="Enable authentication for registry. "
                                               "Disable anonymous catalog listing.",
                                ))
                            except json.JSONDecodeError:
                                pass
                                
                        elif path == "/v2/":
                            findings.append(Finding(
                                name="Container Registry Exposed",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="Container registry API v2 accessible",
                                endpoint=url,
                                evidence=["Registry API responds"],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                                remediation="Restrict registry access. Require authentication.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing registry: {e}")
        
        return findings
    
    async def _test_helm_tiller(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed Helm Tiller."""
        findings = []
        
        tiller_ports = [44134, 44135]
        
        for port in tiller_ports:
            await rate_limiter.acquire()
            
            try:
                # Tiller uses gRPC, but we can check if port responds
                url = f"http://{host}:{port}/version"
                response = await client.get(url, timeout=5.0)
                
                # If port responds at all, Tiller might be there
                findings.append(Finding(
                    name="Helm Tiller Port Open",
                    severity=Severity.HIGH,
                    confidence_score=40.0,
                    description=f"Helm Tiller port {port} appears open",
                    endpoint=f"{host}:{port}",
                    evidence=["Port responds - may be Tiller"],
                    cwe_id="CWE-284",
                    cvss_score=7.5,
                    remediation="Helm v3 doesn't use Tiller. "
                               "If using Helm v2, restrict Tiller access.",
                ))
                
            except Exception:
                pass  # Port closed or error
        
        return findings
    
    async def _test_container_escape(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for container escape vectors via web."""
        findings = []
        
        # Test for Docker socket exposure via web
        docker_paths = [
            "/var/run/docker.sock",
            "/_docker/",
            "/docker",
            "/containers/json",
        ]
        
        base_url = f"https://{host}"
        
        for path in docker_paths:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, timeout=5.0)
                
                if response.status_code == 200:
                    if "docker" in response.text.lower() or "container" in response.text.lower():
                        findings.append(Finding(
                            name="Docker Socket/API Exposed via Web",
                            severity=Severity.CRITICAL,
                            confidence_score=65.0,
                            description="Docker API or socket may be exposed via web",
                            endpoint=url,
                            evidence=["Docker-related endpoint accessible"],
                            cwe_id="CWE-284",
                            cvss_score=9.8,
                            remediation="Never expose Docker socket to web. "
                                       "Use proper access controls.",
                        ))
                        
            except Exception:
                pass
        
        return findings
    
    async def _test_metrics_endpoints(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for exposed metrics and debug endpoints."""
        findings = []
        
        metrics_paths = [
            "/metrics",
            "/debug/pprof",
            "/debug/vars",
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/actuator/heapdump",
            "/_status",
            "/status",
            "/healthz",
        ]
        
        base_url = f"https://{host}"
        
        for path in metrics_paths:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, timeout=5.0)
                
                if response.status_code == 200:
                    if path == "/debug/pprof":
                        findings.append(Finding(
                            name="Go pprof Debug Endpoint Exposed",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description="Go pprof profiling endpoint exposed",
                            endpoint=url,
                            evidence=["pprof endpoint accessible"],
                            cwe_id="CWE-200",
                            cvss_score=6.5,
                            remediation="Disable pprof in production or restrict access.",
                        ))
                    elif "/actuator" in path:
                        findings.append(Finding(
                            name="Spring Boot Actuator Exposed",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description="Spring Boot actuator endpoints exposed",
                            endpoint=url,
                            evidence=[f"Actuator endpoint: {path}"],
                            cwe_id="CWE-200",
                            cvss_score=6.5,
                            remediation="Restrict actuator endpoints. "
                                       "Use management.endpoints.web.exposure.include to limit.",
                        ))
                    elif path == "/metrics":
                        # Check if it's Prometheus metrics
                        if "# HELP" in response.text or "# TYPE" in response.text:
                            findings.append(Finding(
                                name="Prometheus Metrics Exposed",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="Prometheus metrics endpoint publicly accessible",
                                endpoint=url,
                                evidence=["Prometheus metrics format detected"],
                                cwe_id="CWE-200",
                                cvss_score=4.3,
                                remediation="Protect metrics endpoint with authentication.",
                            ))
                            
            except Exception:
                pass
        
        return findings
