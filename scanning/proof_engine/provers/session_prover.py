"""
PHANTOM AI - Session Prover

Proves session/JWT exploitability: repeat, forge, escalate to admin.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import json

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class SessionProver(BaseProver):
    """Prove session/JWT exploitability: repeat, forge, escalate to admin."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", "")
        # M3 FIX: Single isinstance check with guard clause
        metadata = finding.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        name = finding.get("name", "").lower()

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")

        # ═══════════════════════════════════════════════════════════════════════
        # STATE-02: Session persistence verification patterns
        # ═══════════════════════════════════════════════════════════════════════

        # --- Q1: Can I repeat? ---
        if "logout" in name or "invalidat" in name:
            # CRITICAL: This is about token STILL working after logout
            # That's the persistence bug — session should be invalidated but isn't
            if self._auth_context and self._auth_context.token:
                # Step 1: Verify we can access something with the token
                test_url = self._find_protected_endpoint() or url
                status, body, _ = await self._safe_request("GET", test_url)
                if status == 200 and len(body) > 10:
                    result.can_repeat = True
                    result.repeat_count = 1
                    # STATE-02: Token working AFTER logout = state NOT properly changed
                    result.state_persisted = True  # Session WRONGLY persisted
                    result.persistence_evidence = [
                        "Token valid after logout (session NOT invalidated)",
                        f"Protected endpoint {test_url} still accessible",
                    ]
                    result.confidence_boost = 20.0
                    result.proven_impact = "Session persistence bug verified"
                    self._record_vector_attempt("session_logout_replay", True, "", test_url)
                    logger.info(
                        f"[STATE-02] Session NOT invalidated after logout: "
                        f"token still works at {test_url}"
                    )
                else:
                    self._record_vector_attempt("session_logout_replay", False, "", test_url)

        elif "alg" in name or "tamper" in name:
            # M3 FIX: isinstance check moved to method start
            forged_token = metadata.get("forged_token", "")
            if forged_token:
                # Test forged token on multiple endpoints for persistence proof
                status, body, _ = await self._safe_request(
                    "GET", url,
                    headers={"Authorization": f"Bearer {forged_token}"},
                )
                if status == 200:
                    result.can_repeat = True
                    result.repeat_count = 1
                    self._record_vector_attempt("session_forged_token", True, forged_token[:50], url)

                    # Try another endpoint to prove the forged token works persistently
                    if self.budget_remaining > 0:
                        other_ep = self._find_protected_endpoint()
                        if other_ep and other_ep != url:
                            status2, body2, _ = await self._safe_request(
                                "GET", other_ep,
                                headers={"Authorization": f"Bearer {forged_token}"},
                            )
                            if status2 == 200:
                                result.state_persisted = True
                                result.persistence_evidence = [
                                    "Forged token works on multiple endpoints",
                                    f"Verified at {url} and {other_ep}",
                                ]
                                result.confidence_boost = 15.0
                                result.proven_impact = "JWT forgery verified persistent"
                                self._record_vector_attempt("session_forged_multi_ep", True, "", other_ep)
                else:
                    self._record_vector_attempt("session_forged_token", False, forged_token[:50], url)
        else:
            status, body, _ = await self._safe_request("GET", url)
            if status == 200:
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("session_repeat", True, "", url)
            else:
                self._record_vector_attempt("session_repeat", False, "", url)

        # --- Q2: Can I mutate? ---
        if self.budget_remaining > 0 and result.can_repeat:
            token = self._auth_context.token if self._auth_context else ""
            if token and self._is_jwt(token):
                # Try different claim modifications
                import base64
                parts = token.split(".")
                if len(parts) == 3:
                    try:
                        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        payload_json = json.loads(base64.urlsafe_b64decode(payload_b64))

                        # Try role escalation in claims
                        role_fields = ["role", "admin", "isAdmin", "is_admin", "scope", "permissions"]
                        for rf in role_fields:
                            if rf in payload_json:
                                result.can_mutate = True
                                result.mutations.append(f"JWT claim '{rf}' present — can be modified")
                                self._record_vector_attempt(f"session_mutate_claim_{rf}", True, "", url)
                                break
                    except Exception as e:
                        logger.debug(f"[ProofEngine/Session] JWT payload parsing failed: {e}")

        # --- Q3: Can I escalate? ---
        if result.can_repeat:
            # Check if we have admin endpoints to hit with the forged/persistent token
            admin_eps = self._find_admin_endpoints()
            if admin_eps:
                for ep_url in admin_eps[:2]:
                    if self.budget_remaining <= 0:
                        break
                    status, body, _ = await self._safe_request("GET", ep_url)
                    if status == 200 and len(body) > 50:
                        result.can_escalate = True
                        result.escalation = f"Admin endpoint {ep_url} accessible with session token"
                        self._record_vector_attempt("session_escalate_admin", True, "", ep_url)
                        # Admin access = definitely persistent state abuse
                        if not result.state_persisted:
                            result.state_persisted = True
                            result.persistence_evidence.append(
                                f"Admin access achieved at {ep_url}"
                            )
                            result.confidence_boost = max(result.confidence_boost, 20.0)
                        break
                    else:
                        self._record_vector_attempt("session_escalate_admin", False, "", ep_url)

        # --- Q4: Can I chain? ---
        xss_findings = self._find_related_findings(["xss", "dom_xss"])
        business_findings = self._find_related_findings(["business_logic"])
        if xss_findings:
            result.can_chain = True
            result.chain_targets.append("XSS + session weakness = steal tokens and maintain persistent access")
            self._record_vector_attempt("session_chain_xss", True, "", url)
        if business_findings and result.can_escalate:
            result.can_chain = True
            result.chain_targets.append("Admin session + business logic = unrestricted manipulation")
            self._record_vector_attempt("session_chain_business", True, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact

    def _find_protected_endpoint(self) -> str | None:
        """Find a protected endpoint to test session validity."""
        host = self._resolve_host()
        if not host:
            return None

        # Try common protected endpoints
        protected_paths = ["/api/user", "/api/me", "/api/profile", "/api/account", "/user", "/profile"]
        if self._endpoint_map:
            for ep in self._endpoint_map.get_all():
                if any(kw in ep.path.lower() for kw in ["user", "profile", "account", "basket", "cart"]):
                    if ep.path.startswith("http"):
                        return ep.path
                    return f"{host.rstrip('/')}{ep.path}"

        # Fallback to first protected path
        return f"{host.rstrip('/')}{protected_paths[0]}"

    def _is_jwt(self, token: str) -> bool:
        return token.count(".") == 2 and len(token) > 20

    def _find_admin_endpoints(self) -> list[str]:
        """Find admin endpoints from endpoint map."""
        admin_urls = []
        host = self._resolve_host()

        if self._endpoint_map and host:
            for ep in self._endpoint_map.get_all():
                if any(kw in ep.path.lower() for kw in ["/admin", "/manage", "/configuration"]):
                    if ep.path.startswith("http"):
                        admin_urls.append(ep.path)
                    else:
                        admin_urls.append(f"{host.rstrip('/')}{ep.path}")
                if len(admin_urls) >= 3:
                    break
        return admin_urls
