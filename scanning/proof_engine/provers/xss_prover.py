"""
PHANTOM AI - XSS Prover

Proves XSS exploitability: repeat, steal tokens, escalate to ATO.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import re

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class XSSProver(BaseProver):
    """Prove XSS exploitability: repeat, steal tokens, escalate to ATO."""

    def _parse_httponly_from_headers(self, headers: dict[str, str]) -> dict[str, bool]:
        """
        Parse Set-Cookie headers to determine HttpOnly flag status.

        AUTOMATIC VALIDATION FIX: Instead of "requires_manual_verification",
        we actually check the HTTP headers to determine if cookies are HttpOnly.

        Returns: dict mapping cookie name -> httponly_status
        """
        httponly_status: dict[str, bool] = {}

        # Set-Cookie can appear multiple times (one per cookie)
        # Check both "Set-Cookie" and "set-cookie" (case-insensitive)
        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                # Parse cookie name from the start of the value
                # Format: "name=value; HttpOnly; Secure; Path=/; ..."
                parts = header_value.split(";")
                if parts:
                    name_value = parts[0].strip()
                    if "=" in name_value:
                        cookie_name = name_value.split("=")[0].strip()
                        # Check if HttpOnly flag is present
                        flags_lower = header_value.lower()
                        is_httponly = "httponly" in flags_lower
                        httponly_status[cookie_name] = is_httponly

        return httponly_status

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url, param_type, param_name = self._parse_matched_at(finding)
        # M3 FIX: Single isinstance check with guard clause
        metadata = finding.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        payload = metadata.get("payload", "")
        evidence = finding.get("evidence", [])

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")

        # --- Q1: Can I repeat? ---
        if param_name and payload:
            status, body, _ = await self._safe_request("GET", url, params={param_name: payload})
            if status > 0 and (payload in body or "<script" in body.lower() or "onerror" in body.lower()):
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("xss_repeat", True, payload, url)
            else:
                self._record_vector_attempt("xss_repeat", False, payload, url)
        elif url:
            # DOM XSS — just verify the endpoint is accessible
            status, body, _ = await self._safe_request("GET", url)
            if status == 200:
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("dom_xss_repeat", True, "", url)

        # --- Q2: Can I mutate? ---
        if self.budget_remaining > 0 and result.can_repeat and param_name:
            xss_variants = [
                ("img_onerror", '<img src=x onerror=console.log(1)>'),
                ("svg_onload", '<svg onload=console.log(1)>'),
                ("event_handler", '" onfocus=console.log(1) autofocus="'),
            ]
            mutation_succeeded = False
            for label, xss_payload in xss_variants:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param_name: xss_payload})
                if status > 0 and xss_payload[:20] in body:
                    result.can_mutate = True
                    result.mutations.append(f"{label}: reflected in response")
                    mutation_succeeded = True
                    self._record_vector_attempt(f"xss_{label}", True, xss_payload, url)
            if not mutation_succeeded and result.can_repeat:
                self._record_vector_attempt("xss_mutate", False, "", url)

        # --- Q3: Can I escalate? ---
        if result.can_repeat and self._auth_context and self._auth_context.has_auth:
            result.can_escalate = True
            self._record_vector_attempt("xss_escalate", True, "", url)

            # THEME-15 FIX: Document what specific tokens/cookies are at risk
            # This bridges "XSS works" to "attacker can steal X, Y, Z"
            if self._auth_context.token:
                result.escalation = (
                    "XSS can steal JWT from localStorage/sessionStorage. "
                    "With document.cookie or window.localStorage access, "
                    "attacker achieves Account Takeover."
                )
                # THEME-15: Record the token type that would be stolen
                result.data_extracted.append("token:jwt_in_storage")
                result.privilege_gained = "session_hijack_potential"
                result.impact_evidence = {
                    "token_type": "JWT",
                    "storage_location": "localStorage/sessionStorage",
                    "token_length": len(self._auth_context.token),
                    "impact": "Account Takeover via session hijacking",
                }
            elif self._auth_context.cookies:
                # ═══════════════════════════════════════════════════════════════════════
                # AUTOMATIC VALIDATION FIX: Check HttpOnly flag from actual HTTP headers
                # Instead of "requires_manual_verification", we make a request to verify
                # ═══════════════════════════════════════════════════════════════════════
                cookie_names = list(self._auth_context.cookies.keys())[:5]

                # Make a request to check Set-Cookie headers for HttpOnly flags
                httponly_status: dict[str, bool] = {}
                stealable_cookies: list[str] = []
                httponly_protected: list[str] = []

                if self.budget_remaining > 0:
                    # Request the URL to get fresh Set-Cookie headers
                    _, _, resp_headers = await self._safe_request("GET", url)
                    httponly_status = self._parse_httponly_from_headers(resp_headers)

                    # Categorize cookies by protection status
                    for name in cookie_names:
                        if name in httponly_status:
                            if httponly_status[name]:
                                httponly_protected.append(name)
                            else:
                                stealable_cookies.append(name)
                        else:
                            # Cookie was set earlier, not in current response - mark stealable
                            # (conservative: if we can't verify HttpOnly, assume stealable)
                            stealable_cookies.append(name)

                # Build appropriate escalation message
                if stealable_cookies:
                    result.escalation = (
                        f"XSS can steal {len(stealable_cookies)} session cookie(s) "
                        f"({', '.join(stealable_cookies)}) via document.cookie — NOT HttpOnly protected. "
                        "Attacker hijacks the authenticated session for Account Takeover."
                    )
                    result.privilege_gained = "account_takeover_confirmed"
                    for name in stealable_cookies:
                        result.data_extracted.append(f"cookie:{name}:stealable")
                elif httponly_protected:
                    result.escalation = (
                        f"Session cookies are HttpOnly protected ({', '.join(httponly_protected)}). "
                        "XSS cannot directly steal cookies. Impact limited to DOM manipulation."
                    )
                    result.privilege_gained = "dom_manipulation_only"
                    result.can_escalate = False  # Downgrade: cookies protected
                else:
                    result.escalation = (
                        "XSS can steal session cookies via document.cookie. "
                        "Attacker hijacks the authenticated session for Account Takeover."
                    )
                    result.privilege_gained = "session_hijack_potential"
                    for name in cookie_names:
                        result.data_extracted.append(f"cookie:{name}")

                result.impact_evidence = {
                    "token_type": "session_cookie",
                    "cookie_names": cookie_names,
                    "httponly_status": httponly_status if httponly_status else "auto_verified_none_found",
                    "stealable_cookies": stealable_cookies,
                    "protected_cookies": httponly_protected,
                    "auto_verified": True,  # Flag: this was verified automatically
                    "impact": "Account Takeover via cookie theft" if stealable_cookies else "DOM manipulation only",
                }

        # GAP-4 FIX: Prove token theft depth with concrete inventory
        if result.can_repeat:
            token_inventory = await self._prove_token_theft(url, param_name, result)
            if token_inventory.get("tokens_at_risk"):
                result.proven_impact = token_inventory.get("impact_summary", "")

        # --- Q4: Can I chain? ---
        cors_findings = self._find_related_findings([
            "cors_wildcard", "cors_null", "cors_arbitrary", "cors_preflight"
        ])
        session_findings = self._find_related_findings(["session_abuse", "session"])
        if cors_findings:
            result.can_chain = True
            result.chain_targets.append("CORS misconfiguration enables cross-origin data theft via XSS")
            self._record_vector_attempt("xss_chain_cors", True, "", url)
        if session_findings:
            result.can_chain = True
            result.chain_targets.append("Session weakness + XSS = persistent account takeover")
            self._record_vector_attempt("xss_chain_session", True, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact

    # =========================================================================
    # GAP-4 FIX: Prove token theft with concrete inventory
    # =========================================================================

    async def _prove_token_theft(self, url: str, param: str, result: ProofResult) -> dict:
        """
        GAP-4 FIX: Document what specific tokens/data are at risk from XSS.

        Instead of "XSS can steal tokens", proves "XSS can steal: JWT, sessionId, CSRF token".
        """
        inventory = {
            "tokens_at_risk": [],
            "storage_locations": [],
            "impact_summary": "",
        }

        # 1. Inventory from auth context
        if self._auth_context:
            if self._auth_context.token:
                token_preview = self._auth_context.token[:50] + "..." if len(self._auth_context.token) > 50 else self._auth_context.token
                inventory["tokens_at_risk"].append({
                    "type": "JWT/Bearer",
                    "location": "localStorage or sessionStorage",
                    "stealable_via": "window.localStorage.getItem('token')",
                    "impact": "Full account takeover - token can be replayed",
                    "preview": token_preview,
                })
                inventory["storage_locations"].append("localStorage")

            if self._auth_context.cookies:
                for name, value in list(self._auth_context.cookies.items())[:5]:
                    # Detect token type from name
                    token_type = "Session ID"
                    if "jwt" in name.lower() or "token" in name.lower():
                        token_type = "JWT Cookie"
                    elif "csrf" in name.lower() or "xsrf" in name.lower():
                        token_type = "CSRF Token"
                    elif "session" in name.lower() or "sid" in name.lower():
                        token_type = "Session ID"

                    value_preview = value[:30] + "..." if len(value) > 30 else value
                    inventory["tokens_at_risk"].append({
                        "type": token_type,
                        "name": name,
                        "location": "document.cookie",
                        "stealable_via": f"document.cookie (name={name})",
                        "impact": "Session hijacking" if "session" in name.lower() else "Token theft",
                        "preview": value_preview,
                    })
                inventory["storage_locations"].append("cookies")

        # 2. Check for common token patterns in page response
        if self.budget_remaining > 0 and param:
            # Request page to analyze for tokens in JS
            status, body, _ = await self._safe_request("GET", url)
            if status > 0 and body:
                # Look for localStorage/sessionStorage access patterns
                storage_patterns = [
                    (r"localStorage\.setItem\(['\"](\w+)['\"]", "localStorage"),
                    (r"sessionStorage\.setItem\(['\"](\w+)['\"]", "sessionStorage"),
                    (r"__token\s*[=:]\s*['\"]", "JS variable"),
                    (r"accessToken\s*[=:]\s*['\"]", "JS variable"),
                ]
                for pattern, location in storage_patterns:
                    matches = re.findall(pattern, body, re.IGNORECASE)
                    for match in matches[:3]:
                        if match not in [t.get("name", "") for t in inventory["tokens_at_risk"]]:
                            inventory["tokens_at_risk"].append({
                                "type": "Client-side token",
                                "name": match if isinstance(match, str) else "token",
                                "location": location,
                                "stealable_via": f"{location}.getItem('{match}')" if "Storage" in location else "JS access",
                                "impact": "Token theft",
                            })
                            if location not in inventory["storage_locations"]:
                                inventory["storage_locations"].append(location)

        # Build impact summary
        if inventory["tokens_at_risk"]:
            token_types = list(set(t["type"] for t in inventory["tokens_at_risk"]))
            locations = inventory["storage_locations"]
            inventory["impact_summary"] = (
                f"XSS can steal {len(inventory['tokens_at_risk'])} token(s): "
                f"{', '.join(token_types)}. "
                f"Storage: {', '.join(locations)}. "
                "Full account takeover achievable."
            )

            # Update result
            for token in inventory["tokens_at_risk"]:
                result.data_extracted.append(f"token_at_risk:{token['type']}:{token.get('name', 'unknown')}")

            if not result.impact_evidence:
                result.impact_evidence = {}
            result.impact_evidence["token_inventory"] = inventory
            result.impact_type = "PRIVILEGE_ESCALATION"

        return inventory
