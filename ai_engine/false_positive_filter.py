"""
False positive filter using AI and signature-based detection.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from ai_engine.model_manager import ModelManager
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class FalsePositiveFilter:
    """
    Filters false positives from vulnerability findings.
    
    Uses:
    - Known false positive signatures
    - AI-based contextual analysis
    - Technology stack awareness
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize filter.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.analysis.fp_filter
        self.model = ModelManager(settings)
        
        # Load FP signatures
        self.signatures = self._load_signatures()
        
        # Load prompt
        self.prompt_template = self._load_prompt()
    
    def _load_signatures(self) -> list[dict[str, Any]]:
        """Load false positive signatures."""
        # FIX 2026-02-18: Massively expanded FP signatures for better precision
        # Built-in signatures
        signatures = [
            # ========================================
            # SSL/TLS False Positives
            # ========================================
            {
                "name": "lets_encrypt_issuer",
                "template": "ssl-issuer",
                "condition": lambda f: "Let's Encrypt" in str(f.get("evidence", [])),
                "reason": "Let's Encrypt is a valid certificate authority",
            },
            {
                "name": "digicert_issuer",
                "condition": lambda f: (
                    "ssl" in f.get("name", "").lower() and
                    "digicert" in str(f.get("evidence", [])).lower()
                ),
                "reason": "DigiCert is a trusted certificate authority",
            },
            {
                "name": "self_signed_localhost",
                "condition": lambda f: (
                    "self-signed" in f.get("name", "").lower() and
                    ("localhost" in str(f.get("matched_at", "")).lower() or
                     "127.0.0.1" in str(f.get("matched_at", "")))
                ),
                "reason": "Self-signed certificates on localhost are expected",
            },

            # ========================================
            # CDN/WAF/Proxy False Positives
            # ========================================
            {
                "name": "cloudflare_cdn",
                "type": "headers",
                "condition": lambda f: "cloudflare" in str(f.get("evidence", [])).lower(),
                "reason": "Cloudflare CDN headers are expected",
            },
            {
                "name": "akamai_cdn",
                "condition": lambda f: (
                    "header" in f.get("name", "").lower() and
                    "akamai" in str(f.get("evidence", [])).lower()
                ),
                "reason": "Akamai CDN headers are expected",
            },
            {
                "name": "fastly_cdn",
                "condition": lambda f: (
                    "header" in f.get("name", "").lower() and
                    "fastly" in str(f.get("evidence", [])).lower()
                ),
                "reason": "Fastly CDN headers are expected",
            },
            {
                "name": "waf_blocked_response",
                "condition": lambda f: any(
                    x in str(f.get("evidence", [])).lower()
                    for x in ["waf", "blocked", "firewall", "mod_security", "request rejected"]
                ),
                "reason": "WAF blocked the request - not a real vulnerability",
            },

            # ========================================
            # Informational/Low Severity FPs
            # ========================================
            {
                "name": "development_server_warning",
                "condition": lambda f: (
                    "development" in f.get("name", "").lower() and
                    f.get("severity", "").upper() == "INFO"
                ),
                "reason": "Development server warnings are informational",
            },
            {
                "name": "version_disclosure_low",
                "condition": lambda f: (
                    "version" in f.get("name", "").lower() and
                    "disclosure" in f.get("name", "").lower() and
                    f.get("severity", "").upper() in ("INFO", "LOW")
                ),
                "reason": "Low severity version disclosure is informational",
            },
            {
                "name": "missing_header_info",
                "condition": lambda f: (
                    "missing" in f.get("name", "").lower() and
                    "header" in f.get("name", "").lower() and
                    f.get("severity", "").upper() in ("INFO", "LOW")
                ),
                "reason": "Missing headers are often informational",
            },

            # ========================================
            # Technology-Specific FPs
            # ========================================
            {
                "name": "react_error_boundary",
                "condition": lambda f: (
                    "xss" in f.get("name", "").lower() and
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ["react", "__react", "data-reactroot"])
                ),
                "reason": "React auto-escapes by default - verify manually",
            },
            {
                "name": "vue_auto_escape",
                "condition": lambda f: (
                    "xss" in f.get("name", "").lower() and
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ["vue", "__vue__", "v-text"])
                ),
                "reason": "Vue.js auto-escapes by default - verify manually",
            },
            {
                "name": "angular_sanitization",
                "condition": lambda f: (
                    "xss" in f.get("name", "").lower() and
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ["angular", "ng-app", "[innertext]"])
                ),
                "reason": "Angular sanitizes by default - verify manually",
            },
            {
                "name": "django_auto_escape",
                "condition": lambda f: (
                    any(x in f.get("name", "").lower() for x in ["xss", "ssti"]) and
                    "django" in str(f.get("evidence", [])).lower()
                ),
                "reason": "Django auto-escapes templates by default",
            },
            {
                "name": "rails_sanitization",
                "condition": lambda f: (
                    "xss" in f.get("name", "").lower() and
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ["rails", "ruby on rails", "erb"])
                ),
                "reason": "Rails auto-escapes ERB by default",
            },
            {
                "name": "laravel_blade_escape",
                "condition": lambda f: (
                    any(x in f.get("name", "").lower() for x in ["xss", "ssti"]) and
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ["laravel", "blade"])
                ),
                "reason": "Laravel Blade auto-escapes {{ }} by default",
            },

            # ========================================
            # API/Response Pattern FPs
            # ========================================
            {
                "name": "graphql_introspection_disabled",
                "condition": lambda f: (
                    "introspection" in f.get("name", "").lower() and
                    "disabled" in str(f.get("evidence", [])).lower()
                ),
                "reason": "GraphQL introspection is already disabled",
            },
            {
                "name": "api_error_response",
                "condition": lambda f: (
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ['"error":', '"status": "error"', '"success": false']) and
                    f.get("confidence", 100) < 70
                ),
                "reason": "API error response - not a vulnerability indicator",
            },
            {
                "name": "rate_limited_response",
                "condition": lambda f: (
                    any(x in str(f.get("evidence", [])).lower()
                        for x in ["rate limit", "too many requests", "429", "throttled"])
                ),
                "reason": "Request was rate limited - not a real vulnerability",
            },

            # ========================================
            # Duplicate/Redundant Findings
            # ========================================
            {
                "name": "cors_with_credentials_false",
                "condition": lambda f: (
                    "cors" in f.get("name", "").lower() and
                    # Only filter CORS findings that explicitly show credentials: false
                    # Do NOT filter wildcard or origin reflection findings
                    "access-control-allow-credentials: false" in str(f.get("evidence", [])).lower()
                ),
                "reason": "CORS without credentials is lower risk",
            },
            {
                "name": "clickjacking_with_csp",
                "condition": lambda f: (
                    "clickjacking" in f.get("name", "").lower() and
                    "frame-ancestors" in str(f.get("evidence", [])).lower()
                ),
                "reason": "CSP frame-ancestors provides clickjacking protection",
            },

            # ========================================
            # Static Asset/Content FPs
            # ========================================
            {
                "name": "static_asset_finding",
                "condition": lambda f: any(
                    f.get("matched_at", "").lower().endswith(ext)
                    for ext in [".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2"]
                ),
                "reason": "Static assets cannot have server-side vulnerabilities",
            },
            {
                "name": "documentation_page",
                "condition": lambda f: any(
                    x in f.get("matched_at", "").lower()
                    for x in ["/docs/", "/api-docs", "/swagger", "/redoc", "/openapi"]
                ),
                "reason": "Documentation pages are not real attack surfaces",
            },

            # ========================================
            # Training App Awareness
            # ========================================
            {
                "name": "known_training_app",
                "condition": lambda f: any(
                    x in str(f.get("evidence", [])).lower() or x in f.get("matched_at", "").lower()
                    for x in ["dvwa", "juice-shop", "webgoat", "bwapp", "mutillidae",
                              "hackthebox", "tryhackme", "portswigger", "railsgoat"]
                ),
                "reason": "Training application - vulnerability is intentional",
            },
        ]
        
        # Load custom signatures from file
        sig_path = Path("config/fp_signatures.json")
        if sig_path.exists():
            try:
                custom = json.loads(sig_path.read_text())
                signatures.extend(custom)
            except Exception as e:
                logger.warning(f"Failed to load custom FP signatures: {e}")
        
        return signatures
    
    def _load_prompt(self) -> str:
        """Load false positive detection prompt."""
        prompt_path = Path("config/ai_prompts/false_positive.txt")
        
        if prompt_path.exists():
            return prompt_path.read_text()
        
        return """Analyze if this vulnerability is a false positive:

{finding_details}

Application Context:
{app_context}

Respond with JSON:
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "explanation",
    "recommendation": "REMOVE|KEEP|MANUAL_REVIEW"
}}
"""
    
    async def filter(
        self,
        findings: list[dict[str, Any]],
        assets: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Filter false positives from findings.
        
        Args:
            findings: List of vulnerability findings
            assets: Asset data from reconnaissance
            
        Returns:
            Filtered list of findings
        """
        if not self.config.enabled:
            logger.info("FP filtering disabled")
            return findings
        
        logger.info(f"Filtering {len(findings)} findings for false positives")
        
        filtered = []
        removed = []
        
        for finding in findings:
            # Check 1: Signature-based filtering
            if self.config.use_signatures:
                is_fp, reason = self._check_signatures(finding)
                if is_fp:
                    removed.append({
                        "finding": finding.get("name"),
                        "reason": reason,
                        "method": "signature",
                    })
                    continue

            # Check 2: Response pattern analysis (FIX 2026-02-18)
            is_fp, confidence, reason = self.analyze_response_patterns(finding)
            if is_fp and confidence >= 0.7:
                removed.append({
                    "finding": finding.get("name"),
                    "reason": reason,
                    "method": f"pattern_analysis ({confidence:.0%})",
                })
                continue

            # Check 3: AI-based filtering (expensive, last)
            if self.config.use_ai:
                is_fp, reason = await self._ai_check(finding, assets)
                if is_fp:
                    removed.append({
                        "finding": finding.get("name"),
                        "reason": reason,
                        "method": "ai",
                    })
                    continue

            filtered.append(finding)
        
        logger.info(
            f"Filtered {len(removed)} false positives, "
            f"keeping {len(filtered)} findings"
        )
        
        # Log removed items for review
        for item in removed:
            logger.debug(
                f"Removed FP: {item['finding']} - {item['reason']} ({item['method']})"
            )
        
        return filtered
    
    def _check_signatures(
        self,
        finding: dict[str, Any],
    ) -> tuple[bool, str]:
        """Check finding against FP signatures."""
        for sig in self.signatures:
            # Check template match
            if "template" in sig:
                if finding.get("id") != sig["template"]:
                    continue
            
            # Check type match
            if "type" in sig:
                if finding.get("type") != sig["type"]:
                    continue
            
            # Check condition
            condition = sig.get("condition")
            if condition:
                if callable(condition):
                    try:
                        if condition(finding):
                            return True, sig.get("reason", "Matched FP signature")
                    except Exception as e:
                        # FIX 2026-02-12: Log FP condition check error
                        logger.debug(f"[FPFilter] Condition check error: {e}")

        return False, ""
    
    async def _ai_check(
        self,
        finding: dict[str, Any],
        assets: dict[str, Any],
    ) -> tuple[bool, str]:
        """Use AI to check for false positive."""
        # Build finding details
        finding_details = f"""
Name: {finding.get('name', 'Unknown')}
Type: {finding.get('type', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Location: {finding.get('matched_at', 'Unknown')}
Evidence: {json.dumps(finding.get('evidence', []))}
Description: {finding.get('description', '')}
"""
        
        # Build context
        host = finding.get("host", "")
        host_assets = assets.get(host, {})
        technologies = host_assets.get("technologies", [])
        
        tech_names = [
            t.get("name", "") if isinstance(t, dict) else str(t)
            for t in technologies
        ]
        
        app_context = f"""
Technologies: {', '.join(tech_names) if tech_names else 'Unknown'}
Ports: {len(host_assets.get('ports', []))}
"""
        
        prompt = self.prompt_template.format(
            finding_details=finding_details,
            app_context=app_context,
        )
        
        try:
            response = await self.model.generate(
                prompt=prompt,
                temperature=0.1,  # Low temperature for consistency
                json_mode=True,
            )
            
            result = self.model.parse_json_response(response)
            
            is_fp = result.get("is_false_positive", False)
            confidence = float(result.get("confidence", 0))
            reasoning = result.get("reasoning", "")
            
            # Only consider FP if confidence exceeds threshold
            if is_fp and confidence >= self.config.confidence_threshold:
                return True, reasoning
            
        except Exception as e:
            logger.debug(f"AI FP check failed: {e}")
        
        return False, ""
    
    def add_signature(
        self,
        name: str,
        condition: Callable[[dict], bool],
        reason: str,
        **kwargs: Any,
    ) -> None:
        """
        Add a custom FP signature.
        
        Args:
            name: Signature name
            condition: Function that returns True for FP
            reason: Explanation
            **kwargs: Additional matching criteria
        """
        self.signatures.append({
            "name": name,
            "condition": condition,
            "reason": reason,
            **kwargs,
        })

    # ========================================================================
    # FIX 2026-02-18: Response Pattern Analysis for FP Detection
    # ========================================================================

    def analyze_response_patterns(
        self,
        finding: dict[str, Any],
    ) -> tuple[bool, float, str]:
        """
        Analyze response patterns to detect common false positive scenarios.

        This supplements signature-based detection with heuristic analysis
        of the actual response content for patterns that indicate FPs.

        Args:
            finding: The finding to analyze

        Returns:
            (is_likely_fp, confidence, reason)
        """
        evidence = str(finding.get("evidence", []))
        evidence_lower = evidence.lower()
        vuln_type = finding.get("type", "").lower()
        vuln_name = finding.get("name", "").lower()
        confidence_val = finding.get("confidence", 100)

        # Convert confidence to float if string
        if isinstance(confidence_val, str):
            confidence_map = {"critical": 95, "high": 85, "medium": 70, "low": 50, "info": 30}
            confidence_val = confidence_map.get(confidence_val.lower(), 70)

        # ========================================
        # Pattern 1: WAF/Security Product Interference
        # ========================================
        waf_indicators = [
            "blocked", "denied", "forbidden", "rejected",
            "waf", "firewall", "security", "captcha",
            "rate limit", "too many requests", "throttle",
            "cloudflare", "akamai", "incapsula", "sucuri",
        ]
        waf_count = sum(1 for ind in waf_indicators if ind in evidence_lower)
        if waf_count >= 2:
            return True, 0.85, f"WAF/security interference detected ({waf_count} indicators)"

        # ========================================
        # Pattern 2: Generic Error Page (not vuln-specific)
        # ========================================
        generic_error_patterns = [
            "something went wrong",
            "an error occurred",
            "please try again",
            "contact support",
            "we're sorry",
            "oops!",
            "500 internal server error",
            "503 service unavailable",
        ]
        if any(p in evidence_lower for p in generic_error_patterns):
            # But not if it contains vuln-specific indicators
            vuln_specific = ["sql", "syntax", "query", "xpath", "ldap", "script", "passwd"]
            if not any(v in evidence_lower for v in vuln_specific):
                return True, 0.7, "Generic error page - not vulnerability specific"

        # ========================================
        # Pattern 3: SPA Catch-All Response
        # ========================================
        spa_patterns = [
            "<div id=\"root\">",
            "<div id=\"app\">",
            "__next_data__",
            "__nuxt__",
            "window.__initial_state__",
            "ng-app",
            "data-reactroot",
        ]
        if any(p in evidence_lower for p in spa_patterns):
            # SPA frameworks often return the same shell for all routes
            return True, 0.65, "SPA framework catch-all response"

        # ========================================
        # Pattern 4: Low Confidence + No Strong Evidence
        # ========================================
        if confidence_val < 60:
            # Check for strong evidence
            strong_evidence = [
                "root:", "uid=", "gid=",  # CMDI/LFI
                "sql syntax", "mysql", "postgresql", "sqlite",  # SQLi
                "<script>", "alert(", "onerror=",  # XSS
                "169.254.169.254", "metadata",  # SSRF
            ]
            has_strong = any(s in evidence_lower for s in strong_evidence)
            if not has_strong:
                return True, 0.6, f"Low confidence ({confidence_val}%) without strong evidence"

        # ========================================
        # Pattern 5: Reflection Detection FP
        # ========================================
        if "xss" in vuln_type or "xss" in vuln_name:
            # Check for encoded/escaped output (not real XSS)
            if "&lt;script" in evidence_lower or "&amp;lt;" in evidence_lower:
                return True, 0.85, "XSS payload is HTML-encoded in response"
            if "&#x3c;" in evidence_lower or "&#60;" in evidence_lower:
                return True, 0.85, "XSS payload is HTML entity-encoded"

        # ========================================
        # Pattern 6: Timing-Based FP (no actual delay)
        # ========================================
        if "time" in vuln_type or "blind" in vuln_name:
            # Check if timing evidence is weak
            if "0." in evidence and "second" in evidence_lower:
                # Very short timing difference
                return True, 0.7, "Timing difference too small to be reliable"

        # ========================================
        # Pattern 7: Content-Type Mismatch
        # ========================================
        # If finding claims injection but response is JSON/image/etc
        content_type_fps = {
            "sqli": ["application/json", "image/", "text/css", "application/javascript"],
            "xss": ["application/json", "image/", "application/pdf"],
            "ssti": ["application/json", "image/"],
            "lfi": ["application/json", "image/"],
        }
        if vuln_type in content_type_fps:
            for ct in content_type_fps[vuln_type]:
                if ct in evidence_lower:
                    # But allow if evidence shows actual injection
                    if "sql" not in evidence_lower and "script" not in evidence_lower:
                        return True, 0.7, f"Content-Type ({ct}) incompatible with {vuln_type}"

        # ========================================
        # Pattern 8: Duplicate Finding Detection
        # ========================================
        # If evidence is very short (likely generic)
        if len(evidence) < 50 and confidence_val < 75:
            return True, 0.55, "Evidence too brief for reliable detection"

        # No FP patterns detected
        return False, 0.0, ""

    def get_fp_statistics(self) -> dict[str, Any]:
        """
        Get statistics about FP filtering.

        Returns:
            dict with signature counts and categories
        """
        categories = {}
        for sig in self.signatures:
            # Extract category from signature structure
            name = sig.get("name", "unknown")
            if "_" in name:
                category = name.split("_")[0]
            else:
                category = "general"

            if category not in categories:
                categories[category] = 0
            categories[category] += 1

        return {
            "total_signatures": len(self.signatures),
            "categories": categories,
            "ai_enabled": self.config.use_ai if hasattr(self.config, "use_ai") else False,
        }
