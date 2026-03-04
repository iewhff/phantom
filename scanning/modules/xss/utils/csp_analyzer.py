"""
XSS Scanner - CSP Analyzer.

Analyzes Content-Security-Policy headers for XSS protection and bypasses.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx


class CSPAnalyzer:
    """Analyze Content-Security-Policy for XSS protection."""

    UNSAFE_DIRECTIVES = [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "blob:",
    ]

    # Domains known to have JSONP endpoints for CSP bypass
    JSONP_BYPASS_DOMAINS = [
        "*.google.com",
        "*.googleapis.com",
        "*.gstatic.com",
        "*.cloudflare.com",
        "*.jquery.com",
        "*.jsdelivr.net",
        "*.unpkg.com",
        "*.cdnjs.cloudflare.com",
    ]

    def analyze(self, response: "httpx.Response") -> dict[str, Any]:
        """Analyze CSP header.

        Returns:
            Dictionary with CSP analysis results including:
            - present: Whether CSP is present
            - report_only: Whether CSP is in report-only mode
            - policy: The CSP policy string
            - script_src: script-src directive value
            - unsafe_inline: Whether 'unsafe-inline' is present
            - unsafe_eval: Whether 'unsafe-eval' is present
            - allows_data: Whether data: URIs are allowed
            - nonce_required: Whether nonce is required
            - strict_dynamic: Whether 'strict-dynamic' is present
            - bypasses: List of potential bypass methods
        """
        csp = response.headers.get("content-security-policy", "")
        csp_ro = response.headers.get("content-security-policy-report-only", "")

        result: dict[str, Any] = {
            "present": bool(csp),
            "report_only": bool(csp_ro) and not csp,
            "policy": csp or csp_ro,
            "script_src": "",
            "unsafe_inline": False,
            "unsafe_eval": False,
            "allows_data": False,
            "nonce_required": False,
            "strict_dynamic": False,
            "bypasses": [],
        }

        if not (csp or csp_ro):
            result["bypasses"].append("No CSP header present")
            return result

        policy = csp or csp_ro

        # Parse directives
        directives = self._parse_directives(policy)

        # Check script-src
        script_src = directives.get("script-src", directives.get("default-src", ""))
        result["script_src"] = script_src

        # Check unsafe directives
        result["unsafe_inline"] = "'unsafe-inline'" in script_src
        result["unsafe_eval"] = "'unsafe-eval'" in script_src
        result["allows_data"] = "data:" in script_src
        result["nonce_required"] = "'nonce-" in script_src or "'strict-dynamic'" in script_src
        result["strict_dynamic"] = "'strict-dynamic'" in script_src

        # Identify bypasses
        result["bypasses"] = self._identify_bypasses(directives, result)

        return result

    def _parse_directives(self, policy: str) -> dict[str, str]:
        """Parse CSP directives into a dictionary."""
        directives: dict[str, str] = {}

        for part in policy.split(";"):
            part = part.strip()
            if not part:
                continue

            parts = part.split(None, 1)
            if len(parts) >= 1:
                directive = parts[0].lower()
                value = parts[1] if len(parts) > 1 else ""
                directives[directive] = value

        return directives

    def _identify_bypasses(
        self,
        directives: dict[str, str],
        analysis: dict[str, Any],
    ) -> list[str]:
        """Identify potential CSP bypasses."""
        bypasses: list[str] = []

        script_src = analysis.get("script_src", "")

        # Unsafe-inline bypass
        if analysis["unsafe_inline"]:
            bypasses.append("'unsafe-inline' allows inline script execution")

        # Unsafe-eval bypass
        if analysis["unsafe_eval"]:
            bypasses.append("'unsafe-eval' allows eval() and similar functions")

        # Data URI bypass
        if analysis["allows_data"]:
            bypasses.append("data: URIs allow script injection via data:text/html")

        # Report-only mode
        if analysis["report_only"]:
            bypasses.append("CSP is in report-only mode - not enforced")

        # JSONP bypass domains
        for domain in self.JSONP_BYPASS_DOMAINS:
            domain_pattern = domain.replace("*", "")
            if domain_pattern in script_src:
                bypasses.append(f"CSP allows {domain} - potential JSONP bypass")

        # Missing object-src
        if "object-src" not in directives and "default-src" not in directives:
            bypasses.append("Missing object-src allows plugin-based XSS")

        # Missing base-uri
        if "base-uri" not in directives:
            bypasses.append("Missing base-uri allows base tag injection")

        # Wildcard domains
        if "*" in script_src:
            bypasses.append("Wildcard (*) in script-src allows many sources")

        # Self with JSONP
        if "'self'" in script_src:
            bypasses.append("'self' with JSONP endpoints on same origin may be bypassable")

        return bypasses

    def can_bypass(self, response: "httpx.Response") -> bool:
        """Quick check if CSP can be bypassed."""
        analysis = self.analyze(response)
        return bool(analysis["bypasses"])


__all__ = ["CSPAnalyzer"]
