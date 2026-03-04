"""
Legal Disclaimer Module for Bug Bounty Testing

This module provides legal protection through:
1. Mandatory disclaimer display before scans
2. Scope confirmation requirement
3. Authorization verification
4. Audit logging for legal compliance

IMPORTANT: This is NOT legal advice. Consult with a lawyer for your jurisdiction.

Version: 1.0.0
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


DISCLAIMER_TEXT = """
================================================================================
                    IMPORTANT LEGAL DISCLAIMER
================================================================================

This tool is designed for AUTHORIZED security testing only.

BY CONTINUING, YOU CONFIRM THAT:

1. You have WRITTEN AUTHORIZATION to test the target system(s)
2. You are participating in an AUTHORIZED bug bounty program
3. You will RESPECT the program's scope and rules
4. You understand that UNAUTHORIZED ACCESS is a CRIME
5. You accept FULL RESPONSIBILITY for your actions

LEGAL WARNINGS:

- Computer Fraud and Abuse Act (CFAA) - US
- Computer Misuse Act 1990 - UK
- GDPR Article 83 - EU
- Similar laws in other jurisdictions

PENALTIES may include:
- Criminal prosecution
- Fines up to $500,000+
- Prison sentences up to 20 years
- Civil lawsuits

================================================================================
                        PROCEED WITH CAUTION
================================================================================
"""

SCOPE_CONFIRMATION_TEXT = """
================================================================================
                    SCOPE CONFIRMATION REQUIRED
================================================================================

You are about to scan the following targets:

{targets}

Program: {program}
Mode: {mode}
Rate Limit: {rate_limit} req/sec

PLEASE CONFIRM:
1. All listed targets are IN SCOPE for your authorized testing
2. You have verified the scope on the bug bounty platform
3. You understand out-of-scope testing may result in legal action

================================================================================
"""


class LegalDisclaimer:
    """
    Legal disclaimer and authorization verification.

    Usage:
        disclaimer = LegalDisclaimer(program_name="HackerOne Example")

        # Show disclaimer and get acceptance
        if not disclaimer.show_and_confirm():
            sys.exit("User did not accept disclaimer")

        # Confirm scope
        if not disclaimer.confirm_scope(targets, mode, rate_limit):
            sys.exit("User did not confirm scope")

        # Log acceptance for audit trail
        disclaimer.log_acceptance(targets)
    """

    def __init__(
        self,
        program_name: str = "Bug Bounty Program",
        log_file: Optional[Path] = None,
        require_confirmation: bool = True,
    ):
        self.program_name = program_name
        self.log_file = log_file or Path("logs/legal_audit.jsonl")
        self.require_confirmation = require_confirmation
        self._accepted = False
        self._scope_confirmed = False

        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def show_and_confirm(self) -> bool:
        """
        Display disclaimer and require user acceptance.

        Returns:
            True if user accepted, False otherwise
        """
        if not self.require_confirmation:
            logger.warning("Disclaimer confirmation disabled - not recommended!")
            self._accepted = True
            return True

        print(DISCLAIMER_TEXT)
        print()

        try:
            response = input("Type 'I ACCEPT' to continue (or anything else to abort): ")

            if response.strip() == "I ACCEPT":
                self._accepted = True
                logger.info("User accepted legal disclaimer")
                self._log_event({
                    "event": "DISCLAIMER_ACCEPTED",
                    "timestamp": datetime.now().isoformat(),
                    "program": self.program_name,
                })
                return True
            else:
                logger.info("User declined legal disclaimer")
                self._log_event({
                    "event": "DISCLAIMER_DECLINED",
                    "timestamp": datetime.now().isoformat(),
                    "program": self.program_name,
                })
                return False

        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return False

    def confirm_scope(
        self,
        targets: list[str],
        mode: str = "safe",
        rate_limit: float = 2.0,
    ) -> bool:
        """
        Display scope and require confirmation.

        Args:
            targets: List of target domains/URLs
            mode: Scanning mode
            rate_limit: Requests per second limit

        Returns:
            True if user confirmed scope
        """
        if not self.require_confirmation:
            self._scope_confirmed = True
            return True

        targets_str = "\n".join(f"  - {t}" for t in targets)
        scope_text = SCOPE_CONFIRMATION_TEXT.format(
            targets=targets_str,
            program=self.program_name,
            mode=mode,
            rate_limit=rate_limit,
        )

        print(scope_text)
        print()

        try:
            response = input("Type 'CONFIRM SCOPE' to proceed: ")

            if response.strip() == "CONFIRM SCOPE":
                self._scope_confirmed = True
                logger.info("User confirmed scope", targets=len(targets))
                self._log_event({
                    "event": "SCOPE_CONFIRMED",
                    "timestamp": datetime.now().isoformat(),
                    "program": self.program_name,
                    "targets": targets,
                    "mode": mode,
                    "rate_limit": rate_limit,
                })
                return True
            else:
                logger.info("User did not confirm scope")
                return False

        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return False

    def log_acceptance(self, targets: list[str]) -> None:
        """Log acceptance for audit trail."""
        self._log_event({
            "event": "SCAN_AUTHORIZED",
            "timestamp": datetime.now().isoformat(),
            "program": self.program_name,
            "targets": targets,
            "disclaimer_accepted": self._accepted,
            "scope_confirmed": self._scope_confirmed,
        })

    def _log_event(self, event: dict) -> None:
        """Write event to audit log."""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write legal audit log: {e}")

    def generate_authorization_document(
        self,
        targets: list[str],
        tester_name: str = "Security Researcher",
        output_path: Optional[Path] = None,
    ) -> str:
        """
        Generate an authorization document for record keeping.

        This is for YOUR records - not a legal contract.
        """
        doc = f"""
================================================================================
                    SECURITY TESTING AUTHORIZATION RECORD
================================================================================

Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Tester: {tester_name}
Program: {self.program_name}

TARGETS AUTHORIZED FOR TESTING:
{chr(10).join(f'  - {t}' for t in targets)}

TESTING PARAMETERS:
- Tool: PetNTester AI Bug Bounty Edition
- Mode: Safe (Bug Bounty Compliant)
- Rate Limit: 2 requests/second maximum
- Scope: As defined by {self.program_name}

ACKNOWLEDGMENTS:
[x] Tester has accepted the legal disclaimer
[x] Tester has confirmed targets are in scope
[x] Tester understands and will follow program rules

LEGAL NOTICE:
This document is for record-keeping purposes only.
It does not constitute legal authorization.
Actual authorization must come from the target organization
or official bug bounty program.

================================================================================
                    KEEP THIS RECORD FOR YOUR FILES
================================================================================
"""
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                f.write(doc)
            logger.info(f"Authorization record saved to {output_path}")

        return doc


def check_authorization(
    program_name: str,
    targets: list[str],
    mode: str = "safe",
    rate_limit: float = 2.0,
    skip_disclaimer: bool = False,
) -> bool:
    """
    Complete authorization check flow.

    Args:
        program_name: Bug bounty program name
        targets: List of targets
        mode: Scanning mode
        rate_limit: Rate limit
        skip_disclaimer: Skip disclaimer (not recommended)

    Returns:
        True if all checks passed
    """
    disclaimer = LegalDisclaimer(
        program_name=program_name,
        require_confirmation=not skip_disclaimer,
    )

    # Show disclaimer
    if not disclaimer.show_and_confirm():
        return False

    # Confirm scope
    if not disclaimer.confirm_scope(targets, mode, rate_limit):
        return False

    # Log for audit
    disclaimer.log_acceptance(targets)

    print("\n[OK] Authorization confirmed. Proceeding with scan...\n")
    return True


# Quick check for non-interactive use
def verify_scope_programmatically(
    allowed_domains: list[str],
    target: str,
) -> tuple[bool, str]:
    """
    Verify target is in allowed scope (for automation).

    Args:
        allowed_domains: List of allowed domains (supports wildcards)
        target: Target to check

    Returns:
        Tuple of (is_allowed, reason)
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(target)
        domain = parsed.netloc.lower()

        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]

        for allowed in allowed_domains:
            allowed = allowed.lower().strip()

            # Strip port from scope entry too (e.g., "localhost:3000" → "localhost")
            allowed_domain = allowed.split(":")[0] if ":" in allowed and not allowed.startswith("*.") else allowed

            # Exact match (with or without port in scope)
            if domain == allowed or domain == allowed_domain:
                return True, f"Exact match: {allowed}"

            # Wildcard match
            if allowed.startswith("*."):
                base = allowed[2:]
                if domain == base or domain.endswith("." + base):
                    return True, f"Wildcard match: {allowed}"

        return False, f"Domain '{domain}' not in allowed scope"

    except Exception as e:
        return False, f"Error checking scope: {e}"
