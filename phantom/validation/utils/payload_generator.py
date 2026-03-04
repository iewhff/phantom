"""
PHANTOM AI - Safe Payload Generator
=====================================

Extracted from phantom/validation_pipeline.py (lines 1264-1307).
"""

from phantom.validation.models import VulnerabilityType


class SafePayloadGenerator:
    """
    Generate safe/harmless variants of payloads for replay testing.
    """

    @staticmethod
    def generate_safe_variant(
        payload: str,
        vuln_type: VulnerabilityType,
    ) -> str:
        """Generate a safe variant of the payload."""
        if vuln_type == VulnerabilityType.SQLI:
            # Replace attack with harmless query
            return "1' AND '1'='1"

        elif vuln_type == VulnerabilityType.XSS:
            # Replace script with harmless content
            return "<b>test</b>"

        elif vuln_type == VulnerabilityType.CMDI:
            # Replace with harmless command
            return "echo test"

        elif vuln_type == VulnerabilityType.LFI:
            # Replace with non-existent file
            return "/nonexistent/file/path.txt"

        elif vuln_type == VulnerabilityType.SSRF:
            # Replace with safe URL
            return "https://httpbin.org/status/200"

        elif vuln_type == VulnerabilityType.SSTI:
            # Replace with safe template
            return "{{1+1}}"

        else:
            # Generic safe variant
            return "safe_test_value"

    @staticmethod
    def generate_benign_payload(vuln_type: VulnerabilityType) -> str:
        """Generate a completely benign payload that should not trigger."""
        return "normal_user_input_12345"
