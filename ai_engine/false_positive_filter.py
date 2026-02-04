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
        # Built-in signatures
        signatures = [
            {
                "name": "lets_encrypt_issuer",
                "template": "ssl-issuer",
                "condition": lambda f: "Let's Encrypt" in str(f.get("evidence", [])),
                "reason": "Let's Encrypt is a valid certificate authority",
            },
            {
                "name": "cloudflare_cdn",
                "type": "headers",
                "condition": lambda f: "cloudflare" in str(f.get("evidence", [])).lower(),
                "reason": "Cloudflare CDN headers are expected",
            },
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
            
            # Check 2: AI-based filtering
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
                    except Exception:
                        pass
        
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
