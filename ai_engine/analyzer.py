"""
Vulnerability analyzer with AI-powered contextual analysis.

SECURITY: Includes input sanitization to prevent prompt injection attacks (CWE-77).
All user-controlled data is sanitized before being included in LLM prompts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ai_engine.model_manager import ModelManager
from ai_engine.knowledge_base import KnowledgeBase
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from core.orchestrator import ScanContext

logger = get_logger(__name__)


# =============================================================================
# INPUT SANITIZATION - Prevent Prompt Injection (CWE-77)
# =============================================================================

# Patterns that could be used for prompt injection
_INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|all)\s+(instructions?|prompts?)",
    r"ignore\s+all\s+previous",  # Catch "ignore all previous prompts"
    r"disregard\s+(previous|above|all)",
    r"forget\s+(everything|all|previous)",
    r"new\s+instructions?:",
    r"system\s*:",
    r"admin\s*:",
    r"<\s*system\s*>",
    r"<\s*/?\s*prompt\s*>",
    r"\[\[.*system.*\]\]",
    r"act\s+as\s+(if\s+)?(you\s+are|a)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"roleplay\s+as",
    r"you\s+are\s+now",
    r"execute\s+(code|command|shell)",
    r"run\s+(this|the\s+following)\s+(code|command)",
    r"jailbreak",
    r"bypass\s+(safety|security|filter)",
]

# Maximum length for user-controlled input fields
_MAX_INPUT_LENGTHS = {
    "name": 500,
    "description": 2000,
    "evidence": 5000,
    "host": 500,
    "type": 100,
    "cwe": 50,
    "matched_at": 1000,
    "default": 1000,
}


def _sanitize_string(value: str, field_name: str = "default") -> str:
    """
    Sanitize a string value to prevent prompt injection.

    SECURITY: Removes or escapes content that could manipulate the LLM.
    """
    if not isinstance(value, str):
        return str(value)[:_MAX_INPUT_LENGTHS.get(field_name, 500)]

    # Truncate to max length
    max_len = _MAX_INPUT_LENGTHS.get(field_name, _MAX_INPUT_LENGTHS["default"])
    value = value[:max_len]

    # Check for injection patterns
    value_lower = value.lower()
    for pattern in _INJECTION_PATTERNS:
        if re.search(pattern, value_lower):
            logger.warning(
                f"Potential prompt injection detected in field '{field_name}'. "
                f"Sanitizing input."
            )
            # Replace the matched content with a placeholder
            value = re.sub(pattern, "[FILTERED]", value, flags=re.IGNORECASE)

    # Escape special characters that could break prompt structure
    value = value.replace("```", "'''")  # Prevent code block injection
    value = value.replace("###", "---")  # Prevent header injection

    return value


def _sanitize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitize all user-controlled fields in a finding.

    SECURITY: Ensures finding data cannot inject prompts into the LLM.
    """
    sanitized = {}

    for key, value in finding.items():
        if isinstance(value, str):
            sanitized[key] = _sanitize_string(value, key)
        elif isinstance(value, list):
            # Sanitize list items if they're strings
            sanitized[key] = [
                _sanitize_string(item, key) if isinstance(item, str) else item
                for item in value[:50]  # Limit list length
            ]
        elif isinstance(value, dict):
            # Recursively sanitize nested dicts (limited depth)
            sanitized[key] = {
                k: _sanitize_string(v, k) if isinstance(v, str) else v
                for k, v in list(value.items())[:20]  # Limit dict size
            }
        else:
            sanitized[key] = value

    return sanitized


class Analyzer:
    """
    AI-powered vulnerability analyzer.
    
    Provides:
    - Contextual exploitability assessment
    - Business impact analysis
    - Attack scenario generation
    - CVSS adjustment recommendations
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize analyzer.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.model = ModelManager(settings)
        self.kb = KnowledgeBase(settings)
        
        # Load prompt template
        self.prompt_template = self._load_prompt()
    
    def _load_prompt(self) -> str:
        """Load analysis prompt template."""
        prompt_path = Path("config/ai_prompts/analysis.txt")
        
        if prompt_path.exists():
            return prompt_path.read_text()
        
        # Default template
        return """Analyze this vulnerability finding:

{finding_info}

Application Context:
{app_context}

Provide analysis in JSON format with:
- is_exploitable: boolean
- exploitability_details: object with complexity, prerequisites, attack_vector
- business_impact: object with description, affected_assets, data_at_risk
- attack_scenario: object with steps, tools_needed
- confidence: float 0-1
- recommended_actions: object with immediate, long_term, detection lists
"""
    
    async def analyze(
        self,
        finding: dict[str, Any],
        context: ScanContext,
    ) -> dict[str, Any]:
        """
        Perform deep analysis of a vulnerability.

        Args:
            finding: Vulnerability finding
            context: Scan context

        Returns:
            Analysis results

        SECURITY: Finding data is sanitized to prevent prompt injection.
        """
        logger.debug(f"Analyzing finding: {finding.get('name', 'Unknown')}")

        # SECURITY: Sanitize finding data to prevent prompt injection
        sanitized_finding = _sanitize_finding(finding)

        # Build prompt with sanitized data
        prompt = self._build_prompt(sanitized_finding, context)
        
        # Get relevant knowledge (use sanitized data for search query)
        knowledge = await self._get_relevant_knowledge(sanitized_finding)
        if knowledge:
            prompt += f"\n\n## Relevant Knowledge:\n{knowledge}"

        # Generate analysis
        try:
            response = await self.model.generate(
                prompt=prompt,
                temperature=0.3,
                json_mode=True,
            )

            analysis = self.model.parse_json_response(response)

            # Validate and enrich
            analysis = self._validate_analysis(analysis, sanitized_finding)

            # Store for future reference (use sanitized data)
            await self._store_analysis(sanitized_finding, analysis)

            return analysis

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return self._default_analysis(sanitized_finding)
    
    def _build_prompt(
        self,
        finding: dict[str, Any],
        context: ScanContext,
    ) -> str:
        """Build analysis prompt."""
        # Finding information
        finding_info = f"""
**Vulnerability:** {finding.get('name', 'Unknown')}
**Type:** {finding.get('type', 'Unknown')}
**Severity:** {finding.get('severity', 'Unknown')}
**CVSS Score:** {finding.get('cvss_score', 'N/A')}
**CWE:** {finding.get('cwe', 'N/A')}
**Location:** {finding.get('matched_at', 'N/A')}
**Description:** {finding.get('description', 'No description')}
**Evidence:** {json.dumps(finding.get('evidence', []))}
"""
        
        # Application context
        host = finding.get('host', '')
        asset_data = context.assets.get(host, {})
        technologies = asset_data.get('technologies', [])
        
        tech_names = [
            t.get('name', '') if isinstance(t, dict) else str(t)
            for t in technologies
        ]
        
        app_context = f"""
**Host:** {host}
**Technologies:** {', '.join(tech_names) if tech_names else 'Unknown'}
**Open Ports:** {len(asset_data.get('ports', []))}
**Discovered URLs:** {len(asset_data.get('urls', []))}
**Total Findings:** {len(context.findings)}
"""
        
        return self.prompt_template.format(
            finding_info=finding_info,
            app_context=app_context,
        )
    
    async def _get_relevant_knowledge(
        self,
        finding: dict[str, Any],
    ) -> str | None:
        """Get relevant knowledge from vector store."""
        try:
            query = f"{finding.get('name', '')} {finding.get('type', '')} {finding.get('cwe', '')}"
            results = await self.kb.search(query, n_results=3)
            
            if results:
                return "\n".join(results)
                
        except Exception as e:
            logger.debug(f"Knowledge search failed: {e}")
        
        return None
    
    def _validate_analysis(
        self,
        analysis: dict[str, Any],
        finding: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate and enrich analysis."""
        # Ensure required fields
        defaults = {
            "is_exploitable": False,
            "exploitability_details": {
                "complexity": "UNKNOWN",
                "prerequisites": [],
                "attack_vector": "NETWORK",
            },
            "business_impact": {
                "description": "Unknown impact",
                "affected_assets": [],
                "data_at_risk": [],
            },
            "attack_scenario": {
                "steps": [],
                "tools_needed": [],
            },
            "confidence": 0.5,
            "recommended_actions": {
                "immediate": [],
                "long_term": [],
                "detection": [],
            },
        }
        
        for key, default in defaults.items():
            if key not in analysis:
                analysis[key] = default
        
        # Ensure confidence is in range
        analysis["confidence"] = max(0.0, min(1.0, float(analysis.get("confidence", 0.5))))
        
        return analysis
    
    def _default_analysis(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Generate default analysis when AI fails."""
        severity = finding.get("severity", "MEDIUM").upper()
        
        return {
            "is_exploitable": severity in ("CRITICAL", "HIGH"),
            "exploitability_details": {
                "complexity": "MEDIUM",
                "prerequisites": [],
                "attack_vector": "NETWORK",
            },
            "business_impact": {
                "description": f"{severity} severity vulnerability detected",
                "affected_assets": [finding.get("host", "unknown")],
                "data_at_risk": [],
            },
            "attack_scenario": {
                "steps": ["Manual verification required"],
                "tools_needed": [],
            },
            "confidence": 0.3,
            "recommended_actions": {
                "immediate": ["Verify vulnerability manually"],
                "long_term": ["Apply vendor patches"],
                "detection": ["Monitor for exploitation attempts"],
            },
        }
    
    async def _store_analysis(
        self,
        finding: dict[str, Any],
        analysis: dict[str, Any],
    ) -> None:
        """Store analysis in knowledge base."""
        try:
            text = (
                f"Analysis of {finding.get('name')}: "
                f"Exploitable: {analysis.get('is_exploitable')}, "
                f"Confidence: {analysis.get('confidence')}"
            )
            
            metadata = {
                "finding_type": finding.get("type", "unknown"),
                "severity": finding.get("severity", "unknown"),
            }
            
            await self.kb.add(text, metadata)
            
        except Exception as e:
            logger.debug(f"Failed to store analysis: {e}")
    
    async def batch_analyze(
        self,
        findings: list[dict[str, Any]],
        context: ScanContext,
        max_concurrent: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Analyze multiple findings.
        
        Args:
            findings: List of findings
            context: Scan context
            max_concurrent: Max concurrent analyses
            
        Returns:
            List of analysis results
        """
        import asyncio
        
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def analyze_one(finding: dict) -> dict:
            async with semaphore:
                return await self.analyze(finding, context)
        
        tasks = [analyze_one(f) for f in findings]
        return await asyncio.gather(*tasks)
