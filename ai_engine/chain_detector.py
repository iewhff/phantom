"""
Exploit chain detector using AI and pattern matching.
"""

from __future__ import annotations

import json
from itertools import combinations
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ai_engine.model_manager import ModelManager
from scanning.constants import normalize_vuln_type
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class ChainDetector:
    """
    Detects exploit chains from vulnerability findings.
    
    Identifies:
    - Known chain patterns
    - AI-discovered chain opportunities
    - Multi-step attack paths
    """
    
    # Known chain patterns
    KNOWN_CHAINS = [
        {
            "name": "XSS + CSRF → Account Takeover",
            "required_types": {"xss", "csrf"},
            "severity": "CRITICAL",
            "description": "XSS can steal CSRF tokens, enabling unauthorized actions",
            "impact": "Complete account compromise",
        },
        {
            "name": "SQLi + File Upload → RCE",
            "required_types": {"sqli", "file_upload"},
            "severity": "CRITICAL",
            "description": "SQL injection can write webshell via INTO OUTFILE",
            "impact": "Remote Code Execution",
        },
        {
            "name": "SSRF + Internal Service → Data Breach",
            "required_types": {"ssrf"},
            "required_patterns": ["internal", "metadata", "169.254"],
            "severity": "CRITICAL",
            "description": "SSRF accessing internal services or cloud metadata",
            "impact": "Internal network access, credential theft",
        },
        {
            "name": "XXE + SSRF → Internal Access",
            "required_types": {"xxe", "ssrf"},
            "severity": "HIGH",
            "description": "XXE can be escalated to SSRF for internal access",
            "impact": "Internal network reconnaissance",
        },
        {
            "name": "IDOR + Sensitive Data → Mass Data Theft",
            "required_types": {"idor"},
            "required_patterns": ["user", "account", "profile"],
            "severity": "HIGH",
            "description": "IDOR accessing sensitive user data at scale",
            "impact": "Mass data exfiltration",
        },
        {
            "name": "Auth Bypass + Admin Function → Privilege Escalation",
            "required_types": {"auth_bypass", "broken_access"},
            "severity": "CRITICAL",
            "description": "Authentication bypass combined with admin access",
            "impact": "Full system compromise",
        },
        {
            "name": "Information Disclosure + Brute Force → Account Access",
            "required_types": {"info_disclosure"},
            "required_patterns": ["username", "email", "user"],
            "severity": "MEDIUM",
            "description": "User enumeration enabling targeted attacks",
            "impact": "Account compromise via brute force",
        },
    ]
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize detector.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.analysis.chain_detection
        self.model = ModelManager(settings)
        
        # Load prompt
        self.prompt_template = self._load_prompt()
    
    def _load_prompt(self) -> str:
        """Load chain detection prompt."""
        prompt_path = Path("config/ai_prompts/chain_detection.txt")
        
        if prompt_path.exists():
            return prompt_path.read_text()
        
        return """Analyze these vulnerabilities for exploit chains:

{vulnerabilities_json}

Target Information:
{target_info}

Identify vulnerability combinations that could be chained for greater impact.
Respond with JSON array of chains.
"""
    
    async def detect(
        self,
        findings: list[dict[str, Any]],
        assets: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Detect exploit chains in findings.
        
        Args:
            findings: Vulnerability findings
            assets: Asset data
            
        Returns:
            List of detected chains
        """
        if not self.config.enabled or len(findings) < 2:
            return []
        
        logger.info(f"Detecting exploit chains in {len(findings)} findings")
        
        chains: list[dict[str, Any]] = []
        
        # Group findings by host
        by_host: dict[str, list[dict]] = {}
        for f in findings:
            host = f.get("host", "unknown")
            by_host.setdefault(host, []).append(f)
        
        # Detect chains for each host
        for host, host_findings in by_host.items():
            # Pattern-based detection
            pattern_chains = self._detect_known_chains(host, host_findings)
            chains.extend(pattern_chains)
            
            # AI-based detection for non-obvious chains
            if len(host_findings) >= 2:
                ai_chains = await self._ai_detect_chains(host, host_findings, assets)
                chains.extend(ai_chains)
        
        # Deduplicate and sort by severity
        chains = self._deduplicate_chains(chains)
        chains.sort(
            key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                c.get("severity", "LOW"), 4
            )
        )
        
        logger.info(f"Detected {len(chains)} exploit chains")
        return chains
    
    def _detect_known_chains(
        self,
        host: str,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Detect known chain patterns."""
        chains = []

        # Extract and normalize finding types
        # Maps canonical type → list of findings with that type
        findings_by_canonical: dict[str, list[dict]] = {}
        all_evidence = []

        for f in findings:
            # Normalize both type and name fields
            raw_type = f.get("type", "")
            raw_name = f.get("name", "")

            canonical_type = normalize_vuln_type(raw_type)
            canonical_name = normalize_vuln_type(raw_name)

            # Add finding under its canonical type
            findings_by_canonical.setdefault(canonical_type, []).append(f)
            if canonical_name != canonical_type and canonical_name != "unknown":
                findings_by_canonical.setdefault(canonical_name, []).append(f)

            all_evidence.extend(f.get("evidence", []))

        # Set of all canonical types present
        canonical_types = set(findings_by_canonical.keys())
        evidence_text = " ".join(str(e) for e in all_evidence).lower()

        for pattern in self.KNOWN_CHAINS:
            # Check required types (pattern uses canonical names)
            required = pattern.get("required_types", set())
            if not required.issubset(canonical_types):
                continue

            # Check required patterns in evidence
            required_patterns = pattern.get("required_patterns", [])
            if required_patterns:
                pattern_match = any(
                    p.lower() in evidence_text
                    for p in required_patterns
                )
                if not pattern_match:
                    continue

            # Build chain — collect findings matching required types
            chain_findings_all = []
            for req_type in required:
                chain_findings_all.extend(findings_by_canonical.get(req_type, []))

            # Keep only the highest-confidence finding per canonical type
            best_by_type: dict[str, dict] = {}
            for f in chain_findings_all:
                canonical = normalize_vuln_type(f.get("type", "unknown"))
                existing = best_by_type.get(canonical)
                if not existing or (f.get("confidence", 0) or 0) > (existing.get("confidence", 0) or 0):
                    best_by_type[canonical] = f
            chain_findings = list(best_by_type.values())

            chains.append({
                "chain_id": f"pattern_{len(chains)}",
                "name": pattern["name"],
                "host": host,
                "severity": pattern["severity"],
                "confidence": 0.8,
                "description": pattern["description"],
                "impact": pattern["impact"],
                "vulnerabilities": [
                    {
                        "finding_id": f.get("id", ""),
                        "name": f.get("name", ""),
                        "type": f.get("type", ""),
                    }
                    for f in chain_findings[:self.config.max_chain_length]
                ],
                "detection_method": "pattern",
            })
        
        return chains
    
    async def _ai_detect_chains(
        self,
        host: str,
        findings: list[dict[str, Any]],
        assets: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Use AI to detect non-obvious chains."""
        # Prepare findings summary
        findings_summary = [
            {
                "id": f.get("id", ""),
                "name": f.get("name", ""),
                "type": f.get("type", ""),
                "severity": f.get("severity", ""),
                "matched_at": f.get("matched_at", ""),
            }
            for f in findings[:20]  # Limit to prevent token overflow
        ]
        
        # Prepare target info
        host_assets = assets.get(host, {})
        target_info = f"""
Host: {host}
Technologies: {host_assets.get('technologies', [])}
Open Ports: {[p.get('port') for p in host_assets.get('ports', [])[:10]]}
"""
        
        # Use replace instead of format to avoid conflicts with JSON braces in template
        prompt = self.prompt_template.replace(
            "{vulnerabilities_json}", json.dumps(findings_summary, indent=2)
        ).replace(
            "{target_info}", target_info
        )
        
        try:
            response = await self.model.generate(
                prompt=prompt,
                temperature=0.4,
                json_mode=True,
            )

            result = self.model.parse_json_response(response)

            # Handle different response formats with robust error handling
            chains = []
            if isinstance(result, list):
                chains = result
            elif isinstance(result, dict):
                # Use .get() to safely access keys
                chains = result.get("chains_detected", result.get("chains", []))
            elif isinstance(result, str):
                # Try to parse if result is still a string
                try:
                    parsed = json.loads(result)
                    if isinstance(parsed, list):
                        chains = parsed
                    elif isinstance(parsed, dict):
                        chains = parsed.get("chains_detected", parsed.get("chains", []))
                except (json.JSONDecodeError, TypeError):
                    logger.debug(f"Could not parse chain detection response as JSON")
                    chains = []
            
            # Validate and enrich chains
            validated = []
            for chain in chains:
                if not isinstance(chain, dict):
                    continue
                
                confidence = float(chain.get("confidence", 0.5))
                if confidence < self.config.min_confidence:
                    continue
                
                validated.append({
                    "chain_id": f"ai_{len(validated)}",
                    "name": chain.get("name", "Unknown Chain"),
                    "host": host,
                    "severity": chain.get("severity", "MEDIUM"),
                    "confidence": confidence,
                    "description": chain.get("description", ""),
                    "impact": chain.get("final_impact", chain.get("impact", "")),
                    "vulnerabilities": chain.get("vulnerabilities", chain.get("steps", [])),
                    "attack_narrative": chain.get("attack_narrative", ""),
                    "detection_method": "ai",
                })
            
            return validated
            
        except Exception as e:
            logger.debug(f"AI chain detection failed: {e}")
            return []
    
    def _deduplicate_chains(
        self,
        chains: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Remove duplicate chains."""
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        
        for chain in chains:
            # Create key from name and host
            key = f"{chain.get('name', '')}-{chain.get('host', '')}"
            
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        
        return unique
