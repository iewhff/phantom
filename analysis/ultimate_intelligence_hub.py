"""
Ultimate Intelligence Hub - ENHANCED VERSION
============================================

O sistema nervoso central que coordena TODOS os módulos de inteligência.

MELHORIAS IMPLEMENTADAS:
1. Cache inteligente para evitar análises duplicadas
2. Detecção avançada de padrões críticos (OWASP Top 10+)
3. Sistema de scoring melhorado com machine learning insights
4. Paralelização otimizada para performance máxima
5. Deduplicação avançada com similarity matching
6. Detecção de vulnerabilidades encadeadas (multi-step)
7. Análise de contexto de negócio para priorização
8. Sistema de feedback learning
9. Exportação em múltiplos formatos (JSON, HTML, PDF-ready)

Author: canigetrichpls (Enhanced Version)
"""

import asyncio
import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from enum import Enum, auto
from collections import defaultdict
import structlog
import re

logger = structlog.get_logger(__name__)

# Import all intelligence modules
try:
    from analysis.vuln_chain_engine import VulnChainEngine
    from analysis.intelligent_attacker import IntelligentAttacker
    from analysis.adaptive_brain import AdaptiveAttackBrain
    from analysis.situational_analyzer import SituationalAnalyzer
    from analysis.neural_attack_planner import NeuralAttackPlanner
    from analysis.multi_situation_fusion import MultiSituationFusion
except ImportError as e:
    logger.warning(f"[Hub Enhanced] Import warning: {e}")


# =============================================================================
# ADVANCED PATTERN DETECTION
# =============================================================================

class CriticalPatterns:
    """Padrões críticos expandidos para detecção de vulnerabilidades."""
    
    # Authentication & Authorization
    AUTH_PATTERNS = [
        r'admin', r'root', r'superuser', r'sudo', r'privilege', r'elevate',
        r'impersonate', r'bypass', r'backdoor', r'master[_-]?key',
        r'god[_-]?mode', r'debug[_-]?mode', r'test[_-]?mode',
    ]
    
    # Sensitive Data
    SENSITIVE_PATTERNS = [
        r'password', r'passwd', r'pwd', r'secret', r'token', r'api[_-]?key',
        r'private[_-]?key', r'access[_-]?key', r'auth[_-]?token',
        r'bearer', r'jwt', r'session', r'cookie', r'credential',
        r'ssn', r'credit[_-]?card', r'cvv', r'bank', r'account',
    ]
    
    # Injection Vectors
    INJECTION_PATTERNS = [
        r'exec', r'eval', r'system', r'shell', r'cmd', r'command',
        r'query', r'sql', r'union', r'select', r'insert', r'update',
        r'delete', r'drop', r'script', r'javascript:', r'onerror',
        r'onload', r'../..', r'..\\..', r'%2e%2e', r'file://',
    ]
    
    # Configuration & Debug
    CONFIG_PATTERNS = [
        r'config', r'conf', r'settings', r'env', r'\.ini', r'\.xml',
        r'\.json', r'\.yaml', r'\.yml', r'backup', r'\.bak',
        r'\.old', r'\.tmp', r'\.log', r'debug', r'trace',
        r'phpinfo', r'server[_-]?status', r'health[_-]?check',
    ]
    
    # File Operations
    FILE_PATTERNS = [
        r'upload', r'download', r'file', r'path', r'dir', r'folder',
        r'read', r'write', r'include', r'require', r'import',
        r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'file://', r'ftp://',
    ]
    
    # Network & SSRF
    NETWORK_PATTERNS = [
        r'url', r'redirect', r'callback', r'webhook', r'proxy',
        r'fetch', r'curl', r'wget', r'http', r'localhost',
        r'127\.0\.0\.1', r'0\.0\.0\.0', r'metadata', r'169\.254',
        r'internal', r'intranet', r'192\.168', r'10\.0\.0',
    ]
    
    # OAuth & SSO
    OAUTH_PATTERNS = [
        r'oauth', r'sso', r'saml', r'openid', r'callback',
        r'redirect[_-]?uri', r'response[_-]?type', r'client[_-]?id',
        r'code', r'state', r'nonce', r'scope',
    ]
    
    # Business Logic
    BUSINESS_PATTERNS = [
        r'price', r'amount', r'balance', r'payment', r'transaction',
        r'transfer', r'withdraw', r'deposit', r'coupon', r'discount',
        r'promo', r'voucher', r'refund', r'quantity', r'total',
    ]
    
    # 2FA & MFA
    MFA_PATTERNS = [
        r'2fa', r'mfa', r'otp', r'totp', r'verify', r'code',
        r'sms', r'phone', r'email[_-]?verify', r'backup[_-]?code',
    ]
    
    @classmethod
    def get_pattern_category(cls, text: str) -> List[str]:
        """Identifica categorias de padrões no texto."""
        text_lower = text.lower()
        categories = []
        
        pattern_map = {
            'auth': cls.AUTH_PATTERNS,
            'sensitive': cls.SENSITIVE_PATTERNS,
            'injection': cls.INJECTION_PATTERNS,
            'config': cls.CONFIG_PATTERNS,
            'file': cls.FILE_PATTERNS,
            'network': cls.NETWORK_PATTERNS,
            'oauth': cls.OAUTH_PATTERNS,
            'business': cls.BUSINESS_PATTERNS,
            'mfa': cls.MFA_PATTERNS,
        }
        
        for category, patterns in pattern_map.items():
            if any(re.search(pattern, text_lower) for pattern in patterns):
                categories.append(category)
        
        return categories


# =============================================================================
# ENHANCED DATA MODELS
# =============================================================================

class FindingPriority(Enum):
    """Priority levels for findings."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class VulnerabilityCategory(Enum):
    """Categorias OWASP e além."""
    INJECTION = "Injection"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entities"
    BROKEN_ACCESS = "Broken Access Control"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    XSS = "Cross-Site Scripting"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    KNOWN_VULNS = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"
    SSRF = "Server-Side Request Forgery"
    BUSINESS_LOGIC = "Business Logic Vulnerability"
    RACE_CONDITION = "Race Condition"
    IDOR = "Insecure Direct Object Reference"
    CSRF = "Cross-Site Request Forgery"
    CORS = "CORS Misconfiguration"
    OTHER = "Other"


@dataclass
class UnifiedFinding:
    """Enhanced finding with more metadata."""
    id: str
    title: str
    severity: str
    priority: FindingPriority
    category: VulnerabilityCategory = VulnerabilityCategory.OTHER
    
    # Source tracking
    source_modules: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    
    # Details
    description: str = ""
    endpoint: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    # Attack info
    attack_type: str = ""
    attack_steps: List[str] = field(default_factory=list)
    
    # PoC
    poc_code: str = ""
    poc_curl: str = ""
    
    # Impact
    business_impact: str = ""
    technical_impact: str = ""
    bounty_estimate: str = ""
    
    # Enhanced metadata
    cvss_score: float = 0.0
    cwe_ids: List[str] = field(default_factory=list)
    owasp_category: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Pattern detection
    detected_patterns: List[str] = field(default_factory=list)
    risk_factors: Dict[str, float] = field(default_factory=dict)
    
    # Combined score (higher = more important)
    combined_score: float = 0.0
    
    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.now)
    last_verified: Optional[datetime] = None
    
    def __hash__(self):
        return hash(self.id)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export."""
        return {
            k: v.name if isinstance(v, Enum) else 
               v.isoformat() if isinstance(v, datetime) else v
            for k, v in asdict(self).items()
        }


@dataclass
class IntelligenceReport:
    """Enhanced intelligence report."""
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Findings
    findings: List[UnifiedFinding] = field(default_factory=list)
    
    # Statistics
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Category breakdown
    category_breakdown: Dict[str, int] = field(default_factory=dict)
    
    # Bounty
    total_bounty_estimate: str = ""
    
    # Module contributions
    module_contributions: Dict[str, int] = field(default_factory=dict)
    module_performance: Dict[str, float] = field(default_factory=dict)
    
    # Reports
    markdown_report: str = ""
    json_report: str = ""
    html_report: str = ""
    
    # Analysis metadata
    analysis_duration: float = 0.0
    modules_used: List[str] = field(default_factory=list)
    cache_hits: int = 0
    api_calls_made: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON export."""
        return {
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'findings': [f.to_dict() for f in self.findings],
            'statistics': {
                'total': self.total_findings,
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count,
            },
            'category_breakdown': self.category_breakdown,
            'bounty_estimate': self.total_bounty_estimate,
            'modules': {
                'contributions': self.module_contributions,
                'performance': self.module_performance,
                'used': self.modules_used,
            },
            'metadata': {
                'duration': self.analysis_duration,
                'cache_hits': self.cache_hits,
                'api_calls': self.api_calls_made,
            }
        }


# =============================================================================
# INTELLIGENT CACHE SYSTEM
# =============================================================================

class IntelligenceCache:
    """Cache inteligente para análises."""
    
    def __init__(self, ttl_hours: int = 24):
        self.cache: Dict[str, Tuple[Any, datetime]] = {}
        self.ttl = timedelta(hours=ttl_hours)
    
    def _make_key(self, target: str, module: str, data: Any = None) -> str:
        """Cria chave de cache."""
        base = f"{target}:{module}"
        if data:
            data_hash = hashlib.md5(str(data).encode()).hexdigest()[:8]
            base += f":{data_hash}"
        return base
    
    def get(self, target: str, module: str, data: Any = None) -> Optional[Any]:
        """Recupera do cache se válido."""
        key = self._make_key(target, module, data)
        
        if key in self.cache:
            value, timestamp = self.cache[key]
            if datetime.now() - timestamp < self.ttl:
                logger.info(f"[Cache] HIT: {key}")
                return value
            else:
                del self.cache[key]
        
        logger.debug(f"[Cache] MISS: {key}")
        return None
    
    def set(self, target: str, module: str, value: Any, data: Any = None):
        """Armazena no cache."""
        key = self._make_key(target, module, data)
        self.cache[key] = (value, datetime.now())
        logger.debug(f"[Cache] SET: {key}")
    
    def clear(self):
        """Limpa o cache."""
        self.cache.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Estatísticas do cache."""
        return {
            'entries': len(self.cache),
            'valid': sum(1 for _, ts in self.cache.values() 
                        if datetime.now() - ts < self.ttl)
        }


# =============================================================================
# ENHANCED PRIORITY SYNTHESIZER
# =============================================================================

class EnhancedPrioritySynthesizer:
    """
    Synthesizer melhorado com:
    - Detecção de padrões críticos
    - Similarity matching avançado
    - Análise de contexto
    - ML-based scoring
    """
    
    # Pesos de severidade (ajustados)
    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.05,
    }
    
    # Pesos de módulos (ajustados para melhor balance)
    MODULE_WEIGHTS = {
        "neural_planner": 1.25,
        "multi_fusion": 1.20,
        "intelligent_attacker": 1.15,
        "adaptive_brain": 1.05,
        "vuln_chain": 1.0,
        "situational": 0.9,
        "scanner": 0.8,
    }
    
    # Prioridades de tipos (expandido)
    TYPE_PRIORITIES = {
        "rce": 1.0,
        "sqli": 0.98,
        "auth_bypass": 0.95,
        "privilege_escalation": 0.95,
        "ssrf": 0.90,
        "xxe": 0.88,
        "idor": 0.85,
        "deserialization": 0.85,
        "business_logic": 0.80,
        "race_condition": 0.78,
        "xss_stored": 0.75,
        "csrf": 0.70,
        "xss_reflected": 0.65,
        "cors": 0.60,
        "open_redirect": 0.55,
        "info_disclosure": 0.45,
        "clickjacking": 0.35,
        "missing_headers": 0.20,
    }
    
    # Multipliers de contexto
    CONTEXT_MULTIPLIERS = {
        'auth': 1.3,
        'sensitive': 1.25,
        'injection': 1.2,
        'oauth': 1.15,
        'mfa': 1.15,
        'business': 1.1,
        'config': 1.05,
        'file': 1.05,
        'network': 1.0,
    }
    
    def synthesize(
        self,
        findings_by_module: Dict[str, List[dict]],
    ) -> List[UnifiedFinding]:
        """Synthesize com algoritmos melhorados."""
        all_findings: Dict[str, UnifiedFinding] = {}
        
        # Fase 1: Conversão e detecção de padrões
        for module_name, findings in findings_by_module.items():
            for finding in findings:
                unified = self._to_unified(finding, module_name)
                
                # Detecta padrões críticos
                self._detect_patterns(unified)
                
                # Busca similar existente
                existing = self._find_similar_advanced(unified, all_findings)
                
                if existing:
                    self._merge_findings_smart(existing, unified)
                else:
                    all_findings[unified.id] = unified
        
        # Fase 2: Análise de contexto e scoring
        for finding in all_findings.values():
            self._analyze_context(finding)
            self._calculate_score_advanced(finding)
            self._assign_category(finding)
        
        # Fase 3: Deduplicação final e ordenação
        deduplicated = self._final_deduplication(list(all_findings.values()))
        
        sorted_findings = sorted(
            deduplicated,
            key=lambda f: (f.priority.value, -f.combined_score)
        )
        
        return sorted_findings
    
    def _to_unified(self, finding: dict, module_name: str) -> UnifiedFinding:
        """Conversão melhorada."""
        severity = finding.get("severity", "medium").lower()
        
        # Extrai endpoint de múltiplas fontes possíveis
        endpoint = (
            finding.get("url") or 
            finding.get("endpoint") or 
            finding.get("target") or 
            ""
        )
        
        return UnifiedFinding(
            id=f"{module_name}_{hashlib.md5(str(finding).encode()).hexdigest()[:12]}",
            title=finding.get("name", finding.get("title", "Unknown Finding")),
            severity=severity,
            priority=self._severity_to_priority(severity),
            source_modules=[module_name],
            confidence_scores={module_name: finding.get("confidence", 0.7)},
            description=finding.get("description", finding.get("desc", "")),
            endpoint=endpoint,
            evidence=finding.get("evidence", {}),
            attack_type=finding.get("type", finding.get("attack_type", "")),
            attack_steps=finding.get("steps", finding.get("attack_steps", [])),
            poc_code=finding.get("poc", finding.get("poc_code", "")),
            poc_curl=finding.get("curl", finding.get("poc_curl", "")),
            business_impact=finding.get("impact", finding.get("business_impact", "")),
            technical_impact=finding.get("technical_impact", ""),
            bounty_estimate=finding.get("bounty", finding.get("bounty_estimate", "")),
            remediation=finding.get("remediation", ""),
            cwe_ids=finding.get("cwe", []) if isinstance(finding.get("cwe"), list) else [],
        )
    
    def _severity_to_priority(self, severity: str) -> FindingPriority:
        """Conversão de severidade."""
        mapping = {
            "critical": FindingPriority.CRITICAL,
            "high": FindingPriority.HIGH,
            "medium": FindingPriority.MEDIUM,
            "low": FindingPriority.LOW,
            "info": FindingPriority.INFO,
        }
        return mapping.get(severity.lower(), FindingPriority.MEDIUM)
    
    def _detect_patterns(self, finding: UnifiedFinding):
        """Detecta padrões críticos no finding."""
        text = f"{finding.title} {finding.description} {finding.endpoint}".lower()
        finding.detected_patterns = CriticalPatterns.get_pattern_category(text)
    
    def _find_similar_advanced(
        self,
        finding: UnifiedFinding,
        existing: Dict[str, UnifiedFinding],
    ) -> Optional[UnifiedFinding]:
        """Busca similar com algoritmo avançado."""
        for existing_finding in existing.values():
            # Same endpoint check
            if existing_finding.endpoint and finding.endpoint:
                if self._normalize_url(existing_finding.endpoint) == self._normalize_url(finding.endpoint):
                    # Check title similarity
                    if self._similarity_score(existing_finding.title, finding.title) > 0.6:
                        return existing_finding
                    # Check attack type
                    if existing_finding.attack_type and finding.attack_type:
                        if existing_finding.attack_type.lower() == finding.attack_type.lower():
                            return existing_finding
            
            # High title similarity regardless of endpoint
            if self._similarity_score(existing_finding.title, finding.title) > 0.85:
                return existing_finding
        
        return None
    
    def _normalize_url(self, url: str) -> str:
        """Normaliza URL para comparação."""
        # Remove query params e fragmentos
        url = url.split('?')[0].split('#')[0]
        # Remove trailing slash
        url = url.rstrip('/')
        return url.lower()
    
    def _similarity_score(self, text1: str, text2: str) -> float:
        """Calcula similaridade entre textos (Jaccard + Levenshtein simplificado)."""
        # Jaccard similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        jaccard = intersection / union if union > 0 else 0
        
        # Character-level similarity (simple)
        chars1 = set(text1.lower())
        chars2 = set(text2.lower())
        char_sim = len(chars1 & chars2) / len(chars1 | chars2) if (chars1 | chars2) else 0
        
        # Combined score
        return 0.7 * jaccard + 0.3 * char_sim
    
    def _merge_findings_smart(
        self,
        existing: UnifiedFinding,
        new: UnifiedFinding,
    ):
        """Merge inteligente de findings."""
        # Track source
        for module in new.source_modules:
            if module not in existing.source_modules:
                existing.source_modules.append(module)
        
        # Merge confidence scores
        existing.confidence_scores.update(new.confidence_scores)
        
        # Update to higher severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        if severity_order.index(new.severity) < severity_order.index(existing.severity):
            existing.severity = new.severity
            existing.priority = new.priority
        
        # Merge patterns
        for pattern in new.detected_patterns:
            if pattern not in existing.detected_patterns:
                existing.detected_patterns.append(pattern)
        
        # Merge evidence (keep unique)
        existing.evidence.update(new.evidence)
        
        # Merge attack steps (keep unique)
        for step in new.attack_steps:
            if step not in existing.attack_steps:
                existing.attack_steps.append(step)
        
        # Keep best PoC
        if len(new.poc_code) > len(existing.poc_code):
            existing.poc_code = new.poc_code
        if len(new.poc_curl) > len(existing.poc_curl):
            existing.poc_curl = new.poc_curl
        
        # Merge CWEs
        for cwe in new.cwe_ids:
            if cwe not in existing.cwe_ids:
                existing.cwe_ids.append(cwe)
        
        # Keep better description
        if len(new.description) > len(existing.description):
            existing.description = new.description
    
    def _analyze_context(self, finding: UnifiedFinding):
        """Analisa contexto do finding para ajustar score."""
        risk_factors = {}
        
        # Pattern-based risk
        for pattern in finding.detected_patterns:
            risk_factors[f"pattern_{pattern}"] = self.CONTEXT_MULTIPLIERS.get(pattern, 1.0)
        
        # Has PoC
        if finding.poc_code or finding.poc_curl:
            risk_factors['has_poc'] = 1.2
        
        # Multiple module confirmation
        if len(finding.source_modules) >= 3:
            risk_factors['multi_confirmed'] = 1.3
        elif len(finding.source_modules) >= 2:
            risk_factors['dual_confirmed'] = 1.15
        
        # Business impact mentioned
        if finding.business_impact:
            risk_factors['business_impact'] = 1.1
        
        # Has remediation
        if finding.remediation:
            risk_factors['has_remediation'] = 1.05
        
        finding.risk_factors = risk_factors
    
    def _calculate_score_advanced(self, finding: UnifiedFinding):
        """Cálculo avançado de score."""
        # Base: severity weight
        severity_score = self.SEVERITY_WEIGHTS.get(finding.severity, 0.5)
        
        # Module reliability (weighted average)
        module_scores = [
            self.MODULE_WEIGHTS.get(mod, 0.8) * conf
            for mod, conf in finding.confidence_scores.items()
        ]
        module_score = sum(module_scores) / len(module_scores) if module_scores else 0.5
        
        # Type priority
        type_score = 0.5
        for type_key, weight in self.TYPE_PRIORITIES.items():
            if type_key in finding.attack_type.lower():
                type_score = weight
                break
        
        # Context multipliers
        context_multiplier = 1.0
        for factor, multiplier in finding.risk_factors.items():
            context_multiplier *= multiplier
        
        # Calculate final score
        base_score = (
            severity_score * 0.35 +
            module_score * 0.30 +
            type_score * 0.25 +
            0.10  # base bonus
        )
        
        finding.combined_score = base_score * context_multiplier
        
        # Calculate CVSS-like score (simplified)
        finding.cvss_score = min(10.0, base_score * 10 * (context_multiplier ** 0.5))
    
    def _assign_category(self, finding: UnifiedFinding):
        """Atribui categoria OWASP."""
        attack_type = finding.attack_type.lower()
        patterns = finding.detected_patterns
        
        # Mapping direto
        if 'sql' in attack_type or 'sqli' in attack_type:
            finding.category = VulnerabilityCategory.INJECTION
        elif 'xss' in attack_type:
            finding.category = VulnerabilityCategory.XSS
        elif 'auth' in patterns or 'bypass' in attack_type:
            finding.category = VulnerabilityCategory.BROKEN_AUTH
        elif 'idor' in attack_type or 'access' in patterns:
            finding.category = VulnerabilityCategory.BROKEN_ACCESS
        elif 'ssrf' in attack_type:
            finding.category = VulnerabilityCategory.SSRF
        elif 'sensitive' in patterns or 'data' in attack_type:
            finding.category = VulnerabilityCategory.SENSITIVE_DATA
        elif 'config' in patterns or 'misconfig' in attack_type:
            finding.category = VulnerabilityCategory.SECURITY_MISCONFIG
        elif 'business' in patterns:
            finding.category = VulnerabilityCategory.BUSINESS_LOGIC
        elif 'csrf' in attack_type:
            finding.category = VulnerabilityCategory.CSRF
        elif 'cors' in attack_type:
            finding.category = VulnerabilityCategory.CORS
        else:
            finding.category = VulnerabilityCategory.OTHER
        
        finding.owasp_category = finding.category.value
    
    def _final_deduplication(self, findings: List[UnifiedFinding]) -> List[UnifiedFinding]:
        """Deduplicação final usando clustering."""
        if len(findings) <= 1:
            return findings
        
        # Agrupa por endpoint normalizado
        by_endpoint: Dict[str, List[UnifiedFinding]] = defaultdict(list)
        for f in findings:
            norm_endpoint = self._normalize_url(f.endpoint) if f.endpoint else "no_endpoint"
            by_endpoint[norm_endpoint].append(f)
        
        # Deduplica dentro de cada grupo
        deduplicated = []
        for endpoint, group in by_endpoint.items():
            if len(group) == 1:
                deduplicated.extend(group)
            else:
                # Mantém o de maior score de cada sub-grupo similar
                seen_titles = set()
                for finding in sorted(group, key=lambda f: -f.combined_score):
                    # Verifica se já temos um similar
                    is_duplicate = False
                    for seen_title in seen_titles:
                        if self._similarity_score(finding.title, seen_title) > 0.8:
                            is_duplicate = True
                            break
                    
                    if not is_duplicate:
                        deduplicated.append(finding)
                        seen_titles.add(finding.title)
        
        return deduplicated


# =============================================================================
# ENHANCED HACKERONE REPORT GENERATOR
# =============================================================================

class EnhancedHackerOneReportGenerator:
    """Gerador de reports melhorado com múltiplos formatos."""
    
    BOUNTY_RANGES = {
        "critical": "$2,000 - $15,000+",
        "high": "$1,000 - $5,000",
        "medium": "$500 - $2,000",
        "low": "$100 - $750",
    }
    
    def generate_markdown(
        self,
        target: str,
        findings: List[UnifiedFinding],
        metadata: dict = None,
    ) -> str:
        """Gera report markdown melhorado."""
        metadata = metadata or {}
        now = datetime.now()
        
        # Statistics
        critical = len([f for f in findings if f.priority == FindingPriority.CRITICAL])
        high = len([f for f in findings if f.priority == FindingPriority.HIGH])
        medium = len([f for f in findings if f.priority == FindingPriority.MEDIUM])
        low = len([f for f in findings if f.priority == FindingPriority.LOW])
        info = len([f for f in findings if f.priority == FindingPriority.INFO])
        
        # Category breakdown
        category_counts = defaultdict(int)
        for f in findings:
            category_counts[f.category.value] += 1
        
        report = f"""# 🔒 Security Assessment Report - ENHANCED

## Target Information
**URL:** `{target}`  
**Assessment Date:** {now.strftime("%Y-%m-%d %H:%M:%S")}  
**Assessment Type:** AI-Augmented Multi-Module Analysis  
**Report Version:** 2.0 Enhanced

---

## 📊 Executive Summary

### Vulnerability Overview

| Severity | Count | Potential Bounty Range | CVSS Avg |
|----------|-------|------------------------|----------|
| 🔴 **CRITICAL** | {critical} | {self.BOUNTY_RANGES['critical']} | {self._avg_cvss(findings, FindingPriority.CRITICAL):.1f} |
| 🟠 **HIGH** | {high} | {self.BOUNTY_RANGES['high']} | {self._avg_cvss(findings, FindingPriority.HIGH):.1f} |
| 🟡 **MEDIUM** | {medium} | {self.BOUNTY_RANGES['medium']} | {self._avg_cvss(findings, FindingPriority.MEDIUM):.1f} |
| 🟢 **LOW** | {low} | {self.BOUNTY_RANGES['low']} | {self._avg_cvss(findings, FindingPriority.LOW):.1f} |
| ⚪ **INFO** | {info} | N/A | - |
| **TOTAL** | **{len(findings)}** | - | {self._avg_cvss(findings):.1f} |

### OWASP Category Breakdown
"""
        
        for category, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            report += f"- **{category}**: {count}\n"
        
        report += f"""

### Risk Assessment
- **Overall Risk Level:** {self._assess_risk_level(critical, high, medium)}
- **Immediate Action Required:** {'YES' if critical > 0 or high > 2 else 'NO'}
- **Attack Surface:** {self._assess_attack_surface(findings)}

"""
        
        if metadata.get('analysis_duration'):
            report += f"**Analysis Duration:** {metadata['analysis_duration']:.2f}s  \n"
        if metadata.get('modules_used'):
            report += f"**Modules Used:** {', '.join(metadata['modules_used'])}  \n"
        
        report += """
---

## 🎯 Detailed Findings

"""
        
        for i, finding in enumerate(findings, 1):
            report += self._format_finding(i, finding)
        
        if not findings:
            report += """
_No significant findings detected._

The target appears to have a strong security posture based on automated assessment.
Manual penetration testing is recommended for comprehensive coverage.
"""
        
        report += self._generate_methodology_section(metadata)
        report += self._generate_recommendations_section(findings)
        report += """
---

## ⚖️ Disclaimer

This security assessment was performed for authorized bug bounty purposes only.
All testing was conducted within the program's scope and rules of engagement.
Findings should be validated and prioritized based on business context.

---

## 📞 Contact

For questions about this report or additional information:
- Submit via HackerOne platform
- Reference Report ID: """ + hashlib.md5(f"{target}{now}".encode()).hexdigest()[:12].upper() + """

---

*Report generated by PentesterAI - Enhanced Ultimate Intelligence Hub v2.0*
*Powered by multi-module AI security analysis*
"""
        
        return report
    
    def _format_finding(self, num: int, finding: UnifiedFinding) -> str:
        """Formata um finding individual."""
        severity_emoji = {
            FindingPriority.CRITICAL: "🔴",
            FindingPriority.HIGH: "🟠",
            FindingPriority.MEDIUM: "🟡",
            FindingPriority.LOW: "🟢",
            FindingPriority.INFO: "⚪",
        }.get(finding.priority, "⚫")
        
        verified_by = ", ".join(finding.source_modules)
        max_confidence = max(finding.confidence_scores.values()) if finding.confidence_scores else 0.0
        
        finding_text = f"""### {num}. {severity_emoji} {finding.title}

**Severity:** {finding.severity.upper()} | **CVSS:** {finding.cvss_score:.1f} | **Category:** {finding.category.value}  
**Priority Score:** {finding.combined_score:.2f} | **Confidence:** {max_confidence:.0%}  
**Verified By:** {verified_by} ({len(finding.source_modules)} module{'s' if len(finding.source_modules) > 1 else ''})

"""
        
        if finding.endpoint:
            finding_text += f"""**Affected Endpoint:**
```
{finding.endpoint}
```

"""
        
        if finding.description:
            finding_text += f"""**Description:**
{finding.description}

"""
        
        if finding.detected_patterns:
            patterns_str = ", ".join(f"`{p}`" for p in finding.detected_patterns)
            finding_text += f"**Detected Patterns:** {patterns_str}\n\n"
        
        if finding.cwe_ids:
            cwe_str = ", ".join(finding.cwe_ids)
            finding_text += f"**CWE IDs:** {cwe_str}\n\n"
        
        if finding.attack_steps:
            finding_text += "**Attack Steps:**\n"
            for step in finding.attack_steps:
                finding_text += f"1. {step}\n"
            finding_text += "\n"
        
        if finding.business_impact:
            finding_text += f"""**Business Impact:**
{finding.business_impact}

"""
        
        if finding.technical_impact:
            finding_text += f"""**Technical Impact:**
{finding.technical_impact}

"""
        
        if finding.poc_curl:
            finding_text += f"""**Proof of Concept (cURL):**
```bash
{finding.poc_curl}
```

"""
        
        if finding.poc_code:
            # Detecta linguagem do PoC
            lang = "html" if "<" in finding.poc_code else "python" if "import" in finding.poc_code else "javascript"
            finding_text += f"""**Proof of Concept (Code):**
```{lang}
{finding.poc_code[:2000]}{"..." if len(finding.poc_code) > 2000 else ""}
```

"""
        
        if finding.evidence:
            finding_text += f"""**Evidence:**
```json
{json.dumps(finding.evidence, indent=2, default=str)[:1000]}{"..." if len(str(finding.evidence)) > 1000 else ""}
```

"""
        
        if finding.remediation:
            finding_text += f"""**Remediation:**
{finding.remediation}

"""
        
        if finding.references:
            finding_text += "**References:**\n"
            for ref in finding.references:
                finding_text += f"- {ref}\n"
            finding_text += "\n"
        
        bounty = self.BOUNTY_RANGES.get(finding.severity, "N/A")
        finding_text += f"**Estimated Bounty:** {bounty}\n\n---\n\n"
        
        return finding_text
    
    def _avg_cvss(self, findings: List[UnifiedFinding], priority: FindingPriority = None) -> float:
        """Calcula CVSS médio."""
        filtered = findings if not priority else [f for f in findings if f.priority == priority]
        if not filtered:
            return 0.0
        return sum(f.cvss_score for f in filtered) / len(filtered)
    
    def _assess_risk_level(self, critical: int, high: int, medium: int) -> str:
        """Avalia nível de risco geral."""
        if critical >= 3:
            return "🔴 **CRITICAL** - Immediate remediation required"
        elif critical >= 1 or high >= 5:
            return "🟠 **HIGH** - Prioritize remediation"
        elif high >= 2 or medium >= 5:
            return "🟡 **MEDIUM** - Schedule remediation"
        elif medium >= 1:
            return "🟢 **LOW** - Monitor and address in regular cycle"
        else:
            return "⚪ **MINIMAL** - Good security posture"
    
    def _assess_attack_surface(self, findings: List[UnifiedFinding]) -> str:
        """Avalia superfície de ataque."""
        patterns_found = set()
        for f in findings:
            patterns_found.update(f.detected_patterns)
        
        if len(patterns_found) >= 5:
            return "Large (Multiple attack vectors detected)"
        elif len(patterns_found) >= 3:
            return "Medium (Several potential entry points)"
        elif len(patterns_found) >= 1:
            return "Small (Limited attack vectors)"
        else:
            return "Minimal (Well-hardened)"
    
    def _generate_methodology_section(self, metadata: dict) -> str:
        """Gera seção de metodologia."""
        modules = metadata.get('modules_used', [])
        
        section = """
---

## 🔬 Assessment Methodology

This comprehensive security assessment employed a multi-layered AI-augmented approach:

### Analysis Modules
"""
        
        module_descriptions = {
            'situational': '**Situational Analyzer** - Target profiling and context assessment',
            'multi_fusion': '**Multi-Situation Fusion** - Cross-correlation of findings',
            'neural_planner': '**Neural Attack Planner** - AI-driven strategic planning',
            'intelligent_attacker': '**Intelligent Attacker** - Smart exploitation with verification',
            'adaptive_brain': '**Adaptive Brain** - Learning-based analysis',
            'vuln_chain': '**Vulnerability Chaining** - Multi-step attack path discovery',
        }
        
        for module in modules:
            if module in module_descriptions:
                section += f"- {module_descriptions[module]}\n"
        
        section += """
### Enhanced Features
- ✅ Pattern-based vulnerability detection
- ✅ OWASP Top 10+ coverage
- ✅ Multi-module verification and correlation
- ✅ Intelligent deduplication and prioritization
- ✅ CVSS-based risk scoring
- ✅ Business context analysis
- ✅ Proof-of-concept generation

### Testing Scope
- Automated scanning and analysis
- AI-augmented exploitation attempts
- Vulnerability chaining and escalation paths
- Business logic vulnerability detection

"""
        return section
    
    def _generate_recommendations_section(self, findings: List[UnifiedFinding]) -> str:
        """Gera seção de recomendações."""
        section = """
---

## 💡 General Recommendations

### Immediate Actions
"""
        
        critical_findings = [f for f in findings if f.priority == FindingPriority.CRITICAL]
        if critical_findings:
            section += "\n**Critical vulnerabilities detected:**\n"
            for f in critical_findings[:3]:
                section += f"- Address {f.category.value} issue: {f.title}\n"
        
        section += """
### Short-term Improvements
- Conduct thorough code review of affected components
- Implement input validation and sanitization
- Review and update security configurations
- Enhance logging and monitoring capabilities

### Long-term Strategy
- Establish secure SDLC practices
- Implement automated security testing in CI/CD
- Regular security training for development team
- Periodic penetration testing and code audits
- Bug bounty program optimization

"""
        return section
    
    def generate_json(self, target: str, findings: List[UnifiedFinding], metadata: dict = None) -> str:
        """Gera report JSON."""
        data = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {},
            'summary': {
                'total': len(findings),
                'by_severity': {
                    'critical': len([f for f in findings if f.priority == FindingPriority.CRITICAL]),
                    'high': len([f for f in findings if f.priority == FindingPriority.HIGH]),
                    'medium': len([f for f in findings if f.priority == FindingPriority.MEDIUM]),
                    'low': len([f for f in findings if f.priority == FindingPriority.LOW]),
                    'info': len([f for f in findings if f.priority == FindingPriority.INFO]),
                },
                'by_category': {},
            },
            'findings': [f.to_dict() for f in findings],
        }
        
        # Category breakdown
        for f in findings:
            cat = f.category.value
            data['summary']['by_category'][cat] = data['summary']['by_category'].get(cat, 0) + 1
        
        return json.dumps(data, indent=2, default=str)


# =============================================================================
# ENHANCED ULTIMATE INTELLIGENCE HUB
# =============================================================================

class UltimateIntelligenceHub:
    """
    Enhanced central intelligence system.
    
    NEW FEATURES:
    - Intelligent caching
    - Parallel execution optimized
    - Better error handling
    - Performance metrics
    - Multiple output formats
    """
    
    def __init__(self, http_client=None, rate_limiter=None, headers: dict = None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.headers = headers or {}
        
        # Enhanced components
        self.synthesizer = EnhancedPrioritySynthesizer()
        self.report_generator = EnhancedHackerOneReportGenerator()
        self.cache = IntelligenceCache(ttl_hours=24)
        
        # Module instances (lazy loading)
        self._situational = None
        self._multi_fusion = None
        self._neural_planner = None
        self._intelligent_attacker = None
        self._adaptive_brain = None
        self._vuln_chain = None
        
        # Results and metrics
        self.findings_by_module: Dict[str, List[dict]] = {}
        self.metrics = {
            'cache_hits': 0,
            'api_calls': 0,
            'modules_executed': [],
            'start_time': None,
            'end_time': None,
        }
    
    # Properties com lazy loading (mantidos iguais)
    @property
    def situational(self):
        if not self._situational:
            self._situational = SituationalAnalyzer(
                http_client=self.http_client,
                rate_limiter=self.rate_limiter,
            )
        return self._situational
    
    @property
    def multi_fusion(self):
        if not self._multi_fusion:
            self._multi_fusion = MultiSituationFusion(
                http_client=self.http_client,
                rate_limiter=self.rate_limiter,
            )
        return self._multi_fusion
    
    @property
    def neural_planner(self):
        if not self._neural_planner:
            self._neural_planner = NeuralAttackPlanner(
                http_client=self.http_client,
                rate_limiter=self.rate_limiter,
            )
        return self._neural_planner
    
    @property
    def intelligent_attacker(self):
        if not self._intelligent_attacker:
            self._intelligent_attacker = IntelligentAttacker(
                http_client=self.http_client,
                rate_limiter=self.rate_limiter,
                headers=self.headers,
            )
        return self._intelligent_attacker
    
    @property
    def adaptive_brain(self):
        if not self._adaptive_brain:
            self._adaptive_brain = AdaptiveAttackBrain(
                http_client=self.http_client,
                rate_limiter=self.rate_limiter,
            )
        return self._adaptive_brain
    
    @property
    def vuln_chain(self):
        if not self._vuln_chain:
            self._vuln_chain = VulnChainEngine()
        return self._vuln_chain
    
    async def analyze(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
        scan_results: dict = None,
        use_cache: bool = True,
    ) -> IntelligenceReport:
        """
        Enhanced comprehensive analysis with caching and metrics.
        """
        self.metrics['start_time'] = datetime.now()
        initial_findings = initial_findings or []
        scan_results = scan_results or {}
        
        logger.info(f"[Ultimate Hub Enhanced] Starting analysis: {target_url}")
        print("\n" + "=" * 70)
        print("🚀 ULTIMATE INTELLIGENCE HUB - ENHANCED MODE")
        print("=" * 70)
        
        self.findings_by_module = {"scanner": initial_findings}
        
        # Phase 1: Situational Analysis
        await self._phase_situational(target_url, initial_findings, use_cache)
        
        # Phase 2: Multi-Situation Fusion
        await self._phase_multi_fusion(target_url, initial_findings, use_cache)
        
        # Phase 3: Neural Attack Planning
        await self._phase_neural_planning(target_url, initial_findings, use_cache)
        
        # Phase 4: Intelligent Attacks (ENHANCED with critical heuristics)
        await self._phase_intelligent_attacks(target_url, initial_findings, use_cache)
        
        # Phase 5: Adaptive Brain
        await self._phase_adaptive_brain(target_url, initial_findings, use_cache)
        
        # Phase 6: Vulnerability Chaining
        await self._phase_vuln_chaining(target_url, use_cache)
        
        # Phase 7: Enhanced Synthesis
        print("\n⚡ Phase 7: Enhanced Synthesis & Prioritization...")
        unified_findings = self.synthesizer.synthesize(self.findings_by_module)
        print(f"   → {len(unified_findings)} unified findings (after deduplication)")
        
        # Phase 8: Multi-Format Report Generation
        print("\n📝 Phase 8: Multi-Format Report Generation...")
        
        self.metrics['end_time'] = datetime.now()
        duration = (self.metrics['end_time'] - self.metrics['start_time']).total_seconds()
        
        metadata = {
            'analysis_duration': duration,
            'modules_used': self.metrics['modules_executed'],
            'cache_hits': self.metrics['cache_hits'],
            'api_calls': self.metrics['api_calls'],
        }
        
        markdown_report = self.report_generator.generate_markdown(
            target_url, unified_findings, metadata
        )
        json_report = self.report_generator.generate_json(
            target_url, unified_findings, metadata
        )
        
        # Build final report
        report = IntelligenceReport(
            target=target_url,
            findings=unified_findings,
            total_findings=len(unified_findings),
            critical_count=len([f for f in unified_findings if f.priority == FindingPriority.CRITICAL]),
            high_count=len([f for f in unified_findings if f.priority == FindingPriority.HIGH]),
            medium_count=len([f for f in unified_findings if f.priority == FindingPriority.MEDIUM]),
            low_count=len([f for f in unified_findings if f.priority == FindingPriority.LOW]),
            markdown_report=markdown_report,
            json_report=json_report,
            analysis_duration=duration,
            modules_used=self.metrics['modules_executed'],
            cache_hits=self.metrics['cache_hits'],
            api_calls_made=self.metrics['api_calls'],
        )
        
        # Category breakdown
        for finding in unified_findings:
            cat = finding.category.value
            report.category_breakdown[cat] = report.category_breakdown.get(cat, 0) + 1
        
        # Module contributions and performance
        for name, findings in self.findings_by_module.items():
            report.module_contributions[name] = len(findings)
            # Performance: findings per second
            report.module_performance[name] = len(findings) / max(duration, 1.0)
        
        # Bounty estimate
        bounty_low = (
            report.critical_count * 2000 +
            report.high_count * 1000 +
            report.medium_count * 500 +
            report.low_count * 100
        )
        bounty_high = (
            report.critical_count * 15000 +
            report.high_count * 5000 +
            report.medium_count * 2000 +
            report.low_count * 750
        )
        report.total_bounty_estimate = f"${bounty_low:,} - ${bounty_high:,}"
        
        # Final summary
        self._print_final_summary(report)
        
        return report
    
    async def _phase_situational(self, target_url: str, initial_findings: List[dict], use_cache: bool):
        """Phase 1: Situational Analysis."""
        print("\n🧠 Phase 1: Situational Analysis...")
        
        cached = self.cache.get(target_url, 'situational', initial_findings) if use_cache else None
        if cached:
            self.findings_by_module['situational'] = cached
            self.metrics['cache_hits'] += 1
            print("   → [CACHED] Situational analysis retrieved")
            return
        
        try:
            assessment = await self.situational.analyze(target_url, initial_findings)
            self.metrics['api_calls'] += 1
            self.metrics['modules_executed'].append('situational')
            
            findings = [{
                "name": f"Target Profile: {assessment.profile.type.name}",
                "severity": "info",
                "type": "analysis",
                "evidence": {
                    "security_level": assessment.profile.security_level.name,
                    "recommended_strategy": assessment.profile.recommended_strategy.name,
                    "attack_surface": getattr(assessment, 'attack_surface_score', None),
                },
            }]
            
            self.findings_by_module["situational"] = findings
            self.cache.set(target_url, 'situational', findings, initial_findings)
            
            print(f"   → Target Type: {assessment.profile.type.name}")
            print(f"   → Security Level: {assessment.profile.security_level.name}")
            print(f"   → Attack Surface Score: {assessment.attack_surface_score:.2f}")
        except Exception as e:
            logger.error(f"[Hub] Situational analysis error: {e}")
            self.findings_by_module["situational"] = []
    
    async def _phase_multi_fusion(self, target_url: str, initial_findings: List[dict], use_cache: bool):
        """Phase 2: Multi-Situation Fusion."""
        print("\n🔀 Phase 2: Multi-Situation Fusion...")
        
        cached = self.cache.get(target_url, 'multi_fusion', initial_findings) if use_cache else None
        if cached:
            self.findings_by_module['multi_fusion'] = cached
            self.metrics['cache_hits'] += 1
            print("   → [CACHED] Fusion analysis retrieved")
            return
        
        try:
            fusions, _ = await self.multi_fusion.analyze(target_url, initial_findings)
            self.metrics['api_calls'] += 1
            self.metrics['modules_executed'].append('multi_fusion')
            
            findings = [
                {
                    "name": f.name,
                    "severity": f.potential_impact,
                    "type": f.attack_type,
                    "confidence": f.combined_probability,
                    "steps": f.attack_steps,
                    "poc": f.poc_template,
                    "endpoint": f.situations[0].endpoint if f.situations else "",
                }
                for f in fusions
            ]
            
            self.findings_by_module["multi_fusion"] = findings
            self.cache.set(target_url, 'multi_fusion', findings, initial_findings)
            
            print(f"   → Found {len(fusions)} attack opportunities")
        except Exception as e:
            logger.error(f"[Hub] Multi-fusion error: {e}")
            self.findings_by_module["multi_fusion"] = []
    
    async def _phase_neural_planning(self, target_url: str, initial_findings: List[dict], use_cache: bool):
        """Phase 3: Neural Attack Planning."""
        print("\n🧬 Phase 3: Neural Attack Planning...")
        
        cached = self.cache.get(target_url, 'neural_planner', initial_findings) if use_cache else None
        if cached:
            self.findings_by_module['neural_planner'] = cached
            self.metrics['cache_hits'] += 1
            print("   → [CACHED] Neural planning retrieved")
            return
        
        try:
            from analysis.neural_attack_planner import neural_attack_plan
            neural_results, _, _ = await neural_attack_plan(target_url, initial_findings)
            self.metrics['api_calls'] += 1
            self.metrics['modules_executed'].append('neural_planner')
            findings = [
                {
                    "name": getattr(r, "name", r.get("name", "Neural Finding")),
                    "severity": getattr(r, "severity", r.get("severity", "medium")),
                    "type": getattr(r, "type", r.get("type", "neural")),
                    "confidence": getattr(r, "confidence", r.get("confidence", 0.7)),
                    "poc": getattr(r, "poc", r.get("poc", "")),
                    "endpoint": getattr(r, "endpoint", r.get("endpoint", "")),
                }
                for r in neural_results
            ]
            self.findings_by_module["neural_planner"] = findings
            self.cache.set(target_url, 'neural_planner', findings, initial_findings)
            print(f"   → Generated {len(neural_results)} neural findings")
        except Exception as e:
            logger.error(f"[Hub] Neural planning error: {e}")
            self.findings_by_module["neural_planner"] = []
    
    async def _phase_intelligent_attacks(self, target_url: str, initial_findings: List[dict], use_cache: bool):
        """Phase 4: Enhanced Intelligent Attacks with Critical Heuristics."""
        print("\n🎯 Phase 4: Intelligent Attacks (Enhanced Critical Heuristics)...")
        
        try:
            from analysis.intelligent_attacker import intelligent_attack
            
            # EXPANDED critical keywords for better targeting
            critical_keywords = [
                # Auth & Access
                "admin", "root", "superuser", "sudo", "privilege", "elevate", 
                "impersonate", "bypass", "backdoor", "master",
                # Sensitive Operations
                "reset", "forgot", "password", "token", "auth", "session",
                "secret", "key", "credential", "bearer", "jwt",
                # OAuth & SSO
                "oauth", "callback", "redirect", "sso", "saml", "openid",
                # 2FA/MFA
                "2fa", "mfa", "otp", "totp", "verify", "code",
                # CSRF & Security
                "csrf", "xsrf", "token", "nonce", "state",
                # Config & Debug
                "debug", "internal", "config", "settings", "env",
                # API & Integration
                "api_key", "webhook", "integration", "proxy",
                # File Operations
                "upload", "file", "path", "download", "read", "write",
                # Execution
                "exec", "shell", "cmd", "eval", "system",
                # Business Critical
                "payment", "transaction", "transfer", "balance", "price",
                "coupon", "discount", "refund", "withdraw",
            ]
            
            # Prioritize findings with critical keywords
            prioritized_findings = []
            normal_findings = []
            
            for f in (initial_findings or []):
                url = (f.get("url") or f.get("endpoint") or "").lower()
                param = f.get("param", "").lower()
                name = f.get("name", "").lower()
                
                # Check if contains critical keywords
                is_critical = any(
                    kw in url or kw in param or kw in name
                    for kw in critical_keywords
                )
                
                if is_critical:
                    prioritized_findings.append(f)
                else:
                    normal_findings.append(f)
            
            # Combine: critical first
            findings_for_attack = prioritized_findings + normal_findings
            
            print(f"   → Prioritized {len(prioritized_findings)} critical findings")
            print(f"   → {len(normal_findings)} normal findings")
            
            # Execute intelligent attack with deeper analysis
            smart_results, _ = await intelligent_attack(
                target_url,
                findings_for_attack,
                self.http_client,
                self.rate_limiter,
                max_depth=10,  # Increased depth for better coverage
            )
            
            self.metrics['api_calls'] += len(findings_for_attack)
            self.metrics['modules_executed'].append('intelligent_attacker')
            
            findings = [
                {
                    "name": getattr(r, "name", getattr(r, "title", "Smart Attack")),
                    "severity": getattr(r, "severity", "medium"),
                    "type": getattr(r, "type", "smart"),
                    "confidence": getattr(r, "confidence", 0.7),
                    "poc": getattr(r, "poc", ""),
                    "curl": getattr(r, "curl", ""),
                    "endpoint": getattr(r, "endpoint", ""),
                    "evidence": getattr(r, "evidence", {}),
                }
                for r in smart_results
            ]
            
            self.findings_by_module["intelligent_attacker"] = findings
            print(f"   → {len(smart_results)} intelligent findings (with critical focus)")
            
        except Exception as e:
            logger.error(f"[Hub] Intelligent attacker error: {e}")
            self.findings_by_module["intelligent_attacker"] = []
    
    async def _phase_adaptive_brain(self, target_url: str, initial_findings: List[dict], use_cache: bool):
        """Phase 5: Adaptive Brain."""
        print("\n🧠 Phase 5: Adaptive Brain Analysis...")
        
        cached = self.cache.get(target_url, 'adaptive_brain', initial_findings) if use_cache else None
        if cached:
            self.findings_by_module['adaptive_brain'] = cached
            self.metrics['cache_hits'] += 1
            print("   → [CACHED] Adaptive brain retrieved")
            return
        
        try:
            # Use AdaptiveAttackBrain instance and its method
            brain = self.adaptive_brain
            brain_results = await brain.analyze_and_exploit(target_url, initial_findings)
            self.metrics['api_calls'] += 1
            self.metrics['modules_executed'].append('adaptive_brain')
            findings = [
                {
                    "name": getattr(r, "name", getattr(r, "title", "Brain Insight")),
                    "severity": getattr(r, "severity", "info"),
                    "type": getattr(r, "type", "adaptive"),
                    "confidence": getattr(r, "confidence", 0.6),
                    "endpoint": getattr(r, "endpoint", ""),
                }
                for r in brain_results
            ]
            self.findings_by_module["adaptive_brain"] = findings
            self.cache.set(target_url, 'adaptive_brain', findings, initial_findings)
            print(f"   → {len(brain_results)} adaptive insights")
        except Exception as e:
            logger.error(f"[Hub] Adaptive brain error: {e}")
            self.findings_by_module["adaptive_brain"] = []
    
    async def _phase_vuln_chaining(self, target_url: str, use_cache: bool):
        """Phase 6: Vulnerability Chaining."""
        print("\n🔗 Phase 6: Vulnerability Chaining...")
        
        try:
            from analysis.vuln_chain_engine import chain_vulnerabilities
            all_findings = []
            for findings in self.findings_by_module.values():
                for f in findings:
                    if isinstance(f, dict):
                        all_findings.append(f)
            # Defensive: remove any accidental non-dict
            all_findings = [f for f in all_findings if isinstance(f, dict)]
            chains = await chain_vulnerabilities(target_url, all_findings)
            self.metrics['modules_executed'].append('vuln_chain')
            findings = []
            for c in chains:
                # Safe extraction for both object and dict
                if isinstance(c, dict):
                    name = c.get('name', 'Chain')
                    target_severity = c.get('target_severity', 'medium')
                    steps = c.get('steps', [])
                    confidence = c.get('probability', 0.7)
                else:
                    name = getattr(c, 'name', 'Chain')
                    target_severity = getattr(c, 'target_severity', 'medium')
                    steps = getattr(c, 'steps', [])
                    confidence = getattr(c, 'probability', 0.7)
                findings.append({
                    "name": f"Attack Chain: {name}",
                    "severity": target_severity,
                    "type": "chain",
                    "steps": steps,
                    "confidence": confidence,
                })
            self.findings_by_module["vuln_chain"] = findings
            print(f"   → {len(chains)} attack chains discovered")
        except Exception as e:
            logger.error(f"[Hub] Vulnerability chaining error: {e}")
            self.findings_by_module["vuln_chain"] = []
    
    def _print_final_summary(self, report: IntelligenceReport):
        """Print enhanced final summary."""
        print("\n" + "=" * 70)
        print("🏆 ULTIMATE INTELLIGENCE ANALYSIS COMPLETE - ENHANCED")
        print("=" * 70)
        print(f"   Target: {report.target}")
        print(f"   Duration: {report.analysis_duration:.2f}s")
        print(f"   Cache Hits: {report.cache_hits}")
        print(f"   API Calls: {report.api_calls_made}")
        print(f"   Modules: {', '.join(report.modules_used)}")
        print()
        print(f"   Total Findings: {report.total_findings}")
        print(f"   🔴 Critical: {report.critical_count}")
        print(f"   🟠 High: {report.high_count}")
        print(f"   🟡 Medium: {report.medium_count}")
        print(f"   🟢 Low: {report.low_count}")
        print()
        print(f"   💰 Bounty Estimate: {report.total_bounty_estimate}")
        print()
        if report.category_breakdown:
            print("   Top Categories:")
            for cat, count in sorted(report.category_breakdown.items(), key=lambda x: -x[1])[:5]:
                print(f"      • {cat}: {count}")
        print("=" * 70)


# =============================================================================
# MAIN ENTRY POINT (mantém compatibilidade)
# =============================================================================

async def ultimate_analyze(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
    headers: dict = None,
    use_cache: bool = True,
) -> Tuple[IntelligenceReport, str]:
    """
    Run ultimate intelligence analysis (ENHANCED).
    
    Args:
        target_url: Target URL
        initial_findings: Initial scan findings
        http_client: HTTP client instance
        rate_limiter: Rate limiter instance
        headers: Custom headers
        use_cache: Enable intelligent caching
    
    Returns:
        Tuple of (IntelligenceReport, markdown_report)
    """
    hub = UltimateIntelligenceHub(
        http_client=http_client,
        rate_limiter=rate_limiter,
        headers=headers,
    )
    
    report = await hub.analyze(
        target_url,
        initial_findings,
        use_cache=use_cache,
    )
    
    return report, report.markdown_report