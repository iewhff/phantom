"""
Threat Modeler - Comprehensive threat modeling with data flow analysis.
Generates threat models, data flow diagrams, and security recommendations.
"""

from __future__ import annotations

import json
import html
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from enum import Enum

from threat_modeling.stride_analyzer import STRIDEAnalyzer, STRIDECategory, Threat, AbuseCase
from utils.logger import get_logger

logger = get_logger(__name__)


class ComponentType(Enum):
    """Types of system components."""
    WEB_APP = "web_application"
    API = "api"
    DATABASE = "database"
    EXTERNAL_SERVICE = "external_service"
    USER = "user"
    ADMIN = "admin"
    FILE_STORAGE = "file_storage"
    CACHE = "cache"
    MESSAGE_QUEUE = "message_queue"
    AUTH_SERVICE = "auth_service"


@dataclass
class DataFlow:
    """Represents a data flow between components."""
    id: str
    source: str
    destination: str
    data_type: str
    protocol: str
    is_encrypted: bool
    crosses_trust_boundary: bool
    description: str = ""
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "destination": self.destination,
            "data_type": self.data_type,
            "protocol": self.protocol,
            "is_encrypted": self.is_encrypted,
            "crosses_trust_boundary": self.crosses_trust_boundary,
            "description": self.description,
        }


@dataclass
class TrustBoundary:
    """Represents a trust boundary in the system."""
    id: str
    name: str
    description: str
    components: list[str]
    trust_level: int  # 1-5, higher = more trusted
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "components": self.components,
            "trust_level": self.trust_level,
        }


@dataclass
class ThreatModel:
    """Complete threat model for a system."""
    id: str
    name: str
    version: str
    description: str
    created_at: datetime
    components: dict[str, ComponentType]
    data_flows: list[DataFlow]
    trust_boundaries: list[TrustBoundary]
    threats: list[Threat]
    abuse_cases: list[AbuseCase]
    assumptions: list[str]
    recommendations: list[dict[str, Any]]
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "components": {k: v.value for k, v in self.components.items()},
            "data_flows": [df.to_dict() for df in self.data_flows],
            "trust_boundaries": [tb.to_dict() for tb in self.trust_boundaries],
            "threats": [t.to_dict() for t in self.threats],
            "abuse_cases": [ac.to_dict() for ac in self.abuse_cases],
            "assumptions": self.assumptions,
            "recommendations": self.recommendations,
        }


class ThreatModeler:
    """
    Comprehensive threat modeling system.
    
    Features:
    - Automatic component discovery
    - Data flow analysis
    - Trust boundary identification
    - STRIDE threat mapping
    - Abuse case generation
    - Security recommendations
    - Visual diagram generation
    """
    
    def __init__(self):
        self.stride_analyzer = STRIDEAnalyzer()
        self.components: dict[str, ComponentType] = {}
        self.data_flows: list[DataFlow] = []
        self.trust_boundaries: list[TrustBoundary] = []
    
    def create_threat_model(
        self,
        name: str,
        endpoints: list[dict[str, Any]],
        description: str = "",
    ) -> ThreatModel:
        """
        Create a comprehensive threat model.
        
        Args:
            name: Name of the system being modeled
            endpoints: List of endpoint configurations
            description: System description
            
        Returns:
            Complete ThreatModel object
        """
        logger.info(f"Creating threat model for: {name}")
        
        # Step 1: Discover components from endpoints
        self._discover_components(endpoints)
        
        # Step 2: Identify data flows
        self._identify_data_flows(endpoints)
        
        # Step 3: Define trust boundaries
        self._define_trust_boundaries()
        
        # Step 4: Analyze each endpoint for STRIDE threats
        for endpoint in endpoints:
            self.stride_analyzer.analyze_endpoint(
                endpoint=endpoint.get("path", ""),
                method=endpoint.get("method", "GET"),
                parameters=endpoint.get("parameters", []),
                requires_auth=endpoint.get("requires_auth", True),
                data_types=endpoint.get("data_types", []),
            )
        
        # Step 5: Generate recommendations
        recommendations = self._generate_recommendations()
        
        # Step 6: Build threat model
        model = ThreatModel(
            id=f"TM-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            name=name,
            version="1.0",
            description=description,
            created_at=datetime.now(),
            components=self.components,
            data_flows=self.data_flows,
            trust_boundaries=self.trust_boundaries,
            threats=self.stride_analyzer.threats,
            abuse_cases=self.stride_analyzer.abuse_cases,
            assumptions=self._get_assumptions(),
            recommendations=recommendations,
        )
        
        logger.info(f"Threat model created with {len(model.threats)} threats, {len(model.abuse_cases)} abuse cases")
        
        return model
    
    def _discover_components(self, endpoints: list[dict[str, Any]]) -> None:
        """Discover system components from endpoints."""
        self.components = {
            "user": ComponentType.USER,
            "web_frontend": ComponentType.WEB_APP,
            "api_gateway": ComponentType.API,
        }
        
        for endpoint in endpoints:
            path = endpoint.get("path", "").lower()
            
            if any(p in path for p in ["/db", "/data", "/query"]):
                self.components["database"] = ComponentType.DATABASE
            
            if any(p in path for p in ["/auth", "/login", "/token"]):
                self.components["auth_service"] = ComponentType.AUTH_SERVICE
            
            if any(p in path for p in ["/file", "/upload", "/storage"]):
                self.components["file_storage"] = ComponentType.FILE_STORAGE
            
            if any(p in path for p in ["/cache", "/redis"]):
                self.components["cache"] = ComponentType.CACHE
            
            if any(p in path for p in ["/external", "/webhook", "/integration"]):
                self.components["external_service"] = ComponentType.EXTERNAL_SERVICE
            
            if any(p in path for p in ["/admin", "/manage"]):
                self.components["admin"] = ComponentType.ADMIN
    
    def _identify_data_flows(self, endpoints: list[dict[str, Any]]) -> None:
        """Identify data flows between components."""
        flow_id = 0
        
        # User to Frontend
        self.data_flows.append(DataFlow(
            id=f"DF-{flow_id:03d}",
            source="user",
            destination="web_frontend",
            data_type="user_input",
            protocol="HTTPS",
            is_encrypted=True,
            crosses_trust_boundary=True,
            description="User interacts with web application",
        ))
        flow_id += 1
        
        # Frontend to API
        self.data_flows.append(DataFlow(
            id=f"DF-{flow_id:03d}",
            source="web_frontend",
            destination="api_gateway",
            data_type="api_requests",
            protocol="HTTPS",
            is_encrypted=True,
            crosses_trust_boundary=False,
            description="Frontend makes API calls",
        ))
        flow_id += 1
        
        # Add flows based on discovered components
        if "database" in self.components:
            self.data_flows.append(DataFlow(
                id=f"DF-{flow_id:03d}",
                source="api_gateway",
                destination="database",
                data_type="queries",
                protocol="TCP",
                is_encrypted=False,  # Often internal
                crosses_trust_boundary=True,
                description="API queries database",
            ))
            flow_id += 1
        
        if "auth_service" in self.components:
            self.data_flows.append(DataFlow(
                id=f"DF-{flow_id:03d}",
                source="api_gateway",
                destination="auth_service",
                data_type="credentials",
                protocol="HTTPS",
                is_encrypted=True,
                crosses_trust_boundary=True,
                description="Authentication requests",
            ))
            flow_id += 1
        
        if "external_service" in self.components:
            self.data_flows.append(DataFlow(
                id=f"DF-{flow_id:03d}",
                source="api_gateway",
                destination="external_service",
                data_type="integration_data",
                protocol="HTTPS",
                is_encrypted=True,
                crosses_trust_boundary=True,
                description="External API integrations",
            ))
            flow_id += 1
    
    def _define_trust_boundaries(self) -> None:
        """Define trust boundaries based on components."""
        self.trust_boundaries = [
            TrustBoundary(
                id="TB-001",
                name="Internet Boundary",
                description="Boundary between external users and internal systems",
                components=["user", "web_frontend"],
                trust_level=1,
            ),
            TrustBoundary(
                id="TB-002",
                name="DMZ",
                description="Demilitarized zone containing public-facing services",
                components=["api_gateway", "web_frontend"],
                trust_level=2,
            ),
            TrustBoundary(
                id="TB-003",
                name="Internal Network",
                description="Internal services and databases",
                components=["database", "auth_service", "cache", "file_storage"],
                trust_level=4,
            ),
            TrustBoundary(
                id="TB-004",
                name="Admin Zone",
                description="Administrative access zone",
                components=["admin"],
                trust_level=5,
            ),
        ]
    
    def _generate_recommendations(self) -> list[dict[str, Any]]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        priority = 1
        
        # Check for high-risk threats
        high_risk_threats = [t for t in self.stride_analyzer.threats if t.risk_score >= 6]
        if high_risk_threats:
            for threat in high_risk_threats[:5]:
                recommendations.append({
                    "priority": priority,
                    "category": threat.category.value,
                    "title": f"Mitigate: {threat.name}",
                    "description": threat.description,
                    "actions": threat.mitigations,
                    "affected": threat.affected_component,
                })
                priority += 1
        
        # Check for unencrypted data flows
        unencrypted = [df for df in self.data_flows if not df.is_encrypted]
        if unencrypted:
            recommendations.append({
                "priority": priority,
                "category": "encryption",
                "title": "Encrypt Data in Transit",
                "description": "Some data flows are not encrypted",
                "actions": [
                    "Enable TLS for all internal communications",
                    "Use mTLS for service-to-service communication",
                    "Encrypt database connections",
                ],
                "affected": [df.id for df in unencrypted],
            })
            priority += 1
        
        # Flows crossing trust boundaries
        boundary_crossings = [df for df in self.data_flows if df.crosses_trust_boundary]
        if boundary_crossings:
            recommendations.append({
                "priority": priority,
                "category": "access_control",
                "title": "Secure Trust Boundary Crossings",
                "description": f"{len(boundary_crossings)} data flows cross trust boundaries",
                "actions": [
                    "Implement strict input validation at boundaries",
                    "Add authentication for all boundary crossings",
                    "Log all cross-boundary access",
                    "Consider network segmentation",
                ],
                "affected": [df.id for df in boundary_crossings],
            })
            priority += 1
        
        # General recommendations based on components
        if "database" in self.components:
            recommendations.append({
                "priority": priority,
                "category": "database",
                "title": "Database Security Hardening",
                "description": "Ensure database is properly secured",
                "actions": [
                    "Use parameterized queries",
                    "Implement least privilege database accounts",
                    "Enable query logging and monitoring",
                    "Regular security patching",
                ],
                "affected": "database",
            })
            priority += 1
        
        if "auth_service" in self.components:
            recommendations.append({
                "priority": priority,
                "category": "authentication",
                "title": "Authentication Hardening",
                "description": "Strengthen authentication mechanisms",
                "actions": [
                    "Implement MFA",
                    "Use secure session management",
                    "Add brute-force protection",
                    "Regular credential rotation",
                ],
                "affected": "auth_service",
            })
            priority += 1
        
        return recommendations
    
    def _get_assumptions(self) -> list[str]:
        """Get security assumptions."""
        return [
            "TLS 1.2+ is enforced for all external communications",
            "Authentication is required for all non-public endpoints",
            "Input validation is performed on all user inputs",
            "Logging is enabled for security-relevant events",
            "Regular security assessments are conducted",
        ]
    
    def generate_dfd_diagram(self, model: ThreatModel) -> str:
        """Generate Data Flow Diagram in Mermaid format."""
        lines = ["```mermaid", "flowchart TB"]
        
        # Add subgraphs for trust boundaries
        for tb in model.trust_boundaries:
            lines.append(f"    subgraph {tb.id}[{tb.name}]")
            for comp in tb.components:
                if comp in model.components:
                    lines.append(f"        {comp}[{comp.replace('_', ' ').title()}]")
            lines.append("    end")
        
        lines.append("")
        
        # Add data flows
        for df in model.data_flows:
            encrypted = "🔒" if df.is_encrypted else "⚠️"
            lines.append(f"    {df.source} -->|{encrypted} {df.data_type}| {df.destination}")
        
        # Style based on component type
        lines.append("")
        lines.append("    classDef user fill:#e1f5fe,stroke:#01579b")
        lines.append("    classDef service fill:#f3e5f5,stroke:#4a148c")
        lines.append("    classDef data fill:#fff3e0,stroke:#e65100")
        lines.append("    classDef external fill:#ffebee,stroke:#b71c1c")
        
        lines.append("```")
        
        return "\n".join(lines)
    
    def generate_html_report(self, model: ThreatModel) -> str:
        """Generate comprehensive HTML threat model report."""
        
        # Calculate stats
        threats_by_category = {}
        for cat in STRIDECategory:
            count = len([t for t in model.threats if t.category == cat])
            threats_by_category[cat.value] = count
        
        total_risk = sum(t.risk_score for t in model.threats)
        critical_threats = len([t for t in model.threats if t.risk_score >= 6])
        
        threats_html = ""
        for threat in sorted(model.threats, key=lambda t: -t.risk_score)[:20]:
            threats_html += f"""
            <div class="threat-card {threat.category.value}">
                <div class="threat-header">
                    <h4>{html.escape(threat.name)}</h4>
                    <span class="badge risk-{threat.risk_score}">{threat.category.value.upper()} | Risk: {threat.risk_score}</span>
                </div>
                <p>{html.escape(threat.description)}</p>
                <div class="threat-details">
                    <p><strong>Affected:</strong> {html.escape(threat.affected_component)}</p>
                    <p><strong>Attack Vector:</strong> {html.escape(threat.attack_vector)}</p>
                    <p><strong>Mitigations:</strong></p>
                    <ul>
                        {''.join(f'<li>{html.escape(m)}</li>' for m in threat.mitigations)}
                    </ul>
                </div>
            </div>
            """
        
        abuse_html = ""
        for case in model.abuse_cases[:15]:
            abuse_html += f"""
            <div class="abuse-card">
                <div class="abuse-header">
                    <h4>{html.escape(case.name)}</h4>
                    <span class="badge severity-{case.severity.value}">{case.severity.value.upper()}</span>
                </div>
                <p><strong>Endpoint:</strong> {case.method} {html.escape(case.endpoint)}</p>
                <p>{html.escape(case.description)}</p>
                <div class="attack-steps">
                    <strong>Attack Steps:</strong>
                    <ol>
                        {''.join(f'<li>{html.escape(step)}</li>' for step in case.attack_steps)}
                    </ol>
                </div>
                <p class="impact"><strong>Business Impact:</strong> {html.escape(case.business_impact)}</p>
            </div>
            """
        
        recs_html = ""
        for rec in model.recommendations:
            recs_html += f"""
            <div class="rec-card">
                <div class="rec-header">
                    <span class="priority">#{rec['priority']}</span>
                    <h4>{html.escape(rec['title'])}</h4>
                </div>
                <p>{html.escape(rec['description'])}</p>
                <ul>
                    {''.join(f'<li>{html.escape(a)}</li>' for a in rec['actions'])}
                </ul>
            </div>
            """
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Threat Model Report - {html.escape(model.name)}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --card: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --muted: #8b949e;
            --blue: #58a6ff;
            --green: #3fb950;
            --yellow: #d29922;
            --red: #f85149;
            --purple: #a371f7;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center;
            padding: 40px 20px;
            background: var(--card);
            border-radius: 12px;
            margin-bottom: 30px;
        }}
        header h1 {{
            font-size: 2.5em;
            background: linear-gradient(45deg, var(--blue), var(--purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{
            background: var(--card);
            padding: 25px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card .value {{ font-size: 2.5em; font-weight: bold; }}
        .stat-card.critical .value {{ color: var(--red); }}
        .stat-card.high .value {{ color: var(--yellow); }}
        .stat-card.medium .value {{ color: var(--blue); }}
        section {{
            background: var(--card);
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 25px;
        }}
        section h2 {{
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }}
        .stride-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stride-item {{
            background: var(--bg);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stride-item .letter {{ font-size: 2em; font-weight: bold; color: var(--blue); }}
        .stride-item .name {{ font-size: 0.9em; color: var(--muted); }}
        .stride-item .count {{ font-size: 1.5em; margin-top: 5px; }}
        .threat-card, .abuse-card, .rec-card {{
            background: var(--bg);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid var(--blue);
        }}
        .threat-card.spoofing {{ border-color: var(--red); }}
        .threat-card.tampering {{ border-color: var(--yellow); }}
        .threat-card.repudiation {{ border-color: var(--purple); }}
        .threat-card.info_disclosure {{ border-color: var(--green); }}
        .threat-card.dos {{ border-color: #f0883e; }}
        .threat-card.elevation {{ border-color: var(--red); }}
        .threat-header, .abuse-header, .rec-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            background: var(--card);
        }}
        .severity-critical {{ background: var(--red); color: #fff; }}
        .severity-high {{ background: var(--yellow); color: #000; }}
        .severity-medium {{ background: var(--blue); color: #fff; }}
        .threat-details {{ margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--border); }}
        .threat-details ul {{ margin-left: 20px; }}
        .attack-steps ol {{ margin-left: 20px; margin-top: 10px; }}
        .impact {{ margin-top: 10px; color: var(--yellow); }}
        .rec-header .priority {{
            background: var(--blue);
            color: #fff;
            padding: 5px 12px;
            border-radius: 50%;
            font-weight: bold;
        }}
        .data-flow {{ margin: 10px 0; padding: 10px; background: var(--bg); border-radius: 4px; }}
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--muted);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Threat Model Report</h1>
            <p style="margin-top: 10px;">{html.escape(model.name)} | v{model.version}</p>
            <p style="color: var(--muted);">Generated: {model.created_at.strftime("%Y-%m-%d %H:%M")}</p>
        </header>
        
        <div class="stats">
            <div class="stat-card critical">
                <div class="value">{len(model.threats)}</div>
                <div>Total Threats</div>
            </div>
            <div class="stat-card high">
                <div class="value">{critical_threats}</div>
                <div>High Risk</div>
            </div>
            <div class="stat-card medium">
                <div class="value">{len(model.abuse_cases)}</div>
                <div>Abuse Cases</div>
            </div>
            <div class="stat-card">
                <div class="value">{len(model.recommendations)}</div>
                <div>Recommendations</div>
            </div>
        </div>
        
        <section>
            <h2>📊 STRIDE Analysis Summary</h2>
            <div class="stride-grid">
                <div class="stride-item">
                    <div class="letter">S</div>
                    <div class="name">Spoofing</div>
                    <div class="count">{threats_by_category.get('spoofing', 0)}</div>
                </div>
                <div class="stride-item">
                    <div class="letter">T</div>
                    <div class="name">Tampering</div>
                    <div class="count">{threats_by_category.get('tampering', 0)}</div>
                </div>
                <div class="stride-item">
                    <div class="letter">R</div>
                    <div class="name">Repudiation</div>
                    <div class="count">{threats_by_category.get('repudiation', 0)}</div>
                </div>
                <div class="stride-item">
                    <div class="letter">I</div>
                    <div class="name">Info Disclosure</div>
                    <div class="count">{threats_by_category.get('info_disclosure', 0)}</div>
                </div>
                <div class="stride-item">
                    <div class="letter">D</div>
                    <div class="name">Denial of Service</div>
                    <div class="count">{threats_by_category.get('dos', 0)}</div>
                </div>
                <div class="stride-item">
                    <div class="letter">E</div>
                    <div class="name">Elevation</div>
                    <div class="count">{threats_by_category.get('elevation', 0)}</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>⚠️ Identified Threats</h2>
            {threats_html}
        </section>
        
        <section>
            <h2>🎯 Abuse Cases</h2>
            {abuse_html}
        </section>
        
        <section>
            <h2>✅ Security Recommendations</h2>
            {recs_html}
        </section>
        
        <section>
            <h2>🔀 Data Flows</h2>
            {''.join(f'''
            <div class="data-flow">
                <strong>{df.source}</strong> → <strong>{df.destination}</strong>
                <span style="margin-left: 15px;">{'🔒' if df.is_encrypted else '⚠️'} {df.protocol}</span>
                <span style="margin-left: 15px; color: var(--muted);">{df.data_type}</span>
                {'<span style="margin-left: 15px; color: var(--yellow);">⚡ Crosses Trust Boundary</span>' if df.crosses_trust_boundary else ''}
            </div>
            ''' for df in model.data_flows)}
        </section>
        
        <footer>
            <p>🛡️ Threat Model Report | AI-Enhanced Pentesting Framework</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
</body>
</html>
"""
