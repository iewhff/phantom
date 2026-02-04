"""
Attack Chain Visualizer - Visual representation of attack chains.
Generates ASCII, Mermaid, HTML, and interactive visualizations.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analysis.attack_chain_engine import AttackChain, ChainNode, AttackPhase

from utils.logger import get_logger

logger = get_logger(__name__)


class ChainVisualizer:
    """
    Generates visual representations of attack chains.
    
    Formats:
    - ASCII art for terminal
    - Mermaid diagrams for documentation
    - HTML interactive reports
    - JSON for custom rendering
    """
    
    # Color codes for severity
    SEVERITY_COLORS = {
        "CRITICAL": "#dc3545",  # Red
        "HIGH": "#fd7e14",      # Orange
        "MEDIUM": "#ffc107",    # Yellow
        "LOW": "#28a745",       # Green
        "INFO": "#17a2b8",      # Blue
    }
    
    # Icons for phases
    PHASE_ICONS = {
        "reconnaissance": "🔍",
        "initial_access": "🚪",
        "execution": "⚡",
        "persistence": "🔒",
        "privilege_escalation": "📈",
        "defense_evasion": "🛡️",
        "credential_access": "🔑",
        "discovery": "🗺️",
        "lateral_movement": "↔️",
        "collection": "📦",
        "exfiltration": "📤",
        "impact": "💥",
    }
    
    def __init__(self):
        pass
    
    def generate_ascii(self, chain: AttackChain) -> str:
        """Generate ASCII art representation of attack chain."""
        lines = []
        
        # Header
        lines.append("=" * 70)
        lines.append(f"🔗 ATTACK CHAIN: {chain.name}")
        lines.append(f"   Priority: {chain.remediation_priority}/10 | Severity: {chain.max_severity}")
        lines.append(f"   Impact: {chain.impact_type.value.replace('_', ' ').title()}")
        lines.append("=" * 70)
        lines.append("")
        
        # Nodes
        for i, node in enumerate(chain.nodes):
            icon = self.PHASE_ICONS.get(node.phase.value, "•")
            
            # Node box
            lines.append(f"    ┌{'─' * 60}┐")
            lines.append(f"    │ {icon} {node.name[:55]:<55} │")
            lines.append(f"    │   Phase: {node.phase.value:<45} │")
            lines.append(f"    │   Severity: {node.severity:<10} CVSS: {node.cvss:<6} │")
            lines.append(f"    │   Endpoint: {node.endpoint[:43]:<43} │")
            lines.append(f"    │   {node.cwe:<15} {node.owasp:<30} │")
            lines.append(f"    └{'─' * 60}┘")
            
            # Arrow to next node
            if i < len(chain.nodes) - 1:
                lines.append("                          │")
                lines.append("                          ▼")
                lines.append("")
        
        # Impact box
        lines.append("")
        lines.append("    ╔" + "═" * 60 + "╗")
        lines.append(f"    ║ 💥 BUSINESS IMPACT{' ' * 42}║")
        lines.append("    ╠" + "═" * 60 + "╣")
        
        # Word wrap impact
        impact = chain.business_impact
        while len(impact) > 56:
            lines.append(f"    ║ {impact[:56]:<58} ║")
            impact = impact[56:]
        lines.append(f"    ║ {impact:<58} ║")
        
        lines.append("    ║" + " " * 60 + "║")
        lines.append(f"    ║ ⏱️  Time to Exploit: {chain.estimated_time_to_exploit:<35} ║")
        lines.append(f"    ║ 📊 Likelihood: {chain.likelihood:<42} ║")
        lines.append(f"    ║ 🔧 Exploitability: {chain.exploitability:<38} ║")
        lines.append("    ╚" + "═" * 60 + "╝")
        
        return "\n".join(lines)
    
    def generate_mermaid(self, chain: AttackChain) -> str:
        """Generate Mermaid flowchart diagram."""
        lines = ["```mermaid", "flowchart TD"]
        
        # Style definitions
        lines.append("    classDef critical fill:#dc3545,color:#fff,stroke:#fff")
        lines.append("    classDef high fill:#fd7e14,color:#fff,stroke:#fff")
        lines.append("    classDef medium fill:#ffc107,color:#000,stroke:#000")
        lines.append("    classDef low fill:#28a745,color:#fff,stroke:#fff")
        lines.append("    classDef impact fill:#6f42c1,color:#fff,stroke:#fff")
        lines.append("")
        
        # Nodes
        for i, node in enumerate(chain.nodes):
            node_id = f"N{i}"
            icon = self.PHASE_ICONS.get(node.phase.value, "•")
            label = f"{icon} {node.name}<br/>{node.phase.value}<br/>CVSS: {node.cvss}"
            lines.append(f'    {node_id}["{label}"]')
        
        # Impact node
        lines.append(f'    IMPACT["💥 {chain.impact_type.value.replace("_", " ").upper()}<br/>{chain.business_impact[:50]}..."]')
        
        # Edges
        for i in range(len(chain.nodes) - 1):
            lines.append(f"    N{i} --> N{i+1}")
        
        if chain.nodes:
            lines.append(f"    N{len(chain.nodes)-1} --> IMPACT")
        
        # Apply styles
        for i, node in enumerate(chain.nodes):
            style_class = node.severity.lower()
            lines.append(f"    class N{i} {style_class}")
        
        lines.append("    class IMPACT impact")
        lines.append("```")
        
        return "\n".join(lines)
    
    def generate_html_report(self, chains: list[AttackChain], target: str = "Unknown") -> str:
        """Generate full HTML report with interactive visualizations."""
        
        # Generate chain cards HTML
        chain_cards = ""
        for i, chain in enumerate(chains):
            chain_cards += self._generate_chain_card(chain, i)
        
        # Generate summary stats
        total_chains = len(chains)
        critical_chains = len([c for c in chains if c.max_severity == "CRITICAL"])
        high_chains = len([c for c in chains if c.max_severity == "HIGH"])
        avg_priority = sum(c.remediation_priority for c in chains) / total_chains if chains else 0
        
        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Chain Analysis Report - {html.escape(target)}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        :root {{
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #28a745;
            --info: #17a2b8;
            --dark: #1a1a2e;
            --darker: #16213e;
            --accent: #0f3460;
            --text: #e8e8e8;
            --text-muted: #a0a0a0;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--dark) 0%, var(--darker) 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            text-align: center;
            padding: 40px 20px;
            background: var(--accent);
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #fff, #00d4ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        header .subtitle {{
            color: var(--text-muted);
            font-size: 1.1em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--accent);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        
        .stat-card .value {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card .label {{
            color: var(--text-muted);
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .stat-card.critical .value {{ color: var(--critical); }}
        .stat-card.high .value {{ color: var(--high); }}
        .stat-card.medium .value {{ color: var(--medium); }}
        
        .chain-card {{
            background: var(--darker);
            border-radius: 15px;
            margin-bottom: 30px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        
        .chain-header {{
            padding: 20px 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            transition: background 0.3s ease;
        }}
        
        .chain-header:hover {{
            background: var(--accent);
        }}
        
        .chain-header h2 {{
            font-size: 1.4em;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); color: #000; }}
        .severity-badge.low {{ background: var(--low); }}
        
        .priority-badge {{
            background: linear-gradient(45deg, #667eea, #764ba2);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
        }}
        
        .chain-body {{
            padding: 25px;
            display: none;
            border-top: 1px solid var(--accent);
        }}
        
        .chain-body.active {{
            display: block;
        }}
        
        .chain-flow {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 15px;
            margin-bottom: 25px;
            padding: 20px;
            background: var(--dark);
            border-radius: 10px;
        }}
        
        .chain-node {{
            background: var(--accent);
            padding: 15px 20px;
            border-radius: 10px;
            min-width: 200px;
            position: relative;
            border-left: 4px solid;
        }}
        
        .chain-node.critical {{ border-color: var(--critical); }}
        .chain-node.high {{ border-color: var(--high); }}
        .chain-node.medium {{ border-color: var(--medium); }}
        .chain-node.low {{ border-color: var(--low); }}
        
        .chain-node .phase {{
            font-size: 0.75em;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}
        
        .chain-node .name {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .chain-node .meta {{
            font-size: 0.85em;
            color: var(--text-muted);
        }}
        
        .chain-arrow {{
            font-size: 1.5em;
            color: var(--text-muted);
        }}
        
        .impact-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }}
        
        .impact-box h3 {{
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .impact-box .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .impact-box .metric {{
            background: rgba(255,255,255,0.1);
            padding: 10px 15px;
            border-radius: 8px;
        }}
        
        .impact-box .metric .label {{
            font-size: 0.8em;
            opacity: 0.8;
        }}
        
        .impact-box .metric .value {{
            font-size: 1.2em;
            font-weight: bold;
        }}
        
        .mermaid-container {{
            background: #fff;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }}
        
        .executive-summary {{
            background: var(--accent);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        
        .executive-summary h2 {{
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .executive-summary p {{
            line-height: 1.8;
            margin-bottom: 15px;
        }}
        
        footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            margin-top: 40px;
        }}
        
        @media (max-width: 768px) {{
            .chain-flow {{
                flex-direction: column;
            }}
            
            .chain-arrow {{
                transform: rotate(90deg);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔗 Attack Chain Analysis</h1>
            <p class="subtitle">Target: {html.escape(target)} | Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{total_chains}</div>
                <div class="label">Attack Chains</div>
            </div>
            <div class="stat-card critical">
                <div class="value">{critical_chains}</div>
                <div class="label">Critical Chains</div>
            </div>
            <div class="stat-card high">
                <div class="value">{high_chains}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="stat-card medium">
                <div class="value">{avg_priority:.1f}</div>
                <div class="label">Avg Priority</div>
            </div>
        </div>
        
        <div class="executive-summary">
            <h2>📋 Executive Summary</h2>
            <p>
                Esta análise identificou <strong>{total_chains} cadeias de ataque</strong> que demonstram como 
                vulnerabilidades individuais podem ser encadeadas para causar impacto real no negócio.
            </p>
            <p>
                <strong>{critical_chains} cadeias críticas</strong> requerem atenção imediata, pois representam 
                caminhos de ataque que podem ser explorados em menos de 4 horas por um atacante experiente.
            </p>
            <p>
                A prioridade média de remediação é <strong>{avg_priority:.1f}/10</strong>. Recomenda-se focar 
                primeiro nas vulnerabilidades que servem como ponto de entrada (Initial Access) nas cadeias críticas.
            </p>
        </div>
        
        {chain_cards}
        
        <footer>
            <p>🔒 Attack Chain Analysis Report | AI-Enhanced Pentesting Framework</p>
            <p>Gerado automaticamente em {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
    
    <script>
        mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
        
        document.querySelectorAll('.chain-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const body = header.nextElementSibling;
                body.classList.toggle('active');
            }});
        }});
        
        // Open first chain by default
        const firstBody = document.querySelector('.chain-body');
        if (firstBody) firstBody.classList.add('active');
    </script>
</body>
</html>
"""
        return html_content
    
    def _generate_chain_card(self, chain: AttackChain, index: int) -> str:
        """Generate HTML card for a single chain."""
        
        # Generate nodes HTML
        nodes_html = ""
        for i, node in enumerate(chain.nodes):
            icon = self.PHASE_ICONS.get(node.phase.value, "•")
            nodes_html += f"""
            <div class="chain-node {node.severity.lower()}">
                <div class="phase">{icon} {node.phase.value.replace('_', ' ')}</div>
                <div class="name">{html.escape(node.name)}</div>
                <div class="meta">CVSS: {node.cvss} | {html.escape(node.cwe)}</div>
                <div class="meta">{html.escape(node.endpoint[:50])}</div>
            </div>
            """
            if i < len(chain.nodes) - 1:
                nodes_html += '<div class="chain-arrow">→</div>'
        
        # Generate mermaid diagram
        mermaid_code = self._generate_mermaid_inline(chain)
        
        return f"""
        <div class="chain-card">
            <div class="chain-header">
                <h2>🔗 Chain #{index + 1}: {html.escape(chain.name)}</h2>
                <div>
                    <span class="severity-badge {chain.max_severity.lower()}">{chain.max_severity}</span>
                    <span class="priority-badge">Priority: {chain.remediation_priority}/10</span>
                </div>
            </div>
            <div class="chain-body">
                <div class="chain-flow">
                    {nodes_html}
                </div>
                
                <div class="impact-box">
                    <h3>💥 Business Impact</h3>
                    <p>{html.escape(chain.business_impact)}</p>
                    <div class="metrics">
                        <div class="metric">
                            <div class="label">Likelihood</div>
                            <div class="value">{chain.likelihood}</div>
                        </div>
                        <div class="metric">
                            <div class="label">Exploitability</div>
                            <div class="value">{chain.exploitability}</div>
                        </div>
                        <div class="metric">
                            <div class="label">Time to Exploit</div>
                            <div class="value">{chain.estimated_time_to_exploit}</div>
                        </div>
                        <div class="metric">
                            <div class="label">Total CVSS</div>
                            <div class="value">{chain.total_cvss:.1f}</div>
                        </div>
                    </div>
                </div>
                
                <div class="mermaid-container">
                    <div class="mermaid">
{mermaid_code}
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_mermaid_inline(self, chain: AttackChain) -> str:
        """Generate inline Mermaid code (without code fences)."""
        lines = ["flowchart LR"]
        
        for i, node in enumerate(chain.nodes):
            icon = self.PHASE_ICONS.get(node.phase.value, "•")
            short_name = node.name[:30] + "..." if len(node.name) > 30 else node.name
            lines.append(f'    N{i}["{icon} {short_name}"]')
        
        lines.append(f'    IMPACT["💥 {chain.impact_type.value.upper()}"]')
        
        for i in range(len(chain.nodes) - 1):
            lines.append(f"    N{i} --> N{i+1}")
        
        if chain.nodes:
            lines.append(f"    N{len(chain.nodes)-1} --> IMPACT")
        
        # Styles
        for i, node in enumerate(chain.nodes):
            color = self.SEVERITY_COLORS.get(node.severity.upper(), "#6c757d")
            lines.append(f"    style N{i} fill:{color},color:#fff")
        
        lines.append("    style IMPACT fill:#6f42c1,color:#fff")
        
        return "\n".join(lines)
    
    def generate_json(self, chains: list[AttackChain]) -> str:
        """Generate JSON representation of all chains."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "total_chains": len(chains),
            "chains": [c.to_dict() for c in chains],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)
    
    def print_ascii_report(self, chains: list[AttackChain]) -> None:
        """Print ASCII report to console."""
        print("\n" + "=" * 70)
        print("           🔗 ATTACK CHAIN ANALYSIS REPORT")
        print("=" * 70)
        print(f"\n  Total Chains Detected: {len(chains)}")
        print(f"  Critical Chains: {len([c for c in chains if c.max_severity == 'CRITICAL'])}")
        print(f"  High Priority: {len([c for c in chains if c.remediation_priority >= 7])}")
        print("\n" + "-" * 70)
        
        for i, chain in enumerate(chains, 1):
            print(f"\n[Chain {i}/{len(chains)}]")
            print(self.generate_ascii(chain))
            print("\n" + "-" * 70)
