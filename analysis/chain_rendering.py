"""
Attack Chain Rendering - Visual representation of attack chains.

Consolidates all chain visualization into a single module:
- ASCII art for terminal output
- Mermaid diagrams for documentation
- HTML interactive reports
- HTML interactive dashboards (Chart.js + vis-network)
- JSON for custom rendering
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analysis.attack_chain_engine import AttackChain

from utils.logger import get_logger

logger = get_logger(__name__)


# Shared constants

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
    "INFO": "#17a2b8",
}

PHASE_ICONS = {
    "reconnaissance": "\U0001f50d",
    "initial_access": "\U0001f6aa",
    "execution": "\u26a1",
    "persistence": "\U0001f512",
    "privilege_escalation": "\U0001f4c8",
    "defense_evasion": "\U0001f6e1\ufe0f",
    "credential_access": "\U0001f511",
    "discovery": "\U0001f5fa\ufe0f",
    "lateral_movement": "\u2194\ufe0f",
    "collection": "\U0001f4e6",
    "exfiltration": "\U0001f4e4",
    "impact": "\U0001f4a5",
}


class ChainVisualizer:
    """
    Generates visual representations of attack chains.

    Formats:
    - ASCII art for terminal
    - Mermaid diagrams for documentation
    - HTML interactive reports
    - JSON for custom rendering
    """

    SEVERITY_COLORS = SEVERITY_COLORS
    PHASE_ICONS = PHASE_ICONS

    def __init__(self):
        pass

    def generate_ascii(self, chain: AttackChain) -> str:
        """Generate ASCII art representation of attack chain."""
        lines = []

        lines.append("=" * 70)
        lines.append(f"\U0001f517 ATTACK CHAIN: {chain.name}")
        lines.append(f"   Priority: {chain.remediation_priority}/10 | Severity: {chain.max_severity}")
        lines.append(f"   Impact: {chain.impact_type.value.replace('_', ' ').title()}")
        lines.append("=" * 70)
        lines.append("")

        for i, node in enumerate(chain.nodes):
            icon = self.PHASE_ICONS.get(node.phase.value, "\u2022")

            lines.append(f"    \u250c{'\u2500' * 60}\u2510")
            lines.append(f"    \u2502 {icon} {node.name[:55]:<55} \u2502")
            lines.append(f"    \u2502   Phase: {node.phase.value:<45} \u2502")
            lines.append(f"    \u2502   Severity: {node.severity:<10} CVSS: {node.cvss:<6} \u2502")
            lines.append(f"    \u2502   Endpoint: {node.endpoint[:43]:<43} \u2502")
            technique = f"  ATT&CK: {node.technique_id}" if node.technique_id else ""
            lines.append(f"    \u2502   {node.cwe:<15} {node.owasp:<30} \u2502")
            if technique:
                lines.append(f"    \u2502   {technique:<57} \u2502")
            lines.append(f"    \u2514{'\u2500' * 60}\u2518")

            if i < len(chain.nodes) - 1:
                lines.append("                          \u2502")
                lines.append("                          \u25bc")
                lines.append("")

        lines.append("")
        lines.append("    \u2554" + "\u2550" * 60 + "\u2557")
        lines.append(f"    \u2551 \U0001f4a5 BUSINESS IMPACT{' ' * 42}\u2551")
        lines.append("    \u2560" + "\u2550" * 60 + "\u2563")

        impact = chain.business_impact
        while len(impact) > 56:
            lines.append(f"    \u2551 {impact[:56]:<58} \u2551")
            impact = impact[56:]
        lines.append(f"    \u2551 {impact:<58} \u2551")

        lines.append("    \u2551" + " " * 60 + "\u2551")
        lines.append(f"    \u2551 \u23f1\ufe0f  Time to Exploit: {chain.estimated_time_to_exploit:<35} \u2551")
        lines.append(f"    \u2551 \U0001f4ca Likelihood: {chain.likelihood:<42} \u2551")
        lines.append(f"    \u2551 \U0001f527 Exploitability: {chain.exploitability:<38} \u2551")
        if chain.unique_endpoints:
            lines.append(f"    \u2551 \U0001f310 Endpoints Hit: {chain.unique_endpoints:<39} \u2551")
        if chain.phase_depth:
            lines.append(f"    \u2551 \U0001f4c9 Phase Depth: {chain.phase_depth:<41} \u2551")
        lines.append("    \u255a" + "\u2550" * 60 + "\u255d")

        return "\n".join(lines)

    def generate_mermaid(self, chain_or_chains: AttackChain | list[AttackChain]) -> str:
        """Generate Mermaid flowchart diagram(s).

        Accepts a single AttackChain or a list. When given a list, each chain
        is rendered as a separate Mermaid diagram separated by blank lines.
        """
        if isinstance(chain_or_chains, list):
            return "\n\n".join(self._mermaid_single(c) for c in chain_or_chains)
        return self._mermaid_single(chain_or_chains)

    def _mermaid_single(self, chain: AttackChain) -> str:
        """Generate a single Mermaid flowchart diagram."""
        lines = ["```mermaid", "flowchart TD"]

        lines.append("    classDef critical fill:#dc3545,color:#fff,stroke:#fff")
        lines.append("    classDef high fill:#fd7e14,color:#fff,stroke:#fff")
        lines.append("    classDef medium fill:#ffc107,color:#000,stroke:#000")
        lines.append("    classDef low fill:#28a745,color:#fff,stroke:#fff")
        lines.append("    classDef impact fill:#6f42c1,color:#fff,stroke:#fff")
        lines.append("")

        for i, node in enumerate(chain.nodes):
            node_id = f"N{i}"
            icon = self.PHASE_ICONS.get(node.phase.value, "\u2022")
            label = f"{icon} {node.name}<br/>{node.phase.value}<br/>CVSS: {node.cvss}"
            lines.append(f'    {node_id}["{label}"]')

        lines.append(f'    IMPACT["\U0001f4a5 {chain.impact_type.value.replace("_", " ").upper()}<br/>{chain.business_impact[:50]}..."]')

        for i in range(len(chain.nodes) - 1):
            lines.append(f"    N{i} --> N{i+1}")

        if chain.nodes:
            lines.append(f"    N{len(chain.nodes)-1} --> IMPACT")

        for i, node in enumerate(chain.nodes):
            style_class = node.severity.lower()
            lines.append(f"    class N{i} {style_class}")

        lines.append("    class IMPACT impact")
        lines.append("```")

        return "\n".join(lines)

    def generate_html_report(self, chains: list[AttackChain], target: str = "Unknown") -> str:
        """Generate full HTML report with interactive visualizations."""

        chain_cards = ""
        for i, chain in enumerate(chains):
            chain_cards += self._generate_chain_card(chain, i)

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
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--dark) 0%, var(--darker) 100%);
            color: var(--text);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            text-align: center; padding: 40px 20px; background: var(--accent);
            border-radius: 15px; margin-bottom: 30px; box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        header h1 {{
            font-size: 2.5em; margin-bottom: 10px;
            background: linear-gradient(45deg, #fff, #00d4ff);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }}
        header .subtitle {{ color: var(--text-muted); font-size: 1.1em; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{
            background: var(--accent); padding: 25px; border-radius: 12px; text-align: center;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2); transition: transform 0.3s ease;
        }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-card .value {{ font-size: 3em; font-weight: bold; margin-bottom: 5px; }}
        .stat-card .label {{ color: var(--text-muted); font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }}
        .stat-card.critical .value {{ color: var(--critical); }}
        .stat-card.high .value {{ color: var(--high); }}
        .stat-card.medium .value {{ color: var(--medium); }}
        .chain-card {{
            background: var(--darker); border-radius: 15px; margin-bottom: 30px;
            overflow: hidden; box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }}
        .chain-header {{
            padding: 20px 25px; display: flex; justify-content: space-between;
            align-items: center; cursor: pointer; transition: background 0.3s ease;
        }}
        .chain-header:hover {{ background: var(--accent); }}
        .chain-header h2 {{ font-size: 1.4em; display: flex; align-items: center; gap: 10px; }}
        .severity-badge {{ padding: 5px 15px; border-radius: 20px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }}
        .severity-badge.critical {{ background: var(--critical); }}
        .severity-badge.high {{ background: var(--high); }}
        .severity-badge.medium {{ background: var(--medium); color: #000; }}
        .severity-badge.low {{ background: var(--low); }}
        .priority-badge {{ background: linear-gradient(45deg, #667eea, #764ba2); padding: 5px 12px; border-radius: 20px; font-size: 0.8em; }}
        .chain-body {{ padding: 25px; display: none; border-top: 1px solid var(--accent); }}
        .chain-body.active {{ display: block; }}
        .chain-flow {{
            display: flex; flex-wrap: wrap; align-items: center; gap: 15px;
            margin-bottom: 25px; padding: 20px; background: var(--dark); border-radius: 10px;
        }}
        .chain-node {{
            background: var(--accent); padding: 15px 20px; border-radius: 10px;
            min-width: 200px; position: relative; border-left: 4px solid;
        }}
        .chain-node.critical {{ border-color: var(--critical); }}
        .chain-node.high {{ border-color: var(--high); }}
        .chain-node.medium {{ border-color: var(--medium); }}
        .chain-node.low {{ border-color: var(--low); }}
        .chain-node .phase {{ font-size: 0.75em; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }}
        .chain-node .name {{ font-weight: bold; margin-bottom: 5px; }}
        .chain-node .meta {{ font-size: 0.85em; color: var(--text-muted); }}
        .chain-arrow {{ font-size: 1.5em; color: var(--text-muted); }}
        .impact-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px; border-radius: 10px; margin-top: 20px;
        }}
        .impact-box h3 {{ margin-bottom: 10px; display: flex; align-items: center; gap: 10px; }}
        .impact-box .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-top: 15px; }}
        .impact-box .metric {{ background: rgba(255,255,255,0.1); padding: 10px 15px; border-radius: 8px; }}
        .impact-box .metric .label {{ font-size: 0.8em; opacity: 0.8; }}
        .impact-box .metric .value {{ font-size: 1.2em; font-weight: bold; }}
        .mermaid-container {{ background: #fff; padding: 20px; border-radius: 10px; margin-top: 20px; }}
        .executive-summary {{ background: var(--accent); padding: 30px; border-radius: 15px; margin-bottom: 30px; }}
        .executive-summary h2 {{ margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}
        .executive-summary p {{ line-height: 1.8; margin-bottom: 15px; }}
        footer {{ text-align: center; padding: 30px; color: var(--text-muted); margin-top: 40px; }}
        @media (max-width: 768px) {{
            .chain-flow {{ flex-direction: column; }}
            .chain-arrow {{ transform: rotate(90deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>\U0001f517 Attack Chain Analysis</h1>
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
            <h2>\U0001f4cb Executive Summary</h2>
            <p>
                Esta an\u00e1lise identificou <strong>{total_chains} cadeias de ataque</strong> que demonstram como
                vulnerabilidades individuais podem ser encadeadas para causar impacto real no neg\u00f3cio.
            </p>
            <p>
                <strong>{critical_chains} cadeias cr\u00edticas</strong> requerem aten\u00e7\u00e3o imediata, pois representam
                caminhos de ataque que podem ser explorados em menos de 4 horas por um atacante experiente.
            </p>
            <p>
                A prioridade m\u00e9dia de remedia\u00e7\u00e3o \u00e9 <strong>{avg_priority:.1f}/10</strong>. Recomenda-se focar
                primeiro nas vulnerabilidades que servem como ponto de entrada (Initial Access) nas cadeias cr\u00edticas.
            </p>
        </div>
        {chain_cards}
        <footer>
            <p>\U0001f512 Attack Chain Analysis Report | AI-Enhanced Pentesting Framework</p>
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
        const firstBody = document.querySelector('.chain-body');
        if (firstBody) firstBody.classList.add('active');
    </script>
</body>
</html>
"""
        return html_content

    def _generate_chain_card(self, chain: AttackChain, index: int) -> str:
        """Generate HTML card for a single chain."""

        nodes_html = ""
        for i, node in enumerate(chain.nodes):
            icon = self.PHASE_ICONS.get(node.phase.value, "\u2022")
            technique = f" | {html.escape(node.technique_id)}" if node.technique_id else ""
            nodes_html += f"""
            <div class="chain-node {node.severity.lower()}">
                <div class="phase">{icon} {node.phase.value.replace('_', ' ')}</div>
                <div class="name">{html.escape(node.name)}</div>
                <div class="meta">CVSS: {node.cvss} | {html.escape(node.cwe)}{technique}</div>
                <div class="meta">{html.escape(node.endpoint[:50])}</div>
            </div>
            """
            if i < len(chain.nodes) - 1:
                nodes_html += '<div class="chain-arrow">\u2192</div>'

        mermaid_code = self._generate_mermaid_inline(chain)

        return f"""
        <div class="chain-card">
            <div class="chain-header">
                <h2>\U0001f517 Chain #{index + 1}: {html.escape(chain.name)}</h2>
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
                    <h3>\U0001f4a5 Business Impact</h3>
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
                        <div class="metric">
                            <div class="label">Endpoints Hit</div>
                            <div class="value">{chain.unique_endpoints}</div>
                        </div>
                        <div class="metric">
                            <div class="label">Phase Depth</div>
                            <div class="value">{chain.phase_depth}</div>
                        </div>
                    </div>
                </div>
                <div style="background: var(--accent); padding: 15px 20px; border-radius: 10px; margin-top: 15px; border-left: 4px solid #28a745;">
                    <h3 style="margin-bottom: 8px; display: flex; align-items: center; gap: 8px;">\U0001f6e1\ufe0f Remediation</h3>
                    <p style="line-height: 1.6;">{html.escape(self._remediation_for_chain(chain))}</p>
                </div>
                <div class="mermaid-container">
                    <div class="mermaid">
{mermaid_code}
                    </div>
                </div>
            </div>
        </div>
        """

    _REMEDIATION_BY_IMPACT = {
        "data_breach": "Encrypt data at rest/transit, enforce least-privilege access, add DLP controls.",
        "account_takeover": "Enforce MFA, validate password-reset flows, harden session management.",
        "service_disruption": "Rate-limit all endpoints, add circuit breakers, deploy DDoS mitigation.",
        "financial_loss": "Add transaction signing, enforce approval workflows, audit financial APIs.",
        "compliance_violation": "Map controls to regulatory requirements, fix data-exposure paths, add audit logging.",
        "reputation_damage": "Fix public-facing vulnerabilities first, monitor brand mentions, prepare incident comms.",
        "ransomware": "Patch injection vectors (SQLi, SSTI, command injection), segment networks, harden backups.",
        "supply_chain": "Audit third-party dependencies, enforce SRI, pin package versions, restrict CDN origins.",
    }

    def _remediation_for_chain(self, chain: AttackChain) -> str:
        impact_key = chain.impact_type.value
        return self._REMEDIATION_BY_IMPACT.get(
            impact_key, "Review all findings in this chain and apply defense-in-depth."
        )

    def _generate_mermaid_inline(self, chain: AttackChain) -> str:
        """Generate inline Mermaid code (without code fences)."""
        lines = ["flowchart LR"]

        for i, node in enumerate(chain.nodes):
            icon = self.PHASE_ICONS.get(node.phase.value, "\u2022")
            short_name = node.name[:30] + "..." if len(node.name) > 30 else node.name
            lines.append(f'    N{i}["{icon} {short_name}"]')

        lines.append(f'    IMPACT["\U0001f4a5 {chain.impact_type.value.upper()}"]')

        for i in range(len(chain.nodes) - 1):
            lines.append(f"    N{i} --> N{i+1}")

        if chain.nodes:
            lines.append(f"    N{len(chain.nodes)-1} --> IMPACT")

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
        print("           \U0001f517 ATTACK CHAIN ANALYSIS REPORT")
        print("=" * 70)
        print(f"\n  Total Chains Detected: {len(chains)}")
        print(f"  Critical Chains: {len([c for c in chains if c.max_severity == 'CRITICAL'])}")
        print(f"  High Priority: {len([c for c in chains if c.remediation_priority >= 7])}")
        print("\n" + "-" * 70)

        for i, chain in enumerate(chains, 1):
            print(f"\n[Chain {i}/{len(chains)}]")
            print(self.generate_ascii(chain))
            print("\n" + "-" * 70)


class AttackChainDashboard:
    """
    Interactive web dashboard for attack chain visualization.

    Features:
    - Interactive chain exploration with Chart.js + vis-network
    - Drill-down into individual vulnerabilities
    - Export functionality
    - Executive summary view
    """

    def __init__(self, title: str = "Attack Chain Dashboard"):
        self.title = title
        self.chains: list[AttackChain] = []
        self.findings: list[dict[str, Any]] = []

    def set_data(
        self,
        chains: list[AttackChain],
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """Set the data for the dashboard."""
        self.chains = chains
        self.findings = findings or []

    async def generate(
        self,
        findings: list[dict[str, Any]] | None = None,
        chains: list[AttackChain] | None = None,
        threat_model: dict | None = None,
        output_dir: str = ".",
    ) -> str:
        """Orchestrator-compatible entry point.

        Called by ``core/orchestrator.py`` as
        ``await dashboard.generate(findings=..., chains=..., output_dir=...)``.
        Writes the HTML dashboard to ``output_dir`` and returns the file path.
        """
        import os

        if chains is not None:
            self.set_data(chains, findings)

        target = "Unknown"
        if threat_model and isinstance(threat_model, dict):
            target = threat_model.get("target", target)

        html = self.generate_dashboard(target)
        out_dir = output_dir or "."
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, "attack_chain_dashboard.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def generate_dashboard(self, target: str = "Unknown") -> str:
        """Generate the complete HTML dashboard."""

        chains_data = json.dumps([c.to_dict() for c in self.chains], ensure_ascii=False)
        stats = self._calculate_stats()

        return f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.title)} - {html.escape(target)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0d1117; --bg-secondary: #161b22; --bg-tertiary: #21262d;
            --border: #30363d; --text-primary: #c9d1d9; --text-secondary: #8b949e;
            --accent-blue: #58a6ff; --accent-green: #3fb950; --accent-yellow: #d29922;
            --accent-red: #f85149; --accent-purple: #a371f7;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary); color: var(--text-primary); min-height: 100vh;
        }}
        .dashboard {{ display: grid; grid-template-columns: 280px 1fr; min-height: 100vh; }}
        .sidebar {{
            background: var(--bg-secondary); border-right: 1px solid var(--border);
            padding: 20px; overflow-y: auto;
        }}
        .logo {{
            display: flex; align-items: center; gap: 10px;
            padding-bottom: 20px; border-bottom: 1px solid var(--border); margin-bottom: 20px;
        }}
        .logo h1 {{
            font-size: 1.2em;
            background: linear-gradient(45deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
        }}
        .nav-item {{
            display: flex; align-items: center; gap: 10px; padding: 12px 15px;
            border-radius: 6px; cursor: pointer; transition: background 0.2s; margin-bottom: 5px;
        }}
        .nav-item:hover, .nav-item.active {{ background: var(--bg-tertiary); }}
        .nav-item.active {{ border-left: 3px solid var(--accent-blue); }}
        .main-content {{ padding: 20px; overflow-y: auto; }}
        .header {{
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 25px; padding-bottom: 20px; border-bottom: 1px solid var(--border);
        }}
        .header h2 {{ font-size: 1.5em; }}
        .header-actions {{ display: flex; gap: 10px; }}
        .btn {{
            padding: 8px 16px; border: 1px solid var(--border); border-radius: 6px;
            background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer;
            transition: all 0.2s; font-size: 0.9em;
        }}
        .btn:hover {{ background: var(--bg-secondary); border-color: var(--accent-blue); }}
        .btn-primary {{ background: var(--accent-blue); border-color: var(--accent-blue); }}
        .btn-primary:hover {{ filter: brightness(1.1); }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .stat-box {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
        .stat-box .value {{ font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }}
        .stat-box .label {{ color: var(--text-secondary); font-size: 0.9em; }}
        .stat-box.critical .value {{ color: var(--accent-red); }}
        .stat-box.high .value {{ color: var(--accent-yellow); }}
        .stat-box.medium .value {{ color: var(--accent-blue); }}
        .stat-box.success .value {{ color: var(--accent-green); }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 25px; }}
        .chart-box {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
        .chart-box h3 {{ margin-bottom: 15px; font-size: 1em; color: var(--text-secondary); }}
        #network-graph {{
            height: 500px; background: var(--bg-secondary); border: 1px solid var(--border);
            border-radius: 8px; margin-bottom: 25px;
        }}
        .chain-list {{ background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
        .chain-item {{ padding: 20px; border-bottom: 1px solid var(--border); cursor: pointer; transition: background 0.2s; }}
        .chain-item:hover {{ background: var(--bg-tertiary); }}
        .chain-item:last-child {{ border-bottom: none; }}
        .chain-header-dash {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .chain-header-dash h4 {{ display: flex; align-items: center; gap: 8px; }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 0.75em; font-weight: bold; }}
        .badge.critical {{ background: var(--accent-red); color: #fff; }}
        .badge.high {{ background: var(--accent-yellow); color: #000; }}
        .badge.medium {{ background: var(--accent-blue); color: #fff; }}
        .badge.low {{ background: var(--accent-green); color: #fff; }}
        .chain-flow-dash {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 10px; }}
        .chain-node-dash {{
            background: var(--bg-tertiary); padding: 6px 12px; border-radius: 6px;
            font-size: 0.85em; border-left: 3px solid;
        }}
        .chain-node-dash.critical {{ border-color: var(--accent-red); }}
        .chain-node-dash.high {{ border-color: var(--accent-yellow); }}
        .chain-node-dash.medium {{ border-color: var(--accent-blue); }}
        .chain-node-dash.low {{ border-color: var(--accent-green); }}
        .chain-arrow-dash {{ color: var(--text-secondary); }}
        .chain-impact {{ color: var(--text-secondary); font-size: 0.9em; }}
        .modal {{
            display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.8); z-index: 1000; justify-content: center; align-items: center;
        }}
        .modal.active {{ display: flex; }}
        .modal-content {{
            background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 12px;
            width: 90%; max-width: 900px; max-height: 90vh; overflow-y: auto; padding: 30px;
        }}
        .modal-header {{
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid var(--border);
        }}
        .close-btn {{ background: none; border: none; color: var(--text-primary); font-size: 1.5em; cursor: pointer; }}
        .view {{ display: none; }}
        .view.active {{ display: block; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <aside class="sidebar">
            <div class="logo">
                <span style="font-size: 2em;">\U0001f517</span>
                <h1>Attack Chain<br>Dashboard</h1>
            </div>
            <nav>
                <div class="nav-item active" data-view="overview"><span>\U0001f4ca</span><span>Overview</span></div>
                <div class="nav-item" data-view="chains"><span>\u26d3\ufe0f</span><span>Attack Chains</span></div>
                <div class="nav-item" data-view="graph"><span>\U0001f578\ufe0f</span><span>Network Graph</span></div>
                <div class="nav-item" data-view="executive"><span>\U0001f4cb</span><span>Executive Summary</span></div>
            </nav>
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid var(--border);">
                <p style="color: var(--text-secondary); font-size: 0.85em; margin-bottom: 10px;">Target</p>
                <p style="font-weight: bold;">{html.escape(target)}</p>
                <p style="color: var(--text-secondary); font-size: 0.85em; margin-top: 15px;">Generated</p>
                <p>{datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
            </div>
        </aside>
        <main class="main-content">
            <div class="view active" id="view-overview">
                <div class="header">
                    <h2>\U0001f4ca Security Overview</h2>
                    <div class="header-actions">
                        <button class="btn" onclick="exportReport('pdf')">\U0001f4c4 Export PDF</button>
                        <button class="btn" onclick="exportReport('json')">\U0001f4e6 Export JSON</button>
                    </div>
                </div>
                <div class="stats-grid">
                    <div class="stat-box critical"><div class="value">{stats['total_chains']}</div><div class="label">Attack Chains</div></div>
                    <div class="stat-box high"><div class="value">{stats['critical_chains']}</div><div class="label">Critical Chains</div></div>
                    <div class="stat-box medium"><div class="value">{stats['total_nodes']}</div><div class="label">Total Vulnerabilities</div></div>
                    <div class="stat-box success"><div class="value">{stats['avg_priority']:.1f}</div><div class="label">Avg Priority Score</div></div>
                </div>
                <div class="charts-grid">
                    <div class="chart-box"><h3>Chains by Severity</h3><canvas id="severityChart"></canvas></div>
                    <div class="chart-box"><h3>Impact Types Distribution</h3><canvas id="impactChart"></canvas></div>
                </div>
                <div class="chart-box"><h3>Attack Phases Coverage</h3><canvas id="phasesChart" height="100"></canvas></div>
            </div>
            <div class="view" id="view-chains">
                <div class="header">
                    <h2>\u26d3\ufe0f Attack Chains</h2>
                    <div class="header-actions">
                        <input type="text" class="btn" placeholder="\U0001f50d Search..." id="chainSearch" style="min-width: 200px;">
                    </div>
                </div>
                <div class="chain-list" id="chainList"></div>
            </div>
            <div class="view" id="view-graph">
                <div class="header">
                    <h2>\U0001f578\ufe0f Network Graph</h2>
                    <div class="header-actions"><button class="btn" onclick="resetGraph()">\U0001f504 Reset View</button></div>
                </div>
                <div id="network-graph"></div>
            </div>
            <div class="view" id="view-executive">
                <div class="header">
                    <h2>\U0001f4cb Executive Summary</h2>
                    <div class="header-actions"><button class="btn btn-primary" onclick="printSummary()">\U0001f5a8\ufe0f Print</button></div>
                </div>
                <div id="executiveSummary"></div>
            </div>
        </main>
    </div>
    <div class="modal" id="chainModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Chain Details</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalContent"></div>
        </div>
    </div>
    <script>
        const chainsData = {chains_data};
        let network = null;
        document.querySelectorAll('.nav-item').forEach(item => {{
            item.addEventListener('click', () => {{
                document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
                item.classList.add('active');
                document.getElementById('view-' + item.dataset.view).classList.add('active');
                if (item.dataset.view === 'graph') initNetworkGraph();
            }});
        }});
        function initCharts() {{
            const severityCounts = chainsData.reduce((acc, c) => {{ acc[c.max_severity] = (acc[c.max_severity] || 0) + 1; return acc; }}, {{}});
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{ labels: Object.keys(severityCounts), datasets: [{{ data: Object.values(severityCounts), backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'] }}] }},
                options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9' }} }} }} }}
            }});
            const impactCounts = chainsData.reduce((acc, c) => {{ const i = c.impact_type || 'unknown'; acc[i] = (acc[i] || 0) + 1; return acc; }}, {{}});
            new Chart(document.getElementById('impactChart'), {{
                type: 'pie',
                data: {{ labels: Object.keys(impactCounts).map(i => i.replace(/_/g, ' ')), datasets: [{{ data: Object.values(impactCounts), backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950', '#a371f7', '#f0883e'] }}] }},
                options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#c9d1d9' }} }} }} }}
            }});
            const phaseCounts = {{}};
            chainsData.forEach(c => {{ c.nodes.forEach(n => {{ phaseCounts[n.phase || 'unknown'] = (phaseCounts[n.phase || 'unknown'] || 0) + 1; }}); }});
            new Chart(document.getElementById('phasesChart'), {{
                type: 'bar',
                data: {{ labels: Object.keys(phaseCounts).map(p => p.replace(/_/g, ' ')), datasets: [{{ label: 'Occurrences', data: Object.values(phaseCounts), backgroundColor: '#58a6ff' }}] }},
                options: {{ responsive: true, scales: {{ y: {{ grid: {{ color: '#30363d' }}, ticks: {{ color: '#c9d1d9' }} }}, x: {{ grid: {{ color: '#30363d' }}, ticks: {{ color: '#c9d1d9' }} }} }}, plugins: {{ legend: {{ display: false }} }} }}
            }});
        }}
        function populateChainList() {{
            document.getElementById('chainList').innerHTML = chainsData.map((chain, i) => `
                <div class="chain-item" onclick="showChainDetail(${{i}})">
                    <div class="chain-header-dash">
                        <h4><span>\U0001f517</span><span>${{chain.name || 'Chain ' + (i + 1)}}</span></h4>
                        <div><span class="badge ${{chain.max_severity?.toLowerCase()}}">${{chain.max_severity}}</span></div>
                    </div>
                    <div class="chain-flow-dash">
                        ${{chain.nodes.map((n, j) => `<span class="chain-node-dash ${{n.severity?.toLowerCase()}}">${{n.name}}</span>${{j < chain.nodes.length - 1 ? '<span class="chain-arrow-dash">\u2192</span>' : ''}}`).join('')}}
                    </div>
                    <div class="chain-impact">\U0001f4a5 ${{chain.business_impact?.substring(0, 100)}}...</div>
                </div>
            `).join('');
        }}
        function initNetworkGraph() {{
            const container = document.getElementById('network-graph');
            const nodes = [], edges = [];
            chainsData.forEach((chain, ci) => {{
                chain.nodes.forEach((node, ni) => {{
                    const id = `${{ci}}-${{ni}}`;
                    nodes.push({{ id, label: node.name, color: getColorForSeverity(node.severity), title: `${{node.name}}\\nCVSS: ${{node.cvss}}\\n${{node.phase}}` }});
                    if (ni > 0) edges.push({{ from: `${{ci}}-${{ni - 1}}`, to: id, arrows: 'to', color: {{ color: '#58a6ff' }} }});
                }});
            }});
            network = new vis.Network(container, {{ nodes, edges }}, {{
                physics: {{ stabilization: true, barnesHut: {{ gravitationalConstant: -2000, springLength: 150 }} }},
                nodes: {{ shape: 'box', font: {{ color: '#fff' }}, borderWidth: 2 }},
                edges: {{ smooth: {{ type: 'continuous' }} }}
            }});
        }}
        function getColorForSeverity(s) {{
            return {{'CRITICAL': '#f85149', 'HIGH': '#d29922', 'MEDIUM': '#58a6ff', 'LOW': '#3fb950'}}[s?.toUpperCase()] || '#6e7681';
        }}
        function showChainDetail(index) {{
            const chain = chainsData[index];
            document.getElementById('modalTitle').textContent = chain.name || 'Chain ' + (index + 1);
            document.getElementById('modalContent').innerHTML = `
                <div style="margin-bottom: 20px;">
                    <span class="badge ${{chain.max_severity?.toLowerCase()}}">${{chain.max_severity}}</span>
                    <span style="margin-left: 10px; color: var(--text-secondary);">Priority: ${{chain.remediation_priority}}/10</span>
                </div>
                <h4 style="margin-bottom: 15px;">Attack Flow</h4>
                <div class="chain-flow-dash" style="margin-bottom: 20px; padding: 15px; background: var(--bg-tertiary); border-radius: 8px;">
                    ${{chain.nodes.map((n, j) => `<span class="chain-node-dash ${{n.severity?.toLowerCase()}}">${{n.name}}</span>${{j < chain.nodes.length - 1 ? '<span class="chain-arrow-dash">\u2192</span>' : ''}}`).join('')}}
                </div>
                <h4 style="margin-bottom: 15px;">Vulnerabilities</h4>
                ${{chain.nodes.map(n => `
                    <div style="padding: 15px; background: var(--bg-tertiary); border-radius: 8px; margin-bottom: 10px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <strong>${{n.name}}</strong>
                            <span class="badge ${{n.severity?.toLowerCase()}}">${{n.severity}} - CVSS ${{n.cvss}}</span>
                        </div>
                        <p style="color: var(--text-secondary); font-size: 0.9em; margin-bottom: 8px;">${{n.description || 'No description'}}</p>
                        ${{(n.evidence && n.evidence.length) ? '<div style="margin: 8px 0; padding: 8px 12px; background: var(--bg-primary); border-radius: 4px; border-left: 3px solid var(--accent-blue); font-family: monospace; font-size: 0.82em; white-space: pre-wrap; overflow-x: auto;">' + n.evidence.map(e => e.replace(/</g, '&lt;')).join('\\n') + '</div>' : ''}}
                        <div style="font-size: 0.85em; color: var(--text-secondary);">
                            <span>\U0001f4cd ${{n.endpoint}}</span><br>
                            <span>\U0001f3f7\ufe0f ${{n.cwe}} | ${{n.owasp}}${{n.technique_id ? ' | ' + n.technique_id : ''}}</span>
                        </div>
                    </div>
                `).join('')}}
                <h4 style="margin: 20px 0 15px;">Business Impact</h4>
                <div style="padding: 20px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 8px;">
                    <p>${{chain.business_impact}}</p>
                    <div style="margin-top: 15px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                        <div><span style="opacity: 0.8; font-size: 0.85em;">Likelihood</span><br><strong>${{chain.likelihood}}</strong></div>
                        <div><span style="opacity: 0.8; font-size: 0.85em;">Exploitability</span><br><strong>${{chain.exploitability}}</strong></div>
                        <div><span style="opacity: 0.8; font-size: 0.85em;">Time to Exploit</span><br><strong>${{chain.estimated_time_to_exploit}}</strong></div>
                        <div><span style="opacity: 0.8; font-size: 0.85em;">Endpoints Hit</span><br><strong>${{chain.unique_endpoints || '-'}}</strong></div>
                        <div><span style="opacity: 0.8; font-size: 0.85em;">Phase Depth</span><br><strong>${{chain.phase_depth || '-'}}</strong></div>
                        <div><span style="opacity: 0.8; font-size: 0.85em;">Total CVSS</span><br><strong>${{chain.total_cvss?.toFixed(1) || '-'}}</strong></div>
                    </div>
                </div>
            `;
            document.getElementById('chainModal').classList.add('active');
        }}
        function closeModal() {{ document.getElementById('chainModal').classList.remove('active'); }}
        function generateExecutiveSummary() {{
            const critical = chainsData.filter(c => c.max_severity === 'CRITICAL').length;
            const high = chainsData.filter(c => c.max_severity === 'HIGH').length;
            document.getElementById('executiveSummary').innerHTML = `
                <div style="padding: 30px; background: var(--bg-secondary); border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 20px;">\U0001f3af Key Findings</h3>
                    <p style="line-height: 1.8; margin-bottom: 15px;">
                        A an\u00e1lise identificou <strong style="color: var(--accent-red);">${{chainsData.length}} cadeias de ataque</strong>
                        que demonstram como vulnerabilidades aparentemente isoladas podem ser combinadas para comprometer sistemas cr\u00edticos.
                    </p>
                    <p style="line-height: 1.8; margin-bottom: 15px;">
                        <strong style="color: var(--accent-red);">${{critical}} cadeias cr\u00edticas</strong> e
                        <strong style="color: var(--accent-yellow);">${{high}} cadeias de alta severidade</strong>
                        representam riscos que podem resultar em viola\u00e7\u00f5es de dados, perdas financeiras ou interrup\u00e7\u00e3o de servi\u00e7os.
                    </p>
                </div>
                <div style="padding: 30px; background: var(--bg-secondary); border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 20px;">\U0001f4ca Risk Distribution</h3>
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;">
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-red);">${{critical}}</div><div style="color: var(--text-secondary);">Critical</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-yellow);">${{high}}</div><div style="color: var(--text-secondary);">High</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-blue);">${{chainsData.filter(c => c.max_severity === 'MEDIUM').length}}</div><div style="color: var(--text-secondary);">Medium</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-green);">${{chainsData.filter(c => c.max_severity === 'LOW').length}}</div><div style="color: var(--text-secondary);">Low</div>
                        </div>
                    </div>
                </div>
                <div style="padding: 30px; background: var(--bg-secondary); border-radius: 8px;">
                    <h3 style="margin-bottom: 20px;">\U0001f6e1\ufe0f Recommendations</h3>
                    <ol style="line-height: 2; padding-left: 20px;">
                        <li>Priorizar remedia\u00e7\u00e3o das vulnerabilidades de <strong>Initial Access</strong></li>
                        <li>Implementar controles de segmenta\u00e7\u00e3o para dificultar <strong>Lateral Movement</strong></li>
                        <li>Refor\u00e7ar autentica\u00e7\u00e3o e autoriza\u00e7\u00e3o para prevenir <strong>Privilege Escalation</strong></li>
                        <li>Implementar monitoramento para detectar padr\u00f5es de ataque identificados</li>
                        <li>Realizar exerc\u00edcios de red team focados nos cen\u00e1rios de alto impacto</li>
                    </ol>
                </div>
            `;
        }}
        function exportReport(format) {{
            if (format === 'json') {{
                const blob = new Blob([JSON.stringify(chainsData, null, 2)], {{type: 'application/json'}});
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'attack-chains.json';
                a.click();
            }} else if (format === 'pdf') {{
                window.print();
            }}
        }}
        function printSummary() {{ window.print(); }}
        function resetGraph() {{ if (network) network.fit(); }}
        function filterChains() {{
            const query = document.getElementById('chainSearch').value.toLowerCase();
            document.querySelectorAll('.chain-item').forEach(item => {{
                const text = item.textContent.toLowerCase();
                item.style.display = text.includes(query) ? '' : 'none';
            }});
        }}
        document.addEventListener('DOMContentLoaded', () => {{
            initCharts(); populateChainList(); generateExecutiveSummary();
            document.getElementById('chainSearch').addEventListener('input', filterChains);
        }});
        document.getElementById('chainModal').addEventListener('click', (e) => {{ if (e.target.id === 'chainModal') closeModal(); }});
    </script>
</body>
</html>
"""

    def _calculate_stats(self) -> dict[str, Any]:
        """Calculate statistics for the dashboard."""
        if not self.chains:
            return {
                "total_chains": 0,
                "critical_chains": 0,
                "high_chains": 0,
                "total_nodes": 0,
                "avg_priority": 0,
            }

        return {
            "total_chains": len(self.chains),
            "critical_chains": len([c for c in self.chains if c.max_severity == "CRITICAL"]),
            "high_chains": len([c for c in self.chains if c.max_severity == "HIGH"]),
            "total_nodes": sum(len(c.nodes) for c in self.chains),
            "avg_priority": sum(c.remediation_priority for c in self.chains) / len(self.chains),
        }
