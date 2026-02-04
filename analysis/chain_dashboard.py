"""
Attack Chain Dashboard - Real-time web dashboard for attack chain visualization.
Uses WebSocket for live updates and interactive exploration.
"""

from __future__ import annotations

import json
import html
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analysis.attack_chain_engine import AttackChain

from utils.logger import get_logger

logger = get_logger(__name__)


class AttackChainDashboard:
    """
    Interactive web dashboard for attack chain visualization.
    
    Features:
    - Real-time updates via WebSocket
    - Interactive chain exploration
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
        findings: list[dict[str, Any]] | None = None
    ) -> None:
        """Set the data for the dashboard."""
        self.chains = chains
        self.findings = findings or []
    
    def generate_dashboard(self, target: str = "Unknown") -> str:
        """Generate the complete HTML dashboard."""
        
        # Prepare data for JavaScript
        chains_data = json.dumps([c.to_dict() for c in self.chains], ensure_ascii=False)
        
        # Calculate statistics
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
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #a371f7;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }}
        
        .dashboard {{
            display: grid;
            grid-template-columns: 280px 1fr;
            min-height: 100vh;
        }}
        
        /* Sidebar */
        .sidebar {{
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            padding: 20px;
            overflow-y: auto;
        }}
        
        .logo {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }}
        
        .logo h1 {{
            font-size: 1.2em;
            background: linear-gradient(45deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .nav-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 15px;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
            margin-bottom: 5px;
        }}
        
        .nav-item:hover, .nav-item.active {{
            background: var(--bg-tertiary);
        }}
        
        .nav-item.active {{
            border-left: 3px solid var(--accent-blue);
        }}
        
        /* Main Content */
        .main-content {{
            padding: 20px;
            overflow-y: auto;
        }}
        
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }}
        
        .header h2 {{
            font-size: 1.5em;
        }}
        
        .header-actions {{
            display: flex;
            gap: 10px;
        }}
        
        .btn {{
            padding: 8px 16px;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9em;
        }}
        
        .btn:hover {{
            background: var(--bg-secondary);
            border-color: var(--accent-blue);
        }}
        
        .btn-primary {{
            background: var(--accent-blue);
            border-color: var(--accent-blue);
        }}
        
        .btn-primary:hover {{
            filter: brightness(1.1);
        }}
        
        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        
        .stat-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        
        .stat-box .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-box .label {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        
        .stat-box.critical .value {{ color: var(--accent-red); }}
        .stat-box.high .value {{ color: var(--accent-yellow); }}
        .stat-box.medium .value {{ color: var(--accent-blue); }}
        .stat-box.success .value {{ color: var(--accent-green); }}
        
        /* Charts */
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }}
        
        .chart-box {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 20px;
        }}
        
        .chart-box h3 {{
            margin-bottom: 15px;
            font-size: 1em;
            color: var(--text-secondary);
        }}
        
        /* Network Graph */
        #network-graph {{
            height: 500px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 25px;
        }}
        
        /* Chain List */
        .chain-list {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .chain-item {{
            padding: 20px;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            transition: background 0.2s;
        }}
        
        .chain-item:hover {{
            background: var(--bg-tertiary);
        }}
        
        .chain-item:last-child {{
            border-bottom: none;
        }}
        
        .chain-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .chain-header h4 {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .badge {{
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: bold;
        }}
        
        .badge.critical {{ background: var(--accent-red); color: #fff; }}
        .badge.high {{ background: var(--accent-yellow); color: #000; }}
        .badge.medium {{ background: var(--accent-blue); color: #fff; }}
        .badge.low {{ background: var(--accent-green); color: #fff; }}
        
        .chain-flow {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
            margin-bottom: 10px;
        }}
        
        .chain-node {{
            background: var(--bg-tertiary);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            border-left: 3px solid;
        }}
        
        .chain-node.critical {{ border-color: var(--accent-red); }}
        .chain-node.high {{ border-color: var(--accent-yellow); }}
        .chain-node.medium {{ border-color: var(--accent-blue); }}
        .chain-node.low {{ border-color: var(--accent-green); }}
        
        .chain-arrow {{
            color: var(--text-secondary);
        }}
        
        .chain-impact {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        
        /* Modal */
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        
        .modal.active {{
            display: flex;
        }}
        
        .modal-content {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            width: 90%;
            max-width: 900px;
            max-height: 90vh;
            overflow-y: auto;
            padding: 30px;
        }}
        
        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border);
        }}
        
        .close-btn {{
            background: none;
            border: none;
            color: var(--text-primary);
            font-size: 1.5em;
            cursor: pointer;
        }}
        
        /* Views */
        .view {{
            display: none;
        }}
        
        .view.active {{
            display: block;
        }}
    </style>
</head>
<body>
    <div class="dashboard">
        <aside class="sidebar">
            <div class="logo">
                <span style="font-size: 2em;">🔗</span>
                <h1>Attack Chain<br>Dashboard</h1>
            </div>
            
            <nav>
                <div class="nav-item active" data-view="overview">
                    <span>📊</span>
                    <span>Overview</span>
                </div>
                <div class="nav-item" data-view="chains">
                    <span>⛓️</span>
                    <span>Attack Chains</span>
                </div>
                <div class="nav-item" data-view="graph">
                    <span>🕸️</span>
                    <span>Network Graph</span>
                </div>
                <div class="nav-item" data-view="executive">
                    <span>📋</span>
                    <span>Executive Summary</span>
                </div>
            </nav>
            
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid var(--border);">
                <p style="color: var(--text-secondary); font-size: 0.85em; margin-bottom: 10px;">Target</p>
                <p style="font-weight: bold;">{html.escape(target)}</p>
                <p style="color: var(--text-secondary); font-size: 0.85em; margin-top: 15px;">Generated</p>
                <p>{datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
            </div>
        </aside>
        
        <main class="main-content">
            <!-- Overview View -->
            <div class="view active" id="view-overview">
                <div class="header">
                    <h2>📊 Security Overview</h2>
                    <div class="header-actions">
                        <button class="btn" onclick="exportReport('pdf')">📄 Export PDF</button>
                        <button class="btn" onclick="exportReport('json')">📦 Export JSON</button>
                    </div>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-box critical">
                        <div class="value">{stats['total_chains']}</div>
                        <div class="label">Attack Chains</div>
                    </div>
                    <div class="stat-box high">
                        <div class="value">{stats['critical_chains']}</div>
                        <div class="label">Critical Chains</div>
                    </div>
                    <div class="stat-box medium">
                        <div class="value">{stats['total_nodes']}</div>
                        <div class="label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-box success">
                        <div class="value">{stats['avg_priority']:.1f}</div>
                        <div class="label">Avg Priority Score</div>
                    </div>
                </div>
                
                <div class="charts-grid">
                    <div class="chart-box">
                        <h3>Chains by Severity</h3>
                        <canvas id="severityChart"></canvas>
                    </div>
                    <div class="chart-box">
                        <h3>Impact Types Distribution</h3>
                        <canvas id="impactChart"></canvas>
                    </div>
                </div>
                
                <div class="chart-box">
                    <h3>Attack Phases Coverage</h3>
                    <canvas id="phasesChart" height="100"></canvas>
                </div>
            </div>
            
            <!-- Chains View -->
            <div class="view" id="view-chains">
                <div class="header">
                    <h2>⛓️ Attack Chains</h2>
                    <div class="header-actions">
                        <input type="text" class="btn" placeholder="🔍 Search..." id="chainSearch" style="min-width: 200px;">
                    </div>
                </div>
                
                <div class="chain-list" id="chainList">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
            
            <!-- Graph View -->
            <div class="view" id="view-graph">
                <div class="header">
                    <h2>🕸️ Network Graph</h2>
                    <div class="header-actions">
                        <button class="btn" onclick="resetGraph()">🔄 Reset View</button>
                    </div>
                </div>
                
                <div id="network-graph"></div>
            </div>
            
            <!-- Executive View -->
            <div class="view" id="view-executive">
                <div class="header">
                    <h2>📋 Executive Summary</h2>
                    <div class="header-actions">
                        <button class="btn btn-primary" onclick="printSummary()">🖨️ Print</button>
                    </div>
                </div>
                
                <div id="executiveSummary">
                    <!-- Populated by JavaScript -->
                </div>
            </div>
        </main>
    </div>
    
    <!-- Chain Detail Modal -->
    <div class="modal" id="chainModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Chain Details</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalContent">
                <!-- Populated by JavaScript -->
            </div>
        </div>
    </div>
    
    <script>
        // Data
        const chainsData = {chains_data};
        
        // State
        let network = null;
        
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {{
            item.addEventListener('click', () => {{
                document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
                
                item.classList.add('active');
                const viewId = 'view-' + item.dataset.view;
                document.getElementById(viewId).classList.add('active');
                
                if (item.dataset.view === 'graph') {{
                    initNetworkGraph();
                }}
            }});
        }});
        
        // Initialize charts
        function initCharts() {{
            // Severity Chart
            const severityCounts = chainsData.reduce((acc, chain) => {{
                acc[chain.max_severity] = (acc[chain.max_severity] || 0) + 1;
                return acc;
            }}, {{}});
            
            new Chart(document.getElementById('severityChart'), {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(severityCounts),
                    datasets: [{{
                        data: Object.values(severityCounts),
                        backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'],
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ color: '#c9d1d9' }}
                        }}
                    }}
                }}
            }});
            
            // Impact Chart
            const impactCounts = chainsData.reduce((acc, chain) => {{
                const impact = chain.impact_type || 'unknown';
                acc[impact] = (acc[impact] || 0) + 1;
                return acc;
            }}, {{}});
            
            new Chart(document.getElementById('impactChart'), {{
                type: 'pie',
                data: {{
                    labels: Object.keys(impactCounts).map(i => i.replace(/_/g, ' ')),
                    datasets: [{{
                        data: Object.values(impactCounts),
                        backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950', '#a371f7', '#f0883e'],
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ color: '#c9d1d9' }}
                        }}
                    }}
                }}
            }});
            
            // Phases Chart
            const phaseCounts = {{}};
            chainsData.forEach(chain => {{
                chain.nodes.forEach(node => {{
                    const phase = node.phase || 'unknown';
                    phaseCounts[phase] = (phaseCounts[phase] || 0) + 1;
                }});
            }});
            
            new Chart(document.getElementById('phasesChart'), {{
                type: 'bar',
                data: {{
                    labels: Object.keys(phaseCounts).map(p => p.replace(/_/g, ' ')),
                    datasets: [{{
                        label: 'Occurrences',
                        data: Object.values(phaseCounts),
                        backgroundColor: '#58a6ff',
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        y: {{ grid: {{ color: '#30363d' }}, ticks: {{ color: '#c9d1d9' }} }},
                        x: {{ grid: {{ color: '#30363d' }}, ticks: {{ color: '#c9d1d9' }} }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
        }}
        
        // Populate chain list
        function populateChainList() {{
            const container = document.getElementById('chainList');
            container.innerHTML = chainsData.map((chain, i) => `
                <div class="chain-item" onclick="showChainDetail(${{i}})">
                    <div class="chain-header">
                        <h4>
                            <span>🔗</span>
                            <span>${{chain.name || 'Chain ' + (i + 1)}}</span>
                        </h4>
                        <div>
                            <span class="badge ${{chain.max_severity?.toLowerCase()}}">${{chain.max_severity}}</span>
                        </div>
                    </div>
                    <div class="chain-flow">
                        ${{chain.nodes.map((n, j) => `
                            <span class="chain-node ${{n.severity?.toLowerCase()}}">${{n.name}}</span>
                            ${{j < chain.nodes.length - 1 ? '<span class="chain-arrow">→</span>' : ''}}
                        `).join('')}}
                    </div>
                    <div class="chain-impact">
                        💥 ${{chain.business_impact?.substring(0, 100)}}...
                    </div>
                </div>
            `).join('');
        }}
        
        // Network Graph
        function initNetworkGraph() {{
            const container = document.getElementById('network-graph');
            
            const nodes = [];
            const edges = [];
            let nodeId = 0;
            
            chainsData.forEach((chain, chainIndex) => {{
                chain.nodes.forEach((node, nodeIndex) => {{
                    const id = `${{chainIndex}}-${{nodeIndex}}`;
                    nodes.push({{
                        id: id,
                        label: node.name,
                        color: getColorForSeverity(node.severity),
                        title: `${{node.name}}\\nCVSS: ${{node.cvss}}\\n${{node.phase}}`,
                    }});
                    
                    if (nodeIndex > 0) {{
                        edges.push({{
                            from: `${{chainIndex}}-${{nodeIndex - 1}}`,
                            to: id,
                            arrows: 'to',
                            color: {{ color: '#58a6ff' }},
                        }});
                    }}
                }});
            }});
            
            const data = {{ nodes, edges }};
            const options = {{
                physics: {{
                    stabilization: true,
                    barnesHut: {{
                        gravitationalConstant: -2000,
                        springLength: 150,
                    }}
                }},
                nodes: {{
                    shape: 'box',
                    font: {{ color: '#fff' }},
                    borderWidth: 2,
                }},
                edges: {{
                    smooth: {{ type: 'continuous' }},
                }},
            }};
            
            network = new vis.Network(container, data, options);
        }}
        
        function getColorForSeverity(severity) {{
            const colors = {{
                'CRITICAL': '#f85149',
                'HIGH': '#d29922',
                'MEDIUM': '#58a6ff',
                'LOW': '#3fb950',
            }};
            return colors[severity?.toUpperCase()] || '#6e7681';
        }}
        
        // Modal
        function showChainDetail(index) {{
            const chain = chainsData[index];
            document.getElementById('modalTitle').textContent = chain.name || 'Chain ' + (index + 1);
            
            document.getElementById('modalContent').innerHTML = `
                <div style="margin-bottom: 20px;">
                    <span class="badge ${{chain.max_severity?.toLowerCase()}}">${{chain.max_severity}}</span>
                    <span style="margin-left: 10px; color: var(--text-secondary);">Priority: ${{chain.remediation_priority}}/10</span>
                </div>
                
                <h4 style="margin-bottom: 15px;">Attack Flow</h4>
                <div class="chain-flow" style="margin-bottom: 20px; padding: 15px; background: var(--bg-tertiary); border-radius: 8px;">
                    ${{chain.nodes.map((n, j) => `
                        <span class="chain-node ${{n.severity?.toLowerCase()}}">${{n.name}}</span>
                        ${{j < chain.nodes.length - 1 ? '<span class="chain-arrow">→</span>' : ''}}
                    `).join('')}}
                </div>
                
                <h4 style="margin-bottom: 15px;">Vulnerabilities</h4>
                ${{chain.nodes.map(n => `
                    <div style="padding: 15px; background: var(--bg-tertiary); border-radius: 8px; margin-bottom: 10px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <strong>${{n.name}}</strong>
                            <span class="badge ${{n.severity?.toLowerCase()}}">${{n.severity}} - CVSS ${{n.cvss}}</span>
                        </div>
                        <p style="color: var(--text-secondary); font-size: 0.9em; margin-bottom: 8px;">${{n.description || 'No description'}}</p>
                        <div style="font-size: 0.85em; color: var(--text-secondary);">
                            <span>📍 ${{n.endpoint}}</span><br>
                            <span>🏷️ ${{n.cwe}} | ${{n.owasp}}</span>
                        </div>
                    </div>
                `).join('')}}
                
                <h4 style="margin: 20px 0 15px;">Business Impact</h4>
                <div style="padding: 20px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 8px;">
                    <p>${{chain.business_impact}}</p>
                    <div style="margin-top: 15px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                        <div>
                            <span style="opacity: 0.8; font-size: 0.85em;">Likelihood</span><br>
                            <strong>${{chain.likelihood}}</strong>
                        </div>
                        <div>
                            <span style="opacity: 0.8; font-size: 0.85em;">Exploitability</span><br>
                            <strong>${{chain.exploitability}}</strong>
                        </div>
                        <div>
                            <span style="opacity: 0.8; font-size: 0.85em;">Time to Exploit</span><br>
                            <strong>${{chain.estimated_time_to_exploit}}</strong>
                        </div>
                    </div>
                </div>
            `;
            
            document.getElementById('chainModal').classList.add('active');
        }}
        
        function closeModal() {{
            document.getElementById('chainModal').classList.remove('active');
        }}
        
        // Executive Summary
        function generateExecutiveSummary() {{
            const critical = chainsData.filter(c => c.max_severity === 'CRITICAL').length;
            const high = chainsData.filter(c => c.max_severity === 'HIGH').length;
            
            document.getElementById('executiveSummary').innerHTML = `
                <div style="padding: 30px; background: var(--bg-secondary); border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 20px;">🎯 Key Findings</h3>
                    <p style="line-height: 1.8; margin-bottom: 15px;">
                        A análise identificou <strong style="color: var(--accent-red);">${{chainsData.length}} cadeias de ataque</strong> 
                        que demonstram como vulnerabilidades aparentemente isoladas podem ser combinadas para comprometer 
                        sistemas críticos da organização.
                    </p>
                    <p style="line-height: 1.8; margin-bottom: 15px;">
                        <strong style="color: var(--accent-red);">${{critical}} cadeias críticas</strong> e 
                        <strong style="color: var(--accent-yellow);">${{high}} cadeias de alta severidade</strong> 
                        representam riscos que podem resultar em violações de dados, perdas financeiras significativas 
                        ou interrupção de serviços essenciais.
                    </p>
                </div>
                
                <div style="padding: 30px; background: var(--bg-secondary); border-radius: 8px; margin-bottom: 20px;">
                    <h3 style="margin-bottom: 20px;">📊 Risk Distribution</h3>
                    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px;">
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-red);">${{critical}}</div>
                            <div style="color: var(--text-secondary);">Critical</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-yellow);">${{high}}</div>
                            <div style="color: var(--text-secondary);">High</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-blue);">${{chainsData.filter(c => c.max_severity === 'MEDIUM').length}}</div>
                            <div style="color: var(--text-secondary);">Medium</div>
                        </div>
                        <div style="text-align: center; padding: 20px; background: var(--bg-tertiary); border-radius: 8px;">
                            <div style="font-size: 2em; font-weight: bold; color: var(--accent-green);">${{chainsData.filter(c => c.max_severity === 'LOW').length}}</div>
                            <div style="color: var(--text-secondary);">Low</div>
                        </div>
                    </div>
                </div>
                
                <div style="padding: 30px; background: var(--bg-secondary); border-radius: 8px;">
                    <h3 style="margin-bottom: 20px;">🛡️ Recommendations</h3>
                    <ol style="line-height: 2; padding-left: 20px;">
                        <li>Priorizar remediação das vulnerabilidades de <strong>Initial Access</strong> que servem como ponto de entrada nas cadeias críticas</li>
                        <li>Implementar controles de segmentação para dificultar <strong>Lateral Movement</strong></li>
                        <li>Reforçar mecanismos de autenticação e autorização para prevenir <strong>Privilege Escalation</strong></li>
                        <li>Implementar monitoramento para detectar padrões de ataque identificados nas cadeias</li>
                        <li>Realizar exercícios de red team focados nos cenários de alto impacto identificados</li>
                    </ol>
                </div>
            `;
        }}
        
        // Export
        function exportReport(format) {{
            if (format === 'json') {{
                const blob = new Blob([JSON.stringify(chainsData, null, 2)], {{type: 'application/json'}});
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'attack-chains.json';
                a.click();
            }}
        }}
        
        function printSummary() {{
            window.print();
        }}
        
        function resetGraph() {{
            if (network) {{
                network.fit();
            }}
        }}
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {{
            initCharts();
            populateChainList();
            generateExecutiveSummary();
        }});
        
        // Close modal on outside click
        document.getElementById('chainModal').addEventListener('click', (e) => {{
            if (e.target.id === 'chainModal') closeModal();
        }});
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
