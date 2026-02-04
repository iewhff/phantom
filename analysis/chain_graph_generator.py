"""
Attack Chain Graph Generator - Advanced graph visualization using D3.js and Cytoscape.
Generates interactive network diagrams showing attack paths.
"""

from __future__ import annotations

import json
import html
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from analysis.attack_chain_engine import AttackChain, ChainNode

from utils.logger import get_logger

logger = get_logger(__name__)


class ChainGraphGenerator:
    """
    Generates advanced interactive graph visualizations for attack chains.
    
    Features:
    - D3.js force-directed graphs
    - Cytoscape.js network diagrams
    - Hierarchical tree layouts
    - Sankey diagrams for flow visualization
    - Export to various formats (SVG, PNG, PDF)
    """
    
    SEVERITY_COLORS = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "INFO": "#17a2b8",
    }
    
    PHASE_COLORS = {
        "reconnaissance": "#6c757d",
        "initial_access": "#dc3545",
        "execution": "#fd7e14",
        "persistence": "#ffc107",
        "privilege_escalation": "#20c997",
        "defense_evasion": "#17a2b8",
        "credential_access": "#6610f2",
        "discovery": "#e83e8c",
        "lateral_movement": "#007bff",
        "collection": "#6f42c1",
        "exfiltration": "#28a745",
        "impact": "#343a40",
    }
    
    def generate_d3_force_graph(self, chains: list[AttackChain], target: str = "Unknown") -> str:
        """Generate D3.js force-directed graph visualization."""
        
        # Prepare nodes and links
        nodes = []
        links = []
        node_ids = set()
        
        for chain_idx, chain in enumerate(chains):
            for node_idx, node in enumerate(chain.nodes):
                node_id = f"c{chain_idx}_n{node_idx}"
                if node_id not in node_ids:
                    nodes.append({
                        "id": node_id,
                        "name": node.name,
                        "phase": node.phase.value,
                        "severity": node.severity,
                        "cvss": node.cvss,
                        "chain": chain_idx,
                        "endpoint": node.endpoint,
                        "cwe": node.cwe,
                    })
                    node_ids.add(node_id)
                
                # Add link to next node
                if node_idx < len(chain.nodes) - 1:
                    links.append({
                        "source": node_id,
                        "target": f"c{chain_idx}_n{node_idx + 1}",
                        "chain": chain_idx,
                    })
            
            # Add impact node
            impact_id = f"c{chain_idx}_impact"
            nodes.append({
                "id": impact_id,
                "name": chain.impact_type.value.replace("_", " ").upper(),
                "phase": "impact",
                "severity": chain.max_severity,
                "cvss": chain.total_cvss,
                "chain": chain_idx,
                "isImpact": True,
            })
            
            if chain.nodes:
                links.append({
                    "source": f"c{chain_idx}_n{len(chain.nodes) - 1}",
                    "target": impact_id,
                    "chain": chain_idx,
                })
        
        nodes_json = json.dumps(nodes)
        links_json = json.dumps(links)
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Chain Network - {html.escape(target)}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            overflow: hidden;
        }}
        #graph {{ width: 100vw; height: 100vh; }}
        .tooltip {{
            position: absolute;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 12px;
            pointer-events: none;
            opacity: 0;
            transition: opacity 0.2s;
            max-width: 300px;
            z-index: 1000;
        }}
        .tooltip h4 {{ margin-bottom: 8px; color: #58a6ff; }}
        .tooltip p {{ font-size: 0.9em; margin: 4px 0; }}
        .tooltip .severity {{ 
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .controls {{
            position: fixed;
            top: 20px;
            left: 20px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            z-index: 100;
        }}
        .controls h3 {{ margin-bottom: 10px; font-size: 1em; }}
        .controls button {{
            background: #21262d;
            border: 1px solid #30363d;
            color: #c9d1d9;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 5px;
            margin-bottom: 5px;
        }}
        .controls button:hover {{ background: #30363d; }}
        .legend {{
            position: fixed;
            bottom: 20px;
            left: 20px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            z-index: 100;
        }}
        .legend h4 {{ margin-bottom: 10px; font-size: 0.9em; }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.85em;
            margin: 5px 0;
        }}
        .legend-color {{
            width: 16px;
            height: 16px;
            border-radius: 50%;
        }}
        .stats {{
            position: fixed;
            top: 20px;
            right: 20px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 15px;
            z-index: 100;
        }}
        .stats h3 {{ margin-bottom: 10px; font-size: 1em; }}
        .stat-item {{
            display: flex;
            justify-content: space-between;
            font-size: 0.9em;
            margin: 5px 0;
        }}
        .stat-value {{ font-weight: bold; color: #58a6ff; }}
    </style>
</head>
<body>
    <svg id="graph"></svg>
    
    <div class="tooltip" id="tooltip"></div>
    
    <div class="controls">
        <h3>🎮 Controls</h3>
        <button onclick="zoomIn()">➕ Zoom In</button>
        <button onclick="zoomOut()">➖ Zoom Out</button>
        <button onclick="resetZoom()">🔄 Reset</button>
        <button onclick="togglePhysics()">⚡ Toggle Physics</button>
    </div>
    
    <div class="stats">
        <h3>📊 Statistics</h3>
        <div class="stat-item">
            <span>Attack Chains:</span>
            <span class="stat-value">{len(chains)}</span>
        </div>
        <div class="stat-item">
            <span>Total Nodes:</span>
            <span class="stat-value">{sum(len(c.nodes) for c in chains)}</span>
        </div>
        <div class="stat-item">
            <span>Critical Chains:</span>
            <span class="stat-value">{len([c for c in chains if c.max_severity == 'CRITICAL'])}</span>
        </div>
    </div>
    
    <div class="legend">
        <h4>🎨 Severity Legend</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: #dc3545;"></div>
            <span>Critical</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #fd7e14;"></div>
            <span>High</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #ffc107;"></div>
            <span>Medium</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #28a745;"></div>
            <span>Low</span>
        </div>
    </div>
    
    <script>
        const nodes = {nodes_json};
        const links = {links_json};
        
        const width = window.innerWidth;
        const height = window.innerHeight;
        
        const colorMap = {{
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
            'INFO': '#17a2b8'
        }};
        
        const svg = d3.select('#graph')
            .attr('width', width)
            .attr('height', height);
        
        const g = svg.append('g');
        
        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on('zoom', (event) => g.attr('transform', event.transform));
        
        svg.call(zoom);
        
        // Arrow marker
        svg.append('defs').append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '-0 -5 10 10')
            .attr('refX', 20)
            .attr('refY', 0)
            .attr('orient', 'auto')
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#58a6ff');
        
        // Force simulation
        let simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(120))
            .force('charge', d3.forceManyBody().strength(-400))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(50));
        
        // Links
        const link = g.append('g')
            .selectAll('line')
            .data(links)
            .join('line')
            .attr('stroke', '#58a6ff')
            .attr('stroke-opacity', 0.6)
            .attr('stroke-width', 2)
            .attr('marker-end', 'url(#arrowhead)');
        
        // Nodes
        const node = g.append('g')
            .selectAll('g')
            .data(nodes)
            .join('g')
            .call(d3.drag()
                .on('start', dragstarted)
                .on('drag', dragged)
                .on('end', dragended));
        
        // Node circles
        node.append('circle')
            .attr('r', d => d.isImpact ? 30 : 20)
            .attr('fill', d => colorMap[d.severity] || '#6c757d')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2)
            .style('cursor', 'pointer');
        
        // Node labels
        node.append('text')
            .text(d => d.name.length > 20 ? d.name.substring(0, 17) + '...' : d.name)
            .attr('x', 0)
            .attr('y', d => d.isImpact ? 45 : 35)
            .attr('text-anchor', 'middle')
            .attr('fill', '#c9d1d9')
            .attr('font-size', '11px');
        
        // Tooltip
        const tooltip = d3.select('#tooltip');
        
        node.on('mouseover', function(event, d) {{
            tooltip.style('opacity', 1)
                .html(`
                    <h4>${{d.name}}</h4>
                    <p class="severity" style="background: ${{colorMap[d.severity] || '#6c757d'}}; color: #fff;">${{d.severity}}</p>
                    <p><strong>Phase:</strong> ${{d.phase}}</p>
                    <p><strong>CVSS:</strong> ${{d.cvss}}</p>
                    ${{d.endpoint ? `<p><strong>Endpoint:</strong> ${{d.endpoint}}</p>` : ''}}
                    ${{d.cwe ? `<p><strong>CWE:</strong> ${{d.cwe}}</p>` : ''}}
                `)
                .style('left', (event.pageX + 15) + 'px')
                .style('top', (event.pageY - 10) + 'px');
        }})
        .on('mouseout', function() {{
            tooltip.style('opacity', 0);
        }});
        
        // Update positions
        simulation.on('tick', () => {{
            link
                .attr('x1', d => d.source.x)
                .attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x)
                .attr('y2', d => d.target.y);
            
            node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        // Drag functions
        function dragstarted(event) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        }}
        
        function dragged(event) {{
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        }}
        
        function dragended(event) {{
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        }}
        
        // Control functions
        let physicsEnabled = true;
        
        function zoomIn() {{
            svg.transition().call(zoom.scaleBy, 1.5);
        }}
        
        function zoomOut() {{
            svg.transition().call(zoom.scaleBy, 0.67);
        }}
        
        function resetZoom() {{
            svg.transition().call(zoom.transform, d3.zoomIdentity);
        }}
        
        function togglePhysics() {{
            physicsEnabled = !physicsEnabled;
            if (physicsEnabled) {{
                simulation.alpha(1).restart();
            }} else {{
                simulation.stop();
            }}
        }}
    </script>
</body>
</html>
"""
    
    def generate_hierarchical_graph(self, chains: list[AttackChain], target: str = "Unknown") -> str:
        """Generate hierarchical tree layout for attack chains."""
        
        # Build hierarchical data structure
        hierarchical_data = {
            "name": target,
            "children": []
        }
        
        for i, chain in enumerate(chains):
            chain_node = {
                "name": chain.name or f"Chain {i+1}",
                "severity": chain.max_severity,
                "children": []
            }
            
            for node in chain.nodes:
                chain_node["children"].append({
                    "name": node.name,
                    "severity": node.severity,
                    "phase": node.phase.value,
                    "cvss": node.cvss,
                })
            
            # Add impact
            chain_node["children"].append({
                "name": f"💥 {chain.impact_type.value.upper()}",
                "severity": chain.max_severity,
                "isImpact": True,
            })
            
            hierarchical_data["children"].append(chain_node)
        
        data_json = json.dumps(hierarchical_data)
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attack Chain Hierarchy - {html.escape(target)}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            margin: 0;
            overflow: hidden;
        }}
        svg {{ width: 100vw; height: 100vh; }}
        .node circle {{
            stroke: #fff;
            stroke-width: 2px;
            cursor: pointer;
        }}
        .node text {{
            font-size: 11px;
            fill: #c9d1d9;
        }}
        .link {{
            fill: none;
            stroke: #30363d;
            stroke-width: 1.5px;
        }}
        .title {{
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.5em;
            color: #58a6ff;
        }}
    </style>
</head>
<body>
    <div class="title">🌳 Attack Chain Hierarchy - {html.escape(target)}</div>
    <svg id="tree"></svg>
    
    <script>
        const data = {data_json};
        
        const width = window.innerWidth;
        const height = window.innerHeight;
        const margin = {{top: 80, right: 120, bottom: 20, left: 120}};
        
        const colorMap = {{
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
        }};
        
        const svg = d3.select('#tree')
            .attr('width', width)
            .attr('height', height);
        
        const g = svg.append('g')
            .attr('transform', `translate(${{margin.left}},${{margin.top}})`);
        
        const tree = d3.tree()
            .size([height - margin.top - margin.bottom, width - margin.left - margin.right]);
        
        const root = d3.hierarchy(data);
        tree(root);
        
        // Links
        g.selectAll('.link')
            .data(root.links())
            .join('path')
            .attr('class', 'link')
            .attr('d', d3.linkHorizontal()
                .x(d => d.y)
                .y(d => d.x));
        
        // Nodes
        const node = g.selectAll('.node')
            .data(root.descendants())
            .join('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(${{d.y}},${{d.x}})`);
        
        node.append('circle')
            .attr('r', d => d.depth === 0 ? 15 : d.data.isImpact ? 12 : 8)
            .attr('fill', d => colorMap[d.data.severity] || '#58a6ff');
        
        node.append('text')
            .attr('dy', '0.31em')
            .attr('x', d => d.children ? -15 : 15)
            .attr('text-anchor', d => d.children ? 'end' : 'start')
            .text(d => d.data.name.length > 30 ? d.data.name.substring(0, 27) + '...' : d.data.name);
        
        // Zoom
        const zoom = d3.zoom()
            .scaleExtent([0.1, 3])
            .on('zoom', (event) => g.attr('transform', event.transform));
        
        svg.call(zoom);
        svg.call(zoom.transform, d3.zoomIdentity.translate(margin.left, margin.top));
    </script>
</body>
</html>
"""
    
    def generate_sankey_diagram(self, chains: list[AttackChain], target: str = "Unknown") -> str:
        """Generate Sankey diagram showing flow between attack phases."""
        
        # Count flows between phases
        phase_flows: dict[tuple[str, str], int] = {}
        phases_set = set()
        
        for chain in chains:
            for i in range(len(chain.nodes) - 1):
                source_phase = chain.nodes[i].phase.value
                target_phase = chain.nodes[i + 1].phase.value
                
                phases_set.add(source_phase)
                phases_set.add(target_phase)
                
                key = (source_phase, target_phase)
                phase_flows[key] = phase_flows.get(key, 0) + 1
            
            # Flow to impact
            if chain.nodes:
                last_phase = chain.nodes[-1].phase.value
                impact = chain.impact_type.value
                phases_set.add(last_phase)
                phases_set.add(impact)
                key = (last_phase, impact)
                phase_flows[key] = phase_flows.get(key, 0) + 1
        
        # Build nodes and links for Sankey
        phases_list = list(phases_set)
        nodes = [{"name": p} for p in phases_list]
        links = [
            {"source": phases_list.index(s), "target": phases_list.index(t), "value": v}
            for (s, t), v in phase_flows.items()
        ]
        
        nodes_json = json.dumps(nodes)
        links_json = json.dumps(links)
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Attack Flow Sankey - {html.escape(target)}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12.3/dist/d3-sankey.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            margin: 0;
        }}
        svg {{ width: 100vw; height: 100vh; }}
        .node rect {{ cursor: pointer; }}
        .node text {{ font-size: 12px; fill: #c9d1d9; }}
        .link {{ fill: none; stroke-opacity: 0.4; }}
        .link:hover {{ stroke-opacity: 0.7; }}
        .title {{
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            font-size: 1.5em;
            color: #58a6ff;
        }}
    </style>
</head>
<body>
    <div class="title">🌊 Attack Flow Analysis - {html.escape(target)}</div>
    <svg id="sankey"></svg>
    
    <script>
        const nodes = {nodes_json};
        const links = {links_json};
        
        const width = window.innerWidth;
        const height = window.innerHeight;
        const margin = {{top: 80, right: 50, bottom: 20, left: 50}};
        
        const svg = d3.select('#sankey')
            .attr('width', width)
            .attr('height', height);
        
        const g = svg.append('g')
            .attr('transform', `translate(${{margin.left}},${{margin.top}})`);
        
        const sankey = d3.sankey()
            .nodeWidth(20)
            .nodePadding(20)
            .extent([[0, 0], [width - margin.left - margin.right, height - margin.top - margin.bottom]]);
        
        const graph = sankey({{
            nodes: nodes.map(d => Object.assign({{}}, d)),
            links: links.map(d => Object.assign({{}}, d))
        }});
        
        const color = d3.scaleOrdinal()
            .domain(nodes.map(d => d.name))
            .range(d3.schemeTableau10);
        
        // Links
        g.append('g')
            .selectAll('.link')
            .data(graph.links)
            .join('path')
            .attr('class', 'link')
            .attr('d', d3.sankeyLinkHorizontal())
            .attr('stroke', d => color(d.source.name))
            .attr('stroke-width', d => Math.max(1, d.width));
        
        // Nodes
        const node = g.append('g')
            .selectAll('.node')
            .data(graph.nodes)
            .join('g')
            .attr('class', 'node');
        
        node.append('rect')
            .attr('x', d => d.x0)
            .attr('y', d => d.y0)
            .attr('height', d => d.y1 - d.y0)
            .attr('width', d => d.x1 - d.x0)
            .attr('fill', d => color(d.name));
        
        node.append('text')
            .attr('x', d => d.x0 < width / 2 ? d.x1 + 6 : d.x0 - 6)
            .attr('y', d => (d.y1 + d.y0) / 2)
            .attr('dy', '0.35em')
            .attr('text-anchor', d => d.x0 < width / 2 ? 'start' : 'end')
            .text(d => d.name.replace(/_/g, ' '));
    </script>
</body>
</html>
"""
