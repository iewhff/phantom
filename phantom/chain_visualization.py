"""
PHANTOM AI - Chain Visualization Module

NetworkX-based attack path visualization with multiple output formats.
Generates visual representations of vulnerability chains and attack graphs.

Version: 3.0.0
Date: 2026-01-30

Features:
- NetworkX graph generation
- Attack path visualization
- Multiple output formats (SVG, PNG, HTML, DOT, JSON)
- Severity-based color coding
- Interactive HTML with D3.js
- Graphviz DOT format export
- Chain complexity metrics
"""

from __future__ import annotations

import html
import json
import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# =============================================================================
# M1 FIX 2026-02-13: Module-level NetworkX import with fallback
# =============================================================================

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    nx = None  # type: ignore
    NETWORKX_AVAILABLE = False
    logger.warning("NetworkX not available - some layout features disabled")

# =============================================================================
# CONSTANTS (M3 FIX 2026-02-13)
# =============================================================================

LAYOUT_MARGIN = 100
SPRING_K = 2
SPRING_ITERATIONS = 50
D3_LINK_DISTANCE = 150
D3_CHARGE_STRENGTH = -400
D3_COLLISION_RADIUS = 50


# =============================================================================
# ENUMS
# =============================================================================


class OutputFormat(Enum):
    """Supported output formats."""

    SVG = "svg"
    PNG = "png"
    HTML = "html"
    DOT = "dot"
    JSON = "json"
    GRAPHML = "graphml"
    MERMAID = "mermaid"


class NodeType(Enum):
    """Node types in attack graph."""

    VULNERABILITY = auto()
    ASSET = auto()
    TECHNIQUE = auto()
    CONDITION = auto()
    GOAL = auto()
    ENTRY_POINT = auto()
    DATA = auto()


class EdgeType(Enum):
    """Edge types in attack graph."""

    ENABLES = "enables"
    LEADS_TO = "leads_to"
    REQUIRES = "requires"
    ACCESSES = "accesses"
    EXPLOITS = "exploits"
    COMPROMISES = "compromises"


class SeverityColor(Enum):
    """Colors for severity levels."""

    CRITICAL = "#E74C3C"     # Red
    HIGH = "#E67E22"         # Orange
    MEDIUM = "#F39C12"       # Yellow
    LOW = "#3498DB"          # Blue
    INFO = "#95A5A6"         # Gray
    NONE = "#BDC3C7"         # Light gray


class LayoutAlgorithm(Enum):
    """Graph layout algorithms."""

    HIERARCHICAL = "hierarchical"
    SPRING = "spring"
    CIRCULAR = "circular"
    KAMADA_KAWAI = "kamada_kawai"
    SPECTRAL = "spectral"
    SHELL = "shell"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class GraphNode:
    """Node in the attack graph."""

    id: str
    label: str
    node_type: NodeType
    severity: str = "medium"       # critical, high, medium, low, info
    description: str = ""
    cvss_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Position (set by layout algorithm)
    x: float = 0.0
    y: float = 0.0

    @property
    def color(self) -> str:
        """Get color based on severity."""
        color_map = {
            "critical": SeverityColor.CRITICAL.value,
            "high": SeverityColor.HIGH.value,
            "medium": SeverityColor.MEDIUM.value,
            "low": SeverityColor.LOW.value,
            "info": SeverityColor.INFO.value,
        }
        return color_map.get(self.severity.lower(), SeverityColor.NONE.value)

    @property
    def shape(self) -> str:
        """Get shape based on node type."""
        shape_map = {
            NodeType.VULNERABILITY: "ellipse",
            NodeType.ASSET: "box",
            NodeType.TECHNIQUE: "diamond",
            NodeType.CONDITION: "hexagon",
            NodeType.GOAL: "doubleoctagon",
            NodeType.ENTRY_POINT: "invtriangle",
            NodeType.DATA: "cylinder",
        }
        return shape_map.get(self.node_type, "ellipse")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "label": self.label,
            "type": self.node_type.name,
            "severity": self.severity,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "color": self.color,
            "shape": self.shape,
            "x": self.x,
            "y": self.y,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """Edge in the attack graph."""

    source: str
    target: str
    edge_type: EdgeType = EdgeType.LEADS_TO
    label: str = ""
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def color(self) -> str:
        """Get edge color based on type."""
        color_map = {
            EdgeType.ENABLES: "#27AE60",      # Green
            EdgeType.LEADS_TO: "#3498DB",     # Blue
            EdgeType.REQUIRES: "#9B59B6",     # Purple
            EdgeType.ACCESSES: "#F39C12",     # Yellow
            EdgeType.EXPLOITS: "#E74C3C",     # Red
            EdgeType.COMPROMISES: "#C0392B",  # Dark red
        }
        return color_map.get(self.edge_type, "#7F8C8D")

    @property
    def style(self) -> str:
        """Get edge style based on type."""
        style_map = {
            EdgeType.REQUIRES: "dashed",
            EdgeType.ENABLES: "solid",
            EdgeType.LEADS_TO: "solid",
        }
        return style_map.get(self.edge_type, "solid")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type.value,
            "label": self.label,
            "weight": self.weight,
            "color": self.color,
            "style": self.style,
            "metadata": self.metadata,
        }


@dataclass
class AttackGraph:
    """Complete attack graph representation."""

    name: str
    description: str = ""
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    @property
    def node_count(self) -> int:
        """Get number of nodes."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Get number of edges."""
        return len(self.edges)

    @property
    def max_severity(self) -> str:
        """Get maximum severity in graph."""
        severity_order = ["critical", "high", "medium", "low", "info"]
        for severity in severity_order:
            if any(n.severity.lower() == severity for n in self.nodes):
                return severity
        return "none"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "statistics": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "max_severity": self.max_severity,
            },
        }


@dataclass
class VisualizationConfig:
    """Configuration for graph visualization."""

    width: int = 1200
    height: int = 800
    node_size: int = 40
    font_size: int = 12
    edge_width: float = 2.0
    layout: LayoutAlgorithm = LayoutAlgorithm.HIERARCHICAL
    show_labels: bool = True
    show_legend: bool = True
    title: str = ""
    background_color: str = "#FFFFFF"
    dark_mode: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "width": self.width,
            "height": self.height,
            "node_size": self.node_size,
            "font_size": self.font_size,
            "edge_width": self.edge_width,
            "layout": self.layout.value,
            "show_labels": self.show_labels,
            "show_legend": self.show_legend,
            "title": self.title,
            "background_color": self.background_color,
            "dark_mode": self.dark_mode,
        }


# =============================================================================
# CHAIN VISUALIZATION ENGINE
# =============================================================================


class ChainVisualizationEngine:
    """
    PHANTOM AI Chain Visualization Engine.

    Generates visual representations of vulnerability chains
    and attack graphs in multiple formats.
    """

    VERSION = "3.0.0"

    def __init__(
        self,
        config: Optional[VisualizationConfig] = None,
    ) -> None:
        """
        Initialize visualization engine.

        Args:
            config: Optional visualization configuration
        """
        self.config = config or VisualizationConfig()
        self._networkx_available = self._check_networkx()

        # H3 FIX 2026-02-13: Thread safety
        self._lock = threading.Lock()

        # H1 FIX 2026-02-13: Initialize metrics
        self._init_metrics()

        logger.info(f"ChainVisualizationEngine v{self.VERSION} initialized")

    def _init_metrics(self) -> None:
        """Initialize metrics tracking. H1 FIX 2026-02-13."""
        self._metrics = {
            "graphs_created": 0,
            "graphs_from_chains": 0,
            "renders_performed": 0,
            "by_format": defaultdict(int),
            "by_layout": defaultdict(int),
            "total_nodes": 0,
            "total_edges": 0,
        }

    def get_metrics(self) -> dict:
        """Get current metrics. H1 FIX 2026-02-13.

        Returns:
            Dictionary with all tracked metrics.
        """
        with self._lock:
            metrics = dict(self._metrics)
            metrics["by_format"] = dict(metrics["by_format"])
            metrics["by_layout"] = dict(metrics["by_layout"])
            return metrics

    def reset_metrics(self) -> None:
        """Reset all metrics to initial values. H1 FIX 2026-02-13."""
        with self._lock:
            self._init_metrics()

    def _check_networkx(self) -> bool:
        """Check if NetworkX is available.

        M1 FIX 2026-02-13: Uses module-level NETWORKX_AVAILABLE constant.

        Returns:
            True if NetworkX can be imported, False otherwise.
        """
        return NETWORKX_AVAILABLE

    def create_graph_from_chain(
        self,
        chain: Dict[str, Any],
        include_assets: bool = True,
    ) -> AttackGraph:
        """
        Create an attack graph from a vulnerability chain.

        Args:
            chain: Chain data from ChainActionsEngine
            include_assets: Whether to include asset nodes

        Returns:
            AttackGraph representation

        Raises:
            ValueError: If chain is not a dict or has invalid structure
        """
        # M4 FIX 2026-02-13: Input validation
        if not isinstance(chain, dict):
            raise ValueError(f"chain must be a dictionary, got {type(chain).__name__}")

        vulnerabilities = chain.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"chain.vulnerabilities must be a list, got {type(vulnerabilities).__name__}")

        graph = AttackGraph(
            name=chain.get("chain_id", "Unknown Chain"),
            description=chain.get("description", ""),
            metadata={
                "chain_type": chain.get("chain_type", ""),
                "total_risk": chain.get("total_risk_score", 0),
            },
        )

        # Add vulnerability nodes (vulnerabilities already validated above)
        for idx, vuln in enumerate(vulnerabilities):
            node = GraphNode(
                id=vuln.get("id", f"vuln_{idx}"),
                label=vuln.get("type", "Unknown").upper(),
                node_type=NodeType.VULNERABILITY,
                severity=vuln.get("severity", "medium"),
                description=vuln.get("description", ""),
                cvss_score=vuln.get("cvss_score", 0.0),
                metadata={
                    "url": vuln.get("url", ""),
                    "parameter": vuln.get("parameter", ""),
                    "position": idx,
                },
            )
            graph.add_node(node)

            # Add edges between consecutive vulnerabilities
            if idx > 0:
                prev_id = vulnerabilities[idx - 1].get("id", f"vuln_{idx - 1}")
                edge = GraphEdge(
                    source=prev_id,
                    target=node.id,
                    edge_type=EdgeType.ENABLES,
                    label=f"Step {idx + 1}",
                )
                graph.add_edge(edge)

        # Add goal node if chain has an outcome
        if chain.get("outcome"):
            goal_node = GraphNode(
                id="goal",
                label=chain["outcome"],
                node_type=NodeType.GOAL,
                severity="CRITICAL",
                description="Chain objective achieved",
            )
            graph.add_node(goal_node)

            # Connect last vulnerability to goal
            if vulnerabilities:
                last_vuln_id = vulnerabilities[-1].get("id", f"vuln_{len(vulnerabilities) - 1}")
                graph.add_edge(GraphEdge(
                    source=last_vuln_id,
                    target="goal",
                    edge_type=EdgeType.COMPROMISES,
                    label="Achieves",
                ))

        # Add entry point
        entry_node = GraphNode(
            id="entry",
            label="Attacker",
            node_type=NodeType.ENTRY_POINT,
            severity="INFO",
            description="Attack entry point",
        )
        graph.add_node(entry_node)

        if vulnerabilities:
            first_vuln_id = vulnerabilities[0].get("id", "vuln_0")
            graph.add_edge(GraphEdge(
                source="entry",
                target=first_vuln_id,
                edge_type=EdgeType.EXPLOITS,
                label="Initial Access",
            ))

        # H1 FIX: Track metrics
        self._metrics["graphs_created"] += 1
        self._metrics["total_nodes"] += graph.node_count
        self._metrics["total_edges"] += graph.edge_count

        return graph

    def create_graph_from_chains(
        self,
        chains: List[Dict[str, Any]],
        name: str = "Attack Graph",
    ) -> AttackGraph:
        """
        Create a unified attack graph from multiple chains.

        Args:
            chains: List of chain data
            name: Graph name

        Returns:
            Combined AttackGraph

        Raises:
            ValueError: If chains is not a list or contains invalid items
        """
        # M4 FIX 2026-02-13: Input validation
        if not isinstance(chains, list):
            raise ValueError(f"chains must be a list, got {type(chains).__name__}")

        for i, chain in enumerate(chains):
            if not isinstance(chain, dict):
                raise ValueError(f"chains[{i}] must be a dictionary, got {type(chain).__name__}")

        graph = AttackGraph(
            name=name,
            description=f"Combined attack graph from {len(chains)} chains",
            metadata={
                "chain_count": len(chains),
            },
        )

        # Track shared nodes
        node_ids: Set[str] = set()

        for chain_idx, chain in enumerate(chains):
            chain_prefix = f"chain{chain_idx}_"
            vulnerabilities = chain.get("vulnerabilities", [])

            for idx, vuln in enumerate(vulnerabilities):
                # Check if vulnerability already exists (shared between chains)
                vuln_id = vuln.get("id", f"{chain_prefix}vuln_{idx}")
                vuln_type = vuln.get("type", "unknown")

                # Use type-based ID for potential node sharing
                shared_id = f"{vuln_type}_{vuln.get('url', '')}"

                if shared_id in node_ids:
                    # Reuse existing node
                    actual_id = shared_id
                else:
                    actual_id = vuln_id
                    node = GraphNode(
                        id=actual_id,
                        label=vuln_type.upper(),
                        node_type=NodeType.VULNERABILITY,
                        severity=vuln.get("severity", "medium"),
                        cvss_score=vuln.get("cvss_score", 0.0),
                        metadata={
                            "chains": [chain_idx],
                        },
                    )
                    graph.add_node(node)
                    node_ids.add(shared_id)

                # Add edges
                if idx > 0:
                    prev_vuln = vulnerabilities[idx - 1]
                    prev_id = prev_vuln.get("id", f"{chain_prefix}vuln_{idx - 1}")
                    graph.add_edge(GraphEdge(
                        source=prev_id,
                        target=actual_id,
                        edge_type=EdgeType.ENABLES,
                    ))

        # Add single entry point
        entry_node = GraphNode(
            id="attacker",
            label="Attacker",
            node_type=NodeType.ENTRY_POINT,
            severity="INFO",
        )
        graph.add_node(entry_node)

        # Connect entry to first vulnerability of each chain
        for chain_idx, chain in enumerate(chains):
            vulns = chain.get("vulnerabilities", [])
            if vulns:
                first_id = vulns[0].get("id", f"chain{chain_idx}_vuln_0")
                graph.add_edge(GraphEdge(
                    source="attacker",
                    target=first_id,
                    edge_type=EdgeType.EXPLOITS,
                ))

        # H1 FIX: Track metrics
        self._metrics["graphs_created"] += 1
        self._metrics["graphs_from_chains"] += 1
        self._metrics["total_nodes"] += graph.node_count
        self._metrics["total_edges"] += graph.edge_count

        return graph

    def apply_layout(
        self,
        graph: AttackGraph,
        algorithm: Optional[LayoutAlgorithm] = None,
    ) -> None:
        """
        Apply layout algorithm to position nodes.

        Args:
            graph: Attack graph to layout
            algorithm: Layout algorithm to use
        """
        algorithm = algorithm or self.config.layout

        # H1 FIX: Track layout usage
        self._metrics["by_layout"][algorithm.value] += 1

        if self._networkx_available:
            self._apply_networkx_layout(graph, algorithm)
        else:
            self._apply_simple_layout(graph, algorithm)

    def _apply_networkx_layout(
        self,
        graph: AttackGraph,
        algorithm: LayoutAlgorithm,
    ) -> None:
        """Apply layout using NetworkX. M1 FIX: Uses module-level nx."""

        # Create NetworkX graph
        G = nx.DiGraph()

        for node in graph.nodes:
            G.add_node(node.id)

        for edge in graph.edges:
            G.add_edge(edge.source, edge.target, weight=edge.weight)

        # Apply layout algorithm (M3 FIX: use constants)
        if algorithm == LayoutAlgorithm.HIERARCHICAL:
            # Use topological sort for DAG-like graphs
            try:
                pos = self._hierarchical_layout(G)
            except nx.NetworkXError:
                pos = nx.spring_layout(G, k=SPRING_K, iterations=SPRING_ITERATIONS)
        elif algorithm == LayoutAlgorithm.SPRING:
            pos = nx.spring_layout(G, k=SPRING_K, iterations=SPRING_ITERATIONS)
        elif algorithm == LayoutAlgorithm.CIRCULAR:
            pos = nx.circular_layout(G)
        elif algorithm == LayoutAlgorithm.KAMADA_KAWAI:
            try:
                pos = nx.kamada_kawai_layout(G)
            except nx.NetworkXError:
                pos = nx.spring_layout(G)
        elif algorithm == LayoutAlgorithm.SPECTRAL:
            try:
                pos = nx.spectral_layout(G)
            except nx.NetworkXError:
                pos = nx.spring_layout(G)
        elif algorithm == LayoutAlgorithm.SHELL:
            pos = nx.shell_layout(G)
        else:
            pos = nx.spring_layout(G)

        # Scale positions to config dimensions (M3 FIX: use constant)
        width = self.config.width - LAYOUT_MARGIN
        height = self.config.height - LAYOUT_MARGIN

        # Normalize and scale positions
        if pos:
            x_vals = [p[0] for p in pos.values()]
            y_vals = [p[1] for p in pos.values()]

            x_min, x_max = min(x_vals), max(x_vals)
            y_min, y_max = min(y_vals), max(y_vals)

            x_range = x_max - x_min if x_max != x_min else 1
            y_range = y_max - y_min if y_max != y_min else 1

            for node in graph.nodes:
                if node.id in pos:
                    raw_x, raw_y = pos[node.id]
                    node.x = 50 + ((raw_x - x_min) / x_range) * width
                    node.y = 50 + ((raw_y - y_min) / y_range) * height

    def _hierarchical_layout(self, G) -> Dict[str, Tuple[float, float]]:
        """Create hierarchical layout for DAG. M1 FIX: Uses module-level nx."""

        # Find levels using BFS from sources
        sources = [n for n in G.nodes() if G.in_degree(n) == 0]
        if not sources:
            sources = list(G.nodes())[:1]

        levels: Dict[str, int] = {}
        queue = [(s, 0) for s in sources]
        visited = set()

        while queue:
            node, level = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            levels[node] = max(levels.get(node, 0), level)

            for neighbor in G.successors(node):
                queue.append((neighbor, level + 1))

        # Handle disconnected nodes
        for node in G.nodes():
            if node not in levels:
                levels[node] = 0

        # Position nodes by level
        max_level = max(levels.values()) if levels else 0
        level_nodes: Dict[int, List[str]] = {}
        for node, level in levels.items():
            if level not in level_nodes:
                level_nodes[level] = []
            level_nodes[level].append(node)

        pos = {}
        for level, nodes in level_nodes.items():
            y = level / (max_level + 1) if max_level > 0 else 0.5
            for i, node in enumerate(nodes):
                x = (i + 1) / (len(nodes) + 1)
                pos[node] = (x, y)

        return pos

    def _apply_simple_layout(
        self,
        graph: AttackGraph,
        algorithm: LayoutAlgorithm,
    ) -> None:
        """Apply simple layout without NetworkX."""
        # Simple hierarchical layout
        nodes_by_depth: Dict[int, List[GraphNode]] = {}

        # Find entry nodes (no incoming edges)
        targets = {e.target for e in graph.edges}
        sources = {e.source for e in graph.edges}
        entry_nodes = [n for n in graph.nodes if n.id not in targets]

        if not entry_nodes:
            entry_nodes = graph.nodes[:1] if graph.nodes else []

        # BFS to assign depths
        visited: Set[str] = set()
        queue: List[Tuple[GraphNode, int]] = [(n, 0) for n in entry_nodes]

        while queue:
            node, depth = queue.pop(0)
            if node.id in visited:
                continue
            visited.add(node.id)

            if depth not in nodes_by_depth:
                nodes_by_depth[depth] = []
            nodes_by_depth[depth].append(node)

            # Find children
            for edge in graph.edges:
                if edge.source == node.id:
                    child = graph.get_node(edge.target)
                    if child:
                        queue.append((child, depth + 1))

        # Handle unvisited nodes
        for node in graph.nodes:
            if node.id not in visited:
                depth = max(nodes_by_depth.keys()) + 1 if nodes_by_depth else 0
                if depth not in nodes_by_depth:
                    nodes_by_depth[depth] = []
                nodes_by_depth[depth].append(node)

        # Position nodes (M3 FIX: use constant for margin)
        max_depth = max(nodes_by_depth.keys()) if nodes_by_depth else 0
        width = self.config.width - LAYOUT_MARGIN
        height = self.config.height - LAYOUT_MARGIN
        half_margin = LAYOUT_MARGIN // 2

        for depth, nodes in nodes_by_depth.items():
            y = half_margin + (depth / (max_depth + 1)) * height if max_depth > 0 else height / 2

            for i, node in enumerate(nodes):
                x = half_margin + ((i + 1) / (len(nodes) + 1)) * width
                node.x = x
                node.y = y

    def render_svg(
        self,
        graph: AttackGraph,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Render graph as SVG.

        Args:
            graph: Attack graph to render
            output_path: Optional path to save SVG

        Returns:
            SVG string
        """
        # Apply layout if nodes don't have positions
        if not any(n.x != 0 or n.y != 0 for n in graph.nodes):
            self.apply_layout(graph)

        config = self.config
        bg_color = "#1a1a2e" if config.dark_mode else config.background_color
        text_color = "#FFFFFF" if config.dark_mode else "#000000"

        # SVG header
        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {config.width} {config.height}" '
            f'width="{config.width}" height="{config.height}">',
            f'<rect width="100%" height="100%" fill="{bg_color}"/>',
        ]

        # Add title
        if config.title or graph.name:
            title = config.title or graph.name
            svg_parts.append(
                f'<text x="{config.width // 2}" y="30" '
                f'text-anchor="middle" font-size="18" '
                f'font-weight="bold" fill="{text_color}">{html.escape(title)}</text>'
            )

        # Draw edges first (so nodes appear on top)
        svg_parts.append('<g class="edges">')
        for edge in graph.edges:
            source = graph.get_node(edge.source)
            target = graph.get_node(edge.target)
            if source and target:
                svg_parts.append(self._render_svg_edge(edge, source, target))
        svg_parts.append('</g>')

        # Draw nodes
        svg_parts.append('<g class="nodes">')
        for node in graph.nodes:
            svg_parts.append(self._render_svg_node(node, text_color))
        svg_parts.append('</g>')

        # Add legend
        if config.show_legend:
            svg_parts.append(self._render_svg_legend(text_color))

        svg_parts.append('</svg>')

        svg_content = '\n'.join(svg_parts)

        if output_path:
            Path(output_path).write_text(svg_content)
            logger.info(f"SVG saved to {output_path}")

        return svg_content

    def _render_svg_node(self, node: GraphNode, text_color: str) -> str:
        """Render a single node as SVG."""
        size = self.config.node_size
        x, y = node.x, node.y

        # Node shape
        if node.node_type == NodeType.VULNERABILITY:
            shape = f'<ellipse cx="{x}" cy="{y}" rx="{size}" ry="{size * 0.7}" '
        elif node.node_type == NodeType.ASSET:
            shape = f'<rect x="{x - size}" y="{y - size * 0.7}" width="{size * 2}" height="{size * 1.4}" '
        elif node.node_type == NodeType.GOAL:
            # Double octagon (simplified as larger shape)
            shape = f'<ellipse cx="{x}" cy="{y}" rx="{size * 1.2}" ry="{size * 0.8}" '
        elif node.node_type == NodeType.ENTRY_POINT:
            # Triangle pointing down
            points = f"{x},{y - size} {x - size},{y + size * 0.7} {x + size},{y + size * 0.7}"
            shape = f'<polygon points="{points}" '
        else:
            shape = f'<circle cx="{x}" cy="{y}" r="{size}" '

        # Build node SVG
        parts = [
            f'{shape}fill="{node.color}" stroke="#333" stroke-width="2" '
            f'opacity="0.9">',
            f'<title>{html.escape(node.description or node.label)}</title>',
        ]

        if node.node_type == NodeType.ENTRY_POINT:
            parts.append('</polygon>')
        elif 'rect' in shape:
            parts.append('</rect>')
        elif 'ellipse' in shape:
            parts.append('</ellipse>')
        else:
            parts.append('</circle>')

        # Add label
        if self.config.show_labels:
            label = node.label[:15] + "..." if len(node.label) > 15 else node.label
            parts.append(
                f'<text x="{x}" y="{y + 4}" text-anchor="middle" '
                f'font-size="{self.config.font_size}" fill="{text_color}" '
                f'font-weight="bold">{html.escape(label)}</text>'
            )

            # Add CVSS score if available
            if node.cvss_score > 0:
                parts.append(
                    f'<text x="{x}" y="{y + size + 15}" text-anchor="middle" '
                    f'font-size="{self.config.font_size - 2}" fill="{text_color}">'
                    f'CVSS: {node.cvss_score:.1f}</text>'
                )

        return '\n'.join(parts)

    def _render_svg_edge(
        self,
        edge: GraphEdge,
        source: GraphNode,
        target: GraphNode,
    ) -> str:
        """Render a single edge as SVG."""
        # Calculate line with arrow
        x1, y1 = source.x, source.y
        x2, y2 = target.x, target.y

        # Shorten line to not overlap with nodes
        node_size = self.config.node_size
        dx, dy = x2 - x1, y2 - y1
        length = (dx * dx + dy * dy) ** 0.5

        if length > 0:
            # Adjust endpoints to node boundaries
            ratio_start = node_size / length
            ratio_end = node_size / length

            x1 = x1 + dx * ratio_start
            y1 = y1 + dy * ratio_start
            x2 = x2 - dx * ratio_end
            y2 = y2 - dy * ratio_end

        # Edge style
        dash = "5,5" if edge.style == "dashed" else "none"

        parts = [
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
            f'stroke="{edge.color}" stroke-width="{self.config.edge_width}" '
            f'stroke-dasharray="{dash}" marker-end="url(#arrow_{edge.edge_type.value})"/>',
        ]

        # Add label if present
        if edge.label:
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2
            parts.append(
                f'<text x="{mid_x}" y="{mid_y - 5}" text-anchor="middle" '
                f'font-size="{self.config.font_size - 2}" fill="{edge.color}">'
                f'{html.escape(edge.label)}</text>'
            )

        return '\n'.join(parts)

    def _render_svg_legend(self, text_color: str) -> str:
        """Render legend as SVG."""
        legend_items = [
            ("Critical", SeverityColor.CRITICAL.value),
            ("High", SeverityColor.HIGH.value),
            ("Medium", SeverityColor.MEDIUM.value),
            ("Low", SeverityColor.LOW.value),
            ("Info", SeverityColor.INFO.value),
        ]

        x_start = 20
        y_start = self.config.height - 30

        parts = [
            f'<g class="legend">',
            f'<text x="{x_start}" y="{y_start - 10}" font-size="10" '
            f'font-weight="bold" fill="{text_color}">Severity:</text>',
        ]

        for i, (label, color) in enumerate(legend_items):
            x = x_start + (i * 100)
            parts.extend([
                f'<rect x="{x}" y="{y_start}" width="15" height="15" fill="{color}"/>',
                f'<text x="{x + 20}" y="{y_start + 12}" font-size="10" '
                f'fill="{text_color}">{label}</text>',
            ])

        parts.append('</g>')
        return '\n'.join(parts)

    def render_html(
        self,
        graph: AttackGraph,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Render graph as interactive HTML with D3.js.

        Args:
            graph: Attack graph to render
            output_path: Optional path to save HTML

        Returns:
            HTML string
        """
        # Convert graph to JSON for D3
        graph_json = json.dumps(graph.to_dict())

        html_template = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{html.escape(graph.name)} - PHANTOM AI Attack Graph</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: {"#1a1a2e" if self.config.dark_mode else "#f5f5f5"};
            color: {"#fff" if self.config.dark_mode else "#333"};
        }}
        h1 {{
            text-align: center;
            margin-bottom: 20px;
        }}
        #graph-container {{
            background: {"#16213e" if self.config.dark_mode else "#fff"};
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
        }}
        .node {{
            cursor: pointer;
        }}
        .node:hover {{
            opacity: 0.8;
        }}
        .link {{
            stroke-opacity: 0.6;
        }}
        .tooltip {{
            position: absolute;
            padding: 10px;
            background: rgba(0,0,0,0.8);
            color: #fff;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
            max-width: 300px;
        }}
        .legend {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-top: 20px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .legend-color {{
            width: 15px;
            height: 15px;
            border-radius: 3px;
        }}
        #controls {{
            margin-bottom: 15px;
            text-align: center;
        }}
        button {{
            padding: 8px 16px;
            margin: 0 5px;
            cursor: pointer;
            border: none;
            border-radius: 4px;
            background: #3498db;
            color: white;
        }}
        button:hover {{
            background: #2980b9;
        }}
    </style>
</head>
<body>
    <h1>{html.escape(graph.name)}</h1>
    <div id="controls">
        <button onclick="zoomIn()">Zoom In</button>
        <button onclick="zoomOut()">Zoom Out</button>
        <button onclick="resetZoom()">Reset</button>
    </div>
    <div id="graph-container">
        <svg id="graph" width="{self.config.width}" height="{self.config.height}"></svg>
    </div>
    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background: {SeverityColor.CRITICAL.value}"></div> Critical</div>
        <div class="legend-item"><div class="legend-color" style="background: {SeverityColor.HIGH.value}"></div> High</div>
        <div class="legend-item"><div class="legend-color" style="background: {SeverityColor.MEDIUM.value}"></div> Medium</div>
        <div class="legend-item"><div class="legend-color" style="background: {SeverityColor.LOW.value}"></div> Low</div>
        <div class="legend-item"><div class="legend-color" style="background: {SeverityColor.INFO.value}"></div> Info</div>
    </div>
    <div id="tooltip" class="tooltip" style="display: none;"></div>

    <script>
        const graphData = {graph_json};

        const width = {self.config.width};
        const height = {self.config.height};

        const svg = d3.select("#graph");
        const g = svg.append("g");

        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => g.attr("transform", event.transform));

        svg.call(zoom);

        function zoomIn() {{ svg.transition().call(zoom.scaleBy, 1.5); }}
        function zoomOut() {{ svg.transition().call(zoom.scaleBy, 0.67); }}
        function resetZoom() {{ svg.transition().call(zoom.transform, d3.zoomIdentity); }}

        // Arrow markers for edges
        svg.append("defs").selectAll("marker")
            .data(["enables", "leads_to", "requires", "accesses", "exploits", "compromises"])
            .join("marker")
            .attr("id", d => "arrow-" + d)
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 20)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("fill", d => {{
                const colors = {{
                    "enables": "#27AE60",
                    "leads_to": "#3498DB",
                    "requires": "#9B59B6",
                    "accesses": "#F39C12",
                    "exploits": "#E74C3C",
                    "compromises": "#C0392B"
                }};
                return colors[d] || "#999";
            }})
            .attr("d", "M0,-5L10,0L0,5");

        // Force simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.edges)
                .id(d => d.id)
                .distance(150))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(50));

        // Draw edges
        const link = g.append("g")
            .selectAll("line")
            .data(graphData.edges)
            .join("line")
            .attr("class", "link")
            .attr("stroke", d => d.color)
            .attr("stroke-width", 2)
            .attr("marker-end", d => "url(#arrow-" + d.type + ")");

        // Draw nodes
        const node = g.append("g")
            .selectAll("g")
            .data(graphData.nodes)
            .join("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        // Node shapes
        node.each(function(d) {{
            const elem = d3.select(this);
            if (d.type === "GOAL") {{
                elem.append("ellipse")
                    .attr("rx", 40)
                    .attr("ry", 25)
                    .attr("fill", d.color)
                    .attr("stroke", "#333")
                    .attr("stroke-width", 2);
            }} else if (d.type === "ENTRY_POINT") {{
                elem.append("polygon")
                    .attr("points", "0,-25 -25,20 25,20")
                    .attr("fill", d.color)
                    .attr("stroke", "#333")
                    .attr("stroke-width", 2);
            }} else {{
                elem.append("ellipse")
                    .attr("rx", 35)
                    .attr("ry", 22)
                    .attr("fill", d.color)
                    .attr("stroke", "#333")
                    .attr("stroke-width", 2);
            }}
        }});

        // Node labels
        node.append("text")
            .attr("text-anchor", "middle")
            .attr("dy", 4)
            .attr("font-size", "11px")
            .attr("font-weight", "bold")
            .attr("fill", "#fff")
            .text(d => d.label.length > 12 ? d.label.slice(0, 12) + "..." : d.label);

        // CVSS labels
        node.append("text")
            .attr("text-anchor", "middle")
            .attr("dy", 40)
            .attr("font-size", "10px")
            .attr("fill", "{"#fff" if self.config.dark_mode else "#666"}")
            .text(d => d.cvss_score > 0 ? "CVSS: " + d.cvss_score.toFixed(1) : "");

        // Tooltip
        const tooltip = d3.select("#tooltip");

        node.on("mouseover", (event, d) => {{
            tooltip.style("display", "block")
                .html(`<strong>${{d.label}}</strong><br/>
                       Type: ${{d.type}}<br/>
                       Severity: ${{d.severity}}<br/>
                       ${{d.cvss_score > 0 ? "CVSS: " + d.cvss_score.toFixed(1) + "<br/>" : ""}}
                       ${{d.description ? d.description : ""}}`);
        }})
        .on("mousemove", (event) => {{
            tooltip.style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        }})
        .on("mouseout", () => {{
            tooltip.style("display", "none");
        }});

        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});

        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}

        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}

        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
    </script>
</body>
</html>'''

        if output_path:
            Path(output_path).write_text(html_template)
            logger.info(f"HTML saved to {output_path}")

        return html_template

    def render_dot(
        self,
        graph: AttackGraph,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Render graph as Graphviz DOT format.

        Args:
            graph: Attack graph to render
            output_path: Optional path to save DOT file

        Returns:
            DOT string
        """
        lines = [
            f'digraph "{graph.name}" {{',
            '    rankdir=TB;',
            '    node [fontname="Arial"];',
            '    edge [fontname="Arial"];',
            '',
        ]

        # Add nodes
        for node in graph.nodes:
            shape = node.shape
            color = node.color
            label = node.label

            if node.cvss_score > 0:
                label += f"\\nCVSS: {node.cvss_score:.1f}"

            lines.append(
                f'    "{node.id}" ['
                f'label="{label}", '
                f'shape={shape}, '
                f'style=filled, '
                f'fillcolor="{color}", '
                f'fontcolor="white"'
                f'];'
            )

        lines.append('')

        # Add edges
        for edge in graph.edges:
            style = "dashed" if edge.style == "dashed" else "solid"
            label = f', label="{edge.label}"' if edge.label else ''

            lines.append(
                f'    "{edge.source}" -> "{edge.target}" ['
                f'color="{edge.color}", '
                f'style={style}'
                f'{label}'
                f'];'
            )

        lines.append('}')

        dot_content = '\n'.join(lines)

        if output_path:
            Path(output_path).write_text(dot_content)
            logger.info(f"DOT saved to {output_path}")

        return dot_content

    def render_mermaid(
        self,
        graph: AttackGraph,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Render graph as Mermaid diagram.

        Args:
            graph: Attack graph to render
            output_path: Optional path to save Mermaid file

        Returns:
            Mermaid string
        """
        lines = [
            'flowchart TD',
            f'    %% {graph.name}',
            '',
        ]

        # Add nodes with styling
        for node in graph.nodes:
            node_id = node.id.replace('-', '_').replace(' ', '_')

            if node.node_type == NodeType.GOAL:
                lines.append(f'    {node_id}[("{node.label}")]')
            elif node.node_type == NodeType.ENTRY_POINT:
                lines.append(f'    {node_id}[/"{node.label}"\\]')
            else:
                lines.append(f'    {node_id}["{node.label}"]')

        lines.append('')

        # Add edges
        for edge in graph.edges:
            source_id = edge.source.replace('-', '_').replace(' ', '_')
            target_id = edge.target.replace('-', '_').replace(' ', '_')

            arrow = "-->" if edge.style != "dashed" else "-.->"
            label = f"|{edge.label}|" if edge.label else ""

            lines.append(f'    {source_id} {arrow}{label} {target_id}')

        lines.append('')

        # Add style classes
        lines.extend([
            '    %% Styling',
            '    classDef critical fill:#E74C3C,stroke:#333,color:#fff',
            '    classDef high fill:#E67E22,stroke:#333,color:#fff',
            '    classDef medium fill:#F39C12,stroke:#333,color:#fff',
            '    classDef low fill:#3498DB,stroke:#333,color:#fff',
            '    classDef info fill:#95A5A6,stroke:#333,color:#fff',
            '',
        ])

        # Apply styles
        for node in graph.nodes:
            node_id = node.id.replace('-', '_').replace(' ', '_')
            severity = node.severity.lower()
            if severity in ['critical', 'high', 'medium', 'low', 'info']:
                lines.append(f'    class {node_id} {severity}')

        mermaid_content = '\n'.join(lines)

        if output_path:
            Path(output_path).write_text(mermaid_content)
            logger.info(f"Mermaid saved to {output_path}")

        return mermaid_content

    def render_json(
        self,
        graph: AttackGraph,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Render graph as JSON.

        Args:
            graph: Attack graph to render
            output_path: Optional path to save JSON file

        Returns:
            JSON string
        """
        json_content = json.dumps(graph.to_dict(), indent=2)

        if output_path:
            Path(output_path).write_text(json_content)
            logger.info(f"JSON saved to {output_path}")

        return json_content

    def render(
        self,
        graph: AttackGraph,
        format: OutputFormat,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Render graph in specified format.

        Args:
            graph: Attack graph to render
            format: Output format
            output_path: Optional path to save output

        Returns:
            Rendered content
        """
        renderers = {
            OutputFormat.SVG: self.render_svg,
            OutputFormat.HTML: self.render_html,
            OutputFormat.DOT: self.render_dot,
            OutputFormat.JSON: self.render_json,
            OutputFormat.MERMAID: self.render_mermaid,
        }

        renderer = renderers.get(format)
        if not renderer:
            raise ValueError(f"Unsupported format: {format}")

        # H1 FIX: Track metrics
        self._metrics["renders_performed"] += 1
        self._metrics["by_format"][format.value] += 1

        return renderer(graph, output_path)

    def get_graph_metrics(self, graph: AttackGraph) -> Dict[str, Any]:
        """
        Calculate graph complexity metrics.

        Args:
            graph: Attack graph to analyze

        Returns:
            Dictionary of metrics
        """
        metrics = {
            "node_count": graph.node_count,
            "edge_count": graph.edge_count,
            "density": 0.0,
            "max_depth": 0,
            "critical_path_length": 0,
            "branching_factor": 0.0,
        }

        if graph.node_count > 1:
            max_edges = graph.node_count * (graph.node_count - 1)
            metrics["density"] = graph.edge_count / max_edges if max_edges > 0 else 0

        # Calculate depth using BFS (M1 FIX: uses module-level nx)
        if self._networkx_available and graph.nodes:

            G = nx.DiGraph()
            for node in graph.nodes:
                G.add_node(node.id)
            for edge in graph.edges:
                G.add_edge(edge.source, edge.target)

            # Find entry nodes
            entry_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]

            if entry_nodes:
                # Calculate max depth
                all_lengths = []
                for source in entry_nodes:
                    try:
                        lengths = nx.single_source_shortest_path_length(G, source)
                        all_lengths.extend(lengths.values())
                    except nx.NetworkXError as e:
                        # M2 FIX 2026-02-13: Log instead of silent pass
                        logger.debug(f"[CHAIN-VIZ] NetworkX depth calculation error: {e}")

                if all_lengths:
                    metrics["max_depth"] = max(all_lengths)

            # Calculate branching factor
            out_degrees = [G.out_degree(n) for n in G.nodes()]
            if out_degrees:
                metrics["branching_factor"] = sum(out_degrees) / len(out_degrees)

            # Find critical path (longest path to goal nodes)
            goal_nodes = [n.id for n in graph.nodes if n.node_type == NodeType.GOAL]
            if goal_nodes and entry_nodes:
                max_path = 0
                for source in entry_nodes:
                    for goal in goal_nodes:
                        try:
                            path_length = nx.shortest_path_length(G, source, goal)
                            max_path = max(max_path, path_length)
                        except (nx.NetworkXNoPath, nx.NodeNotFound) as e:
                            # M2 FIX 2026-02-13: Log instead of silent pass
                            logger.debug(f"[CHAIN-VIZ] Path not found {source}->{goal}: {e}")
                metrics["critical_path_length"] = max_path

        return metrics


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_chain_graph(
    chain: Dict[str, Any],
    config: Optional[VisualizationConfig] = None,
) -> AttackGraph:
    """
    Create attack graph from chain data.

    Args:
        chain: Chain data from ChainActionsEngine
        config: Optional visualization config

    Returns:
        AttackGraph
    """
    engine = ChainVisualizationEngine(config=config)
    return engine.create_graph_from_chain(chain)


def visualize_chain(
    chain: Dict[str, Any],
    format: OutputFormat = OutputFormat.SVG,
    output_path: Optional[str] = None,
    config: Optional[VisualizationConfig] = None,
) -> str:
    """
    Visualize a vulnerability chain.

    Args:
        chain: Chain data from ChainActionsEngine
        format: Output format
        output_path: Optional path to save output
        config: Optional visualization config

    Returns:
        Rendered visualization
    """
    engine = ChainVisualizationEngine(config=config)
    graph = engine.create_graph_from_chain(chain)
    return engine.render(graph, format, output_path)


def visualize_chains(
    chains: List[Dict[str, Any]],
    format: OutputFormat = OutputFormat.HTML,
    output_path: Optional[str] = None,
    name: str = "Attack Graph",
    config: Optional[VisualizationConfig] = None,
) -> str:
    """
    Visualize multiple vulnerability chains.

    Args:
        chains: List of chain data
        format: Output format
        output_path: Optional path to save output
        name: Graph name
        config: Optional visualization config

    Returns:
        Rendered visualization
    """
    engine = ChainVisualizationEngine(config=config)
    graph = engine.create_graph_from_chains(chains, name)
    return engine.render(graph, format, output_path)


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    # Main class
    "ChainVisualizationEngine",

    # Enums
    "OutputFormat",
    "NodeType",
    "EdgeType",
    "SeverityColor",
    "LayoutAlgorithm",

    # Data classes
    "GraphNode",
    "GraphEdge",
    "AttackGraph",
    "VisualizationConfig",

    # Convenience functions
    "create_chain_graph",
    "visualize_chain",
    "visualize_chains",
]
