import networkx as nx
import plotly.graph_objects as go
from typing import List, Dict, Any, Optional
from core.case_store import get_all_indicators, get_all_cases

def get_campaign_clusters() -> List[Dict[str, Any]]:
    """
    Identifies connected threat clusters across historical cases in SQLite.
    Groups cases that share identical IPs, sending domains, attachment hashes, or phishing URLs.
    """
    indicators = get_all_indicators()
    if not indicators:
        return []

    # Build bipartite Graph between cases and indicators
    G = nx.Graph()
    for ind in indicators:
        case_id = ind["case_id"]
        val = ind["value"]
        itype = ind["type"]
        G.add_node(case_id, node_type="Case")
        G.add_node(val, node_type=itype)
        G.add_edge(case_id, val)

    # Connected components
    components = list(nx.connected_components(G))
    campaigns = []
    
    # Sort by number of cases descending
    cluster_idx = 1
    for comp in components:
        cases_in_cluster = [n for n in comp if G.nodes[n].get("node_type") == "Case"]
        iocs_in_cluster = [
            {"value": n, "type": G.nodes[n].get("node_type", "Indicator")}
            for n in comp if G.nodes[n].get("node_type") != "Case"
        ]
        
        # Only label as a campaign cluster if it links 2+ cases, or has high-value malicious IOCs
        cluster_id = f"Campaign C-{cluster_idx:03d}"
        
        # Determine primary shared vector
        types_count = {}
        for ioc in iocs_in_cluster:
            t = ioc["type"]
            types_count[t] = types_count.get(t, 0) + 1
        
        summary_parts = []
        if len(cases_in_cluster) > 1:
            summary_parts.append(f"{len(cases_in_cluster)} Linked Incident(s)")
        else:
            summary_parts.append("Single Incident")
            
        if "IP" in types_count:
            summary_parts.append(f"{types_count['IP']} Shared IP(s)")
        if "URL" in types_count:
            summary_parts.append(f"{types_count['URL']} Phishing Link(s)")
        if "Hash" in types_count:
            summary_parts.append(f"{types_count['Hash']} Malware Hash(es)")
            
        summary = " | ".join(summary_parts)

        campaigns.append({
            "campaign_id": cluster_id,
            "case_count": len(cases_in_cluster),
            "cases": cases_in_cluster,
            "ioc_count": len(iocs_in_cluster),
            "iocs": iocs_in_cluster,
            "summary": summary
        })
        cluster_idx += 1

    return sorted(campaigns, key=lambda c: (c["case_count"], c["ioc_count"]), reverse=True)

def build_correlation_graph(current_case_id: str = None, campaign_filter: str = None) -> go.Figure:
    """
    Constructs an interactive NetworkX + Plotly Attack Graph with cyber aesthetic,
    connecting Cases with their shared infrastructure IOCs (IP, Domain, URL, Hash).
    """
    indicators = get_all_indicators()
    
    G = nx.Graph()
    
    # Type color palette (Cyber / SOC theme)
    TYPE_COLORS = {
        "Case": "#3b82f6",         # Blue
        "Current_Case": "#ef4444", # High-contrast Red
        "IP": "#06b6d4",           # Cyan
        "Domain": "#a855f7",       # Purple
        "URL": "#f59e0b",          # Amber
        "Email": "#10b981",        # Emerald
        "Hash": "#ec4899"          # Pink
    }
    
    filtered_cases = set()
    if campaign_filter:
        clusters = get_campaign_clusters()
        for cl in clusters:
            if cl["campaign_id"] == campaign_filter:
                filtered_cases = set(cl["cases"])
                break

    for ind in indicators:
        case_id = ind["case_id"]
        val = ind["value"]
        itype = ind.get("type", "Indicator")
        
        if filtered_cases and case_id not in filtered_cases:
            continue
            
        # Node properties
        is_curr = (case_id == current_case_id)
        c_color = TYPE_COLORS["Current_Case"] if is_curr else TYPE_COLORS["Case"]
        
        G.add_node(case_id, node_type="Case", color=c_color, size=24 if is_curr else 18, is_current=is_curr)
        G.add_node(val, node_type=itype, color=TYPE_COLORS.get(itype, "#64748b"), size=12, is_current=False)
        G.add_edge(case_id, val)

    if len(G.nodes) == 0:
        fig = go.Figure()
        fig.add_annotation(
            text="No correlated investigation records found yet.",
            showarrow=False,
            font=dict(size=14, color="#94a3b8")
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=420
        )
        return fig

    # Layout with spring physics
    pos = nx.spring_layout(G, k=0.45, iterations=50, seed=42)
    
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.2, color='#334155'),
        hoverinfo='none',
        mode='lines'
    )

    node_x = []
    node_y = []
    node_colors = []
    node_sizes = []
    hover_texts = []
    display_labels = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        data = G.nodes[node]
        node_colors.append(data["color"])
        node_sizes.append(data["size"])
        
        ntype = data["node_type"]
        if ntype == "Case":
            label = f"📁 {node}" + (" (THIS CASE)" if data["is_current"] else "")
            display_labels.append(node)
        else:
            label = f"[{ntype}] {node}"
            display_labels.append(str(node)[:15] + "..." if len(str(node)) > 15 else str(node))
            
        hover_texts.append(label)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=[n if G.nodes[n]["node_type"] == "Case" else "" for n in G.nodes()],
        textposition="top center",
        textfont=dict(size=10, color="#f8fafc"),
        hoverinfo='text',
        hovertext=hover_texts,
        marker=dict(
            showscale=False,
            color=node_colors,
            size=node_sizes,
            line=dict(width=2, color='#0f172a')
        )
    )

    title_text = f"🕸️ Threat Infrastructure Attack Graph"
    if campaign_filter:
        title_text += f" — {campaign_filter}"

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(text=title_text, font=dict(size=15, color="#f8fafc")),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=10, r=10, t=50),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=460
        )
    )
    return fig

