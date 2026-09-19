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
        "Hash": "#ec4899",         # Pink
        "ASN": "#0284c7",          # Sky Blue
        "Registrar": "#8b5cf6",    # Violet
        "Hosting_Provider": "#059669", # Teal
        "Cloud_Provider": "#d97706",   # Amber
        "Threat_Feed": "#dc2626",      # Red
        "VPN": "#10b981",              # Emerald
        "Tor": "#e11d48"               # Rose
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


def build_case_infrastructure_graph(case_id: str, case_data: Dict[str, Any]) -> go.Figure:
    """
    Constructs an interactive NetworkX + Plotly Attack Graph for a single case,
    linking the Case to Origin IP, ASN, Hosting/Cloud Provider, Domain, Registrar,
    and Threat Intelligence Feeds.
    """
    G = nx.Graph()
    
    TYPE_COLORS = {
        "Case": "#ef4444",         # Red for active case
        "IP": "#06b6d4",           # Cyan
        "Domain": "#a855f7",       # Purple
        "URL": "#f59e0b",          # Amber
        "Hash": "#ec4899",         # Pink
        "ASN": "#0284c7",          # Sky Blue
        "Registrar": "#8b5cf6",    # Violet
        "Cloud_Provider": "#d97706", # Orange
        "Threat_Feed": "#dc2626",  # Bright Red
        "VPN": "#10b981",          # Emerald
        "Tor": "#e11d48"           # Rose
    }
    
    # Add Case Node
    G.add_node(case_id, node_type="Case", color=TYPE_COLORS["Case"], size=24, is_current=True)
    
    infra = case_data.get("infrastructure_intel") or {}
    if hasattr(infra, "model_dump"):
        infra = infra.model_dump()
        
    sloc = case_data.get("sender_location") or {}
    
    # 1. IP and Infrastructure connections
    ip = infra.get("origin_ip") or sloc.get("sender_ip")
    if ip and ip not in ["Not available / Relay-masked", "127.0.0.1", "UNKNOWN"]:
        G.add_node(ip, node_type="IP", color=TYPE_COLORS["IP"], size=16, is_current=False)
        G.add_edge(case_id, ip)
        
        # ASN
        asn = infra.get("asn") or sloc.get("asn")
        if asn and asn not in ["None", "Unknown ASN", "UNKNOWN"]:
            asn_label = f"ASN: {asn}"
            G.add_node(asn_label, node_type="ASN", color=TYPE_COLORS["ASN"], size=14, is_current=False)
            G.add_edge(ip, asn_label)
            
        # Cloud Provider
        cloud = infra.get("cloud_indicator") or {}
        if cloud.get("is_cloud_hosted") and cloud.get("provider") not in ["None / Dedicated / Residential", "UNKNOWN"]:
            c_label = f"Cloud: {cloud.get('provider')}"
            G.add_node(c_label, node_type="Cloud_Provider", color=TYPE_COLORS["Cloud_Provider"], size=14, is_current=False)
            G.add_edge(ip, c_label)
            
        # VPN
        vpn = infra.get("vpn_indicator") or {}
        if vpn.get("status") == "DETECTED":
            vpn_label = f"VPN: {vpn.get('provider') or 'Commercial VPN'}"
            G.add_node(vpn_label, node_type="VPN", color=TYPE_COLORS["VPN"], size=14, is_current=False)
            G.add_edge(ip, vpn_label)
            
        # Tor
        tor = infra.get("tor_indicator") or {}
        if tor.get("status") == "DETECTED":
            tor_label = "Tor Exit Relay"
            G.add_node(tor_label, node_type="Tor", color=TYPE_COLORS["Tor"], size=14, is_current=False)
            G.add_edge(ip, tor_label)
            
    # 2. Domain and Registrar connections
    domain = infra.get("domain") or case_data.get("sender_domain")
    if not domain and case_data.get("sender"):
        from core.domain_reputation import extract_domain
        domain = extract_domain(case_data.get("sender"))
    if domain and domain != "unknown.com":
        G.add_node(domain, node_type="Domain", color=TYPE_COLORS["Domain"], size=16, is_current=False)
        G.add_edge(case_id, domain)
        
        # Registrar
        reg_intel = infra.get("registrar_intel") or {}
        reg_name = reg_intel.get("registrar")
        if not reg_name or reg_name == "Unknown":
            drep = case_data.get("domain_reputation") or {}
            reg_name = drep.get("registrar") if isinstance(drep, dict) else getattr(drep, "registrar", None)
        if reg_name and reg_name != "Unknown":
            reg_label = f"Registrar: {reg_name}"
            G.add_node(reg_label, node_type="Registrar", color=TYPE_COLORS["Registrar"], size=14, is_current=False)
            G.add_edge(domain, reg_label)
            
    # 3. Threat Feed
    t_match = infra.get("threat_intel_match") or {}
    if t_match.get("status") == "MATCH":
        tf_label = f"Threat Feed: {t_match.get('feed_name') or 'Blacklist Match'}"
        G.add_node(tf_label, node_type="Threat_Feed", color=TYPE_COLORS["Threat_Feed"], size=16, is_current=False)
        if ip and ip in G.nodes:
            G.add_edge(ip, tf_label)
        elif domain and domain in G.nodes:
            G.add_edge(domain, tf_label)
        else:
            G.add_edge(case_id, tf_label)
            
    # 4. Attachments / Hashes
    for att in (case_data.get("attachment_analyses") or []):
        sha = att.get("sha256") if isinstance(att, dict) else getattr(att, "sha256", None)
        if sha and sha != "N/A":
            h_label = f"SHA256: {sha[:8]}..."
            G.add_node(h_label, node_type="Hash", color=TYPE_COLORS["Hash"], size=12, is_current=False)
            G.add_edge(case_id, h_label)
            
    # 5. Dangerous URLs
    for u in (case_data.get("url_analyses") or []):
        u_risk = u.get("risk_level") if isinstance(u, dict) else getattr(u, "risk_level", "LOW")
        if u_risk in ["CRITICAL", "HIGH", "MEDIUM"]:
            u_dom = u.get("domain") if isinstance(u, dict) else getattr(u, "domain", "")
            if u_dom and u_dom != domain:
                u_label = f"URL: {u_dom}"
                G.add_node(u_label, node_type="URL", color=TYPE_COLORS["URL"], size=12, is_current=False)
                G.add_edge(case_id, u_label)

    # Layout
    pos = nx.spring_layout(G, k=0.55, iterations=60, seed=42)
    
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color='#475569'),
        hoverinfo='none',
        mode='lines'
    )

    node_x = []
    node_y = []
    node_colors = []
    node_sizes = []
    hover_texts = []
    text_labels = []

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        data = G.nodes[node]
        node_colors.append(data["color"])
        node_sizes.append(data["size"])
        ntype = data["node_type"]
        
        if ntype == "Case":
            hover_texts.append(f"📁 Case: {node}")
            text_labels.append(str(node))
        else:
            hover_texts.append(f"[{ntype}] {node}")
            text_labels.append(str(node)[:18] + "..." if len(str(node)) > 18 else str(node))

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=text_labels,
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

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(text=f"🕸️ Threat Infrastructure Attack Graph — {case_id}", font=dict(size=15, color="#f8fafc")),
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

