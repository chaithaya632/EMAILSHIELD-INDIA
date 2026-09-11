import plotly.graph_objects as go
import datetime
from typing import List, Dict, Any, Optional

def build_relay_flight_map(timeline_events: List[Any]) -> Optional[go.Figure]:
    """
    Builds an interactive Plotly world map showing the sequential hop-by-hop relay path
    of an email from Origin Host -> Intermediate Mail Relays -> Destination Gateway.
    """
    hops_with_coords = []
    
    for idx, ev in enumerate(timeline_events):
        # ev can be an EventTimeline model or dict
        if hasattr(ev, 'model_dump'):
            d = ev.model_dump()
        elif isinstance(ev, dict):
            d = ev
        else:
            continue
            
        ip = d.get('ip')
        country = d.get('country') or 'Unknown'
        source = d.get('source') or f'Hop {idx+1}'
        lat = d.get('latitude')
        lon = d.get('longitude')
        city = d.get('city') or ''
        
        # If lat/lon not directly in EventTimeline, try resolving or check if available
        if lat is not None and lon is not None:
            hops_with_coords.append({
                "hop_idx": idx + 1,
                "label": source,
                "ip": ip or "N/A",
                "location": f"{city}, {country}".strip(", "),
                "lat": float(lat),
                "lon": float(lon)
            })

    fig = go.Figure()

    if not hops_with_coords:
        # Return an empty graceful globe
        fig.add_trace(go.Scattergeo(
            lon=[0], lat=[20],
            text=["No public IP coordinates detected in relay chain"],
            mode="text",
            textposition="middle center",
            textfont=dict(size=14, color="#888888")
        ))
        fig.update_layout(
            geo=dict(
                showland=True,
                landcolor="#1e1e24",
                showocean=True,
                oceancolor="#0f1117",
                showcountries=True,
                countrycolor="#2b2d42",
                projection_type="natural earth"
            ),
            margin=dict(l=0, r=0, t=30, b=0),
            height=420,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            title=dict(text="Relay Flight Path: No Public Hops Observed", font=dict(size=14, color="#cccccc"))
        )
        return fig

    # 1. Add Trajectory / Flight lines connecting consecutive hops
    if len(hops_with_coords) > 1:
        for i in range(len(hops_with_coords) - 1):
            h_from = hops_with_coords[i]
            h_to = hops_with_coords[i+1]
            fig.add_trace(go.Scattergeo(
                lon=[h_from['lon'], h_to['lon']],
                lat=[h_from['lat'], h_to['lat']],
                mode='lines',
                line=dict(width=2.5, color='#FFA15A', dash='solid'),
                hoverinfo='none',
                showlegend=False
            ))

    # 2. Add Hop Markers
    lats = [h['lat'] for h in hops_with_coords]
    lons = [h['lon'] for h in hops_with_coords]
    texts = [f"<b>{h['label']}</b><br>IP: {h['ip']}<br>Loc: {h['location']}" for h in hops_with_coords]
    labels = [f"#{h['hop_idx']} {h['ip']}" for h in hops_with_coords]
    
    # Colors: Hop 1 (Origin) is Red, intermediate is Orange, final is Green
    marker_colors = []
    for i in range(len(hops_with_coords)):
        if i == 0:
            marker_colors.append('#EF553B')  # Origin (Red)
        elif i == len(hops_with_coords) - 1 and len(hops_with_coords) > 1:
            marker_colors.append('#00CC96')  # Destination (Green)
        else:
            marker_colors.append('#FFA15A')  # Intermediate Relay (Orange)

    fig.add_trace(go.Scattergeo(
        lon=lons,
        lat=lats,
        text=texts,
        hoverinfo='text',
        mode='markers+text',
        textposition="top center",
        textfont=dict(size=11, color="#ffffff"),
        marker=dict(
            size=14,
            color=marker_colors,
            line=dict(width=2, color='#ffffff'),
            symbol='circle'
        ),
        name="Relay Hops"
    ))

    # Center map on hops
    avg_lat = sum(lats) / len(lats)
    avg_lon = sum(lons) / len(lons)

    fig.update_layout(
        geo=dict(
            showland=True,
            landcolor="#1c202a",
            showocean=True,
            oceancolor="#0e1117",
            showcountries=True,
            countrycolor="#333b4d",
            coastlinecolor="#333b4d",
            projection_type="natural earth",
            center=dict(lat=avg_lat, lon=avg_lon)
        ),
        margin=dict(l=0, r=0, t=40, b=10),
        height=450,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        title=dict(
            text=f"✈️ Physical Email Relay Flight Path ({len(hops_with_coords)} Hops Traced)",
            font=dict(size=15, color="#ffffff")
        ),
        showlegend=False
    )

    return fig

import re
import email.utils

def parse_received_timestamp(received_header: str) -> Optional[datetime.datetime]:
    """Extract and parse RFC 2822 datetime from the end of a Received header."""
    if not received_header or ";" not in received_header:
        return None
    date_part = received_header.split(";")[-1].strip()
    try:
        dt = email.utils.parsedate_to_datetime(date_part)
        return dt
    except Exception:
        return None

def extract_mta_identifiers(received_header: str) -> Dict[str, str]:
    """Extract 'from' and 'by' MTA hostnames and IP candidates from Received header."""
    from_match = re.search(r'\bfrom\s+([^\s;]+)', received_header, re.IGNORECASE)
    by_match = re.search(r'\bby\s+([^\s;]+)', received_header, re.IGNORECASE)
    
    from_host = from_match.group(1) if from_match else "Unknown"
    by_host = by_match.group(1) if by_match else "Unknown"
    
    return {"from_mta": from_host, "by_mta": by_host}

def analyze_relay_transit(received_chain: List[str]) -> Dict[str, Any]:
    """
    Analyzes the chronological MTA relay path (from Origin Host -> Final Gateway).
    Calculates hop latency (Δt), detects forged timestamps, and assigns trust classifications.
    Note: Received headers appear in reverse chronological order in raw email (top is final, bottom is origin).
    """
    if not received_chain:
        return {
            "total_hops": 0,
            "total_transit_time_sec": 0,
            "hops": [],
            "anomalies": []
        }

    # Reverse to chronological order (Origin -> Relays -> Destination)
    chronological_hops = list(reversed(received_chain))
    parsed_hops = []
    anomalies = []

    for idx, rec in enumerate(chronological_hops):
        dt = parse_received_timestamp(rec)
        mta_info = extract_mta_identifiers(rec)
        
        # Determine hop role
        if idx == 0:
            role = "Originating Client / Outbound MTA"
            trust_level = "Untrusted (Sender Controlled)"
        elif idx == len(chronological_hops) - 1:
            role = "Inbound Enterprise MX Gateway"
            trust_level = "Trusted (Receiving Infrastructure)"
        else:
            role = f"Intermediate Relay #{idx}"
            trust_level = "Intermediate Infrastructure"

        parsed_hops.append({
            "hop_number": idx + 1,
            "timestamp": dt,
            "timestamp_str": dt.strftime("%Y-%m-%d %H:%M:%S %Z") if dt else "Unparseable",
            "from_mta": mta_info["from_mta"],
            "by_mta": mta_info["by_mta"],
            "role": role,
            "trust_level": trust_level,
            "delay_sec": 0,
            "delay_display": "0s",
            "raw_snippet": rec[:120].strip()
        })

    # Calculate delays (Δt) between consecutive hops
    total_transit = 0
    for i in range(1, len(parsed_hops)):
        prev = parsed_hops[i - 1]
        curr = parsed_hops[i]
        
        if prev["timestamp"] and curr["timestamp"]:
            try:
                diff = (curr["timestamp"] - prev["timestamp"]).total_seconds()
                curr["delay_sec"] = int(diff)
                
                if diff < 0:
                    curr["delay_display"] = f"⚠️ {int(diff)}s (Negative Delta)"
                    anom_msg = f"Hop #{curr['hop_number']} has negative transit delay ({int(diff)}s) compared to Hop #{prev['hop_number']}. Probable forged header or severe MTA clock drift."
                    anomalies.append(anom_msg)
                elif diff > 3600:
                    hours = diff / 3600
                    curr["delay_display"] = f"{hours:.1f} hours"
                    anomalies.append(f"Hop #{curr['hop_number']} suffered extended delay ({hours:.1f}h) while queued at '{prev['by_mta']}'.")
                elif diff > 60:
                    mins = diff / 60
                    curr["delay_display"] = f"{mins:.1f} mins"
                else:
                    curr["delay_display"] = f"{int(diff)}s"
                
                if diff > 0:
                    total_transit += diff
            except Exception:
                curr["delay_display"] = "N/A"

    return {
        "total_hops": len(parsed_hops),
        "total_transit_time_sec": int(total_transit),
        "total_transit_display": f"{int(total_transit)}s" if total_transit < 60 else f"{total_transit/60:.1f} mins",
        "hops": parsed_hops,
        "anomalies": anomalies
    }

