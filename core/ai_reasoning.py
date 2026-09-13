from typing import Dict, Any, List, Optional

def generate_forensic_reasoning(
    subject: str,
    sender: str,
    risk_score: str,
    risk_reasons: List[str],
    rule_findings: List[Any],
    ml_prob: float,
    domain_rep: Optional[Any] = None,
    origin_geo: Optional[Any] = None
) -> str:
    """
    Synthesizes multi-source telemetry (ML, Heuristics, DNS/RDAP, Geolocation)
    into an executive-level Explainable AI Forensic Briefing mapped to MITRE ATT&CK.
    """
    mitre_ttps = []
    
    # Analyze rule triggers for MITRE mapping
    finding_texts = [getattr(r, 'finding', '') if hasattr(r, 'finding') else r.get('finding', '') for r in rule_findings]
    
    if any("urgency" in f.lower() or "credential" in f.lower() or "link" in f.lower() or "phishing" in f.lower() for f in finding_texts):
        mitre_ttps.append("T1566.002 - Phishing: Spearphishing Link / Social Engineering")
    if any("attachment" in f.lower() for f in finding_texts):
        mitre_ttps.append("T1566.001 - Phishing: Spearphishing Attachment")
    if any("mismatch" in f.lower() for f in finding_texts):
        mitre_ttps.append("T1585.002 - Establish Accounts: Email Accounts / Spoofing")
    if domain_rep and (getattr(domain_rep, "is_nrd", False) or not getattr(domain_rep, "has_mx_record", True)):
        mitre_ttps.append("T1583.001 - Acquire Infrastructure: Domains (Newly Registered / Disposable)")
    if domain_rep and getattr(domain_rep, "risk_level", "") == "HIGH":
        mitre_ttps.append("T1036.005 - Masquerading: Brand Impersonation")

    if not mitre_ttps:
        mitre_ttps.append("Standard Communications Profile (No Adversary TTPs Observed)")

    # Geolocation Origin
    geo_desc = "Unknown Origin"
    if origin_geo:
        city = getattr(origin_geo, "city", "") or ""
        country = getattr(origin_geo, "country", "Unknown") or "Unknown"
        org = getattr(origin_geo, "org", "") or ""
        loc_parts = [p for p in [city, country] if p and p != "UNKNOWN"]
        geo_desc = f"{', '.join(loc_parts)} (Network: {org or 'Public Transit'})"

    # Domain intel
    domain_desc = "Standard Domain Profile"
    if domain_rep:
        d_name = getattr(domain_rep, "domain", "Unknown")
        d_age = getattr(domain_rep, "domain_age_days", None)
        d_reg = getattr(domain_rep, "registrar", "Unknown")
        age_str = f"{d_age} days old" if d_age is not None else "Unknown age"
        domain_desc = f"Domain '{d_name}' ({age_str}, Registrar: {d_reg})"

    # Narrative generation
    if risk_score == "HIGH":
        verdict_summary = (
            f"Adversary activity detected with high confidence (ML Phishing Confidence: {ml_prob*100:.1f}%). "
            f"The payload utilizes deliberate deceptive engineering targeting recipient action."
        )
        recommendation = (
            "1. Immediate Perimeter Containment: Block identified IP and sender domain on perimeter firewalls/MTA.\n"
            "2. DNS Sinkhole: Blacklist sender domain across corporate resolver.\n"
            "3. Endpoint Audit: Check proxy logs for outgoing HTTP/S sessions to identified indicators."
        )
    elif risk_score == "SUSPICIOUS":
        verdict_summary = (
            f"Anomalous telemetry observed (ML Confidence: {ml_prob*100:.1f}%). "
            f"Multiple heuristic thresholds triggered; payload warrants analyst verification."
        )
        recommendation = (
            "1. Secondary Channel Verification: Confirm authenticity with sender out-of-band.\n"
            "2. Quarantine Review: Place email in sandbox inspection queue before release."
        )
    else:
        verdict_summary = (
            f"Legitimate email telemetry (ML Phishing Probability: {ml_prob*100:.1f}%). "
            f"Authentication claims and infrastructural reputation align with benign operational communications."
        )
        recommendation = "Standard operational delivery. No perimeter containment required."

    ttp_bullets = "\n".join([f"  • {t}" for t in mitre_ttps])

    briefing = f"""### 🛡️ Executive Threat Assessment & Attribution Briefing

**Threat Assessment:** {verdict_summary}

---

#### 🎯 MITRE ATT&CK Matrix Alignment
{ttp_bullets}

---

#### 🔬 Multimodal Telemetry Synthesis
• **Sender Infrastructure**: {geo_desc}
• **Domain Reputation**: {domain_desc}
• **Linguistic Classifier**: Scikit-Learn TF-IDF Threat Probability: **{ml_prob*100:.1f}%**
• **Key Trigger Reasons**: {'; '.join(risk_reasons[:3]) if risk_reasons else 'None'}

---

#### 📋 Recommended SOC Containment Plan
{recommendation}
"""
    return briefing
