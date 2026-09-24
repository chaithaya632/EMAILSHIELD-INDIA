import re
from typing import Dict, Any, List
from core.indicators import get_registrable_domain
from core.domain_intel import KNOWN_ESP_DOMAINS
from core.auth_claims import KNOWN_LEGIT_ESPS

def _is_auth_ok(auth: Any) -> bool:
    if not auth:
        return False
    if isinstance(auth, dict):
        eff = auth.get("effective_dmarc", "")
    else:
        eff = getattr(auth, "effective_dmarc", "")
    return eff in ["PASS", "PASS (Delegated ESP)", "PASS (Unverified Alignment)"]

def evaluate_rules(
    parsed_email: Dict[str, Any],
    domain_rep: Any = None,
    url_analyses: Any = None,
    auth_alignment: Any = None,
    attachment_analyses: Any = None,
    lookalike_analysis: Any = None,
    bec_telemetry: Any = None,
    relay_transit: Any = None,
    content_type: Any = None,
    infrastructure_intel: Any = None,
    normalization_data: Any = None
) -> List[Dict[str, str]]:
    findings = []
    headers = parsed_email.get("headers", {})
    body = parsed_email.get("body", "").lower()
    
    # Check if this email is a recognized newsletter or bulk mailing
    is_newsletter = bool(
        headers.get("list-unsubscribe") or
        headers.get("list-id") or
        str(headers.get("precedence", "")).lower() == "bulk" or
        headers.get("feedback-id") or
        (content_type and any(c in str(content_type) for c in ["Newsletter", "Promotional", "Subscription", "Marketing"]))
    )

    # 1. Reply-To Mismatch
    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    
    # Helper to extract just the email address
    def extract_email(header_val: str):
        if not isinstance(header_val, str):
            return ""
        match = re.search(r'<(.+?)>', header_val)
        if match:
            return match.group(1).lower()
        return header_val.strip().lower()

    def get_base_domain(email_str: str):
        if not email_str:
            return ""
        dom = email_str.split("@")[-1].lower() if "@" in email_str else email_str.lower()
        return get_registrable_domain(dom)

    if reply_to and from_header:
        f_email = extract_email(from_header)
        r_email = extract_email(reply_to)
        
        if f_email and r_email and f_email != r_email:
            f_dom = get_base_domain(f_email)
            r_dom = get_base_domain(r_email)
            same_org = (f_dom == r_dom) and bool(f_dom)

            has_bec_fraud = bec_telemetry and (
                bec_telemetry.get("is_financial_lure") or
                bec_telemetry.get("is_display_name_spoof") or
                bec_telemetry.get("is_executive_lure")
            )

            # High severity ONLY when impersonating executives/finance or diverting away from legitimate brand
            if has_bec_fraud:
                findings.append({
                    "rule_id": "RULE-001",
                    "finding": "Reply-To Diversion (Financial/Executive Lure)",
                    "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                    "severity": "HIGH",
                    "explanation": "Reply-To address redirects replies away from apparent sender during an executive/financial lure."
                })
            elif not same_org and not is_newsletter:
                findings.append({
                    "rule_id": "RULE-001",
                    "finding": "Reply-To address mismatch",
                    "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                    "severity": "MEDIUM",
                    "explanation": "Reply-To address differs from sender domain. Verify recipient before sending sensitive data."
                })
            elif is_newsletter or same_org:
                # Standard practice in bulk publishing (e.g. newsletter dispatch email vs personal reply address)
                findings.append({
                    "rule_id": "RULE-001-INFO",
                    "finding": "Author Reply-To configured",
                    "evidence": f"From: {from_header} | Reply-To: {reply_to}",
                    "severity": "LOW",
                    "explanation": "Author or support direct reply address configured for subscriber convenience."
                })

    # 2. Return-Path Mismatch
    return_path = headers.get("return-path", "")
    if return_path and from_header:
        f_email = extract_email(from_header)
        rp_email = extract_email(return_path)
        if f_email and rp_email and f_email != rp_email:
            f_dom = get_base_domain(f_email)
            rp_dom = get_base_domain(rp_email)
            same_rp_org = (f_dom == rp_dom) and bool(f_dom)
            auth_ok = _is_auth_ok(auth_alignment)

            if not same_rp_org and not is_newsletter and not auth_ok:
                findings.append({
                    "rule_id": "RULE-002",
                    "finding": "Return-Path mismatch",
                    "evidence": f"From: {from_header} | Return-Path: {return_path}",
                    "severity": "MEDIUM",
                    "explanation": "Return-Path differs from the From address."
                })
            else:
                findings.append({
                    "rule_id": "RULE-002-INFO",
                    "finding": "ESP Bulk Return-Path routing",
                    "evidence": f"From: {from_header} | Return-Path: {return_path}",
                    "severity": "LOW",
                    "explanation": "Standard bounce handling mailbox routed via authorized email delivery provider."
                })

    # Check authentication status
    auth_ok = _is_auth_ok(auth_alignment)
    if not auth_ok:
        auth_res = str(headers.get("authentication-results", "")).lower()
        if "dmarc=pass" in auth_res or ("spf=pass" in auth_res and "dkim=pass" in auth_res):
            auth_ok = True

    subject_text = str(headers.get("subject", "")).lower()
    full_text = f"{subject_text} {body}".lower()

    # 3. Urgency language & Extortion Scareware
    urgency_keywords = [
        "urgent", "immediate action required", "account suspension", "verify your account",
        "overdue", "final notice", "final warning", "account locked", "account blocked",
        "account has been locked", "account has been blocked", "action required",
        "will be deleted", "will be removed today", "backup halted", "storage full",
        "space full", "payment failed", "payment declined", "reschedule",
        "delivery status notification", "schedule confirmation", "claim your", "2nd attempt"
    ]
    for kw in urgency_keywords:
        if kw in full_text:
            is_suspension = any(s in full_text for s in ["suspension", "verify your account", "locked", "blocked", "deleted"])
            findings.append({
                "rule_id": "RULE-007",
                "finding": "Urgency / Threat language detected",
                "evidence": f"Keyword found: '{kw}'",
                "severity": "HIGH" if (not auth_ok and is_suspension) else ("MEDIUM" if not auth_ok else "LOW"),
                "explanation": "Subject or body contains language intended to create urgency, panic, or accelerated victim response."
            })
            break # Only fire once

    # 4. Credential & Billing Update requests
    cred_keywords = [
        "password", "login", "credentials", "click here to verify", "update your billing",
        "update your payment", "payment failed", "payment declined", "update your walmart",
        "renew your subscription", "confirm the payment", "verify your login"
    ]
    for kw in cred_keywords:
        if kw in full_text:
            findings.append({
                "rule_id": "RULE-006",
                "finding": "Credential / Payment Action request",
                "evidence": f"Keyword found: '{kw}'",
                "severity": "MEDIUM" if not auth_ok else "LOW",
                "explanation": "Message references account login, credential verification, or urgent billing update."
            })
            break

    # 4b. Cloud Storage Deletion / Extortion Scareware
    extortion_patterns = [
        r"photos (?:and|&) videos will be deleted",
        r"cloud (?:space|storage) (?:is )?full",
        r"backup halted",
        r"cloud files will be (?:removed|deleted)",
        r"your storage is (?:almost )?full",
        r"all storage used"
    ]
    is_official_cloud = any(f"@{dom}" in from_header.lower() for dom in ["google.com", "microsoft.com", "apple.com", "icloud.com", "dropbox.com"])
    if not is_official_cloud:
        for ep in extortion_patterns:
            if re.search(ep, full_text):
                findings.append({
                    "rule_id": "RULE-020",
                    "finding": "Cloud Storage Extortion / Scareware Lure",
                    "evidence": f"Scareware pattern matched: '{ep}'",
                    "severity": "HIGH",
                    "explanation": "Email exploits artificial urgency regarding data loss or photo deletion to solicit payment or credentials."
                })
                break

    # 4c. Deceptive Brand Subdomain / Combo-Squatting in Sender Domain
    from core.domain_reputation import OFFICIAL_BRAND_DOMAINS
    raw_from_dom = extract_email(from_header).split("@")[-1].lower() if "@" in extract_email(from_header) else ""
    if not auth_ok and raw_from_dom:
        for mb, legit_doms in OFFICIAL_BRAND_DOMAINS.items():
            if mb in raw_from_dom and not any(raw_from_dom == ld or raw_from_dom.endswith("." + ld) for ld in legit_doms):
                findings.append({
                    "rule_id": "RULE-021",
                    "finding": f"Deceptive Brand Subdomain Spoofing ({mb.upper()})",
                    "evidence": f"Sender domain '{raw_from_dom}' inserts brand '{mb}' into unauthorized host",
                    "severity": "HIGH",
                    "explanation": "Adversary embeds a trusted commercial brand name as a deceptive subdomain or prefix on an unrelated server."
                })
                break

    # 5. Attachment metadata anomaly
    attachments = parsed_email.get("attachments", [])
    suspicious_exts = [".exe", ".scr", ".vbs", ".js", ".bat", ".iso", ".img", ".zip"]
    for att in attachments:
        filename = att.get("filename", "").lower()
        if any(filename.endswith(ext) for ext in suspicious_exts):
            findings.append({
                "rule_id": "RULE-008",
                "finding": "Suspicious attachment extension",
                "evidence": f"File: {filename}",
                "severity": "HIGH",
                "explanation": "Attachment has a potentially dangerous extension."
            })

    # 6. Domain Reputation Anomalies
    if domain_rep:
        if getattr(domain_rep, "is_nrd", False):
            findings.append({
                "rule_id": "RULE-009",
                "finding": "Newly Registered Domain (NRD)",
                "evidence": f"Domain '{domain_rep.domain}' registered {domain_rep.domain_age_days} days ago",
                "severity": "HIGH",
                "explanation": "Newly created domains have high statistical correlation with cyber threats."
            })
        if not getattr(domain_rep, "has_mx_record", True):
            findings.append({
                "rule_id": "RULE-010",
                "finding": "Missing DNS / MX Records",
                "evidence": f"Domain '{domain_rep.domain}' lacks valid DNS records",
                "severity": "HIGH",
                "explanation": "Sender domain cannot legitimately receive mail; probable spoofing."
            })
        if getattr(domain_rep, "risk_level", "LOW") == "HIGH" and not getattr(domain_rep, "is_nrd", False):
            findings.append({
                "rule_id": "RULE-011",
                "finding": "Brand Impersonation / Deceptive Domain",
                "evidence": f"Domain '{domain_rep.domain}' exhibits brand impersonation indicators",
                "severity": "HIGH",
                "explanation": "Domain attempts to mimic a legitimate institutional or financial brand."
            })

    # 7. URL / Link Threat Intelligence
    if url_analyses:
        for u in url_analyses:
            risk = getattr(u, "risk_level", "LOW")
            cat = getattr(u, "threat_category", "Unknown")
            defanged = getattr(u, "defanged_url", getattr(u, "url", "Unknown"))
            impact = getattr(u, "potential_impact", "")
            
            if risk == "CRITICAL":
                findings.append({
                    "rule_id": "RULE-012",
                    "finding": f"Critical Malicious Link ({cat})",
                    "evidence": f"URL: {defanged} | Threat: {cat} | Potential Impact: {impact[:90]}...",
                    "severity": "HIGH",
                    "explanation": "Embedded hyperlink links to a weaponized malware dropper or counterfeit credential harvesting portal."
                })
            elif risk == "HIGH":
                findings.append({
                    "rule_id": "RULE-013",
                    "finding": f"High-Risk Phishing Link ({cat})",
                    "evidence": f"URL: {defanged} | Threat: {cat} | Potential Impact: {impact[:90]}...",
                    "severity": "HIGH",
                    "explanation": "Embedded hyperlink matches known phishing lures, typosquatting patterns, or raw IP hosts."
                })

    # 8. Cryptographic DMARC Alignment Bypass
    if auth_alignment:
        eff_dmarc = auth_alignment.get("effective_dmarc", "") if isinstance(auth_alignment, dict) else getattr(auth_alignment, "effective_dmarc", "")
        threat_det = auth_alignment.get("threat_detected", False) if isinstance(auth_alignment, dict) else getattr(auth_alignment, "threat_detected", False)
        if threat_det or "Alignment Bypass" in eff_dmarc:
            d_reason = auth_alignment.get("dmarc_reason") if isinstance(auth_alignment, dict) else getattr(auth_alignment, "dmarc_reason", None)
            findings.append({
                "rule_id": "RULE-014",
                "finding": "DMARC Alignment Failure / Domain Spoofing",
                "evidence": d_reason or "Header-From domain unaligned with SPF/DKIM",
                "severity": "HIGH",
                "explanation": "Sender attempted SPF/DKIM bypass using third-party signing domain while faking visible Header-From."
            })

    # 9. Attachment Forensics (Double Extensions / Macros / Disk Images)
    if attachment_analyses:
        for att in attachment_analyses:
            r_level = att.get("risk_level", "LOW")
            fname = att.get("filename", "")
            flags = att.get("risk_flags", [])
            
            if att.get("is_double_ext"):
                findings.append({
                    "rule_id": "RULE-015",
                    "finding": f"Double Extension Payload: {fname}",
                    "evidence": f"Attachment: {fname} | SHA-256: {att.get('sha256')[:16]}...",
                    "severity": "HIGH",
                    "explanation": "Adversary masked an executable binary with a false document extension (e.g. .pdf.exe)."
                })
            elif r_level in ["CRITICAL", "HIGH"]:
                findings.append({
                    "rule_id": "RULE-015B",
                    "finding": f"Suspicious/Weaponized Attachment: {fname}",
                    "evidence": f"File: {fname} | Indicators: {'; '.join(flags)}",
                    "severity": "HIGH" if r_level == "CRITICAL" else "MEDIUM",
                    "explanation": "Attachment exhibits weaponized traits (executable headers, macros, or disk container abuse)."
                })

    # 10. Lookalike Domain & Homoglyph Impersonation
    if lookalike_analysis and lookalike_analysis.get("is_lookalike"):
        target_b = lookalike_analysis.get("impersonated_brand", "Established Brand")
        tech = lookalike_analysis.get("technique", "Typosquatting")
        findings.append({
            "rule_id": "RULE-016",
            "finding": f"Brand Impersonation / Lookalike Domain ({target_b})",
            "evidence": f"Domain: {lookalike_analysis.get('domain')} | Technique: {tech} | Reasons: {'; '.join(lookalike_analysis.get('reasons', []))}",
            "severity": "HIGH",
            "explanation": "Adversary registered a deceptive lookalike domain using homoglyphs, brand combos, or typosquatting."
        })

    # 11. Display-Name Spoofing & BEC Wire Fraud Lures
    if bec_telemetry:
        if bec_telemetry.get("is_display_name_spoof"):
            findings.append({
                "rule_id": "RULE-017",
                "finding": f"Display-Name Executive Spoofing ({bec_telemetry.get('display_name')})",
                "evidence": f"Display: '{bec_telemetry.get('display_name')}' | Actual: '{bec_telemetry.get('sender_email')}'",
                "severity": "HIGH",
                "explanation": "Executive persona name used on an unauthorized free webmail address to mislead recipient."
            })
        if bec_telemetry.get("is_financial_lure") and bec_telemetry.get("bec_risk_score", 0) >= 40:
            findings.append({
                "rule_id": "RULE-017B",
                "finding": f"BEC Wire Transfer / Financial Fraud Lure",
                "evidence": f"Flags: {'; '.join(bec_telemetry.get('flags', []))}",
                "severity": "HIGH",
                "explanation": "Email solicits urgent fund redirection, bank account alteration, or confidential invoice processing."
            })

    # 12. MTA Relay Transit Delays & Clock Manipulation
    if relay_transit and relay_transit.get("anomalies"):
        for anom in relay_transit.get("anomalies", []):
            is_negative = "Negative Delta" in anom
            findings.append({
                "rule_id": "RULE-018",
                "finding": "SMTP Relay Header Timestamp Anomaly",
                "evidence": anom,
                "severity": "HIGH" if is_negative else "MEDIUM",
                "explanation": "Negative hop delta detected — possible clock skew, timestamp inconsistency, or header anomaly; requires investigation."
            })

    # 13. Hyperlink Anchor Text Spoofing
    from core.indicators import extract_anchor_spoofs
    anchor_spoofs = extract_anchor_spoofs(parsed_email.get("body", ""))
    
    SENSITIVE_TARGET_BRANDS = {
        "microsoft", "office", "live", "outlook", "google", "gmail", "apple", "icloud",
        "paypal", "chase", "wellsfargo", "bankofamerica", "citi", "sbi", "hdfc", "icici",
        "axisbank", "kotak", "pnbindia", "incometax", "dhl", "fedex", "ups", "amazon",
        "netflix", "dropbox", "onedrive"
    }
    COMMON_SOCIAL_PLATFORMS = {
        "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
        "youtube.com", "t.me", "telegram.org", "discord.com", "reddit.com", "quora.com",
        "github.com"
    }

    from_addr = extract_email(headers.get("from", ""))
    sender_root = get_base_domain(from_addr)
    return_path_root = get_base_domain(extract_email(headers.get("return-path", "")))

    has_active_cred_lure = any(
        (f.get("rule_id") in ["RULE-020", "RULE-021"]) or
        (f.get("rule_id") == "RULE-006" and f.get("severity") in ["HIGH", "MEDIUM"])
        for f in findings
    )
    has_urgency_lure = any(f.get("rule_id") == "RULE-007" and f.get("severity") in ["HIGH", "MEDIUM"] for f in findings)

    for sp in anchor_spoofs:
        disp_dom = sp.get('displayed_domain', '')
        disp_root = sp.get('displayed_root', disp_dom)
        act_dom = sp.get('actual_domain', '')
        act_root = sp.get('actual_root', act_dom)

        is_sensitive = any(b in disp_root for b in SENSITIVE_TARGET_BRANDS)
        is_brand_dest_aligned = bool(disp_root and (disp_root in act_root or act_root in disp_root))
        is_sender_brand_aligned = bool(sender_root and (disp_root in sender_root or sender_root in disp_root))
        is_sender_aligned = bool(sender_root and (sender_root in act_root or act_root in sender_root)) or \
                            bool(return_path_root and (return_path_root in act_root or act_root in return_path_root))
        is_social = (disp_root in COMMON_SOCIAL_PLATFORMS) or any(s in disp_root for s in COMMON_SOCIAL_PLATFORMS)

        is_financial_target = any(f in disp_root for f in [
            "sbi", "hdfc", "icici", "axisbank", "kotak", "pnbindia", "paypal", "chase",
            "wellsfargo", "bankofamerica", "citi", "incometax"
        ])

        if is_financial_target and not is_brand_dest_aligned and not is_sender_brand_aligned and not is_sender_aligned:
            sp_severity = "HIGH"
            explanation = "Adversary masked a sensitive banking or financial address using an unrelated target."
        elif has_active_cred_lure and not is_sender_aligned:
            sp_severity = "HIGH"
            explanation = "Adversary paired credential/payment request with deceptive hyperlink anchor."
        elif not auth_ok and not is_sender_aligned and not is_social:
            sp_severity = "HIGH"
            explanation = "Unauthenticated message contains deceptive anchor routing away from apparent visible host."
        elif auth_ok and is_newsletter and (act_root in KNOWN_ESP_DOMAINS or act_root in KNOWN_LEGIT_ESPS) and not has_active_cred_lure:
            sp_severity = "LOW"
            explanation = "Outbound reference link wrapped in bulk email delivery provider tracking domain."
        elif auth_ok and is_newsletter and is_social:
            sp_severity = "LOW"
            explanation = "Standard social/community platform reference wrapped in authorized ESP click tracker."
        elif auth_ok and is_sender_aligned:
            sp_severity = "LOW"
            explanation = "Hyperlink routed via tracking infrastructure aligned with authenticated sender organization."
        elif is_sensitive and not is_brand_dest_aligned and not is_sender_brand_aligned and not is_sender_aligned:
            sp_severity = "HIGH"
            explanation = "Adversary masked a sensitive institutional brand address using a false visible target."
        else:
            sp_severity = "MEDIUM"
            explanation = "Hyperlink destination differs from visible text. Review target before navigating."

        findings.append({
            "rule_id": "RULE-019",
            "finding": f"Hyperlink Anchor Spoof ({disp_dom})",
            "evidence": f"Displayed domain: '{disp_dom}' | Actual destination: '{sp.get('actual_destination')[:55]}...'",
            "severity": sp_severity,
            "explanation": explanation
        })

    # 22. Infrastructure Intelligence Rules (SIH26106)
    if infrastructure_intel:
        def _get_f(obj, field, default=None):
            if isinstance(obj, dict):
                return obj.get(field, default)
            return getattr(obj, field, default)

        t_match = _get_f(infrastructure_intel, "threat_intel_match")
        tor_ind = _get_f(infrastructure_intel, "tor_indicator")
        vpn_ind = _get_f(infrastructure_intel, "vpn_indicator")
        relay_ind = _get_f(infrastructure_intel, "open_relay_indicator")
        botnet_ind = _get_f(infrastructure_intel, "botnet_indicator")
        cloud_ind = _get_f(infrastructure_intel, "cloud_indicator")

        # RULE-022: Threat Intelligence / Blacklist / Botnet C2 Match
        t_status = _get_f(t_match, "status")
        b_status = _get_f(botnet_ind, "status")
        if t_status == "MATCH":
            findings.append({
                "rule_id": "RULE-022",
                "finding": f"Known Threat Intelligence Blacklist Match ({_get_f(t_match, 'category', 'Malicious')})",
                "evidence": f"Feed: {_get_f(t_match, 'feed_name', 'Local Threat Intel')} | Evidence: {_get_f(t_match, 'evidence', 'Matched malicious IOC')}",
                "severity": "HIGH",
                "explanation": "Originating IP, host, or sending domain is explicitly flagged on an active threat intelligence blacklist."
            })
        elif b_status == "INDICATED":
            findings.append({
                "rule_id": "RULE-022",
                "finding": f"Botnet / Spambot Infrastructure Indicated ({_get_f(botnet_ind, 'botnet_family', 'Spambot Pool')})",
                "evidence": _get_f(botnet_ind, "evidence", "Botnet indicators identified"),
                "severity": "HIGH",
                "explanation": "Originating host or network correlates with automated spambot pools or botnet command-and-control."
            })

        # RULE-023: Tor Exit Node Origin
        tor_status = _get_f(tor_ind, "status")
        if tor_status == "DETECTED":
            findings.append({
                "rule_id": "RULE-023",
                "finding": "Tor Anonymization Exit Node Detected",
                "evidence": _get_f(tor_ind, "evidence", "Verified Tor exit relay"),
                "severity": "HIGH",
                "explanation": "Mail origin connects directly from a verified Tor exit relay. Origin sender identity is anonymized."
            })

        # RULE-024: Commercial VPN / Anonymizing Proxy
        vpn_status = _get_f(vpn_ind, "status")
        if vpn_status == "DETECTED":
            auth_ok = _is_auth_ok(auth_alignment)
            vpn_sev = "LOW" if (auth_ok or is_newsletter) else "MEDIUM"
            findings.append({
                "rule_id": "RULE-024",
                "finding": f"Commercial VPN / Anonymizing Proxy Detected ({_get_f(vpn_ind, 'provider', 'VPN')})",
                "evidence": _get_f(vpn_ind, "evidence", "Commercial VPN network detected"),
                "severity": vpn_sev,
                "explanation": "Originating mail delivery traversed commercial VPN or anonymizing proxy hosting infrastructure."
            })

        # RULE-024-RELAY: Suspect Open Relay / Non-Standard Transit
        relay_status = _get_f(relay_ind, "status")
        if relay_status == "INDICATED":
            findings.append({
                "rule_id": "RULE-024-RELAY",
                "finding": "Suspect Open-Relay Transit Indicators Detected",
                "evidence": _get_f(relay_ind, "evidence", "Unauthenticated relay hop detected"),
                "severity": "MEDIUM",
                "explanation": "Passive Received header analysis indicates potential unauthenticated open-relay transit or transit anomaly."
            })

        # RULE-025: Cloud-Hosted Infrastructure with Identity Anomaly
        is_cloud = _get_f(cloud_ind, "is_cloud_hosted", False)
        if is_cloud:
            auth_ok = _is_auth_ok(auth_alignment)
            is_lookalike = lookalike_analysis and getattr(lookalike_analysis, "is_lookalike", False)
            c_prov = _get_f(cloud_ind, "provider", "Cloud")
            if is_lookalike or not auth_ok:
                findings.append({
                    "rule_id": "RULE-025",
                    "finding": f"Cloud VPS Origin with Identity Anomaly ({c_prov})",
                    "evidence": f"Provider: {c_prov} ({_get_f(cloud_ind, 'asn', '')}) | Auth: {getattr(auth_alignment, 'effective_dmarc', 'FAIL') if auth_alignment else 'UNALIGNED'}",
                    "severity": "HIGH" if is_lookalike else "MEDIUM",
                    "explanation": f"Email originated from {c_prov} cloud infrastructure without proper sender identity alignment or with lookalike brand mimicry."
                })

    # 23. Confusable Character / Mixed-Script Obfuscation (RULE-026)
    # 24. Spaced Token Obfuscation (RULE-027)
    if normalization_data is None:
        try:
            from core.normalization import normalize_email_payload
            normalization_data = normalize_email_payload(
                headers.get("subject", ""),
                parsed_email.get("body", "")
            )
        except Exception:
            normalization_data = None

    if normalization_data:
        # RULE-026: Confusable / Mixed-Script Detection
        conf_ev = normalization_data.get("confusable_evidence", {})
        if conf_ev.get("has_mixed_script") or conf_ev.get("confusable_count", 0) > 0:
            c_count = conf_ev.get("confusable_count", 0)
            sample_toks = [f["token"] for f in conf_ev.get("findings", [])[:3]]
            sample_str = f" in '{', '.join(sample_toks)}'" if sample_toks else ""
            findings.append({
                "rule_id": "RULE-026",
                "finding": f"Mixed-Script / Confusable Homoglyphs Detected ({c_count} char(s))",
                "evidence": f"Found {c_count} confusable character(s){sample_str}",
                "severity": "MEDIUM" if not auth_ok else "LOW",
                "explanation": "Email content contains mixed-script sequences (e.g. Cyrillic/Greek mimicking Latin) often used for visual deception."
            })

        # RULE-027: Bounded Spaced-Token Obfuscation
        # CRITICAL RULE: BRAND ALONE MUST NOT PRODUCE HIGH
        spaced_tokens = normalization_data.get("spaced_token_findings", [])
        if spaced_tokens:
            has_cred = any(f.get("rule_id") in ["RULE-006", "RULE-020"] for f in findings)
            has_urg = any(f.get("rule_id") == "RULE-007" for f in findings)
            has_susp_link = any(f.get("rule_id") in ["RULE-012", "RULE-019"] for f in findings)

            spaced_brands = [st["normalized"] for st in spaced_tokens if st.get("is_brand_or_lure")]
            first_orig = spaced_tokens[0]["original"]
            first_norm = spaced_tokens[0]["normalized"]

            if spaced_brands:
                if (has_cred or has_susp_link) and not auth_ok:
                    sev_27 = "HIGH"
                    expl_27 = "Adversary combined spaced-token brand obfuscation with credential harvesting or deceptive hyperlinks."
                elif has_cred or has_susp_link or has_urg:
                    sev_27 = "MEDIUM"
                    expl_27 = "Spaced brand obfuscation identified alongside urgency or credential keywords."
                else:
                    sev_27 = "LOW"  # BRAND ALONE MUST NOT PRODUCE HIGH
                    expl_27 = "Spaced character sequences identified. Informational signal without corroborating threat lure."

                findings.append({
                    "rule_id": "RULE-027",
                    "finding": f"Spaced Token Brand Obfuscation ('{first_norm}')",
                    "evidence": f"Original spaced text: '{first_orig}' -> Normalized: '{first_norm}'",
                    "severity": sev_27,
                    "explanation": expl_27
                })

    return findings

def calculate_hybrid_risk(
    rule_findings: List[Dict[str, str]],
    ml_prob: float,
    auth_alignment: Any = None,
    content_type: Any = None,
    is_ml_borderline: bool = False
) -> tuple[str, List[str]]:
    risk_score = "LOW"
    reasons = []

    auth_ok = _is_auth_ok(auth_alignment)

    high_rules = sum(1 for f in rule_findings if f.get("severity") == "HIGH")
    medium_rules = sum(1 for f in rule_findings if f.get("severity") == "MEDIUM")

    is_borderline = is_ml_borderline or (0.38 <= ml_prob <= 0.62)

    if high_rules >= 1:
        risk_score = "HIGH"
    elif is_borderline:
        # Borderline ML prediction: ML score alone CANNOT force HIGH
        if not auth_ok and medium_rules >= 3:
            risk_score = "SUSPICIOUS"
        elif auth_ok and high_rules == 0:
            risk_score = "LOW"
        elif medium_rules >= 2 and not auth_ok:
            risk_score = "SUSPICIOUS"
        else:
            risk_score = "LOW"
    elif not auth_ok and (ml_prob > 0.85 or (medium_rules >= 3 and ml_prob > 0.6)):
        risk_score = "HIGH"
    elif not auth_ok and (ml_prob > 0.65 or medium_rules >= 2):
        risk_score = "SUSPICIOUS"
    elif auth_ok and high_rules == 0:
        # Authenticated email with no high-severity forensic violations
        risk_score = "LOW"
    elif ml_prob > 0.88 and medium_rules >= 2:
        risk_score = "SUSPICIOUS"

    if high_rules > 0:
        reasons.append(f"Critical forensic violations detected ({high_rules} High-Severity Finding{'s' if high_rules > 1 else ''}).")
    if medium_rules > 0 and (not auth_ok or high_rules > 0):
        reasons.append(f"Suspicious heuristic indicators detected ({medium_rules}).")

    if is_borderline:
        reasons.append(f"ML confidence is Borderline ({ml_prob:.2f}); final risk verdict is grounded primarily in deterministic forensic rules.")
    elif ml_prob > 0.85 and not auth_ok:
        reasons.append(f"ML probability indicates strong phishing signals ({ml_prob:.2f}).")
    elif ml_prob > 0.65 and not auth_ok:
        reasons.append(f"ML probability indicates moderate phishing signals ({ml_prob:.2f}).")

    if not reasons:
        reasons.append("No significant malicious indicators found.")

    return risk_score, reasons
