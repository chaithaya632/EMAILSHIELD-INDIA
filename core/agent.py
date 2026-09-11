import datetime
from typing import Dict, Any, List, Optional, Tuple
from core.schemas import AgentStep, GeolocationInfo, DomainReputation, RuleFinding
from core.geolocation import get_geolocation
from core.domain_reputation import get_domain_reputation
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.ai_reasoning import generate_forensic_reasoning
from core.url_forensics import analyze_all_urls, defang_url
from core.auth_claims import evaluate_auth_and_alignment
from core.attachments import analyze_all_attachments
from core.lookalike import detect_lookalike_domain
from core.bec_detector import detect_bec_and_impersonation
from core.relay_tracer import analyze_relay_transit

class AutonomousForensicAgent:
    """
    Autonomous ReAct (Reasoning + Action) AI Agent for Email Forensics.
    Coordinates forensic tools (GeoIP, RDAP, Lookalike, DMARC, Attachments, BEC, URL Forensics, ML Classifier)
    and produces an explainable, step-by-step investigation trail.
    """

    def __init__(self, ml_classifier):
        self.ml_classifier = ml_classifier

    def run_investigation(
        self,
        parsed_email: Dict[str, Any],
        raw_iocs: Dict[str, List[str]],
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes the autonomous agentic investigation loop:
        Thought -> Tool Action -> Observation -> Final Synthesis
        """
        headers = parsed_email.get("headers", {})
        body = parsed_email.get("body", "")
        subject = str(headers.get("subject", "No Subject"))
        sender = str(headers.get("from", "Unknown"))
        public_ips = raw_iocs.get("ipv4", [])
        received_chain = parsed_email.get("received_chain", [])

        steps: List[AgentStep] = []
        step_idx = 1

        # ==========================================================
        # STEP 1: Tool - GeoIP & Infrastructure Tracer
        # ==========================================================
        target_ip = public_ips[0] if public_ips else "127.0.0.1"
        thought_1 = (
            f"I must trace the physical network infrastructure associated with the sender. "
            f"Analyzing public IP candidates from Received headers: {target_ip}."
        )
        action_1 = f"call_tool: GeoIP_Tracer_Tool(ip='{target_ip}')"
        
        geo_result = get_geolocation(target_ip)
        obs_1 = (
            f"Geolocated {target_ip} -> {geo_result.get('city')}, {geo_result.get('country')} "
            f"[ISP: {geo_result.get('org')}, ASN: {geo_result.get('asn')}]. "
            f"Database: {geo_result.get('db_provider')} ({geo_result.get('db_version')})."
        )
        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_1,
            action=action_1,
            observation=obs_1,
            tool_used="GeoIP_Tracer_Tool"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 2: Tool - DNS & ICANN RDAP Domain Reputation
        # ==========================================================
        thought_2 = (
            f"I must cross-verify the sender domain reputation to detect Newly Registered Domains (NRD < 30d), "
            f"missing MX records, or deceptive brand impersonation."
        )
        action_2 = f"call_tool: RDAP_Domain_Intel_Tool(sender='{sender}')"
        
        domain_rep = get_domain_reputation(sender)
        age_str = f"{domain_rep.domain_age_days} days" if domain_rep.domain_age_days is not None else "Unknown"
        obs_2 = (
            f"Domain: '{domain_rep.domain}' | Age: {age_str} | Registrar: {domain_rep.registrar} | "
            f"MX Valid: {domain_rep.has_mx_record} | NRD Flag: {domain_rep.is_nrd} | "
            f"Risk Level: {domain_rep.risk_level}. Notes: {'; '.join(domain_rep.notes[:2])}."
        )
        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_2,
            action=action_2,
            observation=obs_2,
            tool_used="RDAP_Domain_Intel_Tool"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 3: Tool - Lookalike & Homoglyph Detector
        # ==========================================================
        thought_3 = (
            f"I must inspect the domain '{domain_rep.domain}' for Punycode (IDN), Cyrillic/Greek homoglyphs, "
            f"typosquatting, or brand affix combo-squatting targeting major institutions."
        )
        action_3 = f"call_tool: Homoglyph_Lookalike_Tool(domain='{domain_rep.domain}')"
        lookalike_res = detect_lookalike_domain(domain_rep.domain)
        if lookalike_res.get("is_lookalike"):
            obs_3 = (
                f"🚨 Lookalike detected! Impersonates '{lookalike_res.get('impersonated_brand')}' "
                f"via {lookalike_res.get('technique')} (Similarity: {lookalike_res.get('similarity_score')}%). "
                f"Details: {'; '.join(lookalike_res.get('reasons', []))}."
            )
        else:
            obs_3 = f"Domain '{domain_rep.domain}' passed homoglyph and brand typosquatting checks (No mimicry detected)."

        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_3,
            action=action_3,
            observation=obs_3,
            tool_used="Homoglyph_Lookalike_Tool"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 4: Tool - Cryptographic Auth & DMARC Alignment Verifier
        # ==========================================================
        thought_4 = (
            "I must perform RFC 7489 alignment checks between visible Header-From, Envelope-From (Return-Path), "
            "and DKIM d= signing domains to ensure the attacker is not authenticating their own rogue domain."
        )
        action_4 = "call_tool: DMARC_Alignment_Verifier_Tool(headers)"
        auth_alignment = evaluate_auth_and_alignment(headers)
        obs_4 = (
            f"DMARC Verdict: {auth_alignment.get('effective_dmarc')} | "
            f"SPF: {auth_alignment.get('spf_result')} (Aligned: {auth_alignment.get('spf_aligned')}) | "
            f"DKIM: {auth_alignment.get('dkim_result')} (Aligned: {auth_alignment.get('dkim_aligned')}). "
            f"Reason: {auth_alignment.get('dmarc_reason')}."
        )
        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_4,
            action=action_4,
            observation=obs_4,
            tool_used="DMARC_Alignment_Verifier_Tool"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 5: Tool - Attachment Deep Forensics & Hashing
        # ==========================================================
        raw_attachments = parsed_email.get("attachments", [])
        attachment_analyses = analyze_all_attachments(raw_attachments)
        if raw_attachments:
            thought_5 = (
                f"Detected {len(raw_attachments)} attachment(s). I must compute SHA-256 hashes, check for double extensions "
                f"(e.g. .pdf.exe), examine macro indicators, and verify declared MIME types."
            )
            action_5 = f"call_tool: Attachment_Forensic_Scanner_Tool(count={len(raw_attachments)})"
            crit_atts = [a for a in attachment_analyses if a.get("risk_level") in ["CRITICAL", "HIGH"]]
            if crit_atts:
                top_a = crit_atts[0]
                obs_5 = (
                    f"🚨 Dangerous attachment identified: '{top_a.get('filename')}' [Verdict: {top_a.get('verdict_label')}]. "
                    f"SHA-256: {top_a.get('sha256')[:16]}... Indicators: {'; '.join(top_a.get('risk_flags', []))}."
                )
            else:
                obs_5 = f"Processed {len(attachment_analyses)} attachment(s). All hashes computed; no malicious double extensions found."

            steps.append(AgentStep(
                step_num=step_idx,
                thought=thought_5,
                action=action_5,
                observation=obs_5,
                tool_used="Attachment_Forensic_Scanner_Tool"
            ))
            step_idx += 1

        # ==========================================================
        # STEP 6: Tool - BEC & Executive Impersonation Detector
        # ==========================================================
        thought_6 = (
            "I must evaluate the email for Business Email Compromise (BEC) traits: Display-Name spoofing, "
            "executive/VIP titles sent from free webmail, and wire transfer or invoice payment lures."
        )
        action_6 = "call_tool: BEC_Impersonation_Detector_Tool(headers, body)"
        bec_telemetry = detect_bec_and_impersonation(headers, body, attachment_analyses)
        obs_6 = (
            f"Threat Classification: {bec_telemetry.get('verdict')} (Confidence: {bec_telemetry.get('confidence_pct')}%). "
            f"Display Spoof: {bec_telemetry.get('is_display_name_spoof')} | Wire Fraud Lures: {bec_telemetry.get('is_financial_lure')}. "
            f"Triggers: {'; '.join(bec_telemetry.get('flags', ['None']))}."
        )
        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_6,
            action=action_6,
            observation=obs_6,
            tool_used="BEC_Impersonation_Detector_Tool"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 7: Tool - Linguistic Machine Learning Classifier
        # ==========================================================
        thought_7 = (
            "I need to evaluate the linguistic sentiment and token distribution of the email body "
            "to assess social engineering and credential harvesting patterns."
        )
        action_7 = f"call_tool: ScikitLearn_NLP_Classifier(tokens={len(body.split())} words)"
        
        ml_pred = self.ml_classifier.predict(subject, body)
        prob = ml_pred.get("probability", 0.0)
        assessment = ml_pred.get("assessment", "Benign")
        obs_7 = (
            f"Model Prediction: {assessment} (Confidence: {prob*100:.1f}%). "
            f"Features Analyzed: {len(ml_pred.get('features_used', []))} lexical n-grams."
        )
        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_7,
            action=action_7,
            observation=obs_7,
            tool_used="ScikitLearn_NLP_Classifier"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 8: Tool - URL & Hyperlink Forensic Inspector
        # ==========================================================
        urls_found = raw_iocs.get("urls", [])
        url_analyses = []
        if urls_found:
            sample_url = urls_found[0]
            thought_8 = (
                f"Detected {len(urls_found)} embedded hyperlink(s) in email body. "
                f"I must run a background forensic inspection to trace redirect paths, "
                f"identify weaponized payloads, detect credential harvesting lures, and evaluate potential impact."
            )
            action_8 = f"call_tool: URL_Forensic_Analyzer_Tool(target='{defang_url(sample_url)[:45]}...')"
            url_analyses = analyze_all_urls(urls_found)
            
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
            top_threat = max(url_analyses, key=lambda u: severity_order.get(u.risk_level, 0))
            
            obs_8 = (
                f"Analyzed {len(url_analyses)} URL(s). Top threat: {top_threat.risk_level} "
                f"[{top_threat.threat_category}]. Destination: '{defang_url(top_threat.final_destination or top_threat.url)[:40]}...'. "
                f"Impact: {top_threat.potential_impact[:75]}..."
            )
            steps.append(AgentStep(
                step_num=step_idx,
                thought=thought_8,
                action=action_8,
                observation=obs_8,
                tool_used="URL_Forensic_Analyzer_Tool"
            ))
            step_idx += 1

        # ==========================================================
        # STEP 9: Tool - SMTP Relay Hop Transit & Latency Analysis
        # ==========================================================
        thought_9 = "I must analyze MTA hop transit timestamps to detect intermediate relay delays and clock anomalies."
        action_9 = f"call_tool: MTA_Relay_Latency_Tool(hops={len(received_chain)})"
        relay_transit = analyze_relay_transit(received_chain)
        if relay_transit.get("anomalies"):
            obs_9 = f"⚠️ Relay Anomaly Detected: {'; '.join(relay_transit['anomalies'][:2])}."
        else:
            obs_9 = f"Traced {relay_transit.get('total_hops')} relay hop(s). Total transit latency: {relay_transit.get('total_transit_display')} (Nominal)."

        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_9,
            action=action_9,
            observation=obs_9,
            tool_used="MTA_Relay_Latency_Tool"
        ))
        step_idx += 1

        # ==========================================================
        # STEP 10: Tool - Forensic Rule Matrix & Synthesis
        # ==========================================================
        thought_10 = (
            "I must evaluate the unified forensic rule matrix correlating domain reputation, "
            "DMARC alignment, attachment hazards, BEC telemetry, URL intelligence, and MTA timestamps."
        )
        action_10 = "call_tool: Forensic_Rule_Matrix(unified_telemetry)"
        
        rule_results = evaluate_rules(
            parsed_email,
            domain_rep=domain_rep,
            url_analyses=url_analyses,
            auth_alignment=auth_alignment,
            attachment_analyses=attachment_analyses,
            lookalike_analysis=lookalike_res,
            bec_telemetry=bec_telemetry,
            relay_transit=relay_transit
        )
        rule_findings = [RuleFinding(**r) for r in rule_results]
        risk_score, reasons = calculate_hybrid_risk(rule_results, prob)
        
        obs_10 = (
            f"Triggered {len(rule_results)} forensic rules. "
            f"Overall Hybrid Verdict: {risk_score}. "
            f"Primary findings: {'; '.join(reasons[:2])}."
        )
        steps.append(AgentStep(
            step_num=step_idx,
            thought=thought_10,
            action=action_10,
            observation=obs_10,
            tool_used="Forensic_Rule_Matrix"
        ))

        # ==========================================================
        # STEP 11: Final Synthesis & Reasoning Briefing
        # ==========================================================
        briefing = generate_forensic_reasoning(
            subject=subject,
            sender=sender,
            risk_score=risk_score,
            risk_reasons=reasons,
            rule_findings=rule_findings,
            ml_prob=prob,
            domain_rep=domain_rep,
            origin_geo=GeolocationInfo(**geo_result) if geo_result else None
        )

        return {
            "risk_score": risk_score,
            "reasons": reasons,
            "rule_findings": rule_findings,
            "ml_pred": ml_pred,
            "domain_rep": domain_rep,
            "url_analyses": url_analyses,
            "auth_alignment": auth_alignment,
            "attachment_analyses": attachment_analyses,
            "lookalike_analysis": lookalike_res,
            "bec_telemetry": bec_telemetry,
            "relay_transit": relay_transit,
            "geo_result": geo_result,
            "agent_steps": steps,
            "briefing": briefing
        }

