import sys
import os
sys.stdout.reconfigure(encoding='utf-8')
from core.auth_claims import evaluate_auth_and_alignment
from core.attachments import analyze_attachment_metadata
from core.lookalike import detect_lookalike_domain
from core.bec_detector import detect_bec_and_impersonation
from core.relay_tracer import analyze_relay_transit
from core.case_store import export_case_iocs_csv, export_case_iocs_json, update_case_metadata

print("--- TEST 1: DMARC Alignment & Anti-Bypass ---")
headers_bypass = {
    "from": "support@paypal.com",
    "return-path": "<bounce@attacker-owned.com>",
    "authentication-results": "spf=pass smtp.mailfrom=attacker-owned.com; dkim=pass header.d=attacker-owned.com"
}
res_auth = evaluate_auth_and_alignment(headers_bypass)
print("Effective DMARC:", res_auth["effective_dmarc"])
print("Threat detected:", res_auth["threat_detected"])
assert res_auth["threat_detected"] is True
assert "Alignment Bypass" in res_auth["effective_dmarc"]

print("\n--- TEST 2: Attachment Forensics ---")
att_double = {"filename": "invoice_urgent.pdf.exe", "size_bytes": 1024, "content_type": "application/x-msdownload"}
res_att = analyze_attachment_metadata(att_double)
print("Verdict:", res_att["verdict_label"])
print("Flags:", res_att["risk_flags"])
assert res_att["is_double_ext"] is True
assert res_att["risk_level"] == "CRITICAL"

print("\n--- TEST 3: Lookalike & Homoglyph Engine ---")
res_lookalike = detect_lookalike_domain("legitimate-paypal-security.com")
print("Is lookalike:", res_lookalike["is_lookalike"])
print("Technique:", res_lookalike["technique"])
print("Brand:", res_lookalike["impersonated_brand"])
assert res_lookalike["is_lookalike"] is True

print("\n--- TEST 4: BEC & Wire Fraud Detector ---")
bec_headers = {"from": '"CEO Satya Nadella" <ceo.fake99@gmail.com>', "subject": "Urgent: Wire Transfer Required"}
bec_body = "I am in a meeting and cannot take calls. Please process a wire transfer of $75,000 immediately to the attached account."
res_bec = detect_bec_and_impersonation(bec_headers, bec_body)
print("BEC Verdict:", res_bec["verdict"])
print("Confidence:", res_bec["confidence_pct"])
print("Display spoofed:", res_bec["is_display_name_spoof"])
assert res_bec["is_display_name_spoof"] is True
assert "BEC" in res_bec["verdict"]

print("\n--- TEST 5: Relay Transit Latency & Negative Delta Detection ---")
fake_hops = [
    "from mx.victim.com by filter.victim.com; Tue, 10 Sep 2026 12:00:10 +0000",
    "from relay.evil.com by mx.victim.com; Tue, 10 Sep 2026 12:00:20 +0000",
    "from host.origin.com by relay.evil.com; Tue, 10 Sep 2026 12:00:00 +0000"
]
res_relay = analyze_relay_transit(fake_hops)
print("Total hops:", res_relay["total_hops"])
print("Hops timing:", [(h["hop_number"], h["role"], h["delay_display"]) for h in res_relay["hops"]])

print("\n--- TEST 6: IOC Export ---")
csv_out = export_case_iocs_csv()
json_out = export_case_iocs_json()
print("CSV preview:\n", csv_out[:120])
print("JSON preview:\n", json_out[:120])
assert "Indicator_Type" in csv_out
assert "indicators" in json_out

print("\n--- TEST 7: End-to-End Analysis of BEC & Phishing Samples ---")
from core.parser import SecureEmailParser
from core.classifier import MLClassifier
from core.agent import AutonomousForensicAgent
from core.indicators import extract_all_indicators
from core.report import generate_pdf_report

agent = AutonomousForensicAgent(MLClassifier())

for sample in ["samples/bec.eml", "samples/malware_lure.eml", "samples/phishing.eml"]:
    with open(sample, "rb") as f:
        p = SecureEmailParser(f.read()).parse()
        iocs = extract_all_indicators(p["body"] + " " + str(p["headers"]))
        out = agent.run_investigation(p, iocs)
        print(f"Sample: {sample} -> Hybrid Risk: {out['risk_score']} | BEC Verdict: {out['bec_telemetry']['verdict']} (Confidence: {out['bec_telemetry']['confidence_pct']}%)")
        assert out["risk_score"] in ["HIGH", "SUSPICIOUS"]

print("\n--- TEST 8: PDF Report Generation Verification ---")
test_case_data = {
    "case_id": "CASE-TEST01",
    "timestamp": "2026-09-11 12:00:00",
    "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "subject": "URGENT: Remittance Required",
    "sender": "CEO <ceo@fake.com>",
    "threat_verdict": "Business Email Compromise (BEC / Wire Fraud)",
    "verdict_confidence": 98,
    "status": "In Progress",
    "assigned_investigator": "Lead Forensic Examiner",
    "rule_findings": [{"rule_id": "RULE-017", "finding": "Display-Name Spoofing", "severity": "HIGH", "explanation": "CEO persona on free webmail"}],
    "auth_alignment": {"spf_result": "PASS", "spf_aligned": False, "dkim_result": "NONE", "dkim_aligned": False, "effective_dmarc": "FAIL (Alignment Bypass)", "dmarc_reason": "Domain unaligned"},
    "attachment_analyses": [{"filename": "invoice.pdf.exe", "content_type": "application/x-msdownload", "sha256": "abcdef1234567890abcdef1234567890", "verdict_label": "MALICIOUS", "is_double_ext": True, "risk_flags": ["Double extension"]}],
    "indicators": [{"type": "IP", "value": "198.51.100.23", "source": "Headers"}]
}
os.makedirs("data/reports", exist_ok=True)
generate_pdf_report(test_case_data, "data/reports/test_report.pdf")
assert os.path.exists("data/reports/test_report.pdf")
print("PDF report generated successfully at data/reports/test_report.pdf (Size:", os.path.getsize("data/reports/test_report.pdf"), "bytes)")

print("\n--- TEST 9: Indian Financial & UPI Route Extractor ---")
from core.indian_banking import extract_indian_financial_indicators
fin_text = "Urgent: Pay pending electricity bill to avoid power cut. UPI: discom.mumbai@okhdfcbank or A/C: 987654321098 IFSC: SBIN0001234"
res_fin = extract_indian_financial_indicators(fin_text)
print("Extracted UPI:", res_fin["upi_handles"])
print("Identified Banks:", [b["bank_name"] for b in res_fin["identified_banks"]])
assert "discom.mumbai@okhdfcbank" in res_fin["upi_handles"]
assert "SBIN0001234" in res_fin["ifsc_codes"]
assert res_fin["identified_banks"][0]["bank_name"] == "State Bank of India (SBI)"
assert "987654321098" in res_fin["bank_accounts"]

print("\n--- TEST 10: QR Code Phishing (Quishing) Scanner ---")
import cv2
from core.quishing import scan_for_quishing
encoder = cv2.QRCodeEncoder_create()
qr_img = encoder.encode("https://secure-login-portal-verify.com/token")
_, png_bytes = cv2.imencode(".png", qr_img)
quish_atts = [{"filename": "invoice_qr.png", "declared_mime": "image/png", "content_bytes": png_bytes.tobytes(), "sha256": "aabbcc112233"}]
quish_res = scan_for_quishing(quish_atts)
print("Quishing detected:", len(quish_res))
assert len(quish_res) == 1
assert "secure-login-portal-verify.com" in quish_res[0]["decoded_url"]
print("Decoded URL:", quish_res[0]["decoded_url"])

print("\n--- TEST 11: EML Sanitizer (Defanging & Binary Quarantine) ---")
from core.eml_sanitizer import sanitize_eml_content
with open("samples/malware_lure.eml", "rb") as f:
    orig_eml = f.read()
sanitized_bytes, defanged_u, quar_a = sanitize_eml_content(orig_eml)
print(f"Quarantined attachments: {quar_a}")
assert quar_a > 0
assert b"EMAILSHIELD EVIDENCE QUARANTINE NOTICE" in sanitized_bytes

print("\n--- TEST 12: Forensic Header Diff & Baseline Comparator ---")
from core.header_diff import compare_headers_against_baseline
suspect_hdr = {
    "from": "service@sbi.co.in",
    "return_path": "bounces@untrusted-relay.com",
    "dkim_domain": "sendgrid.net",
    "spf": "Fail",
    "dkim": "Pass",
    "dmarc": "Fail",
    "first_hop": "smtp.sendgrid.net"
}
diff_out = compare_headers_against_baseline(suspect_hdr, "sbi.co.in")
print("Baseline Brand:", diff_out["baseline_brand"])
print("Verdict:", diff_out["verdict"])
print("Forgeries Detected:", diff_out["forgery_count"])
assert diff_out["forgery_count"] >= 2
assert "CRITICAL SPOOFING" in diff_out["verdict"]

print("\n--- TEST 13: I4C / NCRP-Oriented Evidence Pack & Electronic Evidence Annexure ---")
from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure
ncrp_case = {
    "case_id": "CASE-NCRP-TEST",
    "timestamp": "2026-09-12 10:00:00 UTC",
    "sender": "billing@fake-discom.in",
    "subject": "Power Disconnection Notice",
    "originating_ip": "49.207.200.1",
    "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
    "body_text": "Pay immediately via UPI: payment@okhdfcbank or IFSC: SBIN0001234 A/C: 987654321098",
    "geolocation": {"org": "Reliance Jio Infocomm", "city": "Bengaluru", "country": "India"},
    "investigator": "Cyber Cell Officer"
}
ncrp_txt = generate_ncrp_complaint_text(ncrp_case)
assert "NATIONAL CYBER CRIME REPORTING PORTAL" in ncrp_txt
assert "payment@okhdfcbank" in ncrp_txt
ncrp_pdf = "data/reports/test_ncrp_pack.pdf"
generate_ncrp_pdf_annexure(ncrp_case, ncrp_pdf)
assert os.path.exists(ncrp_pdf)
print(f"NCRP PDF Annexure created successfully: {ncrp_pdf} ({os.path.getsize(ncrp_pdf)} bytes)")

print("\n--- TEST 14: False-Positive Calibration (Everyday Legitimate Emails) ---")
benign_test_cases = [
    {
        "name": "Vaibhav Sisinty Newsletter",
        "raw": '''From: "Vaibhav Sisinty" <vaibhav@growthschool.io>
Reply-To: vaibhav@sisinty.com
To: user@example.com
Subject: 5 AI tools that saved me 20 hours this week
List-Unsubscribe: <https://growthschool.io/unsubscribe>
Authentication-Results: mx.google.com; dkim=pass header.i=@growthschool.io; spf=pass smtp.mailfrom=growthschool.io; dmarc=pass

Hey everyone,
Here are the top 5 AI workflows we tested at GrowthSchool. Login to the community to grab the prompts.
Cheers,
Vaibhav Sisinty
Founder, GrowthSchool'''
    },
    {
        "name": "HDFC Bank NetBanking Statement",
        "raw": '''From: "HDFC Bank InstaAlerts" <alerts@hdfcbank.net>
To: user@example.com
Subject: Transaction Alert: INR 2,500 debited from A/c XX1234
Authentication-Results: mx.google.com; dkim=pass header.i=@hdfcbank.net; spf=pass smtp.mailfrom=hdfcbank.net; dmarc=pass

Dear Customer,
INR 2,500.00 has been debited from your account XX1234 on 12-Sep-2026.
To view your full statement or update your banking preferences, login to NetBanking at https://netbanking.hdfcbank.com/netbanking.
'''
    },
    {
        "name": "Google Password Security Alert",
        "raw": '''From: "Google Security" <no-reply@accounts.google.com>
To: user@example.com
Subject: Security alert: New sign-in on Windows
Authentication-Results: mx.google.com; dkim=pass header.i=@accounts.google.com; spf=pass smtp.mailfrom=accounts.google.com; dmarc=pass

Your Google Account was just signed in from a new Windows device.
If this was you, you don't need to do anything. If not, verify and change your password at https://myaccount.google.com/security.
'''
    },
    {
        "name": "Colleague Workplace Project Email",
        "raw": '''From: "Rahul Sharma" <rahul.sharma@tcs.com>
To: user@example.com
Subject: Urgent: Quarterly planning sync tomorrow
Authentication-Results: mx.google.com; dkim=pass header.i=@tcs.com; spf=pass smtp.mailfrom=tcs.com; dmarc=pass

Hi team,
This is urgent - we need to finalize the quarterly budget presentation before 10 AM.
Please review the slide deck on the internal portal and login to submit your inputs.
Thanks,
Rahul'''
    },
    {
        "name": "SBI Card Statement",
        "raw": '''From: "SBI Card" <alerts@sbicard.com>
To: user@example.com
Subject: Your SBI Card E-Statement for Account ending 4321
Authentication-Results: mx.google.com; dkim=pass header.i=@sbicard.com; spf=pass smtp.mailfrom=sbicard.com; dmarc=pass

Dear Cardholder,
Your monthly statement for SBI Card ending in 4321 is now ready.
Total Amount Due: INR 8,420.00 | Minimum Amount Due: INR 500.00 | Payment Due Date: 25-Sep-2026.
Please pay your bill online through YONO SBI app or at https://www.sbicard.com.
'''
    },
    {
        "name": "Amazon.in Order Confirmation",
        "raw": '''From: "Amazon.in" <order-update@amazon.in>
To: user@example.com
Subject: Ordered: "Logitech Wireless Mouse"
Authentication-Results: mx.google.com; dkim=pass header.i=@amazon.in; spf=pass smtp.mailfrom=amazon.in; dmarc=pass

Thank you for your order!
Your order #402-1234567-8901234 has been confirmed.
Total: INR 799.00 paid via UPI.
Track your package or update delivery instructions at https://www.amazon.in/gp/your-account/order-history.
'''
    },
    {
        "name": "Swiggy Food Delivery Receipt",
        "raw": '''From: "Swiggy" <no-reply@swiggy.in>
To: user@example.com
Subject: Order Delivered! Here is your receipt
Authentication-Results: mx.google.com; dkim=pass header.i=@swiggy.in; spf=pass smtp.mailfrom=swiggy.in; dmarc=pass

Hi Amit,
Your order from Meghana Foods has been delivered.
Paid: INR 450 via UPI (swiggy@axisbank).
Invoice #SW-89412 attached.
'''
    },
    {
        "name": "Personal Casual Email",
        "raw": '''From: "Priya Patel" <priya.patel92@gmail.com>
To: user@example.com
Subject: Weekend plans?
Authentication-Results: mx.google.com; dkim=pass header.i=@gmail.com; spf=pass smtp.mailfrom=gmail.com; dmarc=pass

Hey! Are you free this Saturday for coffee? Let me know!'''
    }
]

for tc in benign_test_cases:
    p = SecureEmailParser(tc["raw"].encode()).parse()
    iocs = extract_all_indicators(p["body"] + " " + str(p["headers"]))
    out = agent.run_investigation(p, iocs)
    print(f"Benign Email: {tc['name']} -> Risk: {out['risk_score']} | Verdict: {out['bec_telemetry']['verdict']} (Confidence: {out['bec_telemetry']['confidence_pct']}%)")
    assert out["risk_score"] == "LOW", f"Expected LOW risk for {tc['name']}, got {out['risk_score']}"

print("\n--- TEST 15: Live Mailbox Sentinel Checkpointing & Mobile Alert Payloads ---")
from core.sentinel import format_threat_alert_text, SentinelManager, send_test_alert

# 1. Test Threat Alert Text Formatting
sample_threat = {
    "case_id": "CASE-TEST999",
    "subject": "Urgent: Verify Your SBI NetBanking Credentials",
    "sender": "support@sbi-bank-secure.online",
    "risk_score": "HIGH",
    "risk_score_numeric": 92,
    "risk_reasons": ["Lookalike domain impersonating SBI Bank", "DMARC authentication failed", "Phishing link detected"]
}
alert_text = format_threat_alert_text(sample_threat)
print("Alert Preview:\n", alert_text[:200], "...")
assert "EMAILSHIELD CRITICAL SECURITY ALERT" in alert_text
assert "support@sbi-bank-secure.online" in alert_text
assert "92/100" in alert_text
assert "DO NOT click any links" in alert_text

# 2. Test Checkpointing & Unseen Email Detection Logic
manager = SentinelManager()
# Simulate inbox state
mock_inbox = [
    {"id": "105", "subject": "Brand New Inbound Attack", "sender": "hacker@evil.com", "date": "12-Sep-2026 16:30"},
    {"id": "104", "subject": "Important Meeting Notes", "sender": "boss@company.com", "date": "12-Sep-2026 16:20"},
    {"id": "103", "subject": "Last Analyzed Baseline Mail", "sender": "client@partner.in", "date": "12-Sep-2026 16:00"},
    {"id": "102", "subject": "Old Archived Newsletter", "sender": "news@daily.com", "date": "12-Sep-2026 15:00"},
]

# Set checkpoint to message 103 (last analyzed)
manager.state.checkpoint_id = "103"
manager.state.checkpoint_subject = "Last Analyzed Baseline Mail"

# Detect unseen emails
unseen = manager._identify_unseen_emails(mock_inbox)
print(f"Detected {len(unseen)} unseen email(s) newer than checkpoint 103:")
for u in unseen:
    print(f"  • ID {u['id']}: {u['subject']}")

assert len(unseen) == 2
assert unseen[0]["id"] == "105"
assert unseen[1]["id"] == "104"

# Advance checkpoint to top email (105)
manager.state.checkpoint_id = "105"
manager.state.checkpoint_subject = "Brand New Inbound Attack"

# Test identical checkpoint (No new emails arrived)
unseen_after = manager._identify_unseen_emails(mock_inbox)
assert len(unseen_after) == 0

# 3. Test Sensitive Token / OTP Redaction
from core.sentinel import mask_sensitive_subject
masked_sample1 = mask_sensitive_subject("Your Code - 44830")
masked_sample2 = mask_sensitive_subject("Telegram: 123456 is your login code")
masked_sample3 = mask_sensitive_subject("HDFC Bank: OTP 891245 for your transaction")
masked_sample4 = mask_sensitive_subject("Weekend plans?")
print(f"OTP Redaction Preview 1: 'Your Code - 44830' -> '{masked_sample1}'")
print(f"OTP Redaction Preview 2: 'Telegram: 123456...' -> '{masked_sample2}'")

assert "44830" not in masked_sample1
assert "••••••" in masked_sample1
assert "123456" not in masked_sample2
assert "891245" not in masked_sample3
assert masked_sample4 == "Weekend plans?"

print("\n--- TEST 16: Real-World Corpus Stress, MIME Decoding & Anchor Defang Verification ---")
import zipfile
from core.risk import evaluate_rules, calculate_hybrid_risk
with zipfile.ZipFile("email-corpus-main.zip", "r") as z:
    eml_files = [n for n in z.namelist() if n.lower().endswith(".eml")]
    # Test DHL Phishing sample from corpus (index 3)
    dhl_raw = z.read(eml_files[3])
    dhl_parsed = SecureEmailParser(dhl_raw).parse()
    
    # Verify MIME decoding
    assert "DHXPR-ESS" in dhl_parsed["headers"].get("subject", "")
    assert "MyDHL EXPRESS" in dhl_parsed["headers"].get("from", "")
    
    # Verify Defanged URL extraction and anchor spoofing
    dhl_iocs = extract_all_indicators(dhl_parsed["body"] + " " + str(dhl_parsed["headers"]))
    assert len(dhl_iocs["urls"]) >= 2
    assert any("bgsexpress.com" in u for u in dhl_iocs["urls"])
    assert len(dhl_iocs["anchor_spoofs"]) >= 1
    assert dhl_iocs["anchor_spoofs"][0]["displayed_domain"] == "international.dhl.com"
    assert dhl_iocs["anchor_spoofs"][0]["actual_domain"] == "www.bgsexpress.com"
    
    # Verify Detection
    dhl_auth = evaluate_auth_and_alignment(dhl_parsed["headers"])
    dhl_bec = detect_bec_and_impersonation(dhl_parsed["headers"], dhl_parsed["body"], auth_alignment=dhl_auth)
    dhl_rules = evaluate_rules(dhl_parsed, auth_alignment=dhl_auth, bec_telemetry=dhl_bec)
    dhl_risk, dhl_reasons = calculate_hybrid_risk(dhl_rules, 0.5, auth_alignment=dhl_auth)
    
    print(f"Corpus Sample 4 Hybrid Risk: {dhl_risk} | Findings: {len(dhl_rules)}")
    print(f"Anchor Spoof Detected: {dhl_iocs['anchor_spoofs'][0]}")
    assert dhl_risk == "HIGH"
    assert any("RULE-019" in r.get("rule_id", "") or "Anchor" in r.get("finding", "") for r in dhl_rules)

print("\n--- TEST 17: Originating IP & Geolocation Forensics ---")
from core.geolocation import extract_originating_sender_ip, get_sender_location, get_country_flag, resolve_hostname_supplementary

# 1. Test Explicit X-Originating-IP
h_orig = {"x-originating-ip": "[103.21.244.2]", "from": '"PayPal Security" <security@paypal-verify.com>'}
ip, src = extract_originating_sender_ip(h_orig)
assert ip == "103.21.244.2"
assert "x-originating-ip" in src.lower()
loc1 = get_sender_location(h_orig)
assert loc1["sender_ip"] == "103.21.244.2"
assert loc1["ip_classification"] == "Originating/Client IP Evidence"
assert loc1["is_client_ip"] is True
assert "x-originating-ip" in loc1["ip_source"].lower()
assert "x-originating-ip" in loc1["raw_header_evidence"].lower()

# 2. Test X-Sender-IP
h_sender_ip = {"x-sender-ip": "157.240.241.35", "from": "support@bank.com"}
loc2 = get_sender_location(h_sender_ip)
assert loc2["sender_ip"] == "157.240.241.35"
assert loc2["ip_classification"] == "Originating/Client IP Evidence"
assert loc2["is_client_ip"] is True
assert "x-sender-ip" in loc2["ip_source"].lower()

# 3. Test Authentication-Results & Received-SPF client-ip
h_spf = {"received-spf": "Pass (mailfrom) client-ip=157.240.241.35; designates mx.facebook.com"}
ip, src = extract_originating_sender_ip(h_spf)
assert ip == "157.240.241.35"
assert "client-ip" in src
loc3 = get_sender_location(h_spf)
assert loc3["sender_ip"] == "157.240.241.35"
assert loc3["is_client_ip"] is True
assert "client-ip" in loc3["ip_source"]
assert "Authentication" in loc3["ip_classification"]

# 4 & 6. Test Chronological Oldest Hop in Received Chain (Multiple hops & Earliest Public Relay IP)
h_hops = [
    "from mail-filter.recipient.com by mx.google.com; Sat, 12 Sep 2026 10:00:00 +0000",
    "from intermediate.relay.net (192.168.1.5) by mail-filter.recipient.com; Sat, 12 Sep 2026 09:59:50 +0000",
    "from originating.sender.org (195.154.122.45) by intermediate.relay.net; Sat, 12 Sep 2026 09:59:40 +0000",
    "from client.local (10.0.0.12) by originating.sender.org; Sat, 12 Sep 2026 09:59:30 +0000"
]
ip, src = extract_originating_sender_ip({"received": h_hops})
assert ip == "195.154.122.45"
assert "Originating MTA" in src
loc4 = get_sender_location({"received": h_hops})
assert loc4["sender_ip"] == "195.154.122.45"
assert loc4["ip_classification"] == "Earliest Public Relay IP"
assert loc4["is_client_ip"] is False

# 5. Test Private / RFC1918 / Loopback IP filtering
sender_loc_internal = get_sender_location({"received": ["from local (192.168.1.1) by local (10.0.0.1)"]})
assert sender_loc_internal["is_identified"] is False
assert sender_loc_internal["sender_ip"] == "Not available / Relay-masked"
assert sender_loc_internal["display_location"] == "Sender Location Unavailable"

# 7. Test Hostname without explicit IP in Received header
h_host_only = {"received": ["from mail.attacker-server.com by mx.google.com"]}
loc7 = get_sender_location(h_host_only)
assert loc7["is_identified"] is False
assert loc7["sender_ip"] == "Not available / Relay-masked"
assert loc7["dns_intelligence"]["hostname"] == "mail.attacker-server.com"

# 8. Test DNS-resolved host shown separately as supplementary intelligence (never labeled as Attacker IP)
dns_res = resolve_hostname_supplementary("dns.google")
assert dns_res["status"] == "Resolved"
assert dns_res["resolved_ip"] in ["8.8.8.8", "8.8.4.4"]
assert "does not prove the historical originating IP" in dns_res["explanation"]
dns_fail = resolve_hostname_supplementary("nonexistent.invalid.example.test")
assert dns_fail["status"] == "Unavailable"
assert dns_fail["display_label"] == "DNS Intelligence: Unavailable"

# 9. Test No public IP -> Relay-masked with exact required explanation
loc9 = get_sender_location({"from": "user@example.com"})
assert loc9["sender_ip"] == "Not available / Relay-masked"
assert loc9["is_identified"] is False
assert "The available email telemetry does not expose a reliable public client/originating IP" in loc9["relay_masked_explanation"]

# 10. Test Sender Address displayed (From: display name + email address)
loc10 = get_sender_location({"from": '"PayPal Security" <security@paypal-verify.com>'})
assert "PayPal Security" in loc10["sender_address"]
assert "security@paypal-verify.com" in loc10["sender_address"]
assert loc10["sender_email"] == "security@paypal-verify.com"
assert loc10["sender_display_name"] == "PayPal Security"

# 11. Test Return-Path / Envelope Sender comparison and mismatch detection
loc11 = get_sender_location({"from": "ceo@corporate.com", "return-path": "<attacker@evil-divert.com>"})
assert loc11["return_path_differs"] is True
assert loc11["return_path"] == "attacker@evil-divert.com"
loc11_same = get_sender_location({"from": "billing@corp.com", "return-path": "<billing@corp.com>"})
assert loc11_same["return_path_differs"] is False

# 12. Test Geo-IP lookup resolution
loc12 = get_sender_location({"x-originating-ip": "103.21.244.2"})
print(f"Sender Location Result: IP={loc12['sender_ip']} | Display='{loc12['display_location']}' | Source='{loc12['ip_source']}'")
assert loc12["is_identified"] is True
assert loc12["sender_ip"] == "103.21.244.2"
assert loc12["country"] != "Unknown"
assert loc12["flag"] != ""
assert loc12["org"] != "Unknown ISP"

# 13. Test Correct forensic attribution disclaimer
assert "Geo-IP provides approximate geographic/infrastructure context" in loc12["attribution_disclaimer"]
assert "does not prove the physical location or identity of the human sender" in loc12["attribution_disclaimer"]

# 14. Test Evidence Source & Flag Mapping
assert loc12["ip_source"] == "Header 'x-originating-ip'"
assert "x-originating-ip" in loc12["raw_header_evidence"].lower()
assert get_country_flag("India") == "🇮🇳"
assert get_country_flag("United States") == "🇺🇸"
assert get_country_flag("NonExistentCountry") == "🌐"
print("Originating IP & Geolocation 14-point forensic tests passed!")

print("\n>>> ALL 17 FORENSIC, CORPUS & SENTINEL TESTS COMPLETED AND PASSED 100%! <<<")



