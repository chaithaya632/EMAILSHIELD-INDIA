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

print("\n--- TEST 13: I4C / NCRP Complaint Packager & Section 65B PDF ---")
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

print("\n>>> ALL 13 FORENSIC TESTS COMPLETED AND PASSED 100%! <<<")


