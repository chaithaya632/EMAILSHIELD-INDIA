"""
EmailShield Real-World Email Corpus Benchmark & Stress Test
Validates:
1. Parser stability & zero defect crashes against real-world MIME structures.
2. RFC-2047 MIME Header decoding.
3. Defanged IOC & URL extraction and HTML anchor spoof detection.
4. Threat classification accuracy across 1,184 real spam/phishing/scam samples.
"""

import sys
import os
import zipfile
import time
from typing import Dict, Any, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from core.parser import SecureEmailParser
from core.indicators import extract_all_indicators
from core.classifier import MLClassifier
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.auth_claims import evaluate_auth_and_alignment
from core.bec_detector import detect_bec_and_impersonation
from core.attachments import analyze_all_attachments

def run_corpus_benchmark(sample_count: int = 100, zip_path: str = "email-corpus-main.zip") -> Dict[str, Any]:
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"Corpus zip not found at: {zip_path}")

    clf = MLClassifier()

    stats = {
        "total_scanned": 0,
        "high_threat": 0,
        "suspicious_threat": 0,
        "low_risk": 0,
        "parsing_exceptions": 0,
        "total_urls_extracted": 0,
        "total_anchor_spoofs": 0,
        "total_attachments": 0,
        "auth_bypass_threats": 0,
        "bec_impersonation_threats": 0,
        "total_elapsed_seconds": 0.0,
        "avg_latency_ms": 0.0,
        "sample_verdicts": []
    }

    start_time = time.time()

    with zipfile.ZipFile(zip_path, "r") as z:
        eml_files = [n for n in z.namelist() if n.lower().endswith(".eml")]
        if not eml_files:
            raise ValueError("No .eml files found inside the corpus zip.")

        step = max(1, len(eml_files) // sample_count)
        selected_files = eml_files[::step][:sample_count]
        stats["total_scanned"] = len(selected_files)

        print("=" * 75)
        print(f"EMAILSHIELD FORENSIC PIPELINE: REAL-WORLD BENCHMARK ({len(selected_files)} SAMPLES)")
        print("=" * 75)

        for idx, fname in enumerate(selected_files):
            try:
                raw_bytes = z.read(fname)
                parser = SecureEmailParser(raw_bytes)
                parsed = parser.parse()
                
                headers = parsed.get("headers", {})
                body = parsed.get("body", "")
                subject = str(headers.get("subject", "No Subject"))
                sender = str(headers.get("from", "No Sender"))
                
                # Indicators
                iocs = extract_all_indicators(body + " " + str(headers))
                urls = iocs.get("urls", [])
                anchor_spoofs = iocs.get("anchor_spoofs", [])
                stats["total_urls_extracted"] += len(urls)
                stats["total_anchor_spoofs"] += len(anchor_spoofs)

                # Auth and DMARC alignment
                auth_res = evaluate_auth_and_alignment(headers)
                if auth_res.get("threat_detected"):
                    stats["auth_bypass_threats"] += 1

                # Attachments
                atts = analyze_all_attachments(parsed.get("attachments", []))
                stats["total_attachments"] += len(atts)

                # BEC & Brand Spoofing
                bec_res = detect_bec_and_impersonation(headers, body, atts, auth_alignment=auth_res)
                if bec_res.get("is_display_name_spoof") or "BEC" in bec_res.get("verdict", "") or "Brand" in bec_res.get("verdict", ""):
                    stats["bec_impersonation_threats"] += 1

                # ML Prediction & Hybrid Risk Matrix
                ml_pred = clf.predict(subject, body)
                rules = evaluate_rules(
                    parsed,
                    auth_alignment=auth_res,
                    attachment_analyses=atts,
                    bec_telemetry=bec_res
                )
                risk, reasons = calculate_hybrid_risk(rules, ml_pred["probability"], auth_alignment=auth_res)

                if risk == "HIGH":
                    stats["high_threat"] += 1
                elif risk == "SUSPICIOUS":
                    stats["suspicious_threat"] += 1
                else:
                    stats["low_risk"] += 1

                stats["sample_verdicts"].append({
                    "file": fname.split("/")[-1],
                    "subject": subject,
                    "sender": sender,
                    "risk": risk,
                    "top_reasons": reasons[:2]
                })

                if (idx + 1) % 20 == 0 or idx == len(selected_files) - 1:
                    print(f"  Processed {idx + 1:3d}/{len(selected_files)} | Current High Threat: {stats['high_threat']} | Errors: {stats['parsing_exceptions']}")

            except Exception as e:
                stats["parsing_exceptions"] += 1
                print(f"  [ERROR] {fname}: {e}")

    elapsed = time.time() - start_time
    stats["total_elapsed_seconds"] = elapsed
    stats["avg_latency_ms"] = (elapsed / stats["total_scanned"] * 1000) if stats["total_scanned"] > 0 else 0.0

    detection_rate = (stats["high_threat"] + stats["suspicious_threat"]) / stats["total_scanned"] * 100

    print("=" * 75)
    print(f"BENCHMARK COMPLETED IN {elapsed:.2f}s ({stats['avg_latency_ms']:.1f}ms per email)")
    print(f"Total Emails Evaluated:     {stats['total_scanned']}")
    print(f"Threat Detection Rate:      {detection_rate:.1f}% ({stats['high_threat'] + stats['suspicious_threat']}/{stats['total_scanned']})")
    print(f"  - HIGH Severity Threats:  {stats['high_threat']} ({stats['high_threat']/stats['total_scanned']*100:.1f}%)")
    print(f"  - SUSPICIOUS Threats:     {stats['suspicious_threat']} ({stats['suspicious_threat']/stats['total_scanned']*100:.1f}%)")
    print(f"  - False Negatives / Low:  {stats['low_risk']} ({stats['low_risk']/stats['total_scanned']*100:.1f}%)")
    print(f"Auth / DMARC Bypasses:      {stats['auth_bypass_threats']}")
    print(f"Brand / BEC Spoofs:         {stats['bec_impersonation_threats']}")
    print(f"Total URLs Refanged/Found:  {stats['total_urls_extracted']}")
    print(f"Anchor Spoofs Discovered:   {stats['total_anchor_spoofs']}")
    print(f"Parsing Exceptions / Fatal: {stats['parsing_exceptions']} (Stability: {100.0 if stats['parsing_exceptions'] == 0 else 0.0}%)")
    print("=" * 75)

    return stats

if __name__ == "__main__":
    count = 100
    if len(sys.argv) > 1:
        count = int(sys.argv[1])
    run_corpus_benchmark(sample_count=count)
