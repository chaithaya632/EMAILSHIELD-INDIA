# EMAILSHIELD INDIA

## AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

**Smart India Hackathon 2026 — SIH26106**

EMAILSHIELD INDIA is an evidence-aware email investigation platform designed for authorized SOC analysts, cybercrime investigators, institutional security teams, and security researchers. 

Instead of just predicting if an email is phishing, it builds a complete investigation, including:
- MIME & Header Forensics
- Authentication Analysis (SPF/DKIM/DMARC)
- IOC Extraction
- Infrastructure Geolocation
- Rule-based & ML-based Threat Detection
- Investigation Timeline & Graph Correlation
- PDF & JSON Evidence Reporting

## Requirements

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Download an offline GeoIP database (e.g., DB-IP Country Lite) and place the `dbip-country-lite.mmdb` file in `data/geo/`.

## Running the Dashboard

```bash
streamlit run app.py
```

## Empirical Benchmark & Performance
Comprehensive evaluation across **1,184 real-world `.eml` samples** (see [`BENCHMARK.md`](file:///e:/EMAILSHEILD/BENCHMARK.md) for full breakdown):

- **Benchmark Label:** Real-world security-research corpus benchmark
- **Threat Detection Rate on Evaluated Corpus:** **88.26%** (1,045 / 1,184 detected threats)
- **High Severity:** 1,044 (88.18%) | **Suspicious:** 1 (0.08%) | **Clean:** 139 (11.74%)
- **Parser Resilience:** 0 exceptions, 0 MIME decoding failures across all 1,184 samples (100% resilience)
- **Extracted Indicators:** 10,042 URLs extracted (9,267 defanged URLs refanged), 249 anchor spoof detections
- **Average Latency:** 66.98 ms / email (Median: 50.31 ms, p95: 130.40 ms)
- **System Throughput:** 14.93 emails / second (Full corpus evaluated in 79.31 seconds)

*Dataset Note: The evaluated corpus is predominantly malicious; this metric represents threat detection rate on this research set, not a general-world accuracy/false-positive measurement. Attack-vector counts overlap as individual samples may trigger multiple indicators.*
