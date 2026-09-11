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
