# EMAILSHIELD INDIA — Empirical Benchmark Evaluation

## Real-world security-research corpus benchmark

### Evaluation Overview
This benchmark evaluates the EMAILSHIELD INDIA detection and forensic parsing pipeline across an offline corpus of **1,184 real-world .eml samples** sourced from live security research archives and threat telemetry captures.

> **Dataset Characterization & Metric Definition:**
> The evaluated dataset is a security-research corpus that is **predominantly malicious**. Therefore, the metric reported below (**88.26%**) is strictly a **Threat detection rate on the evaluated corpus**, and is **NOT** equivalent to a general-world false-positive or accuracy measurement. In a real-world enterprise mailbox distribution where clean emails vastly outnumber attacks, true accuracy is governed by false-positive calibration (which is evaluated separately in our 17-test regression suite under TEST 14).

---

### Benchmark Results (1,184 Samples)

| Benchmark Metric | Measured Result | Percentage / Unit |
| :--- | :--- | :--- |
| **Total Scanned Emails** | **1,184** | 100.00% |
| **Threat Detection Rate on Evaluated Corpus** | **1,045** | **88.26%** |
| • High Severity Verdicts | 1,044 | 88.18% |
| • Suspicious Verdicts | 1 | 0.08% |
| • Clean / Unflagged Samples | 139 | 11.74% |
| **Parser Exceptions / Crashes** | **0** | **0.00%** (100% Resilience) |
| **MIME Decoding Failures** | **0** | **0.00%** (100% Resilience) |
| **Malformed / Problematic Samples** | **0** | **0.00%** |
| **Total URLs Extracted** | **10,042** | ~8.48 URLs / email |
| **Defanged URLs Refanged & Inspected** | **9,267** | 92.28% of extracted URLs |
| **Anchor Text Spoof Detections** | **249** | Hyperlink mismatch attacks |
| **Brand Display-Name Spoof Detections** | **57** | Executive / Brand masquerading |
| **Attack-Vector Findings Triggered** | **5,432** | Multiple findings per email* |

*\* Note on Attack Vectors: Attack-vector counts overlap because a single sophisticated phishing email can trigger multiple distinct heuristic rules (e.g., brand lookalike + SPF unaligned + defanged URL redirect + urgent wire lure).*

---

### Processing Latency & Performance Throughput

The entire corpus was parsed, tokenized, and evaluated across all forensic modules in **79.31 seconds** on standard commodity hardware with no external network blocking:

| Performance Metric | Measured Latency |
| :--- | :--- |
| **Average Processing Time** | **66.98 ms / email** |
| **Median Processing Time** | **50.31 ms / email** |
| **95th Percentile (p95) Latency** | **130.40 ms / email** |
| **Sustained System Throughput** | **14.93 emails / second** |
| **Full Corpus Runtime** | **79.31 seconds** |

---

### Methodology & Engine Integrity
1. **Zero Rule-Tuning for Benchmark:** Core detection weights, heuristics, and classification thresholds were frozen prior to benchmark execution to ensure unbiased real-world measurement.
2. **Defensive Defang & Refang Handling:** All obfuscated security-scanner URLs (e.g., hxxp://, example[.]com) are refanged in memory for inspection and re-defanged before display.
3. **Forensic Attribution Disclaimer:** Originating public IP addresses are derived from available header evidence and relay metadata. GeoIP provides approximate infrastructure location context only and does not establish physical individual identity.
