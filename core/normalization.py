"""
core/normalization.py
EMAILSHIELD INDIA — Normalized Evidence & Obfuscation Processing Pipeline.

Architectural Guarantees:
1. Exact Conceptual Pipeline Ordering:
   RAW EMAIL EVIDENCE
          ↓
   ZERO-WIDTH CHARACTER REMOVAL
          ↓
   CONFUSABLE / HOMOGLYPH DETECTION (strictly before NFKC)
          ↓
   NFKC NORMALIZATION
          ↓
   BOUNDED TOKEN / SPACING NORMALIZATION
          ↓
   RULE ENGINE & ML CLASSIFIER
2. Evidence Preservation: Original raw body, headers, and attachments are NEVER modified.
   Normalized strings are derived artifacts strictly for forensic analysis.
3. Bounded Processing: All regexes and sliding windows enforce strict bounds to prevent
   catastrophic backtracking or CPU exhaustion.
"""

import re
import unicodedata
from typing import Dict, Any, List, Tuple, Optional

# Zero-width and invisible control characters
ZERO_WIDTH_CHARS = {
    '\u200B': 'ZERO_WIDTH_SPACE',
    '\u200C': 'ZERO_WIDTH_NON_JOINER',
    '\u200D': 'ZERO_WIDTH_JOINER',
    '\uFEFF': 'ZERO_WIDTH_NO_BREAK_SPACE',
    '\u200E': 'LEFT_TO_RIGHT_MARK',
    '\u200F': 'RIGHT_TO_LEFT_MARK',
    '\u202A': 'LEFT_TO_RIGHT_EMBEDDING',
    '\u202B': 'RIGHT_TO_LEFT_EMBEDDING',
    '\u202C': 'POP_DIRECTIONAL_FORMATTING',
    '\u202D': 'LEFT_TO_RIGHT_OVERRIDE',
    '\u202E': 'RIGHT_TO_LEFT_OVERRIDE',
    '\u2060': 'WORD_JOINER',
    '\u00AD': 'SOFT_HYPHEN',
    '\u180E': 'MONGOLIAN_VOWEL_SEPARATOR',
}

ZERO_WIDTH_PATTERN = re.compile('[' + ''.join(ZERO_WIDTH_CHARS.keys()) + ']')

# Common cross-script confusables (Cyrillic, Greek to ASCII)
CONFUSABLE_LOOKUP = {
    # Cyrillic lowercase
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0458': 'j', '\u0455': 's', '\u0432': 'b', '\u043C': 'm',
    '\u043D': 'h', '\u0442': 't',
    # Cyrillic uppercase
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K',
    '\u041C': 'M', '\u041D': 'H', '\u041E': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
    # Greek lowercase
    '\u03B1': 'a', '\u03BF': 'o', '\u03C1': 'p', '\u03BD': 'v',
    '\u03B5': 'e', '\u03B9': 'i', '\u03BA': 'k',
    # Greek uppercase
    '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
    '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N',
    '\u039F': 'O', '\u03A1': 'P', '\u03A4': 'T', '\u03A7': 'X'
}

# Targeted brand and lure keywords for bounded spaced token detection
KNOWN_LURE_TOKENS = {
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank", "sbi", "hdfc", "hdfcbank", "icici",
    "axisbank", "kotak", "pnb", "incometax", "dhl", "fedex", "ups",
    "urgent", "warning", "verify", "verification", "security", "account",
    "password", "login", "suspended", "suspension", "locked", "blocked",
    "payment", "invoice", "billing", "update", "confirm"
}


def strip_zero_width_chars(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Identifies and removes zero-width/bidi control characters from text.
    Returns cleaned text and a list of detected zero-width evidence records.
    """
    if not text:
        return "", []

    findings = []
    for idx, ch in enumerate(text):
        if ch in ZERO_WIDTH_CHARS:
            findings.append({
                "char_code": f"U+{ord(ch):04X}",
                "name": ZERO_WIDTH_CHARS[ch],
                "position": idx
            })

    cleaned = ZERO_WIDTH_PATTERN.sub('', text)
    return cleaned, findings


def _get_char_script(ch: str) -> str:
    """Classifies a character into its primary Unicode script category."""
    if not ch.isalpha():
        return "COMMON"
    name = unicodedata.name(ch, "")
    if name.startswith("LATIN"):
        return "LATIN"
    if name.startswith("CYRILLIC"):
        return "CYRILLIC"
    if name.startswith("GREEK"):
        return "GREEK"
    if name.startswith("ARABIC"):
        return "ARABIC"
    if name.startswith("HEBREW"):
        return "HEBREW"
    if name.startswith("DEVANAGARI"):
        return "DEVANAGARI"
    return "OTHER"


def detect_confusables(text: str) -> Dict[str, Any]:
    """
    Detects confusable characters and mixed-script sequences.
    CRITICAL: Must execute BEFORE NFKC normalization to preserve
    compatibility-equivalent character distinctions.
    """
    if not text:
        return {
            "has_mixed_script": False,
            "confusable_count": 0,
            "findings": []
        }

    tokens = re.findall(r'\b[\w\.\-]+\b', text)
    findings = []
    total_confusables = 0

    for token in tokens:
        if len(token) < 2:
            continue

        scripts = set()
        token_confusables = []
        for ch in token:
            script = _get_char_script(ch)
            if script != "COMMON":
                scripts.add(script)
            if ch in CONFUSABLE_LOOKUP:
                token_confusables.append({
                    "char": ch,
                    "code": f"U+{ord(ch):04X}",
                    "latin_equiv": CONFUSABLE_LOOKUP[ch]
                })

        # Mixed script condition: contains Latin AND (Cyrillic or Greek)
        is_mixed = ("LATIN" in scripts) and bool(scripts - {"LATIN", "COMMON"})
        if is_mixed or token_confusables:
            total_confusables += len(token_confusables)
            findings.append({
                "token": token,
                "scripts": sorted(list(scripts)),
                "is_mixed_script": is_mixed,
                "confusables": token_confusables
            })

    return {
        "has_mixed_script": any(f["is_mixed_script"] for f in findings),
        "confusable_count": total_confusables,
        "findings": findings
    }


def normalize_nfkc(text: str) -> str:
    """
    Applies standard Unicode NFKC normalization.
    Must only run AFTER confusable and mixed-script detection.
    """
    if not text:
        return ""
    return unicodedata.normalize("NFKC", text)


def detect_and_normalize_spaced_tokens(
    text: str,
    max_gap: int = 3,
    max_window: int = 40
) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Identifies spaced obfuscated words (e.g. 'p a y p a l', 'm i c r o s o f t')
    using a strictly bounded window that does NOT span arbitrary newlines.
    
    Guarantees:
    - Bounded character window (max_window=40)
    - Bounded maximum gap (1 to max_gap spaces)
    - Line-by-line evaluation (preserves newlines, prevents paragraph collapse)
    - Low CPU overhead (linear per line)
    """
    if not text:
        return "", []

    lines = text.split("\n")
    normalized_lines = []
    findings = []

    # Regex matching runs of single alphabetic characters separated by 1 to max_gap spaces
    # Minimum 3 characters, maximum 15 characters
    gap_spec = f"{{1,{max_gap}}}"
    spaced_re = re.compile(rf'(?<![a-zA-Z])(?:[a-zA-Z][ \t]{gap_spec}){{2,14}}[a-zA-Z](?![a-zA-Z])')

    for line_idx, line in enumerate(lines):
        if not line.strip() or len(line) > 10000:
            normalized_lines.append(line)
            continue

        def _replace_spaced_match(match: re.Match) -> str:
            raw_match = match.group(0)
            if len(raw_match) > max_window:
                return raw_match

            # Collapse spaces between the characters
            collapsed = re.sub(r'[ \t]+', '', raw_match).lower()
            if len(collapsed) >= 3:
                is_known_lure = collapsed in KNOWN_LURE_TOKENS
                findings.append({
                    "original": raw_match,
                    "normalized": collapsed,
                    "is_brand_or_lure": is_known_lure,
                    "line": line_idx + 1
                })
                return collapsed
            return raw_match

        new_line = spaced_re.sub(_replace_spaced_match, line)
        normalized_lines.append(new_line)

    return "\n".join(normalized_lines), findings


def normalize_email_payload(raw_subject: str, raw_body: str) -> Dict[str, Any]:
    """
    Executes the authoritative multi-stage normalization pipeline in exact order:
    1. RAW EMAIL EVIDENCE
    2. ZERO-WIDTH CHARACTER REMOVAL
    3. CONFUSABLE / HOMOGLYPH DETECTION (before NFKC)
    4. NFKC NORMALIZATION
    5. BOUNDED TOKEN / SPACING NORMALIZATION
    6. Downstream Rule Engine & ML preparation
    """
    raw_s = raw_subject or ""
    raw_b = raw_body or ""

    # Stage 1 -> 2: Zero-Width Removal
    clean_s, zw_subject = strip_zero_width_chars(raw_s)
    clean_b, zw_body = strip_zero_width_chars(raw_b)
    all_zero_width = zw_subject + zw_body

    # Stage 2 -> 3: Confusable & Homoglyph Detection (Pre-NFKC)
    confusables_subject = detect_confusables(clean_s)
    confusables_body = detect_confusables(clean_b)
    combined_confusables = {
        "has_mixed_script": confusables_subject["has_mixed_script"] or confusables_body["has_mixed_script"],
        "confusable_count": confusables_subject["confusable_count"] + confusables_body["confusable_count"],
        "findings": confusables_subject["findings"] + confusables_body["findings"]
    }

    # Map confusables to ASCII for downstream Rules and ML representation
    deconfused_s = "".join(CONFUSABLE_LOOKUP.get(c, c) for c in clean_s)
    deconfused_b = "".join(CONFUSABLE_LOOKUP.get(c, c) for c in clean_b)

    # Stage 3 -> 4: NFKC Normalization
    nfkc_s = normalize_nfkc(deconfused_s)
    nfkc_b = normalize_nfkc(deconfused_b)

    # Stage 4 -> 5: Bounded Spaced-Token Normalization
    norm_s, spaced_s = detect_and_normalize_spaced_tokens(nfkc_s)
    norm_b, spaced_b = detect_and_normalize_spaced_tokens(nfkc_b)
    all_spaced_tokens = spaced_s + spaced_b

    return {
        # Raw evidence (unmodified)
        "raw_subject": raw_s,
        "raw_body": raw_b,
        # Intermediate representations
        "clean_subject": clean_s,
        "clean_body": clean_b,
        "nfkc_subject": nfkc_s,
        "nfkc_body": nfkc_b,
        # Final normalized representation for Rules and ML
        "normalized_subject": norm_s,
        "normalized_body": norm_b,
        # Structured forensic evidence
        "zero_width_findings": all_zero_width,
        "confusable_evidence": combined_confusables,
        "spaced_token_findings": all_spaced_tokens
    }
