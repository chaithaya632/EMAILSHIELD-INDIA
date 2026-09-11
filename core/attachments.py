import hashlib
import os
import re
from typing import List, Dict, Any

DANGEROUS_EXTS = {
    ".exe", ".scr", ".vbs", ".js", ".jse", ".bat", ".cmd", ".ps1",
    ".hta", ".cpl", ".wsf", ".msi", ".jar", ".com", ".pif"
}

MACRO_EXTS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".ppsm"
}

ARCHIVE_AND_DISK_EXTS = {
    ".iso", ".img", ".vhd", ".vhdx", ".dmg", ".tar", ".gz", ".7z", ".rar", ".zip"
}

DISGUISED_EXT_PATTERN = re.compile(
    r'\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png|csv)\.(exe|scr|vbs|js|bat|cmd|ps1|hta|cpl|wsf|iso)$',
    re.IGNORECASE
)

def calculate_sha256(data: bytes) -> str:
    if not data:
        return ""
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    return hashlib.sha256(data).hexdigest()

def analyze_attachment_metadata(att: Dict[str, Any], payload: bytes = None) -> Dict[str, Any]:
    """
    Forensic inspection of a single email attachment.
    - Generates immutable SHA-256 hash.
    - Detects deceptive double extensions (e.g. invoice.pdf.exe).
    - Checks for executable signatures (PE 'MZ' header) vs declared type.
    - Assesses macro and disk image abuse.
    """
    filename = att.get("filename") or "unnamed_attachment"
    content_type = (att.get("content_type") or att.get("mime_type") or "application/octet-stream").lower()
    size_bytes = att.get("size_bytes") or (len(payload) if payload else 0)
    
    sha256_hash = att.get("sha256") or (calculate_sha256(payload) if payload else "N/A")
    
    # Split extensions
    base, ext = os.path.splitext(filename.lower())
    full_lower = filename.lower()
    
    risk_level = "LOW"
    risk_flags = []
    is_double_ext = False
    is_dangerous_executable = False
    has_macros = False
    is_disk_image = False
    
    # 1. Double Extension Check (e.g. statement.pdf.exe or document.docx.scr)
    if DISGUISED_EXT_PATTERN.search(full_lower):
        is_double_ext = True
        risk_flags.append(f"🚨 Double Extension Spoofing: Disguised as document but ends with executable '{ext}'")
        risk_level = "CRITICAL"
        
    # 2. Dangerous Executables
    if ext in DANGEROUS_EXTS:
        is_dangerous_executable = True
        risk_flags.append(f"Direct executable file type ({ext})")
        if risk_level != "CRITICAL":
            risk_level = "CRITICAL"
            
    # 3. Macro enabled office documents
    if ext in MACRO_EXTS:
        has_macros = True
        risk_flags.append(f"Macro-enabled document format ({ext}) — may contain auto-executing VBA malware")
        if risk_level not in ["CRITICAL", "HIGH"]:
            risk_level = "HIGH"
            
    # 4. Disk images / Container formats used for Mark-of-the-Web bypass
    if ext in {".iso", ".img", ".vhd", ".vhdx"}:
        is_disk_image = True
        risk_flags.append(f"Disk image container ({ext}) — commonly used to bypass Mark-of-the-Web (MOTW)")
        if risk_level not in ["CRITICAL", "HIGH"]:
            risk_level = "HIGH"
            
    # 5. Magic Byte Verification (if payload is available)
    if payload and len(payload) >= 2:
        if payload[:2] == b'MZ':
            # DOS/PE Header
            if ext not in [".exe", ".dll", ".sys", ".cpl", ".scr"]:
                risk_flags.append(f"🚨 Spoofed Extension: File has Windows PE/MZ executable magic bytes but extension is '{ext}'")
                risk_level = "CRITICAL"
        elif payload[:2] == b'PK' and ext in [".exe", ".scr"]:
            # Zip disguised as exe
            risk_flags.append("Archive structure detected inside executable extension")

    # 6. Content-Type mismatch
    if content_type in ["application/x-msdownload", "application/x-dosexec", "application/x-executable"]:
        if ext not in [".exe", ".msi", ".dll"]:
            risk_flags.append(f"MIME type '{content_type}' indicates binary executable despite extension '{ext}'")
            risk_level = "CRITICAL"

    verdict_label = "CLEAN / BENIGN"
    if risk_level == "CRITICAL":
        verdict_label = "MALICIOUS / WEAPONIZED"
    elif risk_level == "HIGH":
        verdict_label = "SUSPICIOUS"
    elif risk_level == "MEDIUM":
        verdict_label = "ELEVATED CAUTION"

    return {
        "filename": filename,
        "sha256": sha256_hash,
        "size_bytes": size_bytes,
        "content_type": content_type,
        "extension": ext,
        "risk_level": risk_level,
        "verdict_label": verdict_label,
        "is_double_ext": is_double_ext,
        "is_dangerous_executable": is_dangerous_executable,
        "has_macros": has_macros,
        "is_disk_image": is_disk_image,
        "risk_flags": risk_flags
    }

def analyze_all_attachments(attachments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze all attachments in an email."""
    results = []
    for att in attachments:
        analysis = analyze_attachment_metadata(att)
        results.append(analysis)
    return results
