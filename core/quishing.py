"""
core/quishing.py
QR Code Phishing ("Quishing") Detection Engine for EMAILSHIELD INDIA.
Scans image attachments and inline base64 HTML images using OpenCV to decode hidden QR codes,
unmask destination phishing URLs, and assess potential credential harvesting / exploit payload risks.
"""

import re
import base64
from typing import List, Dict, Any
import numpy as np
import cv2
from core.url_forensics import analyze_all_urls

IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif')
IMAGE_MIMES = ('image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/bmp')


def _decode_qr_from_bytes(image_bytes: bytes) -> List[str]:
    """
    Attempts to detect and decode one or more QR codes from raw image bytes using OpenCV.
    Applies resolution scaling and border normalization if needed.
    """
    if not image_bytes or len(image_bytes) < 32:
        return []
        
    try:
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return []
            
        detector = cv2.QRCodeDetector()
        decoded_urls = []
        
        # Helper detection attempt
        def try_decode(target_img):
            nonlocal decoded_urls
            # Try multi-decode
            try:
                ok, decoded_info, _, _ = detector.detectAndDecodeMulti(target_img)
                if ok and decoded_info:
                    for text in decoded_info:
                        if text and text.strip():
                            decoded_urls.append(text.strip())
            except Exception:
                pass
            # Try single decode
            if not decoded_urls:
                text, _, _ = detector.detectAndDecode(target_img)
                if text and text.strip():
                    decoded_urls.append(text.strip())

        # Attempt 1: Direct decode
        try_decode(img)
        
        # Attempt 2: Add border (quiet zone) and scale if small
        if not decoded_urls:
            h, w = img.shape[:2]
            bordered = cv2.copyMakeBorder(img, 15, 15, 15, 15, cv2.BORDER_CONSTANT, value=[255, 255, 255])
            if h < 200 or w < 200:
                scale_factor = max(2, int(300 / max(h, w)))
                scaled = cv2.resize(bordered, (bordered.shape[1] * scale_factor, bordered.shape[0] * scale_factor), interpolation=cv2.INTER_NEAREST)
                try_decode(scaled)
            else:
                try_decode(bordered)
                
        # Attempt 3: Grayscale and contrast normalization
        if not decoded_urls:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            norm = cv2.normalize(gray, None, alpha=0, beta=255, norm_type=cv2.NORM_MINMAX)
            bordered_norm = cv2.copyMakeBorder(norm, 15, 15, 15, 15, cv2.BORDER_CONSTANT, value=[255])
            try_decode(bordered_norm)

        return list(set(decoded_urls))
    except Exception as e:
        print(f"[!] Quishing image decode error: {e}")
        return []


def scan_for_quishing(attachments: List[Dict[str, Any]], html_body: str = "") -> List[Dict[str, Any]]:
    """
    Scans all email attachments and inline embedded images for QR codes.
    Returns a list of detected Quishing artifacts with full URL threat analysis.
    """
    quishing_findings = []
    
    # 1. Scan Attachments
    for att in attachments:
        filename = att.get("filename", "")
        mime = att.get("declared_mime", "").lower()
        content_bytes = att.get("content_bytes") or att.get("payload")
        
        is_image = (
            filename.lower().endswith(IMAGE_EXTENSIONS) or
            any(mime.startswith(m) for m in IMAGE_MIMES)
        )
        
        if is_image and content_bytes:
            if isinstance(content_bytes, str):
                try:
                    content_bytes = base64.b64decode(content_bytes)
                except Exception:
                    continue
                    
            qr_texts = _decode_qr_from_bytes(content_bytes)
            for url in qr_texts:
                url_eval = analyze_all_urls([url])
                url_meta = url_eval[0].model_dump() if url_eval and hasattr(url_eval[0], "model_dump") else (url_eval[0] if isinstance(url_eval[0], dict) else {})
                
                quishing_findings.append({
                    "source": f"Attachment: {filename}",
                    "filename": filename,
                    "decoded_url": url,
                    "defanged_url": url_meta.get("defanged_url", url),
                    "threat_level": url_meta.get("risk_level", "HIGH"),
                    "threat_category": url_meta.get("threat_category", "Potential Credential Phishing"),
                    "what_it_causes": url_meta.get("what_it_causes", "Hidden destination behind QR code bypasses traditional email text filters."),
                    "what_to_do": url_meta.get("what_to_do", "Do NOT scan this QR code. Block destination domain."),
                    "sha256": att.get("sha256", "N/A")
                })

    # 2. Scan Inline Base64 Images in HTML Body
    if html_body and "data:image" in html_body:
        b64_pattern = re.compile(r'data:image/[a-zA-Z]+;base64,([A-Za-z0-9+/=]+)')
        matches = b64_pattern.findall(html_body)
        
        for idx, b64_str in enumerate(matches[:5]): # Scan up to 5 inline images
            try:
                img_data = base64.b64decode(b64_str)
                qr_texts = _decode_qr_from_bytes(img_data)
                for url in qr_texts:
                    url_eval = analyze_all_urls([url])
                    url_meta = url_eval[0].model_dump() if url_eval and hasattr(url_eval[0], "model_dump") else (url_eval[0] if isinstance(url_eval[0], dict) else {})
                    
                    quishing_findings.append({
                        "source": f"Inline Embedded Image #{idx + 1}",
                        "filename": f"inline_qr_{idx + 1}.png",
                        "decoded_url": url,
                        "defanged_url": url_meta.get("defanged_url", url),
                        "threat_level": url_meta.get("risk_level", "HIGH"),
                        "threat_category": url_meta.get("threat_category", "Inline QR Phishing"),
                        "what_it_causes": url_meta.get("what_it_causes", "Bypasses text filters by concealing phishing target inside an inline image."),
                        "what_to_do": url_meta.get("what_to_do", "Do NOT scan with smartphone camera."),
                        "sha256": "N/A (Inline Base64)"
                    })
            except Exception:
                continue
                
    return quishing_findings
