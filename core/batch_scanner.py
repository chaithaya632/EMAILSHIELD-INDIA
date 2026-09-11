from typing import Dict, Any, List
from core.gmail_integration import fetch_recent_emails, fetch_raw_email
from core.parser import SecureEmailParser
from core.risk import evaluate_rules, calculate_hybrid_risk

def categorize_content(subject: str, body: str, sender: str) -> str:
    text = (subject + " " + body).lower()
    
    # Simple heuristics
    if any(k in text for k in ["unsubscribe", "newsletter", "subscription", "opt out"]):
        return "Subscription"
    elif any(k in text for k in ["order", "receipt", "invoice", "shipping", "delivery", "purchase"]):
        return "Purchase/Transaction"
    elif any(k in text for k in ["sale", "discount", "offer", "promo", "deal", "save up to"]):
        return "Ad/Promo"
    elif "no-reply" in sender.lower() or "support" in sender.lower():
        return "Business/Notification"
    else:
        return "Personal/General"

def scan_mailbox_batch(
    ml_classifier,
    max_emails: int = 50,
    query: str = None,
    progress_callback=None,
    custom_emails: List[Dict[str, str]] = None,
    raw_fetcher_fn=None
) -> Dict[str, Any]:
    """Scans a batch of emails and returns aggregated analytics."""
    if custom_emails is not None and raw_fetcher_fn is not None:
        emails = custom_emails[:max_emails]
        fetcher = raw_fetcher_fn
    else:
        emails = fetch_recent_emails(max_emails, query=query)
        fetcher = fetch_raw_email
    
    analytics = {
        "total_scanned": len(emails),
        "clean_count": 0,
        "suspicious_count": 0,
        "phishing_count": 0,
        "flagged_emails": []
    }
    
    for idx, msg in enumerate(emails):
        if progress_callback:
            progress_callback(idx, len(emails), msg['subject'])
            
        try:
            raw_bytes = fetcher(msg['id'])
            parser = SecureEmailParser(raw_bytes)
            parsed_data = parser.parse()
            
            subject = str(parsed_data.get("headers", {}).get("subject", msg['subject']))
            body = parsed_data.get("body", "")
            
            ml_pred = ml_classifier.predict(subject, body)
            rule_results = evaluate_rules(parsed_data)
            risk_score, reasons = calculate_hybrid_risk(rule_results, ml_pred["probability"])
            
            if "content_categories" not in analytics:
                analytics["content_categories"] = {}
                
            content_type = categorize_content(subject, body, msg['sender'])
            analytics["content_categories"][content_type] = analytics["content_categories"].get(content_type, 0) + 1
            
            category = "Clean"
            if risk_score == "HIGH":
                category = "Phishing"
                analytics["phishing_count"] += 1
            elif risk_score == "SUSPICIOUS":
                category = "Suspicious"
                analytics["suspicious_count"] += 1
            else:
                analytics["clean_count"] += 1
                
            analytics["flagged_emails"].append({
                "id": msg['id'],
                "subject": msg['subject'],
                "sender": msg['sender'],
                "date": msg['date'],
                "risk_score": risk_score,
                "threat_category": category,
                "content_type": content_type,
                "reasons": reasons[:3] if category != "Clean" else []
            })
        except Exception as e:
            print(f"Error scanning email {msg['id']}: {e}")
            # If an email fails to parse, just skip it to keep the batch moving
            
    return analytics
