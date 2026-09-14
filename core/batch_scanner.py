import re
import html
from typing import Dict, Any, List, Optional
from core.gmail_integration import fetch_recent_emails, fetch_raw_email
from core.parser import SecureEmailParser
from core.risk import evaluate_rules, calculate_hybrid_risk

def clean_email_text(raw_text: str) -> str:
    """Strip HTML tags, CSS style blocks, scripts, and decode entities."""
    if not raw_text:
        return ""
    # Remove CSS style blocks
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', raw_text, flags=re.DOTALL | re.IGNORECASE)
    # Remove script blocks
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.DOTALL | re.IGNORECASE)
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Unescape HTML entities (&nbsp;, &amp;, etc.)
    text = html.unescape(text)
    # Collapse multiple whitespaces
    return re.sub(r'\s+', ' ', text).strip()

def categorize_content(subject: str, body: str, sender: str, headers: Optional[Dict[str, Any]] = None) -> str:
    """
    Intelligently classifies inbound email content into accurate operational categories.
    Prevents false 'Purchase/Transaction' matches caused by HTML CSS 'border' or phrases like 'in order to'.
    Accurately identifies Google Forms, meeting invites, collaboration shares, security alerts, and financial transactions.
    """
    headers = headers or {}
    clean_body = clean_email_text(body)
    subj_lower = (subject or "").lower()
    snd_lower = (sender or "").lower()
    text_lower = f"{subj_lower} {clean_body.lower()}"

    # 1. Google Forms, Surveys & Feedback
    form_senders = [
        "forms-receipts-noreply@google.com", "google-forms-noreply@google.com", 
        "forms-noreply@google.com", "typeform.com", "surveymonkey.com", "jotform.com",
        "forms.office.com", "zohoforms.com"
    ]
    if any(fs in snd_lower for fs in form_senders):
        return "Form / Survey / Feedback"
    
    form_keywords = [
        "google forms", "docs.google.com/forms", "forms.gle", "fill out this form",
        "form response received", "view your response", "edit your response",
        "thanks for filling out", "new response recorded", "survey invitation",
        "feedback form", "questionnaire", "take our survey", "rate your experience",
        "customer feedback survey", "typeform", "surveymonkey", "microsoft forms", "zoho forms"
    ]
    if any(k in text_lower for k in form_keywords) or any(k in subj_lower for k in ["feedback form", "survey", "questionnaire", "google form", "form response"]):
        return "Form / Survey / Feedback"

    # 2. Meeting, Calendar & Event Invites
    meeting_senders = [
        "calendar-notification@google.com", "zoom.us", "teams.microsoft.com", 
        "meet.google.com", "webex.com", "calendly.com", "cal.com", "eventbrite.com", "lu.ma"
    ]
    if any(ms in snd_lower for ms in meeting_senders):
        return "Meeting / Calendar Invite"
    
    if any(h in subj_lower for h in ["invitation:", "accepted:", "declined:", "tentatively accepted:", "meeting invite:", "webinar:"]):
        return "Meeting / Calendar Invite"
    if any(k in text_lower for k in ["join zoom meeting", "join microsoft teams meeting", "google meet joining info", "calendar event", "add to calendar", "rsvp now", "meeting scheduled"]):
        return "Meeting / Calendar Invite"

    # 3. Collaboration, Documents & Cloud Workspaces
    collab_senders = [
        "comments-noreply@docs.google.com", "drive-shares-dm-noreply@google.com",
        "notifications@github.com", "jira@", "confluence@", "notion.so", "figma.com",
        "trello.com", "asana.com", "slack.com", "canva.com", "clickup.com", "dropbox.com"
    ]
    if any(cs in snd_lower for cs in collab_senders):
        return "Collaboration / Document Share"
    if any(k in text_lower for k in ["shared a document with you", "shared a file with you", "invited you to edit", 
                                     "invited you to view", "commented on", "pull request", "assigned you to an issue", "mentioned you in"]):
        return "Collaboration / Document Share"

    # 4. Account, Security & Authentication Alerts
    sec_senders = [
        "no-reply@accounts.google.com", "account-security-noreply@accountprotection.microsoft.com", 
        "security@", "security-noreply@", "account-protection@", "auth@"
    ]
    if any(ss in snd_lower for ss in sec_senders):
        return "Account / Security Alert"
    sec_phrases = [
        "security alert", "new sign-in", "login from new device", "suspicious sign-in",
        "password reset", "reset your password", "verification code", "one-time password",
        "your otp is", "otp for", "2-step verification", "two-factor authentication",
        "confirm your email", "verify your account", "account recovery", "unauthorized access attempt"
    ]
    if any(p in subj_lower or p in text_lower for p in sec_phrases):
        return "Account / Security Alert"

    # 5. Education, Courses & Academics
    edu_senders = ["classroom.google.com", "coursera.org", "udemy.com", "edx.org", "unacademy", "geeksforgeeks", "leetcode", "hackerrank", "nptel"]
    if any(es in snd_lower for es in edu_senders):
        return "Education / Academic"
    if any(k in subj_lower for k in ["assignment due", "quiz posted", "course announcement", "exam schedule", "certificate of completion"]):
        return "Education / Academic"

    # 6. Career & Job Applications
    career_senders = ["naukri.com", "indeed.com", "internshala.com", "wellfound.com", "foundit.in", "hirist.com", "instahyre.com"]
    if any(cs in snd_lower for cs in career_senders) or ("job" in snd_lower and "alert" in snd_lower):
        return "Career / Job Portal"
    if any(k in subj_lower for k in ["job alert", "application received", "shortlisted for", "interview invitation", "job opening"]):
        return "Career / Job Portal"

    # 7. Social Media & Community
    social_senders = [
        "linkedin.com", "x.com", "twitter.com", "redditmail.com", "discord.com", 
        "instagram.com", "facebookmail.com", "quora.com", "youtube.com"
    ]
    if any(ss in snd_lower for ss in social_senders):
        return "Social / Community"

    # 8. Purchases, Orders, Delivery & Financial Transactions
    # STRICT REGEX with word boundaries: NEVER matches CSS 'border' or 'in order to'
    tx_senders = [
        "amazon.", "flipkart.", "myntra.", "swiggy.", "zomato.", "blinkit.", "zepto.",
        "uber.com", "olacabs.", "irctc.", "makemytrip.", "hdfcbank.", "sbi.co.in",
        "icicibank.", "axisbank.", "paytm.", "phonepe.", "razorpay.", "stripe.com", "paypal."
    ]
    is_tx_sender = any(ts in snd_lower for ts in tx_senders)
    
    tx_patterns = [
        r'\b(order\s+(confirmed|confirmation|placed|summary|details|shipped|delivered|update|receipt|#|id))\b',
        r'\b(your\s+(order|receipt|invoice|delivery|package))\b',
        r'\b(payment\s+(successful|received|confirmation|receipt|processed|debited|completed|failed))\b',
        r'\b(transaction\s+(alert|successful|receipt|details|id))\b',
        r'\b(tax\s+invoice|billing\s+invoice|e-receipt|sales\s+receipt)\b',
        r'\b(amount\s+(debited|credited))\b',
        r'\b(inr|rs\.?|usd|\$|€|£)\s*[\d,]+(\.\d{2})?\s*(debited|credited|paid|charged)\b',
        r'\b(bank\s+statement|account\s+statement|card\s+statement|netbanking\s+statement)\b',
        r'\b(tracking\s+number|out\s+for\s+delivery|delivered\s+on|package\s+delivered|shipment\s+update)\b',
        r'\b(booking\s+(confirmed|confirmation|details)|ticket\s+(booked|details)|pnr\s+status)\b'
    ]
    has_tx_regex = any(re.search(pat, text_lower) for pat in tx_patterns)
    has_tx_subj = any(re.search(pat, subj_lower) for pat in [
        r'\b(order|receipt|invoice|statement|payment|debited|credited|refund|shipment|delivery)\b'
    ])
    
    if (is_tx_sender and (has_tx_regex or has_tx_subj)) or has_tx_regex:
        return "Purchase / Financial Transaction"

    # 9. Promotional, Offers & Deals
    promo_patterns = [
        r'\b(flat\s+\d+%\s+off|save\s+up\s+to|\b\d+%\s+discount|coupon\s+code|promo\s+code)\b',
        r'\b(flash\s+sale|exclusive\s+deal|limited\s+period\s+offer|cashback|clearance\s+sale|shop\s+now)\b'
    ]
    if any(re.search(pat, text_lower) for pat in promo_patterns) or any(k in subj_lower for k in ["sale", "discount", "special offer", "deal of the day"]):
        return "Promotional / Marketing"

    # 10. Newsletters & Subscriptions
    is_list = bool(headers.get("list-unsubscribe") or headers.get("list-id") or str(headers.get("precedence", "")).lower() == "bulk")
    newsletter_terms = ["newsletter", "weekly digest", "daily brief", "weekly brief", "edition #", "read online", "unsubscribe", "view in browser"]
    if is_list or any(k in text_lower for k in newsletter_terms) or "newsletter" in subj_lower:
        return "Newsletter / Subscription"

    # 11. Automated Business & System Notifications
    if any(ns in snd_lower for ns in ["no-reply@", "noreply@", "donotreply@", "support@", "mailer-daemon@", "notifications@", "system@"]):
        return "System / Service Notification"

    # 12. Direct / Personal Correspondence (Human-to-human default)
    return "Personal / Direct Mail"

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
                
            content_type = categorize_content(subject, body, msg['sender'], headers=parsed_data.get("headers", {}))
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
