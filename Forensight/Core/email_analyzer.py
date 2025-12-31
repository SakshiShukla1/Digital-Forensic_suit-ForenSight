# email_analyzer.py
# ForenSight – Email Phishing & Social Engineering Forensics Module

import re
import hashlib
import json
import os
from email import message_from_string
from email.message import Message
from datetime import datetime, timezone
from urllib.parse import urlparse

# ==================================================
# CONFIG
# ==================================================

REPORT_DIR = os.path.join(os.getcwd(), "reports", "email_reports")
os.makedirs(REPORT_DIR, exist_ok=True)

SUSPICIOUS_KEYWORDS = {
    "urgent", "verify", "password", "bank", "click",
    "reset", "confirm", "update", "login",
    "free", "bonus", "winner", "asap"
}

URGENCY_PHRASES = {
    "urgent", "immediately", "act now",
    "asap", "within 24 hours"
}

SHORTENED_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com"
}

# ==================================================
# HELPERS
# ==================================================

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def extract_urls(text: str):
    return re.findall(r"https?://[^\s<>\"']+", text)

def get_domain(email_addr: str) -> str:
    try:
        return email_addr.split("@")[-1].lower()
    except Exception:
        return ""

# ==================================================
# CORE ANALYSIS
# ==================================================

def analyze_email(raw_email: str) -> dict:
    msg: Message = message_from_string(raw_email)

    sender = msg.get("From", "")
    recipient = msg.get("To", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")

    body = msg.get_payload()
    if isinstance(body, list):
        body = "\n".join(part.get_payload() for part in body)

    findings = []
    score = 0

    # --- Keyword detection ---
    found_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS
        if re.search(fr"\b{re.escape(kw)}\b", body, re.IGNORECASE)
    ]

    if found_keywords:
        findings.append({
            "type": "suspicious_keywords",
            "details": found_keywords
        })
        score += min(len(found_keywords) * 5, 20)

    # --- Urgency language ---
    if any(re.search(fr"\b{re.escape(p)}\b", body, re.IGNORECASE) for p in URGENCY_PHRASES):
        findings.append({
            "type": "urgency_language",
            "details": "Creates fear or urgency"
        })
        score += 15

    # --- URL analysis ---
    urls = extract_urls(body)
    suspicious_urls = []

    for url in urls:
        domain = urlparse(url).netloc.lower()
        if any(short in domain for short in SHORTENED_DOMAINS):
            suspicious_urls.append(url)
            score += 15

    if suspicious_urls:
        findings.append({
            "type": "suspicious_urls",
            "urls": suspicious_urls
        })

    # --- Sender spoofing ---
    sender_domain = get_domain(sender)
    if sender_domain in FREE_EMAIL_PROVIDERS and (
        "bank" in subject.lower() or "account" in subject.lower()
    ):
        findings.append({
            "type": "sender_spoofing",
            "details": "Free email provider used for official-looking message"
        })
        score += 20

    verdict = "clean"
    if score >= 60:
        verdict = "high_risk_phishing"
    elif score >= 30:
        verdict = "suspicious"

    report = {
        "email_hash": sha256_hash(raw_email),
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "headers": {
            "from": sender,
            "to": recipient,
            "subject": subject,
            "date": date
        },
        "urls_found": urls,
        "risk_score": min(score, 100),
        "verdict": verdict,
        "findings": findings
    }

    return report

# ==================================================
# REPORT SAVER
# ==================================================

def save_email_report(report: dict) -> str:
    filename = f"email_report_{report['email_hash'][:12]}.json"
    path = os.path.join(REPORT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return path

# ==================================================
# CLI MODE
# ==================================================

if __name__ == "__main__":
    sample_email = """From: sender@gmail.com
To: victim@example.com
Subject: Urgent: Verify Your Bank Account Now!
Date: Mon, 09 Dec 2024 10:30:00 +0000

Dear Customer,

We need you to verify your bank account immediately!

Click here: https://bit.ly/verify-account

Reset your password now to avoid suspension.
Act now or your account will be closed ASAP.

Regards,
Bank Support
"""

    report = analyze_email(sample_email)
    path = save_email_report(report)

    print("\nEMAIL FORENSIC ANALYSIS COMPLETE")
    print("Risk Score:", report["risk_score"])
    print("Verdict:", report["verdict"])
    print("Report saved at:", path)
