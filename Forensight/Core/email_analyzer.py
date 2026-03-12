
import re
import hashlib
import json
import os
from email import message_from_string
from email.message import Message
from datetime import datetime, timezone
from urllib.parse import urlparse


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
    "bit.ly", "tinyurl.com", "goo.gl",
    "t.co", "ow.ly"
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com",
    "outlook.com", "hotmail.com"
}

BRAND_KEYWORDS = {
    "paypal", "amazon", "google",
    "bank", "microsoft", "apple"
}



def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def extract_urls(text: str):
    return re.findall(r"https?://[^\s<>\"']+", text)

def get_domain(email_addr: str) -> str:
    try:
        return email_addr.split("@")[-1].lower()
    except Exception:
        return ""

# CORE ANALYSIS

def analyze_email(raw_email: str) -> dict:
    msg: Message = message_from_string(raw_email)

    sender = msg.get("From", "")
    recipient = msg.get("To", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")

    body = msg.get_payload()
    if isinstance(body, list):
        body = "\n".join(
            part.get_payload()
            for part in body
            if isinstance(part.get_payload(), str)
        )

    findings = []
    score = 0

    # 1️ Suspicious Keywords
    
    found_keywords = [
        kw for kw in SUSPICIOUS_KEYWORDS
        if re.search(fr"\b{re.escape(kw)}\b", body, re.IGNORECASE)
    ]

    if found_keywords:
        findings.append({
            "type": "suspicious_keywords",
            "details": found_keywords
        })
        score += min(len(found_keywords) * 6, 25)

    
    # 2️ Urgency Language
    
    if any(re.search(fr"\b{re.escape(p)}\b", body, re.IGNORECASE)
           for p in URGENCY_PHRASES):
        findings.append({
            "type": "urgency_language"
        })
        score += 15

    
    # 3️ URL Analysis
    
    urls = extract_urls(body)
    suspicious_urls = []

    for u in urls:
        domain = urlparse(u).netloc.lower()

        if any(short in domain for short in SHORTENED_DOMAINS):
            suspicious_urls.append(u)
            score += 18

        if any(char.isdigit() for char in domain):
            suspicious_urls.append(u)
            score += 10

    if suspicious_urls:
        findings.append({
            "type": "suspicious_urls",
            "details": suspicious_urls
        })

    
    # 4️ Sender Domain Risk
    
    sender_domain = get_domain(sender)

    if sender_domain in FREE_EMAIL_PROVIDERS:
        findings.append({
            "type": "free_email_provider"
        })
        score += 12

    
    # 5️ Brand Impersonation Check
   
    subject_lower = subject.lower()
    body_lower = body.lower()

    for brand in BRAND_KEYWORDS:
        if brand in subject_lower or brand in body_lower:
            if brand not in sender_domain:
                findings.append({
                    "type": "brand_impersonation",
                    "brand": brand
                })
                score += 20

   
    # 6️ Header Anomaly Check
   
    if not date:
        findings.append({
            "type": "missing_date_header"
        })
        score += 8


    risk_score = min(score, 100)

    return {
        "module_name": "email",
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "email_hash": sha256_hash(raw_email),
        "headers": {
            "from": sender,
            "to": recipient,
            "subject": subject,
            "date": date
        },
        "total_records": 1,
        "risk_score": risk_score,
        "indicators": findings,
        "top_findings": findings[:5]
    }


def save_email_report(report: dict) -> str:
    filename = f"email_report_{report['email_hash'][:12]}.json"
    path = os.path.join(REPORT_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return path


def run_module(input_data, is_file=False):

    raw_content = ""
    if is_file:
        try:
            with open(input_data, 'r', encoding='utf-8', errors='ignore') as f:
                raw_content = f.read()
        except:
            return {"status": "error", "message": "Invalid File"}
    else:
        raw_content = input_data

    if not raw_content:
        return {"status": "error", "message": "Invalid Input"}

    report = analyze_email(raw_content)
    report_path = save_email_report(report)

    report["json_report"] = report_path

    return report

if __name__ == "__main__":
    test_email = "From: support@gmail.com\nSubject: Bank Account Urgent\n\nClick: http://bit.ly/login"
    print(run_module(test_email))