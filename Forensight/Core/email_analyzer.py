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

SUSPICIOUS_KEYWORDS = {"urgent", "verify", "password", "bank", "click", "reset", "confirm", "update", "login", "free", "bonus", "winner", "asap"}
URGENCY_PHRASES = {"urgent", "immediately", "act now", "asap", "within 24 hours"}
SHORTENED_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"}
FREE_EMAIL_PROVIDERS = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com"}

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

def read_email_file(file_path):
    """Helper for UI to read .eml files"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

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
        body = "\n".join(part.get_payload() for part in body if isinstance(part.get_payload(), str))

    findings = []
    score = 0

    # Keyword detection
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if re.search(fr"\b{re.escape(kw)}\b", body, re.IGNORECASE)]
    if found_keywords:
        findings.append({"type": "suspicious_keywords", "details": found_keywords})
        score += min(len(found_keywords) * 5, 20)

    # Urgency
    if any(re.search(fr"\b{re.escape(p)}\b", body, re.IGNORECASE) for p in URGENCY_PHRASES):
        findings.append({"type": "urgency_language", "details": "Creates fear or urgency"})
        score += 15

    # URL analysis
    urls = extract_urls(body)
    suspicious_urls = [u for u in urls if any(short in urlparse(u).netloc.lower() for short in SHORTENED_DOMAINS)]
    if suspicious_urls:
        findings.append({"type": "suspicious_urls", "urls": suspicious_urls})
        score += (len(suspicious_urls) * 15)

    # Sender spoofing
    sender_domain = get_domain(sender)
    if sender_domain in FREE_EMAIL_PROVIDERS and any(x in subject.lower() for x in ["bank", "account"]):
        findings.append({"type": "sender_spoofing", "details": "Free provider used for official message"})
        score += 20

    verdict = "clean"
    if score >= 60: verdict = "high_risk_phishing"
    elif score >= 30: verdict = "suspicious"

    return {
        "email_hash": sha256_hash(raw_email),
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "headers": {"from": sender, "to": recipient, "subject": subject, "date": date},
        "urls_found": urls,
        "risk_score": min(score, 100),
        "verdict": verdict,
        "findings": findings
    }

def save_email_report(report: dict) -> str:
    filename = f"email_report_{report['email_hash'][:12]}.json"
    path = os.path.join(REPORT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path

# ==================================================
# THE UI BRIDGE (The Single Source of Truth)
# ==================================================
def run_module(input_data, is_file=False):
    """Bridge for the Frontend UI"""
    raw_content = read_email_file(input_data) if is_file else input_data
    
    if not raw_content or "Error reading file" in raw_content:
        return {"status": "error", "message": "Invalid Input"}

    report = analyze_email(raw_content)
    report_path = save_email_report(report)
    
    return {
        "status": "success",
        "verdict": report["verdict"],
        "score": report["risk_score"],
        "sender": report["headers"]["from"],
        "subject": report["headers"]["subject"],
        "findings_count": len(report["findings"]),
        "report_path": report_path,
        "raw_report": report
    }

if __name__ == "__main__":
    test_email = "From: support@gmail.com\nSubject: Bank Account Urgent\n\nClick: http://bit.ly/login"
    print(run_module(test_email))