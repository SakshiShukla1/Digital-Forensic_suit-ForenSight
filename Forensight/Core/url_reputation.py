import re
import json
import os
from urllib.parse import urlparse
from datetime import datetime

# CONFIG
REPORT_DIR = os.path.join(os.getcwd(), "reports", "url_reports")
os.makedirs(REPORT_DIR, exist_ok=True)

def analyze_url(url):
    findings = []
    score = 0
    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. Check for shortened URLs
    shortened_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    if any(short in domain for short in shortened_domains):
        findings.append("Shortened URL → often used to hide malicious links.")
        score += 30

    # 2. Suspicious TLDs
    bad_tlds = [".xyz", ".top", ".click", ".work", ".info", ".zip", ".review"]
    if any(domain.endswith(t) for t in bad_tlds):
        findings.append(f"Suspicious domain ending (.{domain.split('.')[-1]}).")
        score += 25

    # 3. Presence of numbers
    if re.search(r"[0-9]{3,}", domain):
        findings.append("Domain contains unusual long numbers.")
        score += 15

    # 4. Too many hyphens
    if domain.count("-") >= 2:
        findings.append("Domain contains multiple hyphens.")
        score += 15

    # 5. Phishing keywords
    phishing_words = ["verify", "login", "update", "secure", "bank", "confirm"]
    if any(w in url.lower() for w in phishing_words):
        findings.append("URL contains phishing-related keywords.")
        score += 20

    # 6. Brand spoofing
    popular_brands = ["google", "amazon", "paypal", "bank", "apple"]
    for brand in popular_brands:
        if brand in domain.lower() and not domain.startswith(brand):
            findings.append(f"Possible brand-spoofing: '{brand}' found in domain.")
            score += 35

    # Final Verdict Logic
    verdict = "Clean"
    if score >= 60: verdict = "Malicious"
    elif score >= 25: verdict = "Suspicious"

    return {
        "url": url,
        "score": min(score, 100),
        "verdict": verdict,
        "findings": findings,
        "timestamp": datetime.now().isoformat()
    }

# ==================================================
# THE UI BRIDGE
# ==================================================

def run_module(url_input):
    """Bridge for the Frontend UI"""
    if not url_input.strip():
        return {"status": "error", "message": "No URL provided"}
    
    # 1. Run Analysis
    result = analyze_url(url_input)
    
    # 2. Save Report
    report_file = f"url_report_{int(datetime.now().timestamp())}.json"
    report_path = os.path.join(REPORT_DIR, report_file)
    with open(report_path, "w") as f:
        json.dump(result, f, indent=2)
    
    # 3. Return UI Package
    return {
        "status": "success",
        "url": result["url"],
        "score": result["score"],
        "verdict": result["verdict"],
        "findings_count": len(result["findings"]),
        "findings_list": result["findings"],
        "report_path": report_path
    }

if __name__ == "__main__":
    # Test
    print(run_module("http://paypal-login-verify.xyz"))