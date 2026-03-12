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
    domain = parsed.netloc.lower()

    # 1️⃣ Shortened URLs
    shortened_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    if any(short in domain for short in shortened_domains):
        findings.append({"type": "shortened_url"})
        score += 30

    # 2️⃣ Suspicious TLDs
    bad_tlds = [".xyz", ".top", ".click", ".work", ".info", ".zip", ".review"]
    if any(domain.endswith(t) for t in bad_tlds):
        findings.append({"type": "suspicious_tld"})
        score += 25

    # 3️⃣ Long Numbers in Domain
    if re.search(r"[0-9]{3,}", domain):
        findings.append({"type": "numeric_domain"})
        score += 15

    # 4️⃣ Multiple Hyphens
    if domain.count("-") >= 2:
        findings.append({"type": "multiple_hyphens"})
        score += 15

    # 5️⃣ Phishing Keywords
    phishing_words = ["verify", "login", "update", "secure", "bank", "confirm"]
    matched_keywords = [w for w in phishing_words if w in url.lower()]
    if matched_keywords:
        findings.append({
            "type": "phishing_keywords",
            "details": matched_keywords
        })
        score += min(len(matched_keywords) * 8, 25)

    # 6️⃣ Brand Spoofing
    popular_brands = ["google", "amazon", "paypal", "bank", "apple"]
    for brand in popular_brands:
        if brand in domain and not domain.startswith(brand):
            findings.append({
                "type": "brand_spoofing",
                "brand": brand
            })
            score += 35

    return {
        "module_name": "url",
        "url": url,
        "analysis_time": datetime.now().isoformat(),
        "total_records": 1,
        "risk_score": min(score, 100),
        "indicators": findings,
        "top_findings": findings[:5]
    }


# THE UI BRIDGE (Standardized Forensic Contract)

def run_module(url_input):

    if not url_input.strip():
        return {"status": "error", "message": "No URL provided"}

    try:
        result = analyze_url(url_input)

        # --- Save JSON Report ---
        report_file = f"url_report_{int(datetime.now().timestamp())}.json"
        report_path = os.path.join(REPORT_DIR, report_file)

        with open(report_path, "w") as f:
            json.dump(result, f, indent=2)

        # --- Standardized Risk Contract ---
        score = result["risk_score"]

        verdict = (
            "CRITICAL_RISK" if score >= 75 else
            "HIGH_RISK" if score >= 50 else
            "MODERATE_RISK" if score >= 25 else
            "LOW_RISK"
        )

        return {
            "module": "url",
            "score": score,
            "verdict": verdict,
            "indicators": result["indicators"],
            "top_findings": result["top_findings"],
            "summary": {
                "url": result["url"],
                "domain": result["url"].split("//")[-1]
            },
            "json_report": report_path
        }

    except Exception as e:
        return {"status": "error", "message": str(e)}