import re
from urllib.parse import urlparse

def analyze_url(url):
    result = []
    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. Check for shortened URLs
    shortened_domains = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    if any(short in domain for short in shortened_domains):
        result.append("Shortened URL → often used to hide malicious links.")

    # 2. Suspicious TLDs
    bad_tlds = [".xyz", ".top", ".click", ".work", ".info", ".zip", ".review"]
    if any(domain.endswith(t) for t in bad_tlds):
        result.append(f"Suspicious domain ending {domain.split('.')[-1]} (often used in phishing).")

    # 3. Presence of numbers/random characters
    if re.search(r"[0-9]{3,}", domain):
        result.append("Domain contains unusual long numbers → low reputation site.")

    # 4. Too many hyphens
    if domain.count("-") >= 2:
        result.append("Domain contains multiple hyphens → often used in fake sites.")

    # 5. Phishing keywords in URL
    phishing_words = ["verify", "login", "update", "secure", "bank", "confirm"]
    if any(w in url.lower() for w in phishing_words):
        result.append("URL contains phishing-related keywords.")

    # 6. Domain spoofing (fake version of famous site)
    popular_brands = ["google", "amazon", "paypal", "bank", "apple"]
    for brand in popular_brands:
        if brand in domain.lower() and not domain.startswith(brand):
            result.append(f"Possible brand-spoofing detected: '{brand}' appears inside domain.")

    if not result:
        return ["URL seems clean based on rule-based checks."]

    return result

# Example usage
if __name__ == "__main__":
    test_urls = [
        "http://bit.ly/secure-login",
        "http://my-bank-login.xyz",
        "http://paypal-login-123.com",
        "http://google-update-info.com",
        "http://safe-site.com"
    ]

    for url in test_urls:
        print(f"Analyzing URL: {url}")
        analysis = analyze_url(url)
        for line in analysis:
            print(" -", line)
        print()
         