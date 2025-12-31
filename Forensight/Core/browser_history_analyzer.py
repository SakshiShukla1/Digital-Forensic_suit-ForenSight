# browser_history_analyzer.py
# ForenSight – Browser History Forensics Module
# Chromium, Firefox, Tor (Static Analysis)
# Output: browser_reports/browser_timeline.json & browser_timeline.csv

import os
import sqlite3
import shutil
import json
import csv
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

# ==================================================
# ENVIRONMENT PATHS (Windows)
# ==================================================

LOCALAPP = os.path.expandvars(r"%LOCALAPPDATA%")
APPDATA  = os.path.expandvars(r"%APPDATA%")
HOME     = os.path.expanduser("~")

# ==================================================
# BROWSER DATABASE LOCATIONS
# ==================================================

CHROMIUM_BROWSERS = {
    "Chrome":   os.path.join(LOCALAPP, r"Google\Chrome\User Data\Default\History"),
    "Edge":     os.path.join(LOCALAPP, r"Microsoft\Edge\User Data\Default\History"),
    "Brave":    os.path.join(LOCALAPP, r"BraveSoftware\Brave-Browser\User Data\Default\History"),
    "Opera":    os.path.join(APPDATA,  r"Opera Software\Opera Stable\History"),
    "OperaGX":  os.path.join(APPDATA,  r"Opera Software\Opera GX Stable\History"),
    "Vivaldi":  os.path.join(LOCALAPP, r"Vivaldi\User Data\Default\History"),
    "Chromium": os.path.join(LOCALAPP, r"Chromium\User Data\Default\History")
}

FIREFOX_PROFILE_ROOTS = [
    os.path.join(APPDATA, r"Mozilla\Firefox\Profiles"),
    os.path.join(HOME,    r"AppData\Roaming\Mozilla\Firefox\Profiles")
]

TOR_PLACES = os.path.join(
    HOME,
    r"Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\places.sqlite"
)

# ==================================================
# OUTPUT
# ==================================================

OUT_DIR = os.path.join(os.getcwd(), "browser_reports")
os.makedirs(OUT_DIR, exist_ok=True)

# ==================================================
# FORENSIC RULESETS
# ==================================================

SHORTENED_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"}
PHISHING_KEYWORDS = {"verify", "login", "secure", "account", "update", "confirm",
                     "bank", "password", "reset"}
SUSPICIOUS_TLDS   = {".xyz", ".top", ".click", ".work", ".zip", ".review", ".ru", ".tk"}
POPULAR_BRANDS   = {"google", "amazon", "paypal", "apple", "facebook", "instagram"}

# ==================================================
# TIMESTAMP CONVERSIONS
# ==================================================

def chrome_time_to_dt(value):
    """Chrome: microseconds since 1601-01-01"""
    try:
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))
    except Exception:
        return None


def firefox_time_to_dt(value):
    """Firefox: microseconds since Unix epoch"""
    try:
        value = int(value)
        return datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
    except Exception:
        return None

# ==================================================
# URL ANALYSIS
# ==================================================

def extract_domain(url):
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc[4:] if netloc.startswith("www.") else netloc
    except Exception:
        return ""


def analyze_url(url):
    flags = []
    domain = extract_domain(url)
    if not domain:
        return flags

    if domain in SHORTENED_DOMAINS:
        flags.append("shortened_url")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"suspicious_tld:{tld}")

    if re.search(r"\d{3,}", domain):
        flags.append("numeric_domain")

    if domain.count("-") >= 2:
        flags.append("hyphenated_domain")

    lower_url = url.lower()
    for kw in PHISHING_KEYWORDS:
        if kw in lower_url:
            flags.append(f"phishing_keyword:{kw}")
            break

    for brand in POPULAR_BRANDS:
        if brand in domain and not domain.startswith(brand):
            flags.append(f"brand_impersonation:{brand}")

    return list(dict.fromkeys(flags))

# ==================================================
# SAFE DATABASE COPYING
# ==================================================

def safe_copy_db(src):
    if not os.path.exists(src):
        return None
    dst = os.path.join(
        OUT_DIR,
        f"copy_{os.path.basename(src)}_{int(datetime.now().timestamp())}"
    )
    try:
        shutil.copy2(src, dst)
        return dst
    except Exception:
        return None

# ==================================================
# PARSERS
# ==================================================

def parse_chromium_history(db_path, browser_name):
    results = []
    copy = safe_copy_db(db_path)
    if not copy:
        return results

    try:
        conn = sqlite3.connect(copy)
        cur = conn.cursor()
        cur.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
        """)
        for url, title, count, last_visit in cur.fetchall():
            dt = chrome_time_to_dt(last_visit)
            results.append({
                "browser": browser_name,
                "url": url,
                "title": title,
                "domain": extract_domain(url),
                "visit_count": count,
                "last_visit": dt.isoformat() if dt else None,
                "flags": analyze_url(url)
            })
        conn.close()
    except Exception:
        pass
    finally:
        try:
            os.remove(copy)
        except Exception:
            pass

    return results


def parse_firefox_history(db_path):
    results = []
    copy = safe_copy_db(db_path)
    if not copy:
        return results

    try:
        conn = sqlite3.connect(copy)
        cur = conn.cursor()
        cur.execute("""
            SELECT url, title, visit_count, last_visit_date
            FROM moz_places
        """)
        for url, title, count, last_visit in cur.fetchall():
            dt = firefox_time_to_dt(last_visit)
            results.append({
                "browser": "Firefox/Tor",
                "url": url,
                "title": title,
                "domain": extract_domain(url),
                "visit_count": count,
                "last_visit": dt.isoformat() if dt else None,
                "flags": analyze_url(url)
            })
        conn.close()
    except Exception:
        pass
    finally:
        try:
            os.remove(copy)
        except Exception:
            pass

    return results

# ==================================================
# DISCOVERY
# ==================================================

def find_chromium_dbs():
    return {name: path for name, path in CHROMIUM_BROWSERS.items() if os.path.exists(path)}


def find_firefox_dbs():
    found = []
    for root in FIREFOX_PROFILE_ROOTS:
        if os.path.isdir(root):
            for profile in os.listdir(root):
                places = os.path.join(root, profile, "places.sqlite")
                if os.path.exists(places):
                    found.append(places)
    if os.path.exists(TOR_PLACES):
        found.append(TOR_PLACES)
    return found

# ==================================================
# TIMELINE BUILDER
# ==================================================

def build_timeline():
    timeline = []

    for name, path in find_chromium_dbs().items():
        timeline.extend(parse_chromium_history(path, name))

    for path in find_firefox_dbs():
        timeline.extend(parse_firefox_history(path))

    def sort_key(x):
        try:
            return datetime.fromisoformat(x["last_visit"])
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    return sorted(timeline, key=sort_key, reverse=True)

# ==================================================
# REPORTING
# ==================================================

def save_reports(timeline):
    json_path = os.path.join(OUT_DIR, "browser_timeline.json")
    csv_path  = os.path.join(OUT_DIR, "browser_timeline.csv")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2, ensure_ascii=False)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "browser", "last_visit", "domain", "url",
            "title", "visit_count", "flags"
        ])
        for row in timeline:
            writer.writerow([
                row["browser"], row["last_visit"], row["domain"],
                row["url"], row["title"], row["visit_count"],
                "|".join(row["flags"])
            ])

    return json_path, csv_path

# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":
    print("[*] Building browser history forensic timeline...")
    timeline = build_timeline()
    print(f"[+] Total records extracted: {len(timeline)}")
    save_reports(timeline)
    print("[✓] Reports saved to browser_reports/")
