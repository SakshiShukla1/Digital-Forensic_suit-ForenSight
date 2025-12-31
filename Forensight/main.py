# main.py
# ForenSight – Digital Forensics Suite Controller

import os
import json
from datetime import datetime, timezone

from Core.File_Analyzer import analyze_file
from Core.browser_history_analyzer import build_unified_timeline, save_reports
from Core.email_analyzer import analyze_email, save_email_report
from Core.url_reputation import analyze_url

# ==================================================
# CASE MANAGEMENT
# ==================================================

CASE_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(CASE_DIR, exist_ok=True)

def create_case():
    case_id = f"CASE-{int(datetime.now().timestamp())}"
    return {
        "case_id": case_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "modules_used": [],
        "evidence": []
    }

# ==================================================
# MENU
# ==================================================

def menu():
    print("\n====== FORENSIGHT DIGITAL FORENSICS SUITE ======")
    print("1. Analyze File (Static File Forensics)")
    print("2. Analyze Browser History")
    print("3. Analyze Email (Phishing / Social Engineering)")
    print("4. Analyze URL Reputation")
    print("0. Exit")
    return input("Select option: ").strip()

# ==================================================
# MAIN CONTROLLER
# ==================================================

def main():
    case = create_case()

    while True:
        choice = menu()

        # ----------------------------------
        # FILE ANALYSIS
        # ----------------------------------
        if choice == "1":
            path = input("Enter full file path: ").strip()
            if not os.path.exists(path):
                print("File not found.")
                continue

            report = analyze_file(path)

            out_dir = os.path.join(CASE_DIR, "file_reports")
            os.makedirs(out_dir, exist_ok=True)
            out_path = os.path.join(out_dir, f"file_{report['hashes']['sha256'][:12]}.json")

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            print("File analysis complete.")
            print("Risk Score:", report["risk_score"])

            case["modules_used"].append("File Analyzer")
            case["evidence"].append(out_path)

        # ----------------------------------
        # BROWSER HISTORY
        # ----------------------------------
        elif choice == "2":
            timeline = build_unified_timeline()
            json_path, csv_path = save_reports(timeline)

            print("Browser forensic analysis completed.")
            print("Records:", len(timeline))

            case["modules_used"].append("Browser History Analyzer")
            case["evidence"].extend([json_path, csv_path])

        # ----------------------------------
        # EMAIL ANALYSIS
        # ----------------------------------
        elif choice == "3":
            print("Paste raw email content (end with empty line):")
            lines = []
            while True:
                line = input()
                if line.strip() == "":
                    break
                lines.append(line)
            raw_email = "\n".join(lines)

            report = analyze_email(raw_email)
            path = save_email_report(report)

            print("Email analysis complete.")
            print("Verdict:", report["verdict"])
            print("Report saved:", path)

            case["modules_used"].append("Email Analyzer")
            case["evidence"].append(path)

        # ----------------------------------
        # URL ANALYSIS
        # ----------------------------------
        elif choice == "4":
            url = input("Enter URL: ").strip()
            findings = analyze_url(url)

            print("\nURL Reputation Result:")
            for f in findings:
                print("-", f)

            case["modules_used"].append("URL Reputation Analyzer")

        # ----------------------------------
        # EXIT
        # ----------------------------------
        elif choice == "0":
            break

        else:
            print("Invalid option.")

    # ==================================================
    # SAVE CASE SUMMARY
    # ==================================================

    summary_path = os.path.join(CASE_DIR, "case_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2)

    print("\nCase closed.")
    print("Case summary saved at:", summary_path)

# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":
    main()
