# File_Analyzer.py
# ForenSight – File Forensic Analysis Module
# Static File Analysis for Digital Forensics

import os
import sys
import json
import math
import hashlib
import mimetypes
import re
import struct
import subprocess
from datetime import datetime, timezone
from collections import Counter

# Optional forensic libraries
try:
    import magic
except ImportError:
    magic = None

try:
    import exifread
except ImportError:
    exifread = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import docx
except ImportError:
    docx = None


# ==================================================
# BASIC FILE UTILITIES
# ==================================================

def read_file_bytes(path, max_bytes=None):
    with open(path, "rb") as f:
        return f.read(max_bytes) if max_bytes else f.read()


def get_file_size(path):
    return os.path.getsize(path)


def human_readable_size(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def compute_hashes(path):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256()
    }
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


# ==================================================
# MIME & SIGNATURE ANALYSIS
# ==================================================

MAGIC_SIGNATURES = [
    (b"\xFF\xD8\xFF", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "zip/office"),
    (b"MZ", "windows-executable"),
    (b"\x7fELF", "linux-elf"),
]

def detect_magic_header(path):
    header = read_file_bytes(path, 16)
    for sig, desc in MAGIC_SIGNATURES:
        if header.startswith(sig):
            return desc
    return "unknown"


def detect_mime_type(path):
    if magic:
        try:
            return magic.Magic(mime=True).from_file(path)
        except Exception:
            pass
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


# ==================================================
# ENTROPY ANALYSIS
# ==================================================

def shannon_entropy(data):
    if not data:
        return 0.0
    frequency = Counter(data)
    length = len(data)
    return round(
        -sum((count / length) * math.log2(count / length)
        for count in frequency.values()),
        4
    )


# ==================================================
# IMAGE FORENSICS
# ==================================================

def extract_exif_metadata(path):
    if not exifread:
        return {}
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        return {k: str(v) for k, v in tags.items()}
    except Exception as e:
        return {"error": str(e)}


def lsb_steganography_score(path, max_pixels=200000):
    if not Image:
        return None
    try:
        img = Image.open(path).convert("RGB")
        pixels = list(img.getdata())[:max_pixels]
        lsb_count = [0, 0]
        for pixel in pixels:
            for channel in pixel:
                lsb_count[channel & 1] += 1
        total = sum(lsb_count)
        return round(1 - abs(lsb_count[0] - lsb_count[1]) / total, 4)
    except Exception:
        return None


def bits_per_pixel(path):
    if not Image:
        return None
    try:
        img = Image.open(path)
        width, height = img.size
        return round(get_file_size(path) / (width * height), 4)
    except Exception:
        return None


# ==================================================
# DOCUMENT & VIDEO METADATA
# ==================================================

def extract_pdf_metadata(path):
    if not PyPDF2:
        return {}
    try:
        reader = PyPDF2.PdfReader(path)
        meta = dict(reader.metadata) if reader.metadata else {}
        js_detected = any("/JavaScript" in str(page) for page in reader.pages)
        return {
            "metadata": meta,
            "javascript_detected": js_detected
        }
    except Exception as e:
        return {"error": str(e)}


def extract_docx_metadata(path):
    if not docx:
        return {}
    try:
        props = docx.Document(path).core_properties
        return {
            "author": props.author,
            "created": str(props.created),
            "modified": str(props.modified),
            "last_modified_by": props.last_modified_by
        }
    except Exception as e:
        return {"error": str(e)}


def extract_video_metadata(path):
    try:
        output = subprocess.check_output(
            [
                "ffprobe", "-v", "quiet",
                "-print_format", "json",
                "-show_format", "-show_streams",
                path
            ],
            timeout=10
        )
        return json.loads(output.decode())
    except Exception as e:
        return {"error": str(e)}


# ==================================================
# MP4 STRUCTURAL FORENSICS
# ==================================================

COMMON_MP4_ATOMS = {
    b"ftyp", b"moov", b"mdat", b"free", b"mvhd",
    b"trak", b"mdia", b"minf", b"stbl", b"udta"
}

def scan_mp4_structure(path):
    issues = []
    try:
        data = read_file_bytes(path)
        offset = 0

        while offset + 8 <= len(data):
            size = struct.unpack(">I", data[offset:offset + 4])[0]
            atom = data[offset + 4:offset + 8]

            if atom not in COMMON_MP4_ATOMS:
                issues.append(f"Unrecognized atom: {atom.decode(errors='ignore')}")

            if size < 8 or size > len(data):
                issues.append(f"Suspicious atom size at offset {offset}")
                break

            offset += size

        for sig, label in {
            b"MZ": "Embedded EXE",
            b"PK\x03\x04": "Embedded ZIP",
            b"%PDF": "Embedded PDF"
        }.items():
            if sig in data:
                issues.append(label)

    except Exception as e:
        issues.append(str(e))

    return issues


# ==================================================
# STRING EXTRACTION
# ==================================================

def extract_ascii_strings(path, min_length=6, limit=200):
    data = read_file_bytes(path)
    found = re.findall(rb"[ -~]{%d,}" % min_length, data)
    strings = {s.decode("utf-8", "ignore") for s in found}
    return list(strings)[:limit]


# ==================================================
# RISK ASSESSMENT ENGINE
# ==================================================

def compute_risk_score(report):
    score = 0
    reasons = []

    if report["extension_mismatch"]:
        score += 25
        reasons.append("Extension mismatch")

    if report["entropy"] >= 7.5:
        score += 20
        reasons.append("High entropy")

    if report["suspicious_strings"]:
        score += 20
        reasons.append("Suspicious strings")

    if report["mp4_warnings"]:
        score += 20
        reasons.append("MP4 structural anomalies")

    return min(score, 100), reasons


# ==================================================
# CORE ANALYSIS FUNCTION
# ==================================================

def analyze_file(path):
    report = {
        "file_name": os.path.basename(path),
        "file_size": human_readable_size(get_file_size(path)),
        "mime_type": detect_mime_type(path),
        "magic_header": detect_magic_header(path),
        "hashes": compute_hashes(path),
        "entropy": shannon_entropy(read_file_bytes(path, 1024 * 1024)),
        "extension_mismatch": False,
        "metadata": {},
        "suspicious_strings": [],
        "mp4_warnings": [],
        "analysis_timestamp": datetime.now(timezone.utc).isoformat()
    }

    extension = os.path.splitext(path)[1].lower().strip(".")
    if extension and extension not in report["mime_type"]:
        report["extension_mismatch"] = True

    report["suspicious_strings"] = extract_ascii_strings(path)

    if extension in {"jpg", "jpeg", "png"}:
        report["metadata"]["exif"] = extract_exif_metadata(path)
        report["metadata"]["lsb_score"] = lsb_steganography_score(path)
        report["metadata"]["bits_per_pixel"] = bits_per_pixel(path)

    if extension == "pdf":
        report["metadata"]["pdf"] = extract_pdf_metadata(path)

    if extension == "docx":
        report["metadata"]["docx"] = extract_docx_metadata(path)

    if extension in {"mp4", "mov", "mkv"}:
        report["metadata"]["video"] = extract_video_metadata(path)
        report["mp4_warnings"] = scan_mp4_structure(path)

    report["risk_score"], report["risk_reasons"] = compute_risk_score(report)
    return report


# ==================================================
# CLI ENTRY POINT
# ==================================================

def main():
    if len(sys.argv) != 2:
        print("Usage: python File_Analyzer.py <file_path>")
        sys.exit(1)

    target = sys.argv[1]
    if not os.path.isfile(target):
        print("File not found.")
        sys.exit(1)

    result = analyze_file(target)

    with open("file_analysis_report.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    print("✔ Analysis Complete")
    print("Risk Score:", result["risk_score"])
    print("SHA-256:", result["hashes"]["sha256"])


if __name__ == "__main__":
    main()


# ... (all your existing forensic logic functions stay above) ...

# ==================================================
# THE UI BRIDGE (Add this at the bottom)
# ==================================================

def run_module(file_path):
    """
    Bridge function for the Frontend UI.
    Takes a file_path, runs all forensic tests, 
    and returns a package for the Dashboard.
    """
    if not os.path.isfile(file_path):
        return {"status": "error", "message": "File not found"}

    try:
        # 1. Run your core logic
        report = analyze_file(file_path)
        
        # 2. Save the JSON report for the records
        report_dir = os.path.join(os.getcwd(), "reports", "file_reports")
        os.makedirs(report_dir, exist_ok=True)
        
        # We use the MD5 hash to give the report a unique name
        report_name = f"file_report_{report['hashes']['md5'][:8]}.json"
        report_path = os.path.join(report_dir, report_name)
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # 3. Prepare the UI Package (This is what your UI "sees")
        return {
            "status": "success",
            "file_name": report["file_name"],
            "file_size": report["file_size"],
            "mime_type": report["mime_type"],
            "risk_score": report["risk_score"],
            "verdict": "Suspicious" if report["risk_score"] > 50 else "Safe",
            "entropy": report["entropy"],
            "mismatch": report["extension_mismatch"],
            "report_path": report_path,
            "all_data": report 
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# This is the NEW clean entry point for testing
if __name__ == "__main__":
    # If you want to test without the UI, uncomment the line below:
    # print(run_module("path/to/your/test_file.exe"))
    print("File Analyzer Module Loaded. Waiting for UI call...")