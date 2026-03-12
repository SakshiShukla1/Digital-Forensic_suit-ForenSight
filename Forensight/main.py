import os
import hashlib
import sqlite3
import json
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles  # <--- NEW IMPORT
from fpdf import FPDF

# Import your core modules
from Core import browser_history_analyzer
from Core import File_Analyzer
from Core import email_analyzer
from Core import url_reputation

# Ensure reports directory exists
if not os.path.exists('reports'):
    os.makedirs('reports')

app = FastAPI()

# --- THE FIX ---
# This line tells FastAPI: "If someone asks for /reports, look inside the 'reports' folder"
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
# ----------------

def init_db():
    conn = sqlite3.connect('forensics.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS cases 
                      (id TEXT PRIMARY KEY, name TEXT, created_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS evidence 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT, 
                       type TEXT, target TEXT, score INTEGER, verdict TEXT, 
                       findings TEXT, timestamp TEXT, raw_json TEXT)''')
    conn.commit()
    conn.close()

init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/get-all-cases")
async def get_all_cases():
    conn = sqlite3.connect('forensics.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/api/create-case")
async def create_case(case_name: str = Form(...)):
    case_id = f"FS-{hashlib.md5(case_name.encode()).hexdigest()[:5].upper()}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect('forensics.db')
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO cases (id, name, created_at) VALUES (?, ?, ?)", (case_id, case_name, timestamp))
    conn.commit()
    conn.close()
    return {"id": case_id, "name": case_name}

from fastapi import Request

@app.post("/api/save-evidence")
async def save_evidence(request: Request):
    form = await request.form()

    case_id = form.get("case_id")
    type_ = form.get("type")
    target = form.get("target")
    score = form.get("score")
    verdict = form.get("verdict")
    findings = form.get("findings")
    raw_json = form.get("raw_json")

    print("DEBUG RECEIVED:", form)

    try:
        score = int(str(score).replace("%", ""))
    except:
        score = 0

    timestamp = datetime.now().strftime("%H:%M:%S")

    conn = sqlite3.connect('forensics.db')
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO evidence 
        (case_id, type, target, score, verdict, findings, timestamp, raw_json) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, type_, target, score, verdict, findings, timestamp, raw_json))
    conn.commit()
    conn.close()

    return {"status": "success"}

@app.get("/api/get-case-history/{case_id}")
async def get_history(case_id: str):
    conn = sqlite3.connect('forensics.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence WHERE case_id = ? ORDER BY id DESC", (case_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.get("/api/generate-report/{case_id}")
async def generate_report(case_id: str):
    conn = sqlite3.connect('forensics.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    case = cursor.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    evidence = cursor.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY timestamp DESC", (case_id,)).fetchall()
    conn.close()

    if not case:
        return {"error": "Case not found"}

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", 'B', 16)
    pdf.cell(0, 10, f"FORENSIGHT_PRO OFFICIAL REPORT", ln=True, align='C')
    pdf.set_font("Courier", size=10)
    pdf.cell(0, 10, f"CASE: {case['name']} ({case_id})", ln=True, align='C')
    pdf.ln(10)

    for item in evidence:
        pdf.set_fill_color(20, 20, 30) 
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Courier", 'B', 11)
        pdf.cell(0, 8, f" ARTIFACT: {item['target']} | TYPE: {item['type']}", ln=True, fill=True)
        
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Courier", size=9)
        report_text = (
            f" Verdict: {item['verdict']}\n"
            f" Risk Score: {item['score']}%\n"
            f" Timestamp: {item['timestamp']}\n"
            f" Detailed Indicators: {item['findings']}\n"
        )
        pdf.multi_cell(0, 5, report_text)
        pdf.ln(5)

    filename = f"Report_{case_id}.pdf"
    report_path = os.path.join("reports", filename)
    pdf.output(report_path)
    
    # Return the URL that the browser can now access thanks to app.mount
    return {"report_url": f"http://localhost:8000/reports/{filename}"}


# --- MODULE EXECUTION ---

@app.post("/api/analyze-url")
async def analyze_url(url: str = Form(...)):
    return url_reputation.run_module(url)

@app.post("/api/analyze-email")
async def analyze_email(content: str = Form(...)):
    return email_analyzer.run_module(content)

@app.post("/api/analyze-file")
async def analyze_file(file: UploadFile = File(...)):
    file_path = f"temp_{file.filename}"
    with open(file_path, "wb") as f: f.write(await file.read())
    try:
        return File_Analyzer.run_module(file_path)
    finally:
        if os.path.exists(file_path): os.remove(file_path)

@app.get("/api/browser-scan")
async def browser_scan():
    return browser_history_analyzer.run_module()