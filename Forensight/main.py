from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os

# Import your detectives
import Core.browser_history_analyzer as browser_mod
import Core.email_analyzer as email_mod
import Core.File_Analyzer as file_mod
import Core.url_reputation as url_mod

app = FastAPI()

# Allow React to talk to FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/browser-scan")
def scan_browser():
    return browser_mod.run_module()

@app.post("/api/analyze-url")
def scan_url(url: str = Form(...)):
    return url_mod.run_module(url)

@app.post("/api/analyze-file")
async def scan_file(file: UploadFile = File(...)):
    # Save file temporarily to analyze it
    temp_path = f"temp_{file.filename}"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    result = file_mod.run_module(temp_path)
    os.remove(temp_path) # Clean up
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)