"""FastAPI dashboard backend for PromptFuzz."""

import json
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

app = FastAPI(
    title="PromptFuzz Dashboard",
    description="Web interface for viewing PromptFuzz campaign results.",
    version="1.0.0",
)

FRONTEND_DIR = Path(__file__).parent / "frontend"
FRONTEND_DIR.mkdir(parents=True, exist_ok=True)


REPORT_PATH = Path("promptfuzz-results/promptfuzz-report.json")

@app.get("/api/stats")
async def get_stats():
    if not REPORT_PATH.exists():
        raise HTTPException(
            status_code=404, detail="Campaign report not found. Run a campaign first."
        )
    with open(REPORT_PATH) as f:
        data = json.load(f)
        summary = data.get("summary", {})
        return {
            "total_attacks": summary.get("total_attacks", 0),
            "vulnerabilities": summary.get("successful_attacks", 0),
            "success_rate": summary.get("success_rate", 0.0) * 100,
            "duration_seconds": summary.get("duration_seconds", 0.0)
        }

@app.get("/api/findings")
async def get_findings():
    if not REPORT_PATH.exists():
        raise HTTPException(
            status_code=404, detail="Campaign report not found. Run a campaign first."
        )
    with open(REPORT_PATH) as f:
        data = json.load(f)
        return data.get("findings", [])

app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="static")

def run_dashboard(port: int = 8000) -> None:
    """Run the uvicorn server."""
    uvicorn.run(app, host="127.0.0.1", port=port)
