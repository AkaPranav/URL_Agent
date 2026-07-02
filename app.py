from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from models.report import HealthResponse, URLRequest, URLScanReport
from services.reputation_agent import URLReputationAgent

app = FastAPI(
    title="URL Reputation Agent",
    description="Security service for URL reputation analysis.",
    version="1.0.0",
)


@app.get("/", response_model=HealthResponse)
def root() -> dict[str, str]:
    return {
        "application": "URL Reputation Agent",
        "status": "running",
        "version": "1.0.0",
    }


@app.post("/scan", response_model=URLScanReport)
def scan_url(request: URLRequest) -> dict:
    try:
        return URLReputationAgent().scan(request.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.post("/scan/html", response_class=HTMLResponse)
def scan_url_html(request: URLRequest) -> str:
    try:
        report = URLReputationAgent().scan(request.url)
        return report["html_report"]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
