from functools import lru_cache
from secrets import compare_digest

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader

from config import APP_API_KEY
from models.report import HealthResponse, URLRequest, URLScanReport
from services.reputation_agent import URLReputationAgent

app = FastAPI(
    title="URL Reputation Agent",
    description="Security service for URL reputation analysis.",
    version="1.0.0",
)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@lru_cache(maxsize=1)
def get_agent() -> URLReputationAgent:
    return URLReputationAgent()


def verify_api_key(api_key: str | None = Security(api_key_header)) -> None:
    if not APP_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="APP_API_KEY is not configured on the server.",
        )

    if not api_key or not compare_digest(api_key, APP_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )


@app.get("/", response_model=HealthResponse)
def root() -> dict[str, str]:
    return {
        "application": "URL Reputation Agent",
        "status": "running",
        "version": "1.0.0",
    }


@app.get("/health", response_model=HealthResponse)
def health() -> dict[str, str]:
    return root()


@app.post(
    "/scan",
    response_model=URLScanReport,
    response_model_exclude_none=True,
    dependencies=[Depends(verify_api_key)],
)
def scan_url(
    request: URLRequest,
    agent: URLReputationAgent = Depends(get_agent),
) -> dict:
    try:
        return agent.scan(request.url, include_reports=False)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception:  # pragma: no cover - defensive API boundary.
        raise HTTPException(
            status_code=500,
            detail="URL scan failed.",
        )


@app.post(
    "/scan/html",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_api_key)],
)
def scan_url_html(
    request: URLRequest,
    agent: URLReputationAgent = Depends(get_agent),
) -> str:
    try:
        report = agent.scan(request.url, include_reports=True)
        return report["html_report"]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
