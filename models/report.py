
"""
Pydantic models used by the application.
"""

from typing import Any

from pydantic import BaseModel, Field


class URLRequest(BaseModel):
    """
    Incoming request for URL scanning.
    """

    url: str = Field(
        ...,
        description="Target URL to scan",
        examples=["https://example.com"],
    )


class URLScanReport(BaseModel):
    """
    Full security report returned by scans.
    """

    url: str
    virustotal: dict[str, Any]
    google_safe_browsing: dict[str, Any]
    whois: dict[str, Any]
    ssl: dict[str, Any]
    score: dict[str, Any]
    html_report: str | None = None
    pdf_report_base64: str | None = None


class HealthResponse(BaseModel):
    application: str
    status: str
    version: str
