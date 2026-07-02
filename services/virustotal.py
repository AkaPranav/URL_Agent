"""
VirusTotal Service

Handles communication with the VirusTotal API.
"""

from __future__ import annotations

import base64
from typing import Any

import requests

from config import VIRUS_TOTAL_API_KEY


class VirusTotalService:
    """
    Service responsible for querying VirusTotal.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self) -> None:
        self.headers = {
            "x-apikey": VIRUS_TOTAL_API_KEY
        }

    @staticmethod
    def _encode_url(url: str) -> str:
        """
        VirusTotal identifies URLs using a URL-safe base64
        encoding without '=' padding.
        """

        encoded = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("utf-8")

        return encoded.strip("=")

    def scan_url(self, url: str) -> dict[str, Any]:
        """
        Submit a URL for analysis.

        Returns the analysis id.
        """

        response = requests.post(
            f"{self.BASE_URL}/urls",
            headers=self.headers,
            data={"url": url},
            timeout=30,
        )

        response.raise_for_status()

        return response.json()

    def get_url_report(self, url: str) -> dict[str, Any]:
        """
        Retrieve the latest VirusTotal report for a URL.
        """

        encoded = self._encode_url(url)

        response = requests.get(
            f"{self.BASE_URL}/urls/{encoded}",
            headers=self.headers,
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": (
                data.get("data", {})
                .get("attributes", {})
                .get("reputation", 0)
            ),
        }

    def analyze(self, url: str) -> dict[str, Any]:
        """
        Complete VirusTotal workflow.

        1. Submit URL.
        2. Retrieve report.
        3. Return parsed data.
        """

        if not VIRUS_TOTAL_API_KEY:
            return {
                "status": "unavailable",
                "source": "VirusTotal",
                "reason": "VIRUS_TOTAL_API_KEY is not configured.",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "timeout": 0,
                "reputation": None,
            }

        try:
            self.scan_url(url)
            report = self.get_url_report(url)
            report["status"] = "ok"
            report["source"] = "VirusTotal"
            return report
        except requests.RequestException as exc:
            return {
                "status": "error",
                "source": "VirusTotal",
                "reason": str(exc),
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "timeout": 0,
                "reputation": None,
            }
