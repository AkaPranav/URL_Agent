"""URL reputation scan orchestration."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from reports.html_report import generate_html_report
from reports.pdf_report import generate_pdf_report
from services.safe_browsing import SafeBrowsingService
from services.scoring import ScoringEngine
from services.ssl_checker import SSLChecker
from services.virustotal import VirusTotalService
from services.whois_service import WhoisService
from utils.validators import validate_url


ScanFunction = Callable[[str], dict[str, Any]]


class URLReputationAgent:
    """Coordinates all reputation checks and report generation."""

    def __init__(self) -> None:
        self.scoring = ScoringEngine()

    @staticmethod
    def _run_source(name: str, scanner: ScanFunction, url: str) -> dict[str, Any]:
        try:
            return scanner(url)
        except Exception as exc:
            return {
                "status": "error",
                "source": name,
                "reason": str(exc),
            }

    def scan(self, raw_url: str, include_reports: bool = True) -> dict[str, Any]:
        url = validate_url(raw_url)

        checks: dict[str, tuple[str, ScanFunction]] = {
            "virustotal": ("VirusTotal", VirusTotalService().analyze),
            "google_safe_browsing": (
                "Google Safe Browsing",
                SafeBrowsingService().check_url,
            ),
            "whois": ("WHOIS", WhoisService().lookup),
            "ssl": ("SSL Certificate", SSLChecker().check),
        }

        with ThreadPoolExecutor(max_workers=len(checks)) as executor:
            futures = {
                key: executor.submit(self._run_source, name, scanner, url)
                for key, (name, scanner) in checks.items()
            }

        evidence = {
            key: future.result()
            for key, future in futures.items()
        }

        score = self.scoring.calculate(
            virustotal=evidence["virustotal"],
            safe_browsing=evidence["google_safe_browsing"],
            whois=evidence["whois"],
            ssl_data=evidence["ssl"],
        )

        report: dict[str, Any] = {
            "url": url,
            **evidence,
            "score": score,
        }

        if include_reports:
            report["html_report"] = generate_html_report(report)
            report["pdf_report_base64"] = base64.b64encode(
                generate_pdf_report(report)
            ).decode("ascii")

        return report
