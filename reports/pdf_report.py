"""PDF report generation."""

from __future__ import annotations

import io
import json
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer


def _json_default(value: Any) -> str:
    return str(value)


def generate_pdf_report(report: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("URL Reputation Report", styles["Title"]),
        Paragraph(f"URL: {report['url']}", styles["Normal"]),
        Spacer(1, 12),
    ]

    score = report["score"]
    summary = (
        f"Decision: {score['decision']} | "
        f"Risk: {score['risk_level']} | "
        f"Score: {score['total_score']}/100"
    )
    story.extend([
        Paragraph(summary, styles["Heading2"]),
        Paragraph(score["message"], styles["Normal"]),
        Spacer(1, 12),
    ])

    for title, key in (
        ("VirusTotal", "virustotal"),
        ("Google Safe Browsing", "google_safe_browsing"),
        ("WHOIS", "whois"),
        ("SSL Certificate", "ssl"),
    ):
        story.append(Paragraph(title, styles["Heading2"]))
        story.append(
            Preformatted(
                json.dumps(report[key], indent=2, default=_json_default),
                styles["Code"],
            )
        )
        story.append(Spacer(1, 12))

    doc.build(story)
    return buffer.getvalue()
