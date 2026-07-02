"""HTML report generation."""

from __future__ import annotations

import html
import json
from typing import Any


def _json_default(value: Any) -> str:
    return str(value)


def _evidence_block(title: str, evidence: dict[str, Any]) -> str:
    status = html.escape(str(evidence.get("status", "unknown")).upper())
    body = html.escape(json.dumps(evidence, indent=2, default=_json_default))
    return f"""
    <section>
      <h2>{html.escape(title)} <span>{status}</span></h2>
      <pre>{body}</pre>
    </section>
    """


def generate_html_report(report: dict[str, Any]) -> str:
    score = report["score"]
    sections = [
        _evidence_block("VirusTotal", report["virustotal"]),
        _evidence_block("Google Safe Browsing", report["google_safe_browsing"]),
        _evidence_block("WHOIS", report["whois"]),
        _evidence_block("SSL Certificate", report["ssl"]),
    ]

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>URL Reputation Report</title>
  <style>
    body {{
      color: #17202a;
      font-family: Arial, sans-serif;
      line-height: 1.45;
      margin: 32px;
    }}
    header {{
      border-bottom: 2px solid #d5d8dc;
      margin-bottom: 24px;
      padding-bottom: 16px;
    }}
    h1, h2 {{
      margin: 0 0 8px;
    }}
    .summary {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      margin: 18px 0;
    }}
    .metric {{
      border: 1px solid #d5d8dc;
      border-radius: 6px;
      padding: 12px;
    }}
    .metric strong {{
      display: block;
      font-size: 22px;
    }}
    section {{
      border-top: 1px solid #e5e8e8;
      padding: 18px 0;
    }}
    span {{
      color: #566573;
      font-size: 12px;
      margin-left: 8px;
    }}
    pre {{
      background: #f7f9f9;
      border: 1px solid #e5e8e8;
      border-radius: 6px;
      overflow-x: auto;
      padding: 12px;
      white-space: pre-wrap;
    }}
  </style>
</head>
<body>
  <header>
    <h1>URL Reputation Report</h1>
    <p><strong>URL:</strong> {html.escape(report["url"])}</p>
  </header>

  <div class="summary">
    <div class="metric"><span>Decision</span><strong>{html.escape(score["decision"])}</strong></div>
    <div class="metric"><span>Risk</span><strong>{html.escape(score["risk_level"])}</strong></div>
    <div class="metric"><span>Score</span><strong>{score["total_score"]}/100</strong></div>
    <div class="metric"><span>Evidence</span><strong>{'Incomplete' if score["incomplete_evidence"] else 'Complete'}</strong></div>
  </div>

  <p>{html.escape(score["message"])}</p>

  {''.join(sections)}
</body>
</html>
"""
