"""Streamlit UI for the URL Reputation Agent."""

from __future__ import annotations

import base64
import json
from typing import Any

import streamlit as st

from services.reputation_agent import URLReputationAgent


def _json_default(value: Any) -> str:
    return str(value)


def _status_label(source: dict[str, Any]) -> str:
    status = source.get("status", "unknown")
    if status == "ok":
        return "Available"
    if status == "unavailable":
        return "Not configured"
    return "Error"


st.set_page_config(
    page_title="URL Reputation Agent",
    page_icon="URL",
    layout="wide",
)

st.title("URL Reputation Agent")

with st.form("scan-form"):
    url = st.text_input(
        "URL",
        placeholder="https://example.com",
    )
    submitted = st.form_submit_button("Scan URL", type="primary")

if submitted:
    agent = URLReputationAgent()
    with st.spinner("Scanning reputation sources..."):
        try:
            report = agent.scan(url)
        except ValueError as exc:
            st.error(str(exc))
            st.stop()

    score = report["score"]
    decision = score["decision"]
    risk_level = score["risk_level"]
    total_score = score["total_score"]

    if decision == "ALLOW":
        st.success(f"{decision} - {risk_level} risk")
    elif decision == "MANUAL REVIEW":
        st.warning(f"{decision} - {risk_level} risk")
    else:
        st.error(f"{decision} - {risk_level} risk")

    metric_cols = st.columns(5)
    metric_cols[0].metric("Score", f"{total_score}/100")
    metric_cols[1].metric("VirusTotal", score["virustotal_score"])
    metric_cols[2].metric("Safe Browsing", score["safe_browsing_score"])
    metric_cols[3].metric("WHOIS", score["whois_score"])
    metric_cols[4].metric("SSL", score["ssl_score"])

    st.caption(score["message"])

    source_cols = st.columns(4)
    source_keys = [
        ("VirusTotal", "virustotal"),
        ("Google Safe Browsing", "google_safe_browsing"),
        ("WHOIS", "whois"),
        ("SSL Certificate", "ssl"),
    ]
    for col, (label, key) in zip(source_cols, source_keys):
        col.metric(label, _status_label(report[key]))

    st.subheader("Evidence")
    tabs = st.tabs([label for label, _ in source_keys])
    for tab, (label, key) in zip(tabs, source_keys):
        with tab:
            st.json(report[key])

    st.subheader("Downloads")
    html_report = report["html_report"]
    pdf_report = base64.b64decode(report["pdf_report_base64"])

    download_cols = st.columns(3)
    download_cols[0].download_button(
        "Download HTML",
        html_report,
        file_name="url-reputation-report.html",
        mime="text/html",
    )
    download_cols[1].download_button(
        "Download PDF",
        pdf_report,
        file_name="url-reputation-report.pdf",
        mime="application/pdf",
    )
    download_cols[2].download_button(
        "Download JSON",
        json.dumps(report, indent=2, default=_json_default),
        file_name="url-reputation-report.json",
        mime="application/json",
    )
