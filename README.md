# URL Reputation Agent

URL Reputation Agent analyzes URL trustworthiness using VirusTotal, Google Safe
Browsing, WHOIS, and SSL certificate evidence. It returns a weighted score from
0 to 100, a security decision, and downloadable JSON, HTML, and PDF reports.

## Scoring

- VirusTotal: 40 points
- Google Safe Browsing: 30 points
- WHOIS domain age: 15 points
- SSL certificate validity: 15 points

Decisions:

- `ALLOW`: score >= 85
- `MANUAL REVIEW`: 60 <= score < 85, or incomplete evidence with an otherwise acceptable score
- `BLOCK`: score < 60

## Setup

```bash
source .venv/bin/activate
uv sync
```

Create `.env`:

```ini
VIRUS_TOTAL_API_KEY="your_virus_total_api_key"
GOOGLE_SAFE_BROWSING_API_KEY="your_google_safe_browsing_api_key"
```

The app still runs without API keys, but those sources are marked unavailable
and receive zero score.

## Run API

```bash
source .venv/bin/activate
uvicorn app:app --reload
```

Scan a URL:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Run Streamlit UI

```bash
source .venv/bin/activate
streamlit run streamlit_app.py
```

Then open `http://localhost:8501`.

## Structure

```text
.
|-- app.py
|-- config.py
|-- requirements.txt
|-- requirement.txt
|-- streamlit_app.py
|-- models/
|   `-- report.py
|-- reports/
|   |-- html_report.py
|   `-- pdf_report.py
|-- services/
|   |-- reputation_agent.py
|   |-- virustotal.py
|   |-- safe_browsing.py
|   |-- whois_service.py
|   |-- ssl_checker.py
|   `-- scoring.py
`-- utils/
    `-- validators.py
```
