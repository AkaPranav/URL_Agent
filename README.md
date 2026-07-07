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

Create `.env` from the example file and replace the values:

```bash
cp .env.example .env
```

`APP_API_KEY` protects the API scan endpoints. The app still runs without
VirusTotal or Google Safe Browsing keys, but those sources are marked
unavailable and receive zero score.

If you edit `.env`, restart `uvicorn` or Streamlit so the running process picks
up the updated values.

## Run API

```bash
source .venv/bin/activate
uvicorn app:app --reload
```

Health check:

```bash
curl http://localhost:8000/health
```

Scan a URL:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: replace-with-a-long-random-secret" \
  -d '{"url": "https://example.com"}'
```

The `/scan` endpoint returns JSON-only security evidence and score data.
HTML and PDF output are not included in this response.

Generate only the HTML report:

```bash
curl -X POST http://localhost:8000/scan/html \
  -H "Content-Type: application/json" \
  -H "X-API-Key: replace-with-a-long-random-secret" \
  -d '{"url": "https://example.com"}'
```

## Test With Postman

1. Start the API:

   ```bash
   source .venv/bin/activate
   uvicorn app:app --reload
   ```

2. In Postman, create a new request.
3. Set the method to `POST`.
4. Set the URL to `http://localhost:8000/scan`.
5. Open the `Headers` tab and add:

   ```text
   Key: X-API-Key
   Value: replace-with-a-long-random-secret
   ```

6. Open the `Body` tab.
7. Select `raw`.
8. Select `JSON` from the body type dropdown.
9. Paste this body:

   ```json
   {
     "url": "https://example.com"
   }
   ```

10. Click `Send`.

Expected results:

- `200 OK`: API key is correct and the response body contains the scan JSON.
- `401 Unauthorized`: `X-API-Key` is missing or does not match `.env`.
- `503 Service Unavailable`: `APP_API_KEY` is not configured in `.env`.
- `400 Bad Request`: the submitted URL is invalid.

## Test In Swagger UI

1. Open `http://localhost:8000/docs`.
2. Click `Authorize`.
3. Enter your `APP_API_KEY` value in the `X-API-Key` field.
4. Expand `POST /scan`.
5. Click `Try it out`.
6. Send this body:

   ```json
   {
     "url": "https://example.com"
   }
   ```

If you skip the `Authorize` step, Swagger will return `401 Unauthorized`.

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
