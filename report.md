# URL Reputation Agent - Project Report

## 1. Project Overview

URL Reputation Agent is a Python-based security tool that scans a submitted URL and produces a trustworthiness report. The project combines multiple evidence sources, calculates a weighted reputation score, and returns a final decision such as `ALLOW`, `MANUAL REVIEW`, or `BLOCK`.

The main goal of the project is to help identify whether a URL looks safe before a user visits it. Instead of depending on only one signal, the application checks threat intelligence, browser safety data, domain registration information, and SSL certificate details.

## 2. Problem Statement

Malicious URLs are commonly used for phishing, malware delivery, scams, and social engineering. A user may not be able to judge a URL only by looking at it. This project solves that problem by building a small automated URL scanner that:

- accepts a URL from an API or web interface,
- validates and normalizes the input,
- gathers evidence from multiple security sources,
- assigns a score from 0 to 100,
- generates downloadable reports for review.

## 3. Technology Stack

The project uses the following technologies:

| Technology | Purpose |
| --- | --- |
| Python 3.12 | Main programming language |
| FastAPI | REST API for scanning URLs |
| Streamlit | Simple web UI for users |
| Pydantic | Request and response data validation |
| Requests | Calling external APIs such as VirusTotal, Google Safe Browsing, and RDAP |
| Cryptography | Reading and parsing SSL certificates |
| ReportLab | PDF report generation |
| Jinja-style HTML generation | HTML security report output |
| Uvicorn | Running the FastAPI server |
| dotenv / environs | Loading API keys and configuration |
| unittest | Testing service behavior |

## 4. Main Features Implemented

### URL Validation

The application validates user input before scanning. It trims whitespace, adds `https://` when a scheme is missing, and only allows `http` and `https` URLs. This prevents invalid or unsupported inputs from reaching the scanner services.

### FastAPI Backend

The backend exposes API endpoints for scanning URLs:

- `GET /` returns health and version information.
- `POST /scan` returns a full JSON reputation report.
- `POST /scan/html` returns an HTML version of the report.

The API uses Pydantic models to keep request and response formats clear.

### Streamlit Web Interface

A Streamlit interface was implemented so users can scan URLs without using command-line tools. The UI provides:

- URL input form,
- final decision display,
- total score and source-wise scores,
- evidence tabs for each scanner,
- download buttons for HTML, PDF, and JSON reports.

### VirusTotal Integration

The VirusTotal service submits and retrieves URL analysis data. It extracts useful statistics such as:

- malicious detections,
- suspicious detections,
- harmless detections,
- undetected engines,
- reputation score.

If the API key is not configured, the service returns an `unavailable` status instead of crashing.

### Google Safe Browsing Integration

The Google Safe Browsing service checks whether a URL is present in Google's threat database. It scans against threat categories such as malware, social engineering, unwanted software, and potentially harmful applications.

Like VirusTotal, this service handles missing API keys gracefully.

### RDAP / WHOIS Domain Lookup

The WHOIS functionality was implemented using RDAP through `rdap.org`. It collects domain registration details such as:

- domain name,
- registrar,
- creation date,
- expiration date,
- updated date,
- domain age,
- country,
- organization,
- name servers.

A real issue was fixed where scanning `www.google.com` failed because RDAP records usually exist for the registered domain `google.com`, not every subdomain. The service now falls back from the full hostname to parent domains until it finds a valid RDAP record.

### SSL Certificate Checking

The SSL checker connects to the target host on port 443 and extracts certificate information. It checks:

- whether SSL is enabled,
- certificate issuer,
- subject,
- version,
- serial number,
- signature algorithm,
- validity start and end dates,
- expiry status,
- days remaining.

### Scoring Engine

The scoring engine combines evidence into a 100-point reputation score:

- VirusTotal: 40 points
- Google Safe Browsing: 30 points
- WHOIS domain age: 15 points
- SSL certificate validity: 15 points

Based on the final score, the scanner returns:

- `ALLOW` for low-risk URLs,
- `MANUAL REVIEW` for uncertain or incomplete evidence,
- `BLOCK` for high-risk URLs.

### Report Generation

The project generates reports in multiple formats:

- JSON report for API usage,
- HTML report for browser viewing,
- PDF report for sharing or documentation.

The reports include the final score, decision, risk level, message, and detailed evidence from each source.

## 5. Project Architecture

The code is organized into clear modules:

```text
app.py                  FastAPI application and API routes
streamlit_app.py        Streamlit user interface
config.py               Environment and API key configuration
models/report.py        Pydantic request and response models
services/               Core scanning and scoring services
reports/                HTML and PDF report generators
utils/validators.py     URL validation helper
tests/                  Regression tests
```

The central orchestrator is `URLReputationAgent`. It validates the URL, runs the scanning services, sends the evidence to the scoring engine, and attaches generated reports.

## 6. Implementation Details

The project follows a modular service-based design. Each scanner is responsible for one type of evidence:

- `VirusTotalService` handles VirusTotal API calls.
- `SafeBrowsingService` handles Google Safe Browsing checks.
- `WhoisService` handles RDAP domain registration lookups.
- `SSLChecker` handles SSL certificate inspection.
- `ScoringEngine` calculates the final score and decision.

The reputation agent runs these checks through a `ThreadPoolExecutor`, so the sources can be queried concurrently instead of waiting for each check one by one. This improves scan speed because most checks depend on network calls.

The system also uses defensive error handling. If one source fails, the project returns an error object for that source and still produces a report. This is important because external APIs, DNS, RDAP, or SSL endpoints may fail independently.

## 7. Testing and Verification

A regression test was added for the RDAP fallback behavior. The test confirms that when `www.google.com` returns no RDAP record, the service retries with `google.com` and succeeds.

The test suite can be run with:

```bash
source .venv/bin/activate
python -m unittest discover -s tests
```

The live RDAP lookup was also verified for `https://www.google.com`, and it returned a successful record for `GOOGLE.COM`.

## 8. What I Learned

During this project, I learned how to build a practical security scanning application using Python. The most important learning areas were:

- how to design a FastAPI backend with clean request and response models,
- how to create a simple Streamlit interface for non-technical users,
- how to integrate external security APIs,
- how to handle missing API keys without breaking the application,
- how to parse SSL certificates using Python,
- how to use RDAP as a modern replacement for raw WHOIS,
- how to combine multiple weak signals into a stronger security score,
- how to generate HTML and PDF reports from scan results,
- how to structure a project into reusable services,
- how to write regression tests for real bugs.

I also learned that real-world security data is not always clean or predictable. For example, RDAP may not return records for subdomains such as `www.google.com`, even when the parent domain has a valid registration record. This taught me the importance of normalization, fallback logic, and testing with real domains.

## 9. Challenges Faced

Some challenges in the project were:

- handling unavailable API keys while keeping the app usable,
- managing network errors from third-party services,
- normalizing user-entered URLs,
- making the score fair when some evidence is missing,
- parsing SSL certificate fields correctly,
- fixing RDAP lookup failures for subdomains,
- producing reports that are useful in both API and UI workflows.

## 10. Future Improvements

Possible future improvements include:

- adding a database to store scan history,
- adding user authentication,
- adding more threat intelligence sources,
- improving public suffix detection for complex domains,
- adding rate-limit handling for third-party APIs,
- adding a dashboard for past scans,
- adding more automated tests,
- deploying the API and UI to a cloud server.

## 11. Conclusion

URL Reputation Agent is a small but useful cybersecurity project that combines API integration, backend development, UI development, scoring logic, SSL inspection, WHOIS/RDAP lookup, and report generation. It demonstrates how multiple security signals can be collected and converted into a clear decision for users.

The project helped me understand both software engineering and practical security scanning concepts. It also showed the importance of robust error handling, clean architecture, and testing with real-world examples.
