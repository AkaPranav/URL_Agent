<div align="center">
  <h1>🛡️ URL Reputation Agent</h1>
  <p>
    <strong>An advanced, multi-source intelligence tool to evaluate URL trustworthiness and detect malicious web resources.</strong>
  </p>

  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.12-blue.svg?style=for-the-badge&logo=python" alt="Python Version"></a>
    <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/FastAPI-009688.svg?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"></a>
    <a href="https://streamlit.io/"><img src="https://img.shields.io/badge/Streamlit-FF4B4B.svg?style=for-the-badge&logo=streamlit&logoColor=white" alt="Streamlit"></a>
  </p>
</div>

---

## 📖 Overview

**URL Reputation Agent** is a powerful cybersecurity utility designed to automatically analyze URL trustworthiness. Instead of relying on a single data source, it intelligently combines signals from leading threat intelligence providers, domain registration data, and SSL certificate evidence to calculate a weighted security score (0-100) and provide actionable security decisions.

Whether you're investigating phishing attempts, analyzing malware delivery networks, or simply verifying a suspicious link, URL Reputation Agent gives you the comprehensive insights you need through a clean API and an intuitive Web UI.

## ✨ Features

- **🌐 Multi-Source Threat Intelligence**: Integrates seamlessly with VirusTotal and Google Safe Browsing.
- **🔍 Domain & SSL Forensics**: Analyzes WHOIS domain age via RDAP and verifies SSL certificate validity.
- **⚖️ Weighted Risk Scoring**: Computes an intelligent score evaluating all gathered evidence:
  - `VirusTotal`: 40%
  - `Google Safe Browsing`: 30%
  - `WHOIS Age`: 15%
  - `SSL Certificate`: 15%
- **🚦 Smart Decision Engine**: Outputs clear actions: `ALLOW`, `MANUAL REVIEW`, or `BLOCK`.
- **📊 Exportable Reports**: Instantly generates rich downloadable PDF, HTML, and JSON reports.
- **🎨 Interactive Web UI**: Built with Streamlit for a smooth, zero-config user experience.
- **🔌 Robust REST API**: Fast and scalable API powered by FastAPI for seamless system integration.

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.12+ and `uv` installed on your system.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/url-reputation-agent.git
   cd url-reputation-agent
   ```

2. **Install dependencies using `uv`:**
   ```bash
   uv venv
   source .venv/bin/activate
   uv sync
   ```

3. **Configure Environment Variables:**
   ```bash
   cp .env.example .env
   ```
   Open the `.env` file and add your API keys:
   - `VIRUS_TOTAL_API_KEY`: Get one from [VirusTotal](https://www.virustotal.com/)
   - `GOOGLE_SAFE_BROWSING_API_KEY`: Get one from [Google Cloud](https://console.cloud.google.com/)
   - `APP_API_KEY`: Set a secure random string to protect your API endpoints.
   
   *(Note: The application is designed to degrade gracefully. If a key is missing, that module will safely return a 0-score without crashing the application.)*

## 💻 Usage

You can use the URL Reputation Agent in two ways: via the sleek Web UI or the Developer API.

### Option 1: Streamlit Web UI

Run the interactive web interface:

```bash
source .venv/bin/activate
streamlit run streamlit_app.py
```
*Access the dashboard at `http://localhost:8501`*

### Option 2: REST API

Start the FastAPI server:

```bash
source .venv/bin/activate
uvicorn app:app --reload
```
*API will be available at `http://localhost:8000`*

#### API Documentation
Interactive API docs are auto-generated. Visit `http://localhost:8000/docs` (Swagger UI) to explore endpoints and test requests right from your browser. 
*(Remember to Authorize with your `APP_API_KEY` first!)*

#### API Examples

**Health Check:**
```bash
curl http://localhost:8000/health
```

**Scan a URL:**
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: replace-with-a-long-random-secret" \
  -d '{"url": "https://example.com"}'
```

**Generate HTML Report:**
```bash
curl -X POST http://localhost:8000/scan/html \
  -H "Content-Type: application/json" \
  -H "X-API-Key: replace-with-a-long-random-secret" \
  -d '{"url": "https://example.com"}' > report.html
```

## 🏗️ Architecture

```text
📦 url-reputation-agent
 ┣ 📂 models/            # Pydantic data schemas
 ┣ 📂 reports/           # HTML and PDF report generators
 ┣ 📂 services/          # Core scanning engines (VirusTotal, RDAP, SSL, Scoring)
 ┣ 📂 utils/             # Validation helpers
 ┣ 📜 app.py             # FastAPI entrypoint
 ┣ 📜 config.py          # Environment configuration loader
 ┣ 📜 streamlit_app.py   # Web UI entrypoint
 ┗ 📜 pyproject.toml     # Project dependencies
```

## 🛡️ Security & Privacy

We take data hygiene seriously. This project is configured to automatically ignore sensitive data (like `.env` files, local logs, and generated reports) to prevent accidental credential leaks to version control. 

## 🤝 Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---
*Built with ❤️ for better web security.*
