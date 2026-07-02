"""
Google Safe Browsing Service

Checks whether a URL is classified as malicious by
Google Safe Browsing.
"""

from __future__ import annotations

from typing import Any

import requests

from config import GOOGLE_SAFE_BROWSING_API_KEY


class SafeBrowsingService:
    """
    Google Safe Browsing API client.
    """

    BASE_URL = (
        "https://safebrowsing.googleapis.com/v4/"
        "threatMatches:find"
    )

    def __init__(self) -> None:
        pass

    def check_url(self, url: str) -> dict[str, Any]:
        """
        Check whether the URL is present in the Google
        Safe Browsing threat database.
        """

        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return {
                "status": "unavailable",
                "source": "Google Safe Browsing",
                "reason": "GOOGLE_SAFE_BROWSING_API_KEY is not configured.",
                "safe": None,
                "matches": [],
            }

        payload = {
            "client": {
                "clientId": "url-reputation-agent",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": [
                    "ANY_PLATFORM",
                ],
                "threatEntryTypes": [
                    "URL",
                ],
                "threatEntries": [
                    {
                        "url": url,
                    }
                ],
            },
        }

        try:
            response = requests.post(
                f"{self.BASE_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload,
                timeout=30,
            )

            response.raise_for_status()

            data = response.json()

            matches = data.get("matches", [])

            return {
                "status": "ok",
                "source": "Google Safe Browsing",
                "safe": len(matches) == 0,
                "matches": matches,
            }
        except requests.RequestException as exc:
            return {
                "status": "error",
                "source": "Google Safe Browsing",
                "reason": str(exc),
                "safe": None,
                "matches": [],
            }
