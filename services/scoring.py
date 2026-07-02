"""Scoring engine for URL reputation reports."""

from typing import Any


class ScoringEngine:
    """
    Computes the reputation score.
    """

    VIRUSTOTAL_WEIGHT = 40
    SAFE_BROWSING_WEIGHT = 30
    WHOIS_WEIGHT = 15
    SSL_WEIGHT = 15

    def get_decision(self, total_score: int, has_unavailable_sources: bool) -> dict[str, str]:
        """
        Determine the final decision based on the total score.
        """

        if has_unavailable_sources and total_score >= 60:
            return {
                "decision": "MANUAL REVIEW",
                "risk_level": "MEDIUM",
                "message": (
                    "The URL has incomplete third-party evidence. "
                    "Review manually before allowing access."
                ),
            }

        if total_score >= 85:
            return {
                "decision": "ALLOW",
                "risk_level": "LOW",
                "message": (
                    "The URL appears to be safe based on the "
                    "available security checks."
                ),
            }

        if total_score >= 60:
            return {
                "decision": "MANUAL REVIEW",
                "risk_level": "MEDIUM",
                "message": (
                    "The URL requires manual verification "
                    "before it should be accessed."
                ),
            }

        return {
            "decision": "BLOCK",
            "risk_level": "HIGH",
            "message": (
                "The URL is considered unsafe and should "
                "not be accessed."
            ),
        }


    def score_virustotal(self, vt: dict[str, Any]) -> int:
        """
        VirusTotal score.
        """

        if vt.get("status") != "ok":
            return 0

        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        if malicious > 0:
            return 0

        if suspicious > 0:
            return 20

        return self.VIRUSTOTAL_WEIGHT

    def score_safe_browsing(self, sb: dict[str, Any]) -> int:
        """
        Google Safe Browsing score.
        """

        if sb.get("status") != "ok":
            return 0

        if sb.get("safe", False):
            return self.SAFE_BROWSING_WEIGHT

        return 0

    def score_whois(self, whois: dict[str, Any]) -> int:
        """
        WHOIS score.
        """

        if whois.get("status") != "ok":
            return 0

        age = whois.get("domain_age_days")

        if age is None:
            return 0

        if age >= 365:
            return 15

        if age >= 180:
            return 10

        if age >= 30:
            return 5

        return 0

    def score_ssl(self, ssl_data: dict[str, Any]) -> int:
        """
        SSL score.
        """

        if ssl_data.get("status") != "ok":
            return 0

        if (
            ssl_data.get("ssl_enabled")
            and not ssl_data.get("expired")
        ):
            return self.SSL_WEIGHT

        return 0

    def calculate(
        self,
        virustotal: dict[str, Any],
        safe_browsing: dict[str, Any],
        whois: dict[str, Any],
        ssl_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Calculate the final score.
        """

        vt_score = self.score_virustotal(virustotal)

        sb_score = self.score_safe_browsing(
            safe_browsing
        )

        whois_score = self.score_whois(whois)

        ssl_score = self.score_ssl(ssl_data)

        total = (
            vt_score
            + sb_score
            + whois_score
            + ssl_score
        )

        has_unavailable_sources = any(
            source.get("status") != "ok"
            for source in (
                virustotal,
                safe_browsing,
                whois,
                ssl_data,
            )
        )

        decision = self.get_decision(total, has_unavailable_sources)

        return {
            "virustotal_score": vt_score,
            "safe_browsing_score": sb_score,
            "whois_score": whois_score,
            "ssl_score": ssl_score,
            "total_score": total,
            "max_score": 100,
            "decision": decision["decision"],
            "risk_level": decision["risk_level"],
            "message": decision["message"],
            "incomplete_evidence": has_unavailable_sources,
        }
