from __future__ import annotations

"""
SSL Certificate Checker

Retrieves SSL certificate information for HTTPS websites.
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLChecker:
    """
    Service responsible for SSL certificate validation.
    """

    @staticmethod
    def _extract_hostname(url: str) -> str:
        parsed = urlparse(url)
        return parsed.hostname

    def check(self, url: str) -> dict:
        """
        Retrieve SSL certificate details.
        """

        hostname = self._extract_hostname(url)

        if hostname is None:
            raise ValueError("Unable to determine hostname.")

        try:
            pem = ssl.get_server_certificate((hostname, 443), timeout=10)

            certificate = x509.load_pem_x509_certificate(
                pem.encode(),
                default_backend()
            )

            issuer = {
                attribute.oid._name: attribute.value
                for attribute in certificate.issuer
            }

            subject = {
                attribute.oid._name: attribute.value
                for attribute in certificate.subject
            }

            valid_from = certificate.not_valid_before_utc
            valid_until = certificate.not_valid_after_utc

            now = datetime.utcnow().replace(tzinfo=valid_until.tzinfo)

            days_remaining = (valid_until - now).days

            return {
                "status": "ok",
                "source": "SSL Certificate",
                "ssl_enabled": True,
                "issuer": issuer,
                "subject": subject,
                "version": certificate.version.name,
                "serial_number": str(certificate.serial_number),
                "signature_algorithm": (
                    certificate.signature_hash_algorithm.name
                    if certificate.signature_hash_algorithm
                    else None
                ),
                "valid_from": valid_from,
                "valid_until": valid_until,
                "expired": now > valid_until,
                "days_remaining": days_remaining,
            }
        except (ssl.SSLError, socket.error, TimeoutError, OSError) as exc:
            return {
                "status": "error",
                "source": "SSL Certificate",
                "reason": str(exc),
                "ssl_enabled": False,
                "issuer": {},
                "subject": {},
                "version": None,
                "serial_number": None,
                "signature_algorithm": None,
                "valid_from": None,
                "valid_until": None,
                "expired": None,
                "days_remaining": None,
            }
