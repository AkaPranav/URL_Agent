# RDAP-based domain registration lookup service.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests


class WhoisService:
    """Retrieve domain registration metadata using public RDAP."""

    BASE_URL = "https://rdap.org/domain"
    TIMEOUT_SECONDS = 30

    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract the hostname from a URL for RDAP lookup."""
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            raise ValueError("Invalid domain: unable to extract hostname.")

        return domain.lower()

    @staticmethod
    def _domain_candidates(hostname: str) -> list[str]:
        """Return RDAP lookup candidates from host to parent domains."""
        labels = [label for label in hostname.lower().split(".") if label]

        if len(labels) <= 2:
            return [".".join(labels)]

        return [".".join(labels[index:]) for index in range(0, len(labels) - 1)]

    @staticmethod
    def _parse_rdap_datetime(value: str | None) -> datetime | None:
        """Parse an RDAP datetime string into a timezone-aware datetime."""
        if not value:
            return None

        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid RDAP datetime value: {value}") from exc

    @staticmethod
    def _find_event_date(
        events: Any,
        actions: set[str],
    ) -> str | None:
        """Find the first RDAP event date matching one of the actions."""
        if not isinstance(events, list):
            return None

        normalized_actions = {action.lower() for action in actions}

        for event in events:
            if not isinstance(event, dict):
                continue

            action = str(event.get("eventAction", "")).lower()
            if action in normalized_actions:
                return event.get("eventDate")

        return None

    @staticmethod
    def _calculate_age_days(creation_date: str | None) -> int | None:
        """Calculate domain age in days from the registration date."""
        created_at = WhoisService._parse_rdap_datetime(creation_date)

        if created_at is None:
            return None

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        return (datetime.now(timezone.utc) - created_at).days

    @staticmethod
    def _extract_vcard_value(
        vcard_array: list[Any] | None,
        property_name: str,
    ) -> str | None:
        """Extract a property value from an RDAP vCard array."""
        if not vcard_array or len(vcard_array) < 2:
            return None

        for item in vcard_array[1]:
            if not isinstance(item, list) or len(item) < 4:
                continue

            name = item[0]
            value = item[3]

            if name == property_name and isinstance(value, str):
                return value

        return None

    @classmethod
    def _extract_entity_with_role(
        cls,
        entities: Any,
        role: str,
    ) -> dict[str, Any] | None:
        """Return the first RDAP entity containing the requested role."""
        if not isinstance(entities, list):
            return None

        for entity in entities:
            if not isinstance(entity, dict):
                continue

            roles = entity.get("roles", [])
            if role in roles:
                return entity

        return None

    @classmethod
    def _extract_registrar(cls, entities: Any) -> str | None:
        """Extract registrar name or handle from RDAP entities."""
        registrar = cls._extract_entity_with_role(entities, "registrar")

        if not registrar:
            return None

        registrar_name = cls._extract_vcard_value(
            registrar.get("vcardArray"),
            "fn",
        )

        return registrar_name or registrar.get("handle")

    @classmethod
    def _extract_organization(cls, entities: Any) -> str | None:
        """Extract registrant organization when RDAP provides it."""
        registrant = cls._extract_entity_with_role(entities, "registrant")

        if not registrant:
            return None

        return cls._extract_vcard_value(registrant.get("vcardArray"), "org")

    @classmethod
    def _extract_country(cls, entities: Any) -> str | None:
        """Extract registrant country when RDAP provides it."""
        registrant = cls._extract_entity_with_role(entities, "registrant")

        if not registrant:
            return None

        return cls._extract_vcard_value(registrant.get("vcardArray"), "country")

    @staticmethod
    def _extract_name_servers(data: dict[str, Any]) -> list[str] | None:
        """Extract nameserver hostnames from an RDAP response."""
        nameservers = [
            nameserver.get("ldhName")
            for nameserver in data.get("nameservers", [])
            if isinstance(nameserver, dict) and nameserver.get("ldhName")
        ]

        return nameservers or None

    def _fetch_rdap(self, domain: str) -> dict[str, Any]:
        """Fetch and decode RDAP data for a domain."""
        try:
            response = requests.get(
                f"{self.BASE_URL}/{domain}",
                timeout=self.TIMEOUT_SECONDS,
            )
        except requests.Timeout as exc:
            message = f"RDAP lookup timed out for domain: {domain}"
            raise TimeoutError(message) from exc
        except requests.ConnectionError as exc:
            raise ConnectionError(
                f"RDAP connection failed for domain: {domain}"
            ) from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"RDAP lookup failed for domain: {domain}") from exc

        if response.status_code == 404:
            raise ValueError(f"RDAP record not found for domain: {domain}")

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise RuntimeError(
                f"RDAP lookup returned HTTP {response.status_code} for {domain}"
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            message = f"Invalid RDAP JSON response for domain: {domain}"
            raise ValueError(message) from exc

        if not isinstance(data, dict):
            raise ValueError(f"Invalid RDAP response format for domain: {domain}")

        return data

    def _fetch_rdap_for_hostname(self, hostname: str) -> tuple[str, dict[str, Any]]:
        """Fetch RDAP data, falling back from subdomains to parent domains."""
        not_found_errors: list[ValueError] = []

        for candidate in self._domain_candidates(hostname):
            try:
                return candidate, self._fetch_rdap(candidate)
            except ValueError as exc:
                if "RDAP record not found" not in str(exc):
                    raise
                not_found_errors.append(exc)

        if not_found_errors:
            raise ValueError(f"RDAP record not found for domain: {hostname}")

        raise ValueError(f"Invalid domain: unable to extract hostname from {hostname}")

    def lookup(self, url: str) -> dict[str, Any]:
        """Return RDAP registration metadata for a URL's domain.

        The returned dictionary preserves the previous WHOIS service output
        structure used by the scoring engine and report generators.
        """
        hostname = self._extract_domain(url)
        domain, data = self._fetch_rdap_for_hostname(hostname)

        events = data.get("events")
        entities = data.get("entities")

        creation_date = self._find_event_date(
            events,
            {"registration"},
        )
        expiration_date = self._find_event_date(
            events,
            {"expiration"},
        )
        updated_date = self._find_event_date(
            events,
            {"last changed", "last update of rdap database"},
        )

        return {
            "status": "ok",
            "source": "RDAP",
            "domain": data.get("ldhName") or domain,
            "registrar": self._extract_registrar(entities),
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "updated_date": updated_date,
            "domain_age_days": self._calculate_age_days(creation_date),
            "country": self._extract_country(entities),
            "organization": self._extract_organization(entities),
            "name_servers": self._extract_name_servers(data),
        }
