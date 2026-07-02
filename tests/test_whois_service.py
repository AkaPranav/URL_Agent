import unittest
from unittest.mock import Mock, patch

from services.whois_service import WhoisService


def _response(status_code: int, payload: dict | None = None) -> Mock:
    response = Mock()
    response.status_code = status_code
    response.raise_for_status.return_value = None
    response.json.return_value = payload or {"ldhName": "google.com"}
    return response


class WhoisServiceTest(unittest.TestCase):
    def test_lookup_falls_back_from_www_subdomain_to_registered_domain(self) -> None:
        service = WhoisService()

        with patch("services.whois_service.requests.get") as get:
            get.side_effect = [
                _response(404),
                _response(200, {"ldhName": "google.com"}),
            ]

            result = service.lookup("https://www.google.com")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["domain"], "google.com")
        self.assertEqual(
            [call.args[0] for call in get.call_args_list],
            [
                "https://rdap.org/domain/www.google.com",
                "https://rdap.org/domain/google.com",
            ],
        )

    def test_lookup_reports_original_hostname_when_no_candidate_exists(self) -> None:
        service = WhoisService()

        with patch("services.whois_service.requests.get") as get:
            get.side_effect = [
                _response(404),
                _response(404),
            ]

            with self.assertRaisesRegex(ValueError, "www.example.invalid"):
                service.lookup("https://www.example.invalid")
