
"""
URL validation utilities.
"""

from urllib.parse import urlparse


SUPPORTED_SCHEMES = {"http", "https"}


def validate_url(url: str) -> str:
    """
    Validate and normalize a URL.

    Args:
        url: URL supplied by the user.

    Returns:
        Normalized URL.

    Raises:
        ValueError: If the URL is invalid.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)

    if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
        raise ValueError(
            "Only HTTP and HTTPS URLs are supported."
        )

    if not parsed.netloc:
        raise ValueError("Invalid URL format.")

    return url
