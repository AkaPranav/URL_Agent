"""
Configuration loader.

Loads all environment variables required by the application.

Every service should import API keys from here instead of
reading the .env file directly.
"""

from environs import Env

env = Env()
env.read_env()

VIRUS_TOTAL_API_KEY: str = env.str(
    "VIRUS_TOTAL_API_KEY",
    default=""
)

GOOGLE_SAFE_BROWSING_API_KEY: str = env.str(
    "GOOGLE_SAFE_BROWSING_API_KEY",
    default=""
)