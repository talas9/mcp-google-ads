import json

import click
from google.auth.exceptions import RefreshError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from .config import CREDS_PATH
from .output import EXIT_CODES

# Canonical OAuth scope list for this project. Every token-generation path
# (gads-cli/generate_token.py, `gads auth login`, tools/generate_token.py)
# MUST import this constant rather than hardcoding its own copy -- three
# independently-drifted copies previously caused `gads auth login --force`
# to reject a same-repo token as a "scope LOST" regression because its own
# local list omitted analytics.edit. See CHANGELOG for scope history.
SCOPES = [
    "https://www.googleapis.com/auth/adwords",
    "https://www.googleapis.com/auth/business.manage",
    "https://www.googleapis.com/auth/content",
    "https://www.googleapis.com/auth/analytics.readonly",
    "https://www.googleapis.com/auth/analytics.edit",
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/datamanager",
]

SCOPE_NAMES = {
    "https://www.googleapis.com/auth/adwords": "Google Ads",
    "https://www.googleapis.com/auth/business.manage": "Business Profile",
    "https://www.googleapis.com/auth/content": "Merchant Center",
    "https://www.googleapis.com/auth/analytics.readonly": "GA4 Analytics",
    "https://www.googleapis.com/auth/analytics.edit": "GA4 Analytics (edit)",
    "https://www.googleapis.com/auth/webmasters.readonly": "Search Console",
    "https://www.googleapis.com/auth/datamanager": "Data Manager",
}


def get_credentials():
    """Load and refresh OAuth credentials."""
    if not CREDS_PATH.exists():
        click.secho(f"✗ Credentials not found: {CREDS_PATH}", fg="red", err=True)
        raise SystemExit(1)

    with open(CREDS_PATH) as f:
        creds_data = json.load(f)

    creds = Credentials.from_authorized_user_info(creds_data)
    if creds.expired:
        try:
            creds.refresh(Request())
        except RefreshError as e:
            click.secho(f"✗ OAuth token refresh failed: {e}", fg="red", err=True)
            click.secho(
                "  The refresh token is likely expired or has been revoked. "
                "Fix: python generate_token.py (or gads-cli/generate_token.py) "
                "to re-authenticate.",
                fg="yellow",
                err=True,
            )
            raise SystemExit(EXIT_CODES["AUTH"])
        with open(CREDS_PATH, "w") as f:
            f.write(creds.to_json())
    return creds
