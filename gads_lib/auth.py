import json
from urllib.parse import parse_qs, urlparse

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


# ── Two-step OAuth (no local callback listener) ─────────────────────────────
#
# On WSL/headless environments the local `run_local_server()` callback
# listener is often unreliable (it can die, or its CSRF state token can
# mismatch a stale browser tab). The two-step flow avoids it entirely:
#   1. `build_authorization_url()` prints a consent URL. The user opens it,
#      grants access, and lands on a `http://localhost:<port>/?...` page
#      that the browser cannot actually reach (nothing is listening) but
#      whose address bar still carries the `code`.
#   2. The user pastes that full URL (or just the `code` value) back in;
#      `parse_callback_url()` extracts the code and `exchange_authorization_code()`
#      exchanges it directly via `InstalledAppFlow.fetch_token()`, with no
#      server involved.


def build_authorization_url(client_secret_path, redirect_uri, scopes=None):
    """Build the Google OAuth consent URL without starting any local server.

    Returns (auth_url, state).
    """
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), scopes or SCOPES)
    flow.redirect_uri = redirect_uri
    auth_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
    )
    return auth_url, state


def parse_callback_url(url_or_code):
    """Extract the authorization `code` (and `state`, if present) from either
    a full OAuth redirect URL pasted from the browser
    (e.g. 'http://localhost:9090/?state=...&code=4/0A...&scope=...') or a
    bare authorization code.

    Returns (code, state). Raises ValueError with a clear, user-facing
    message if no code can be found (including when the callback reports
    an OAuth error such as `?error=access_denied`).
    """
    candidate = (url_or_code or "").strip()
    if not candidate:
        raise ValueError("empty callback URL / code")

    if "://" in candidate:
        parsed = urlparse(candidate)
        params = parse_qs(parsed.query)
        code_vals = params.get("code")
        if not code_vals or not code_vals[0]:
            error_vals = params.get("error")
            if error_vals:
                desc = (params.get("error_description") or [""])[0]
                detail = f": {desc}" if desc else ""
                raise ValueError(f"callback reports an OAuth error '{error_vals[0]}'{detail}")
            raise ValueError("no 'code' parameter found in the callback URL")
        state = (params.get("state") or [None])[0]
        return code_vals[0], state

    # Not a URL -- treat the whole string as a bare authorization code.
    return candidate, None


def exchange_authorization_code(client_secret_path, code, redirect_uri, scopes=None):
    """Exchange an authorization `code` for OAuth credentials, without
    starting a local callback server.

    Mirrors what `InstalledAppFlow.run_local_server()` produces after a
    successful browser round-trip, using `flow.fetch_token(code=...)`
    directly instead.
    """
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), scopes or SCOPES)
    flow.redirect_uri = redirect_uri
    flow.fetch_token(code=code)
    return flow.credentials
