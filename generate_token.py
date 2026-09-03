"""Generate OAuth token for Google platform API access.

Creates credentials with scopes for Google Ads, Business Profile,
Merchant Center, and Google Analytics (read + edit).

Requires client_secret.json from Google Cloud Console:
  https://console.cloud.google.com/apis/credentials

Usage:
    python generate_token.py                 # browser + local server on 9090
    python generate_token.py --no-browser    # skip opening a browser (WSL/headless)
    python generate_token.py --port 9091     # alternate callback port
    python generate_token.py --print-url-only  # print URL + exit
"""
import argparse
import os
import sys
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow

# gads_lib lives alongside this script (gads-cli/gads_lib/), so it's
# importable without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gads_lib.auth import SCOPES  # noqa: E402 -- canonical scope list, see gads_lib/auth.py

PROJECT_ROOT = Path(os.environ.get("GADS_PROJECT_ROOT", Path(__file__).resolve().parent.parent))
CREDENTIALS_DIR = Path(os.environ.get("GADS_CREDENTIALS_DIR", PROJECT_ROOT / "credentials"))

CLIENT_SECRET = CREDENTIALS_DIR / "client_secret.json"
TOKEN_OUTPUT = CREDENTIALS_DIR / "google-ads-oauth.json"
AUTH_URL_FILE = CREDENTIALS_DIR / ".oauth-auth-url.txt"

SEPARATOR = "=" * 60


def _print_auth_url_block(auth_url: str, port: int) -> None:
    """Print the auth URL with visual separators so terminals don't mangle it."""
    print()
    print(SEPARATOR)
    print("Open this URL in your browser to authorize:")
    print()
    print(auth_url)
    print()
    print(SEPARATOR)
    print(f"(Callback listener will run on http://localhost:{port}/)")
    print()


def _save_auth_url(auth_url: str) -> None:
    try:
        AUTH_URL_FILE.write_text(auth_url + "\n", encoding="utf-8")
        print(f"Auth URL also saved to: {AUTH_URL_FILE}")
    except OSError as exc:
        print(f"WARNING: could not save auth URL to {AUTH_URL_FILE}: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate OAuth token for Google APIs")
    parser.add_argument("--port", type=int, default=9090, help="Local server port for OAuth callback (default: 9090)")
    parser.add_argument("--no-browser", action="store_true", help="Do not attempt to open a browser (WSL/headless/remote)")
    parser.add_argument("--print-url-only", action="store_true", help="Print the auth URL and save it to credentials/.oauth-auth-url.txt, then exit without starting the callback server")
    args = parser.parse_args()

    if not CLIENT_SECRET.exists():
        print(f"ERROR: client_secret.json not found at {CLIENT_SECRET}")
        print("Download it from https://console.cloud.google.com/apis/credentials")
        print(f"Save it to: {CLIENT_SECRET}")
        return 1

    CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)

    flow = InstalledAppFlow.from_client_secrets_file(str(CLIENT_SECRET), SCOPES)
    flow.redirect_uri = f"http://localhost:{args.port}/"
    auth_url, _state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
    )

    _print_auth_url_block(auth_url, args.port)
    _save_auth_url(auth_url)

    if args.print_url_only:
        print("--print-url-only: exiting without starting the local callback server.")
        return 0

    try:
        creds = flow.run_local_server(
            port=args.port,
            open_browser=not args.no_browser,
            authorization_prompt_message="",  # we already printed our own
        )
    except Exception as exc:  # noqa: BLE001 - report whatever blew up
        print()
        print(f"ERROR: OAuth flow failed: {exc}")
        print("Remediation:")
        print(f"  - Confirm the URL above resolves in your browser.")
        print(f"  - Check nothing else is listening on port {args.port} (try --port N).")
        print( "  - On WSL / headless, use --no-browser and open the URL manually.")
        print( "  - Re-run with --print-url-only to inspect the URL before attempting.")
        return 2

    try:
        with open(TOKEN_OUTPUT, "w") as f:
            f.write(creds.to_json())
    except OSError as exc:
        print(f"ERROR: could not write token to {TOKEN_OUTPUT}: {exc}")
        return 3

    scopes = " ".join(getattr(creds, "scopes", None) or [])
    print()
    print(f"\u2713 Token saved to {TOKEN_OUTPUT}")
    print(f"  Token scopes: {scopes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
