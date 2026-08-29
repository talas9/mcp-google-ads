"""gads — Unified Google platform CLI.

Manage Google Ads, Google Business Profile, Google Merchant Center,
and Google Analytics (GA4) from a single CLI. Designed for use with
Claude Code and AI coding agents.

All configuration is via environment variables / .env file.
See .env.example for the full list.
"""

import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta

import click

from gads_lib import (
    CONFIG_HOME,
    CREDS_PATH,
    CURRENCY,
    CUSTOMER_ID,
    DB_PATH,
    DEV_TOKEN,
    GA4_PROPERTY_ID,
    GLOBAL_HOME,
    LOGIN_CUSTOMER_ID,
    MERCHANT_CENTER_ID,
    PROJECT_ROOT,
    SCOPE_ROOT,
    SCOPE_TYPE,
    SNAPSHOTS_DIR,
    TZ_NAME,
    ads_mutate,
    ads_batch_mutate,
    ads_upload_click_conversions,
    flatten,
    ga4_get_metadata,
    ga4_run_realtime_report,
    ga4_run_report,
    ga4_batch_run_reports,
    ga4_run_pivot_report,
    ga4_check_compatibility,
    list_key_events,
    create_key_event,
    delete_key_event,
    VALID_COUNTING_METHODS,
    gbp_delete_reply,
    gbp_get_location,
    gbp_list_accounts,
    gbp_list_locations,
    gbp_list_reviews,
    gbp_reply_review,
    gbp_daily_metrics,
    gbp_multi_daily_metrics,
    gbp_search_keywords_monthly,
    gbp_batch_get_reviews,
    gbp_list_local_posts,
    gbp_create_local_post,
    gbp_delete_local_post,
    DAILY_METRICS,
    extract_target_cpa,
    extract_target_roas,
    generate_keyword_ideas,
    generate_keyword_forecast,
    get_credentials,
    get_db,
    mc_get_account,
    mc_get_account_status,
    mc_get_return_policy,
    mc_get_shipping,
    mc_list_datafeeds,
    mc_list_product_statuses,
    mc_list_products,
    mc_register_gcp,
    now_local,
    print_json,
    print_table,
    run_gaql,
    today_local,
)


from gads_lib import __version__
from gads_lib.gsc import gsc_list_sites, gsc_search_analytics, gsc_list_sitemaps, gsc_url_inspect
from gads_lib.datamanager import (
    datamanager_ingest_events,
    datamanager_ingest_audience_members,
    build_user_identifiers,
    MAX_EVENTS_PER_REQUEST,
    MAX_AUDIENCE_MEMBERS_PER_REQUEST,
)
from gads_lib.kb import check_drift, list_kb_files, show_kb_file, load_manifest
from gads_lib.output import EXIT_CODES, print_error
from gads_lib.catalog import build_catalog
from gads_lib import dbread


@click.group(
    context_settings={"auto_envvar_prefix": "GADS"},
    epilog=(
        "For Meta (Facebook/Instagram) Ads — Marketing API, Business Manager, "
        "Conversions API, and Commerce Manager — see the sister CLI mads-cli: "
        "https://github.com/talas9/mads-cli"
    ),
)
@click.version_option(__version__, prog_name="gads")
@click.option("--plain", is_flag=True, help="Deterministic output: no color, no emoji (for parsing).")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential progress/info output.")
@click.pass_context
def cli(ctx, plain, quiet):
    """gads — Unified Google platform CLI."""
    ctx.ensure_object(dict)
    ctx.obj["plain"] = plain
    ctx.obj["quiet"] = quiet
    if plain:
        # Strip ANSI color globally for deterministic, parseable output.
        import os as _os
        _os.environ["NO_COLOR"] = "1"
        ctx.color = False


@cli.group()
def auth():
    """Authentication and credential diagnostics."""
    pass


@cli.group()
def ads():
    """Google Ads commands."""
    pass


@cli.group()
def gbp():
    """Google Business Profile commands."""
    pass


@cli.group()
def merchant():
    """Google Merchant Center commands."""
    pass


@cli.group()
def ga4():
    """Google Analytics / GA4 commands."""
    pass


def enforce_allowed_caller():
    """Optional caller enforcement for agent delegation models."""
    if os.environ.get("GADS_ENFORCE_CALLER") != "1":
        return
    expected = os.environ.get("GADS_EXPECTED_CALLER", "google-platform-operator")
    caller = os.environ.get("GADS_CALLER_AGENT", "")
    if caller != expected:
        click.secho(
            f"✗ gads is restricted to the '{expected}' agent when GADS_ENFORCE_CALLER=1",
            fg="red", err=True,
        )
        raise SystemExit(1)


# ── Top-level commands ───────────────────────────────────────


@auth.command("status")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def auth_status(as_json):
    """Show current credential and env status (never prints secrets)."""
    scopes = []
    creds_present = CREDS_PATH.exists()
    if creds_present:
        creds = get_credentials()
        scopes = sorted(list(creds.scopes or []))

    payload = {
        "scope": SCOPE_TYPE,
        "scope_root": str(SCOPE_ROOT),
        "credentials_present": creds_present,
        "developer_token_present": bool(DEV_TOKEN),
        "login_customer_id_set": bool(LOGIN_CUSTOMER_ID),
        "customer_id_set": bool(CUSTOMER_ID),
        "merchant_center_id_set": bool(MERCHANT_CENTER_ID),
        "ga4_property_id_set": bool(GA4_PROPERTY_ID),
        "timezone": TZ_NAME,
        "currency": CURRENCY,
        "scopes": scopes,
        "db_path": str(DB_PATH),
        "db_present": DB_PATH.exists(),
    }

    if as_json:
        print_json(payload)
        return

    click.secho("\n  Auth Status\n", fg="white", bold=True)
    rows = [{"field": k, "value": str(v)} for k, v in payload.items()]
    print_table(rows, ["field", "value"])


@auth.command("setup")
def auth_setup():
    """Interactive setup wizard — walks you through full configuration."""
    from pathlib import Path as _Path

    click.secho("\n  ╔══════════════════════════════════════════╗", fg="cyan")
    click.secho("  ║   gads-cli — Setup Wizard     ║", fg="cyan")
    click.secho("  ╚══════════════════════════════════════════╝\n", fg="cyan")

    # ── Step 0: Determine scope ──────────────────────────────
    # Project-local if CWD has .env/.env.example or GADS_PROJECT_ROOT is set.
    # Otherwise user-global (~/.config/gads/).
    cwd = _Path.cwd()
    explicit_root = os.environ.get("GADS_PROJECT_ROOT")
    if explicit_root:
        scope_dir = _Path(explicit_root)
        scope_label = f"project ({scope_dir})"
    elif (cwd / ".env").exists() or (cwd / ".env.example").exists() or (cwd / "data").is_dir():
        scope_dir = cwd
        scope_label = f"project ({cwd})"
    else:
        scope_dir = CONFIG_HOME
        scope_label = f"global ({CONFIG_HOME})"

    scope_dir.mkdir(parents=True, exist_ok=True)
    env_path = scope_dir / ".env"
    click.secho(f"  Scope: {scope_label}\n", fg="white", bold=True)

    # ── Step 1: .env file ────────────────────────────────────
    # Look for .env.example in the CLI package directory
    pkg_dir = _Path(__file__).resolve().parent.parent
    env_example = pkg_dir / ".env.example"

    if env_path.exists():
        click.secho("  ✓ .env file exists", fg="green")
    else:
        click.secho("  Step 1: Create .env configuration file\n", fg="white", bold=True)
        if env_example.exists():
            import shutil
            shutil.copy(env_example, env_path)
            click.secho(f"  ✓ Created .env from template at {env_path}", fg="green")
        else:
            env_path.touch()
            click.secho(f"  ✓ Created empty .env at {env_path}", fg="green")
        click.echo()

    # ── Step 2: Google Cloud project ─────────────────────────
    click.secho("  Step 2: Google Cloud Project & APIs\n", fg="white", bold=True)
    click.echo("  You need a Google Cloud project. If you don't have one:")
    click.echo("    1. Go to:")
    click.secho("       https://console.cloud.google.com/projectcreate", fg="blue")
    click.echo("    2. Name it anything (e.g. 'gads-cli')")
    click.echo("    3. Click 'CREATE'\n")
    click.echo("  Then enable the APIs you need. Click each link → click 'ENABLE':")
    click.echo()
    apis = [
        ("Google Ads API",               "https://console.cloud.google.com/apis/library/googleads.googleapis.com",                          "Required", "Campaign management, reporting, GAQL queries"),
        ("My Business Account Mgmt API", "https://console.cloud.google.com/apis/library/mybusinessaccountmanagement.googleapis.com",        "For GBP",  "List accounts, manage locations"),
        ("My Business Business Info API", "https://console.cloud.google.com/apis/library/mybusinessbusinessinformation.googleapis.com",     "For GBP",  "Location details, hours, attributes"),
        ("My Business v4 (legacy)",       "https://console.cloud.google.com/apis/library/mybusiness.googleapis.com",                        "For GBP",  "Reviews, posts, media, Q&A"),
        ("Business Profile Performance",  "https://console.cloud.google.com/apis/library/businessprofileperformance.googleapis.com",        "For GBP",  "Directions, calls, impressions, search keywords"),
        ("Content API for Shopping",      "https://console.cloud.google.com/apis/library/content.googleapis.com",                           "For MC",   "Products, feeds, shipping, returns"),
        ("GA4 Data API",                  "https://console.cloud.google.com/apis/library/analyticsdata.googleapis.com",                     "For GA4",  "Reports, realtime data"),
        ("GA4 Admin API",                 "https://console.cloud.google.com/apis/library/analyticsadmin.googleapis.com",                    "For GA4",  "Property metadata, account structure"),
        ("Search Console API",            "https://console.cloud.google.com/apis/library/searchconsole.googleapis.com",                     "For GSC",  "Search queries, pages, click data"),
    ]
    for name, url, scope, desc in apis:
        click.echo(f"    • {name}")
        click.secho(f"      {url}", fg="blue")
        click.secho(f"      [{scope}] {desc}", fg="white", dim=True)
        click.echo()
    click.echo("  ℹ  You only need to enable the APIs for services you'll use.")
    click.echo("     Google Ads API is required. The others are optional.\n")
    click.pause("  Press Enter when APIs are enabled...")
    click.echo()

    # ── Step 3: OAuth consent screen + credentials ───────────
    click.secho("  Step 3: OAuth Consent Screen & Client Credentials\n", fg="white", bold=True)
    creds_dir = CREDS_PATH.parent
    client_secret = creds_dir / "client_secret.json"

    if client_secret.exists():
        click.secho("  ✓ client_secret.json found", fg="green")
    else:
        click.echo("  First, configure the OAuth consent screen:")
        click.echo("    1. Go to:")
        click.secho("       https://console.cloud.google.com/apis/credentials/consent", fg="blue")
        click.echo("    2. User Type: 'External' (unless you have Google Workspace)")
        click.echo("    3. App name: anything (e.g. 'gads-cli')")
        click.echo("    4. User support email: your email")
        click.echo("    5. Developer contact: your email")
        click.echo("    6. Click 'SAVE AND CONTINUE' through Scopes and Test Users")
        click.echo("    7. On Test Users, add your Google account email")
        click.echo("    8. Click 'SAVE AND CONTINUE' → 'BACK TO DASHBOARD'\n")
        click.echo("  Then create OAuth credentials:")
        click.echo("    1. Go to:")
        click.secho("       https://console.cloud.google.com/apis/credentials", fg="blue")
        click.echo("    2. Click '+ CREATE CREDENTIALS' → 'OAuth client ID'")
        click.echo("    3. Application type: 'Desktop app'")
        click.echo("    4. Name it anything (e.g. 'gads-cli')")
        click.echo("    5. Click 'CREATE', then 'DOWNLOAD JSON'")
        click.echo(f"    6. Save the downloaded file as:")
        click.secho(f"       {client_secret}\n", fg="yellow")
        click.secho("  ⚠  Your app will be in 'Testing' mode. This is fine —", fg="yellow")
        click.secho("     it means only users you added as test users can log in.", fg="yellow")
        click.secho("     You do NOT need to publish or verify the app.\n", fg="yellow")
        creds_dir.mkdir(parents=True, exist_ok=True)
        click.pause("  Press Enter when client_secret.json is saved...")

        if not client_secret.exists():
            click.secho(f"\n  ✗ client_secret.json still not found at {client_secret}", fg="red")
            click.echo("  Please save it and re-run 'gads auth setup'.")
            raise SystemExit(1)

    click.secho("  ✓ client_secret.json ready\n", fg="green")

    # ── Step 4: Developer token ──────────────────────────────
    click.secho("  Step 4: Google Ads Developer Token\n", fg="white", bold=True)
    if DEV_TOKEN:
        click.secho("  ✓ GOOGLE_ADS_DEVELOPER_TOKEN is set", fg="green")
    else:
        click.echo("  ⚠  Developer tokens are created from a MANAGER (MCC) account,")
        click.echo("     NOT from your regular Google Ads account.\n")
        click.echo("  If you don't have a manager account yet:")
        click.echo("    1. Go to:")
        click.secho("       https://ads.google.com/intl/en/home/tools/manager-accounts/", fg="blue")
        click.echo("    2. Create a manager account (free, takes 2 minutes)")
        click.echo("    3. Link your Google Ads account(s) to it")
        click.echo("    4. Then go to API Center in the manager account:\n")
        click.echo("  The developer token controls your API access level:\n")
        click.echo("    ┌──────────────────────────────────────────────────────────┐")
        click.echo("    │  TEST ACCOUNT TOKEN  (instant, no approval needed)      │")
        click.echo("    │  • Works immediately for test accounts only             │")
        click.echo("    │  • Cannot access real production accounts               │")
        click.echo("    │                                                         │")
        click.echo("    │  BASIC ACCESS  (apply, usually approved in 1-3 days)    │")
        click.echo("    │  • Campaign management, reporting, audience management  │")
        click.echo("    │  • Most commands in this CLI work with Basic Access     │")
        click.echo("    │                                                         │")
        click.echo("    │  STANDARD ACCESS  (apply, may take weeks for approval)  │")
        click.echo("    │  • Required for: Keyword Planner, Keyword Forecasting,  │")
        click.echo("    │    Reach Planner, Content API, Bidding strategies API   │")
        click.echo("    │  • Google reviews your API usage before granting        │")
        click.echo("    └──────────────────────────────────────────────────────────┘\n")
        click.echo("  To get your developer token:")
        click.echo("    1. Log into your MANAGER account (not your regular ads account)")
        click.echo("    2. Go to:")
        click.secho("       https://ads.google.com/aw/apicenter", fg="blue")
        click.echo("    3. If you see 'Apply for Basic Access' → click it and wait")
        click.echo("    4. Copy your developer token once it shows 'Approved'\n")
        click.secho("  ℹ  If you need Keyword Planner commands, apply for Standard", fg="cyan")
        click.secho("     Access after getting Basic. Google may take 1-4 weeks.\n", fg="cyan")
        token = click.prompt("  Paste your developer token (or press Enter to skip)", default="", show_default=False)
        if token.strip():
            _append_env(env_path, "GOOGLE_ADS_DEVELOPER_TOKEN", token.strip())
            click.secho("  ✓ Developer token saved to .env", fg="green")
        else:
            click.secho("  ⚠ Skipped — add GOOGLE_ADS_DEVELOPER_TOKEN to .env later", fg="yellow")
    click.echo()

    # ── Step 5: Customer ID ──────────────────────────────────
    click.secho("  Step 5: Google Ads Customer ID\n", fg="white", bold=True)
    if CUSTOMER_ID:
        click.secho(f"  ✓ GOOGLE_ADS_CUSTOMER_ID is set", fg="green")
    else:
        click.echo("  Find your customer ID:")
        click.echo("    1. Log into Google Ads: https://ads.google.com")
        click.echo("    2. Your account ID is shown at the top (XXX-XXX-XXXX)")
        click.echo("    3. Enter it below WITHOUT dashes (10 digits)\n")
        cid = click.prompt("  Customer ID (10 digits, no dashes)", default="", show_default=False)
        if cid.strip():
            clean_cid = cid.strip().replace("-", "").replace(" ", "")
            if len(clean_cid) == 10 and clean_cid.isdigit():
                _append_env(env_path, "GOOGLE_ADS_CUSTOMER_ID", clean_cid)
                click.secho("  ✓ Customer ID saved to .env", fg="green")
            else:
                click.secho(f"  ⚠ '{cid}' doesn't look like a 10-digit ID — add manually to .env", fg="yellow")
        else:
            click.secho("  ⚠ Skipped — add GOOGLE_ADS_CUSTOMER_ID to .env later", fg="yellow")
    click.echo()

    # ── Step 6: Manager account ─────────────────────────────
    click.secho("  Step 6: Manager Account ID\n", fg="white", bold=True)
    if LOGIN_CUSTOMER_ID:
        click.secho(f"  ✓ GOOGLE_ADS_LOGIN_CUSTOMER_ID is set", fg="green")
    else:
        click.echo("  This is the manager (MCC) account where your developer token")
        click.echo("  was created. It's REQUIRED if you created an MCC in Step 4.")
        click.echo("  Find it at the top of your manager account in Google Ads.\n")
        mcc = click.prompt("  Manager customer ID, 10 digits (or Enter to skip)", default="", show_default=False)
        if mcc.strip():
            clean_mcc = mcc.strip().replace("-", "").replace(" ", "")
            if len(clean_mcc) == 10 and clean_mcc.isdigit():
                _append_env(env_path, "GOOGLE_ADS_LOGIN_CUSTOMER_ID", clean_mcc)
                click.secho("  ✓ Manager ID saved to .env", fg="green")
            else:
                click.secho(f"  ⚠ '{mcc}' doesn't look like a 10-digit ID — add manually to .env", fg="yellow")
        else:
            click.secho("  ⚠ Skipped — if API calls fail with auth errors, set this", fg="yellow")
    click.echo()

    # ── Step 7: Optional services ────────────────────────────
    click.secho("  Step 7: Optional Services\n", fg="white", bold=True)

    if not MERCHANT_CENTER_ID:
        click.echo("  Merchant Center ID (for product management):")
        click.echo("  Find it at: https://merchants.google.com → Settings → Account\n")
        mc_id = click.prompt("  Merchant Center ID (or Enter to skip)", default="", show_default=False)
        if mc_id.strip():
            _append_env(env_path, "GOOGLE_MERCHANT_CENTER_ID", mc_id.strip())
            click.secho("  ✓ Merchant Center ID saved", fg="green")
    else:
        click.secho("  ✓ GOOGLE_MERCHANT_CENTER_ID is set", fg="green")

    click.echo()

    if not GA4_PROPERTY_ID:
        click.echo("  GA4 Property ID (for analytics reporting):")
        click.echo("  Find it at: GA4 → Admin → Property Settings → Property ID\n")
        ga4 = click.prompt("  GA4 Property ID (or Enter to skip)", default="", show_default=False)
        if ga4.strip():
            _append_env(env_path, "GOOGLE_GA4_PROPERTY_ID", ga4.strip())
            click.secho("  ✓ GA4 Property ID saved", fg="green")
    else:
        click.secho("  ✓ GOOGLE_GA4_PROPERTY_ID is set", fg="green")

    click.echo()

    # ── Step 8: Timezone & Currency ────────────────────────────
    click.secho("  Step 8: Timezone & Currency\n", fg="white", bold=True)
    click.echo(f"  Current timezone: {TZ_NAME}")
    click.echo("  Use IANA format (e.g. America/New_York, Europe/London, Asia/Dubai)\n")
    tz = click.prompt("  Timezone (or Enter to keep current)", default=TZ_NAME, show_default=False)
    if tz.strip() and tz.strip() != TZ_NAME:
        _append_env(env_path, "GADS_TIMEZONE", tz.strip())
        click.secho(f"  ✓ Timezone set to {tz.strip()}", fg="green")
    click.echo()

    click.echo(f"  Current currency: {CURRENCY}")
    click.echo("  Use ISO 4217 code (e.g. USD, AED, EUR, GBP)\n")
    cur = click.prompt("  Currency (or Enter to keep current)", default=CURRENCY, show_default=False)
    if cur.strip().upper() and cur.strip().upper() != CURRENCY:
        _append_env(env_path, "GADS_CURRENCY", cur.strip().upper())
        click.secho(f"  ✓ Currency set to {cur.strip().upper()}", fg="green")
    click.echo()

    # ── Step 9: OAuth login ──────────────────────────────────
    click.secho("  Step 9: Authenticate with Google\n", fg="white", bold=True)
    if CREDS_PATH.exists():
        click.secho("  ✓ OAuth token exists", fg="green")
        reauth = click.confirm("  Re-authenticate anyway?", default=False)
        if not reauth:
            click.echo()
            _finish_setup()
            return

    click.echo("  Opening browser for Google sign-in...")
    click.echo("  You'll be asked to grant access to Google Ads, Business Profile,")
    click.echo("  Merchant Center, and Google Analytics.\n")

    _do_oauth_login(client_secret, CREDS_PATH)

    click.echo()
    _finish_setup()


@auth.command("login")
@click.option("--port", type=int, default=9090, help="Local OAuth callback port.")
@click.option("--force", is_flag=True, help="Re-authenticate even if token exists.")
@click.option("--allow-partial", is_flag=True,
              help="Replace the token even if scopes are missing or lost. "
                   "DESTRUCTIVE — only for deliberate downgrades.")
def auth_login(port, force, allow_partial):
    """Authenticate with Google (OAuth browser flow)."""
    client_secret = CREDS_PATH.parent / "client_secret.json"

    if not client_secret.exists():
        click.secho(f"✗ client_secret.json not found at {client_secret}", fg="red", err=True)
        click.echo("\n  To get it:")
        click.echo("    1. Go to https://console.cloud.google.com/apis/credentials")
        click.echo("    2. Create an OAuth 2.0 Client ID (Desktop app)")
        click.echo("    3. Download the JSON and save as:")
        click.secho(f"       {client_secret}", fg="yellow")
        click.echo("\n  Or run 'gads auth setup' for the full guided wizard.")
        raise SystemExit(1)

    if CREDS_PATH.exists() and not force:
        click.secho("  Token already exists. Use --force to re-authenticate.", fg="yellow")
        click.echo(f"  Token: {CREDS_PATH}")
        return

    _do_oauth_login(client_secret, CREDS_PATH, port=port, allow_partial=allow_partial)


@auth.command("revoke")
@click.confirmation_option(prompt="This will delete your OAuth token. Continue?")
def auth_revoke():
    """Revoke and delete the stored OAuth token."""
    if CREDS_PATH.exists():
        # Try to revoke with Google first
        try:
            import json as _json
            import requests as _requests
            with open(CREDS_PATH) as f:
                token_data = _json.load(f)
            token = token_data.get("token", "")
            if token:
                resp = _requests.post(
                    "https://oauth2.googleapis.com/revoke",
                    params={"token": token},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp.status_code == 200:
                    click.secho("  ✓ Token revoked with Google", fg="green")
                else:
                    click.secho("  ⚠ Could not revoke with Google (token may be expired)", fg="yellow")
        except Exception:
            pass

        CREDS_PATH.unlink()
        click.secho(f"  ✓ Deleted {CREDS_PATH}", fg="green")
    else:
        click.echo("  No token to revoke.")


def _svc_probe_detail(e):
    """Render a service-probe exception as a short results-table detail string.

    `get_credentials()` and the HTTP error-routing layer (`request_json()`)
    raise `SystemExit` (not a plain `Exception`) for missing credentials and
    classified API errors respectively. `str(SystemExit(5))` is just the exit
    code ("5"), which is useless in a results table, so it is special-cased
    here. The detailed diagnostic message was already printed to stderr by
    the layer that raised it.
    """
    if isinstance(e, SystemExit):
        return f"API/auth error (exit code {e.code}) — see message above for detail"
    return str(e)[:100]


@auth.command("test")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def auth_test(as_json):
    """Test API access for all configured services."""
    results = []

    # Test Google Ads
    if CUSTOMER_ID and DEV_TOKEN:
        try:
            creds = get_credentials()
            rows = run_gaql(creds, "SELECT customer.id FROM customer LIMIT 1")
            results.append({"service": "Google Ads", "status": "ok", "detail": f"Customer {CUSTOMER_ID} accessible"})
        except (Exception, SystemExit) as e:
            results.append({"service": "Google Ads", "status": "fail", "detail": _svc_probe_detail(e)})
    else:
        results.append({"service": "Google Ads", "status": "skip", "detail": "CUSTOMER_ID or DEV_TOKEN not set"})

    # Test GBP
    try:
        creds = get_credentials()
        accts = gbp_list_accounts(creds)
        count = len(accts) if isinstance(accts, list) else 0
        results.append({"service": "Google Business Profile", "status": "ok", "detail": f"{count} account(s) found"})
    except (Exception, SystemExit) as e:
        msg = _svc_probe_detail(e)
        if "403" in msg:
            results.append({"service": "Google Business Profile", "status": "fail", "detail": "403 — re-run 'gads auth login --force' to add scope"})
        else:
            results.append({"service": "Google Business Profile", "status": "fail", "detail": msg})

    # Test Merchant Center
    if MERCHANT_CENTER_ID:
        try:
            creds = get_credentials()
            mc_get_account(creds)
            results.append({"service": "Merchant Center", "status": "ok", "detail": f"Account {MERCHANT_CENTER_ID} accessible"})
        except (Exception, SystemExit) as e:
            results.append({"service": "Merchant Center", "status": "fail", "detail": _svc_probe_detail(e)})
    else:
        results.append({"service": "Merchant Center", "status": "skip", "detail": "GOOGLE_MERCHANT_CENTER_ID not set"})

    # Test GA4
    if GA4_PROPERTY_ID:
        try:
            creds = get_credentials()
            ga4_get_metadata(creds, GA4_PROPERTY_ID)
            results.append({"service": "GA4", "status": "ok", "detail": f"Property {GA4_PROPERTY_ID} accessible"})
        except (Exception, SystemExit) as e:
            msg = _svc_probe_detail(e)
            if "403" in msg:
                results.append({"service": "GA4", "status": "fail", "detail": "403 — enable Analytics API or re-run 'gads auth login --force'"})
            else:
                results.append({"service": "GA4", "status": "fail", "detail": msg})
    else:
        results.append({"service": "GA4", "status": "skip", "detail": "GOOGLE_GA4_PROPERTY_ID not set"})

    # Test Search Console
    try:
        creds = get_credentials()
        sites = gsc_list_sites(creds)
        count = len(sites.get("siteEntry", []))
        results.append({"service": "Search Console", "status": "ok", "detail": f"{count} site(s) found"})
    except (Exception, SystemExit) as e:
        msg = _svc_probe_detail(e)
        if "403" in msg or "insufficient" in msg.lower():
            results.append({"service": "Search Console", "status": "fail", "detail": "403 — re-run 'gads auth login --force' to add webmasters scope"})
        else:
            results.append({"service": "Search Console", "status": "fail", "detail": msg})

    if as_json:
        print_json(results)
        return

    click.secho("\n  API Access Test\n", fg="white", bold=True)
    print_table(results, ["service", "status", "detail"])
    failures = [r for r in results if r["status"] == "fail"]
    if failures:
        click.echo()
        click.secho("  Tip: Run 'gads auth login --force' to re-authenticate with all scopes.", fg="yellow")
        raise SystemExit(1)


# ── Auth helpers ─────────────────────────────────────────────


def _append_env(env_path, key, value):
    """Append or update a key in the .env file."""
    lines = []
    found = False
    if env_path.exists():
        with open(env_path) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"# {key}="):
                lines[i] = f"{key}={value}\n"
                found = True
                break
    if not found:
        lines.append(f"{key}={value}\n")
    with open(env_path, "w") as f:
        f.writelines(lines)


def _do_oauth_login(client_secret_path, token_output_path, port=9090, allow_partial=False):
    """Run the OAuth browser flow and save the token."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    SCOPES = [
        "https://www.googleapis.com/auth/adwords",
        "https://www.googleapis.com/auth/business.manage",
        "https://www.googleapis.com/auth/content",
        "https://www.googleapis.com/auth/analytics.readonly",
        "https://www.googleapis.com/auth/webmasters.readonly",
    ]

    import json as _json

    scope_names = {
        "https://www.googleapis.com/auth/adwords": "Google Ads",
        "https://www.googleapis.com/auth/business.manage": "Business Profile",
        "https://www.googleapis.com/auth/content": "Merchant Center",
        "https://www.googleapis.com/auth/analytics.readonly": "GA4 Analytics",
        "https://www.googleapis.com/auth/analytics.edit": "GA4 Analytics (edit)",
        "https://www.googleapis.com/auth/webmasters.readonly": "Search Console",
    }

    token_output_path.parent.mkdir(parents=True, exist_ok=True)

    # ── read what we already hold, BEFORE touching anything ──────────────────
    # Re-authentication used to be destructive: the new token was written first
    # and its scopes checked afterwards, with a missing scope only printed in red.
    # A partially-granted consent therefore silently destroyed working access.
    # That is a real risk now that Google gates the `adwords` scope behind a
    # passkey (rolled out 2026-08-05) whose trust can lag ~7 days -- a user with a
    # perfectly good pre-existing token could re-auth, fail to get `adwords`, and
    # be left unable to reach Google Ads at all.
    prior_scopes, prior_refresh = set(), None
    if token_output_path.exists():
        try:
            _prior = _json.loads(token_output_path.read_text())
            prior_scopes = set(_prior.get("scopes") or [])
            prior_refresh = _prior.get("refresh_token")
        except Exception:
            click.secho("  ! existing token is unreadable; treating as absent", fg="yellow")

    backup_path = None
    if token_output_path.exists():
        from datetime import datetime as _dt
        backup_path = token_output_path.with_suffix(
            token_output_path.suffix + f".bak.{_dt.now():%Y%m%d_%H%M%S}")
        shutil.copy2(token_output_path, backup_path)
        click.secho(f"  ✓ existing token backed up → {backup_path.name}", fg="cyan")

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secret_path), SCOPES)

    click.echo(f"  Listening on port {port} for OAuth callback...")
    try:
        creds = flow.run_local_server(port=port, prompt="consent", access_type="offline")
    except Exception as e:
        click.secho(f"\n  ✗ OAuth flow failed: {e}", fg="red", err=True)
        click.echo(f"  Make sure no other process is using port {port}.")
        click.echo("  You can also try: gads auth login --port 8888")
        click.secho("  Your existing token was NOT modified.", fg="green")
        raise SystemExit(1)

    # ── validate BEFORE committing ───────────────────────────────────────────
    granted = set(creds.scopes or [])
    click.echo("  Scopes granted:")
    for scope in SCOPES:
        name = scope_names.get(scope, scope)
        mark, colour = ("✓", "green") if scope in granted else ("✗", "red")
        click.secho(f"    {mark} {name}", fg=colour)

    missing = [s for s in SCOPES if s not in granted]
    regressed = sorted(prior_scopes - granted)
    problems = []
    if missing:
        problems.append(f"{len(missing)} requested scope(s) not granted")
    if regressed:
        problems.append(f"{len(regressed)} scope(s) LOST vs the existing token")
    if not creds.refresh_token:
        problems.append("no refresh_token issued (offline access not granted)")

    if problems and not allow_partial:
        click.secho("\n  ✗ REFUSING TO REPLACE THE EXISTING TOKEN", fg="red", bold=True)
        for p in problems:
            click.secho(f"      - {p}", fg="red")
        for s in regressed:
            click.secho(f"      lost: {scope_names.get(s, s)}", fg="red")
        rejected = token_output_path.with_suffix(token_output_path.suffix + ".rejected")
        rejected.write_text(creds.to_json())
        click.secho(f"\n  Your working token is untouched: {token_output_path}", fg="green")
        click.echo(f"  The rejected token was saved for inspection: {rejected.name}")
        if regressed:
            click.echo("\n  A scope going backwards usually means consent was only")
            click.echo("  partially approved. Since 2026-08-05 Google requires a passkey")
            click.echo("  to authorise the Google Ads (adwords) scope, and a new passkey")
            click.echo("  can take ~7 days to become trusted. Existing refresh tokens keep")
            click.echo("  working throughout — so doing nothing is usually correct.")
        click.echo("\n  To override deliberately: gads auth login --force --allow-partial")
        raise SystemExit(1)

    if problems and allow_partial:
        click.secho("\n  ! --allow-partial: replacing despite " + "; ".join(problems),
                    fg="yellow", bold=True)

    # ── commit atomically ────────────────────────────────────────────────────
    tmp = token_output_path.with_suffix(token_output_path.suffix + ".tmp")
    tmp.write_text(creds.to_json())
    tmp.replace(token_output_path)
    click.secho(f"  ✓ Token saved to {token_output_path}", fg="green")
    if prior_refresh and creds.refresh_token != prior_refresh:
        click.secho("  note: refresh_token was rotated; the old one is in the backup",
                    fg="cyan")


def _finish_setup():
    """Print final setup summary."""
    click.secho("  ╔══════════════════════════════════════════╗", fg="green")
    click.secho("  ║         Setup Complete!                  ║", fg="green")
    click.secho("  ╚══════════════════════════════════════════╝\n", fg="green")
    click.echo("  Next steps:")
    click.echo("    1. Run:  gads doctor        — verify configuration")
    click.echo("    2. Run:  gads auth test     — test API access")
    click.echo("    3. Run:  gads query \"SELECT customer.id FROM customer\"")
    click.echo("    4. Run:  gads refresh       — populate local database")
    click.echo()


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def doctor(as_json):
    """Run local CLI readiness checks."""
    sibling_path = shutil.which("mads")
    sibling_cli = {
        "name": "mads",
        "installed": sibling_path is not None,
        "path": sibling_path,
    }

    checks = [
        {"check": "scope", "status": "ok", "detail": f"{SCOPE_TYPE} → {SCOPE_ROOT}"},
        {"check": "credentials", "status": "ok" if CREDS_PATH.exists() else "fail", "detail": str(CREDS_PATH)},
        {"check": "database", "status": "ok" if DB_PATH.exists() else "fail", "detail": str(DB_PATH)},
        {"check": "developer_token", "status": "ok" if DEV_TOKEN else "fail", "detail": "set" if DEV_TOKEN else "missing — set GOOGLE_ADS_DEVELOPER_TOKEN"},
        {"check": "customer_id", "status": "ok" if CUSTOMER_ID else "fail", "detail": "set" if CUSTOMER_ID else "missing — set GOOGLE_ADS_CUSTOMER_ID"},
        {"check": "login_customer_id", "status": "ok" if LOGIN_CUSTOMER_ID else "warn", "detail": "set" if LOGIN_CUSTOMER_ID else "missing (optional for non-MCC)"},
        {"check": "merchant_center_id", "status": "ok" if MERCHANT_CENTER_ID else "warn", "detail": "set" if MERCHANT_CENTER_ID else "missing (optional)"},
        {"check": "ga4_property_id", "status": "ok" if GA4_PROPERTY_ID else "warn", "detail": "set" if GA4_PROPERTY_ID else "missing (optional)"},
        {"check": "timezone", "status": "ok", "detail": TZ_NAME},
        {"check": "currency", "status": "ok", "detail": CURRENCY},
        {"check": "sibling_cli", "status": "ok" if sibling_cli["installed"] else "warn", "detail": sibling_path or "mads not found on PATH"},
    ]

    if as_json:
        print_json({"checks": checks, "sibling_cli": sibling_cli})
        return

    click.secho("\n  gads doctor\n", fg="white", bold=True)
    print_table(checks, ["check", "status", "detail"])
    click.echo()
    click.echo(f"  sibling_cli (mads-cli): installed={sibling_cli['installed']} path={sibling_cli['path']}")
    failures = [c for c in checks if c["status"] == "fail"]
    if failures:
        raise SystemExit(1)


# ── Google Ads commands ──────────────────────────────────────


@cli.command()
@click.argument("gaql")
@click.option("--limit", "-l", type=int, default=None, help="Max rows.")
@click.option("--json", "as_json", is_flag=True)
def query(gaql, limit, as_json):
    """Run a GAQL query against the Google Ads API."""
    creds = get_credentials()
    results = run_gaql(creds, gaql)
    if limit:
        results = results[:limit]
    if as_json:
        print_json(results)
        return
    if not results:
        click.echo("  (no results)")
        return
    flat_rows = [flatten(r) for r in results]
    print_table(flat_rows)
    click.echo(f"\n  {len(flat_rows)} row(s)")


@cli.command()
@click.argument("action")
@click.argument("details")
@click.option("--reason", "-r", default="")
@click.option("--campaign", "-c", default="")
@click.option("--campaign-id", default="")
@click.option("--agent", default="claude-code")
@click.option("--snapshot-ref", default="")
@click.option("--script", default="")
@click.option("--json", "as_json", is_flag=True)
def log(action, details, reason, campaign, campaign_id, agent, snapshot_ref, script, as_json):
    """Log an action to the changelog (append-only)."""
    import json as _json
    ts = now_local()
    conn = get_db()
    raw = {"timestamp": ts, "action": action, "campaign": campaign,
           "campaign_id": campaign_id, "details": details, "reason": reason,
           "agent": agent, "snapshot_ref": snapshot_ref, "script": script}
    try:
        conn.execute(
            """INSERT INTO changelog
            (timestamp, action, campaign, campaign_id, details, reason, agent, snapshot_ref, script, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, action, campaign, campaign_id, details, reason, agent, snapshot_ref, script, _json.dumps(raw)),
        )
        conn.commit()
        if as_json:
            print_json({"logged": True, "timestamp": ts, "action": action, "details": details})
        else:
            click.secho(f"✓ Logged: {action} at {ts}", fg="green")
    finally:
        conn.close()


@cli.command()
@click.argument("name")
@click.option("--save-file", is_flag=True, help="Also save JSON to snapshots/ directory.")
@click.option("--json", "as_json", is_flag=True)
def snapshot(name, save_file, as_json):
    """Snapshot current campaign configs from the API."""
    import json as _json
    creds = get_credentials()
    gaql = """
    SELECT campaign.name, campaign.id, campaign.status,
           campaign.advertising_channel_type, campaign_budget.amount_micros,
           campaign.bidding_strategy_type,
           campaign.target_cpa.target_cpa_micros, campaign.target_roas.target_roas,
           campaign.maximize_conversions.target_cpa_micros,
           campaign.maximize_conversion_value.target_roas
    FROM campaign WHERE campaign.status != 'REMOVED' ORDER BY campaign.name
    """
    if not as_json:
        click.echo("Fetching campaign configs from API...")
    results = run_gaql(creds, gaql)
    configs = []
    for r in results:
        camp = r.get("campaign", {})
        budget = r.get("campaignBudget", {})
        configs.append({
            "campaign_name": camp.get("name", ""), "campaign_id": camp.get("id", ""),
            "status": camp.get("status", ""), "channel_type": camp.get("advertisingChannelType", ""),
            "budget": int(budget.get("amountMicros", 0)) / 1_000_000,
            "bidding_strategy": camp.get("biddingStrategyType", ""),
            "target_cpa": extract_target_cpa(camp),
            "target_roas": extract_target_roas(camp),
        })

    if not as_json:
        click.echo(f"  Got {len(configs)} campaigns")
    conn = get_db()
    today = today_local()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ts}_{name}.json"

    for cfg in configs:
        conn.execute(
            """INSERT OR REPLACE INTO campaign_config
            (snapshot_date, campaign_name, campaign_id, channel_type, status,
             budget, bidding_strategy, target_cpa, target_roas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (today, cfg["campaign_name"], cfg["campaign_id"], cfg["channel_type"],
             cfg["status"], cfg["budget"], cfg["bidding_strategy"],
             cfg["target_cpa"], cfg["target_roas"]),
        )
    conn.execute(
        "INSERT OR REPLACE INTO snapshots (filename, date, time, description, related_action, platform) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (filename, today, datetime.now().strftime("%H:%M:%S"), name, "", "google_ads"),
    )
    conn.commit()
    conn.close()

    written_path = None
    if save_file:
        SNAPSHOTS_DIR.mkdir(exist_ok=True)
        filepath = SNAPSHOTS_DIR / filename
        with open(filepath, "w") as f:
            _json.dump({"name": name, "date": today, "campaigns": configs}, f, indent=2)
        written_path = str(filepath)

    if as_json:
        print_json({"saved": True, "name": name, "date": today, "count": len(configs),
                    "db_record": filename, "file": written_path, "campaigns": configs})
        return
    click.secho(f"✓ Saved {len(configs)} configs (date={today})", fg="green")
    if written_path:
        click.secho(f"✓ Written: {written_path}", fg="green")


@cli.command()
@click.option("--days", "-d", type=int, default=7)
@click.option("--campaign", "-c", default=None)
@click.option("--json", "as_json", is_flag=True)
def perf(days, campaign, as_json):
    """Performance summary from the local database."""
    conn = get_db()
    date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    date_to = today_local()

    where = "WHERE date >= ? AND date <= ?"
    params = [date_from, date_to]
    if campaign:
        where += " AND campaign_name LIKE ?"
        params.append(f"%{campaign}%")

    q_daily = f"""
    SELECT date, SUM(impressions) AS impressions, SUM(clicks) AS clicks,
           SUM(conversions) AS conversions, SUM(cost) AS cost,
           CASE WHEN SUM(conversions)>0 THEN SUM(cost)/SUM(conversions) END AS cpa,
           CASE WHEN SUM(impressions)>0 THEN CAST(SUM(clicks) AS REAL)/SUM(impressions)*100 END AS ctr,
           CASE WHEN SUM(clicks)>0 THEN SUM(conversions)/CAST(SUM(clicks) AS REAL)*100 END AS cvr
    FROM daily_performance {where} GROUP BY date ORDER BY date
    """
    daily_rows = [dict(r) for r in conn.execute(q_daily, params).fetchall()]

    q_camp = f"""
    SELECT campaign_name, SUM(impressions) AS impressions, SUM(clicks) AS clicks,
           SUM(conversions) AS conversions, SUM(cost) AS cost,
           CASE WHEN SUM(conversions)>0 THEN SUM(cost)/SUM(conversions) END AS cpa,
           CASE WHEN SUM(impressions)>0 THEN CAST(SUM(clicks) AS REAL)/SUM(impressions)*100 END AS ctr,
           CASE WHEN SUM(clicks)>0 THEN SUM(conversions)/CAST(SUM(clicks) AS REAL)*100 END AS cvr
    FROM daily_performance {where} GROUP BY campaign_name ORDER BY SUM(conversions) DESC
    """
    camp_rows = [dict(r) for r in conn.execute(q_camp, params).fetchall()]
    conn.close()

    if as_json:
        print_json({"period": f"{date_from} to {date_to}", "daily": daily_rows, "by_campaign": camp_rows})
        return

    cols = ["date", "impressions", "clicks", "conversions", "cost", "cpa", "ctr", "cvr"]
    click.secho(f"\n  Performance: {date_from} → {date_to}\n", fg="white", bold=True)
    click.secho("  Daily:", bold=True)
    print_table(daily_rows, cols)
    click.echo()
    click.secho("  By Campaign:", bold=True)
    print_table(camp_rows, ["campaign_name"] + cols[1:])


@cli.command()
@click.option("--json", "as_json", is_flag=True)
@click.option("--from-db", is_flag=True)
def config(as_json, from_db):
    """Show current campaign configurations."""
    if from_db:
        conn = get_db()
        row = conn.execute("SELECT MAX(snapshot_date) FROM campaign_config").fetchone()
        snap_date = row[0] if row else None
        if not snap_date:
            click.secho("✗ No snapshots. Run: gads snapshot <name>", fg="red", err=True)
            raise SystemExit(1)
        rows = conn.execute(
            "SELECT * FROM campaign_config WHERE snapshot_date = ? ORDER BY campaign_name",
            (snap_date,),
        ).fetchall()
        configs = [dict(r) for r in rows]
        conn.close()
    else:
        creds = get_credentials()
        gaql = """
        SELECT campaign.name, campaign.id, campaign.status,
               campaign.advertising_channel_type, campaign_budget.amount_micros,
               campaign.bidding_strategy_type,
               campaign.target_cpa.target_cpa_micros, campaign.target_roas.target_roas,
               campaign.maximize_conversions.target_cpa_micros,
               campaign.maximize_conversion_value.target_roas
        FROM campaign WHERE campaign.status != 'REMOVED' ORDER BY campaign.name
        """
        results = run_gaql(creds, gaql)
        configs = []
        for r in results:
            camp = r.get("campaign", {})
            budget = r.get("campaignBudget", {})
            configs.append({
                "campaign_name": camp.get("name", ""), "status": camp.get("status", ""),
                "channel_type": camp.get("advertisingChannelType", ""),
                "budget": int(budget.get("amountMicros", 0)) / 1_000_000,
                "bidding_strategy": camp.get("biddingStrategyType", ""),
                "target_cpa": extract_target_cpa(camp),
                "target_roas": extract_target_roas(camp),
            })
    if as_json:
        print_json(configs)
        return
    click.secho("\n  Campaign Configurations\n", fg="white", bold=True)
    print_table(configs, ["campaign_name", "status", "channel_type", "budget", "bidding_strategy", "target_cpa", "target_roas"])
    click.echo(f"\n  {len(configs)} campaign(s)")


@cli.command()
@click.option("--days", "-d", type=int, default=3)
@click.option("--config", "with_config", is_flag=True)
@click.option("--push", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def refresh(days, with_config, push, as_json):
    """Pull fresh data from the API into the local database."""
    date_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    date_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    if not as_json:
        click.echo(f"Fetching: {date_from} → {date_to}")
    creds = get_credentials()

    q = f"""
    SELECT segments.date, campaign.name, campaign.id, campaign.status,
           campaign.advertising_channel_type, metrics.cost_micros,
           metrics.conversions, metrics.clicks, metrics.impressions,
           metrics.conversions_value, metrics.all_conversions, metrics.interactions
    FROM campaign WHERE segments.date BETWEEN '{date_from}' AND '{date_to}'
    ORDER BY segments.date, campaign.name
    """
    results = run_gaql(creds, q)
    rows = []
    for r in results:
        seg, camp, m = r.get("segments", {}), r.get("campaign", {}), r.get("metrics", {})
        rows.append((
            seg.get("date", ""), camp.get("name", ""), camp.get("id", ""),
            camp.get("advertisingChannelType", ""), camp.get("status", ""),
            int(m.get("impressions", 0)), int(m.get("clicks", 0)),
            float(m.get("conversions", 0)), int(m.get("costMicros", 0)) / 1_000_000,
            float(m.get("conversionsValue", 0)), float(m.get("allConversions", 0)),
            int(m.get("interactions", 0)),
        ))

    conn = get_db()
    for row in rows:
        conn.execute(
            """INSERT OR REPLACE INTO daily_performance
            (date, campaign_name, campaign_id, channel_type, status,
             impressions, clicks, conversions, cost, conv_value,
             all_conversions, interactions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", row)
    conn.commit()
    if not as_json:
        click.secho(f"  ✓ {len(rows)} rows updated", fg="green")
    config_updated = False

    if with_config:
        cfg_q = """
        SELECT campaign.name, campaign.id, campaign.status,
               campaign.advertising_channel_type, campaign_budget.amount_micros,
               campaign.bidding_strategy_type,
               campaign.target_cpa.target_cpa_micros, campaign.target_roas.target_roas,
               campaign.maximize_conversions.target_cpa_micros,
               campaign.maximize_conversion_value.target_roas
        FROM campaign WHERE campaign.status != 'REMOVED' ORDER BY campaign.name
        """
        today = today_local()
        for r in run_gaql(creds, cfg_q):
            camp, budget = r.get("campaign", {}), r.get("campaignBudget", {})
            conn.execute(
                """INSERT OR REPLACE INTO campaign_config
                (snapshot_date, campaign_name, campaign_id, channel_type, status,
                 budget, bidding_strategy, target_cpa, target_roas)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (today, camp.get("name", ""), camp.get("id", ""),
                 camp.get("advertisingChannelType", ""), camp.get("status", ""),
                 int(budget.get("amountMicros", 0)) / 1_000_000,
                 camp.get("biddingStrategyType", ""),
                 extract_target_cpa(camp),
                 extract_target_roas(camp)))
        conn.commit()
        config_updated = True
        if not as_json:
            click.secho("  ✓ Campaign configs updated", fg="green")
    conn.close()

    pushed = False
    if push:
        os.chdir(str(PROJECT_ROOT))
        subprocess.run(["git", "add", str(DB_PATH)], check=True)
        subprocess.run(["git", "commit", "-m", f"data: refresh {date_from} to {date_to}"], check=False)
        subprocess.run(["git", "pull", "--rebase"], check=False)
        subprocess.run(["git", "push"], check=False)
        pushed = True
        if not as_json:
            click.secho("  ✓ Git sync done", fg="green")

    if as_json:
        print_json({"refreshed": True, "date_from": date_from, "date_to": date_to,
                    "rows_updated": len(rows), "config_updated": config_updated, "pushed": pushed})


# ── GBP commands ─────────────────────────────────────────────

@gbp.command("accounts")
@click.option("--json", "as_json", is_flag=True)
def gbp_accounts(as_json):
    """List accessible Business Profile accounts."""
    enforce_allowed_caller()
    data = gbp_list_accounts(get_credentials(), as_json=as_json)
    accounts = data.get("accounts", [])
    if as_json: return print_json(accounts)
    rows = [{"name": a.get("name",""), "account_name": a.get("accountName",""),
             "type": a.get("type",""), "role": a.get("role","")} for a in accounts]
    print_table(rows, ["name", "account_name", "type", "role"])

@gbp.command("locations")
@click.option("--account", "account_name", required=True)
@click.option("--json", "as_json", is_flag=True)
def gbp_locations(account_name, as_json):
    """List locations for an account."""
    enforce_allowed_caller()
    data = gbp_list_locations(get_credentials(), account_name,
        read_mask="name,title,storeCode,phoneNumbers,websiteUri,languageCode,storefrontAddress,metadata",
        as_json=as_json)
    locations = data.get("locations", [])
    if as_json: return print_json(locations)
    rows = []
    for loc in locations:
        phone = ((loc.get("phoneNumbers") or {}).get("primaryPhone")) or ""
        addr = ((loc.get("storefrontAddress") or {}).get("addressLines") or [""])
        rows.append({"name": loc.get("name",""), "title": loc.get("title",""),
                     "phone": phone, "website": loc.get("websiteUri",""),
                     "address": ", ".join(a for a in addr if a)})
    print_table(rows, ["name", "title", "phone", "website", "address"])

@gbp.command("location")
@click.argument("location_name")
@click.option("--read-mask", "read_mask", default=None,
              help="Comma-separated Location fields to return, overriding the default set. "
                   "Fields outside the default are only returned when named here, e.g. "
                   "'name,title,categories,openInfo,latlng'.")
@click.option("--json", "as_json", is_flag=True)
def gbp_location(location_name, read_mask, as_json):
    """Get one location detail."""
    enforce_allowed_caller()
    data = gbp_get_location(get_credentials(), location_name,
        read_mask=read_mask or "name,title,storeCode,phoneNumbers,websiteUri,regularHours,specialHours,serviceArea,storefrontAddress,metadata,profile,labels,languageCode",
        as_json=as_json)
    if as_json: return print_json(data)
    rows = [{"field": k, "value": v} for k, v in data.items() if not isinstance(v, (dict, list))]
    print_table(rows, ["field", "value"])

@gbp.command("reviews")
@click.argument("location_name")
@click.option("--account", "account_name", default=None,
              help="Account resource name (accounts/ID). Auto-resolved if omitted.")
@click.option("--limit", type=int, default=None,
              help="Stop after this many reviews (default: fetch all, following pagination).")
@click.option("--json", "as_json", is_flag=True)
def gbp_reviews(location_name, account_name, limit, as_json):
    """List reviews for a location."""
    enforce_allowed_caller()
    data = gbp_list_reviews(get_credentials(), location_name, account_name=account_name,
                             limit=limit, as_json=as_json)
    reviews = data.get("reviews", [])
    if as_json: return print_json(data)
    total = data.get("totalReviewCount", len(reviews))
    avg = data.get("averageRating", "")
    summary = f"  {len(reviews)} review(s), averageRating {avg}, totalReviewCount {total}"
    if not data.get("complete", True) and limit is None:
        summary += "  ⚠ INCOMPLETE FETCH — pagination stopped early"
    click.secho(summary, bold=True)
    rows = [{"name": r.get("name",""), "reviewer": ((r.get("reviewer") or {}).get("displayName")) or "",
             "stars": r.get("starRating",""),
             "comment": (r.get("comment","")[:80]+"…") if len(r.get("comment",""))>80 else r.get("comment",""),
             "reply": ((r.get("reviewReply") or {}).get("comment")) or "",
             "updated": r.get("updateTime","")} for r in reviews]
    print_table(rows, ["name", "reviewer", "stars", "comment", "reply", "updated"])


@gbp.command("batch-reviews")
@click.argument("location_names", nargs=-1, required=True)
@click.option("--account", "account_name", default=None,
              help="Account resource name (accounts/ID). Auto-resolved per location if omitted.")
@click.option("--limit", type=int, default=None,
              help="Stop after this many reviews per location (default: fetch all).")
@click.option("--json", "as_json", is_flag=True)
def gbp_batch_reviews_cmd(location_names, account_name, limit, as_json):
    """Fetch reviews from multiple locations at once."""
    enforce_allowed_caller()
    data = gbp_batch_get_reviews(get_credentials(), account_name, list(location_names),
                                  limit=limit, as_json=as_json)
    if as_json:
        return print_json(data)
    for loc, payload in data.items():
        reviews = payload.get("reviews", [])
        total = payload.get("totalReviewCount", len(reviews))
        avg = payload.get("averageRating", "")
        header = f"\n  {loc} — {len(reviews)} review(s), averageRating {avg}, totalReviewCount {total}"
        if not payload.get("complete", True) and limit is None:
            header += "  ⚠ INCOMPLETE FETCH — pagination stopped early"
        click.secho(header, bold=True)
        rows = [{"reviewer": ((r.get("reviewer") or {}).get("displayName")) or "",
                 "stars": r.get("starRating", ""),
                 "comment": (r.get("comment", "")[:60] + "…") if len(r.get("comment", "")) > 60 else r.get("comment", ""),
                 "updated": r.get("updateTime", "")} for r in reviews]
        if rows:
            print_table(rows, ["reviewer", "stars", "comment", "updated"])


@gbp.command("local-posts")
@click.option("--account", "account_name", required=True, help="Account resource name (accounts/ID).")
@click.option("--location", "location_id", required=True, help="Location ID (numeric).")
@click.option("--json", "as_json", is_flag=True)
def gbp_local_posts_cmd(account_name, location_id, as_json):
    """List local posts for a GBP location."""
    enforce_allowed_caller()
    data = gbp_list_local_posts(get_credentials(), account_name, location_id, as_json=as_json)
    posts = data.get("localPosts", [])
    if as_json:
        return print_json(posts)
    rows = [{"name": p.get("name", "").split("/")[-1],
             "state": p.get("state", ""),
             "topic_type": p.get("topicType", ""),
             "summary": (p.get("summary", "")[:60] + "…") if len(p.get("summary", "")) > 60 else p.get("summary", ""),
             "created": p.get("createTime", "")} for p in posts]
    print_table(rows, ["name", "state", "topic_type", "summary", "created"])


@gbp.command("create-post")
@click.option("--account", "account_name", required=True, help="Account resource name (accounts/ID).")
@click.option("--location", "location_id", required=True, help="Location ID (numeric).")
@click.option("--summary", required=True, help="Post text (required).")
@click.option("--topic-type", default="STANDARD", help="Post type: STANDARD, EVENT, OFFER, ALERT.")
@click.option("--call-to-action-url", "cta_url", default=None, help="URL for the CTA button.")
@click.option("--call-to-action-type", "cta_type", default=None, help="CTA type: LEARN_MORE, BOOK, ORDER, BUY, SIGN_UP, CALL.")
@click.option("--dry-run", is_flag=True, help="Show what would be sent without creating.")
@click.option("--json", "as_json", is_flag=True)
def gbp_create_post_cmd(account_name, location_id, summary, topic_type, cta_url, cta_type, dry_run, as_json):
    """Create a local post for a GBP location. [WRITE — not live-mutation-verified]"""
    enforce_allowed_caller()
    body = {"summary": summary, "topicType": topic_type.upper()}
    if cta_url and cta_type:
        body["callToAction"] = {"actionType": cta_type.upper(), "url": cta_url}
    if dry_run:
        if as_json:
            return print_json({"dry_run": True, "body": body})
        click.secho(f"  DRY RUN: would POST to accounts/{account_name}/locations/{location_id}/localPosts", fg="yellow")
        click.echo(f"  Body: {body}")
        return
    data = gbp_create_local_post(get_credentials(), account_name, location_id, body, as_json=as_json)
    if as_json:
        return print_json(data)
    click.secho(f"  Created post: {data.get('name', '')}", fg="green")


@gbp.command("delete-post")
@click.option("--account", "account_name", required=True, help="Account resource name (accounts/ID).")
@click.option("--location", "location_id", required=True, help="Location ID (numeric).")
@click.argument("post_id")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.option("--json", "as_json", is_flag=True)
def gbp_delete_post_cmd(account_name, location_id, post_id, yes, as_json):
    """Delete a local post. [WRITE — not live-mutation-verified]"""
    enforce_allowed_caller()
    if not yes:
        click.confirm(f"  Delete local post {post_id}?", abort=True)
    data = gbp_delete_local_post(get_credentials(), account_name, location_id, post_id, as_json=as_json)
    if as_json:
        return print_json(data or {"deleted": True, "post_id": post_id})
    click.secho(f"  Deleted post {post_id}", fg="green")


@gbp.command("reply-review")
@click.argument("review_name")
@click.argument("comment")
@click.option("--account", "account_name", default=None,
              help="Account resource name (accounts/ID). Auto-resolved if omitted.")
def gbp_reply_review_cmd(review_name, comment, account_name):
    """Reply to a review."""
    enforce_allowed_caller()
    print_json(gbp_reply_review(get_credentials(), review_name, comment, account_name=account_name))

@gbp.command("delete-reply")
@click.argument("review_name")
@click.option("--account", "account_name", default=None,
              help="Account resource name (accounts/ID). Auto-resolved if omitted.")
def gbp_delete_reply_cmd(review_name, account_name):
    """Delete a review reply."""
    enforce_allowed_caller()
    gbp_delete_reply(get_credentials(), review_name, account_name=account_name)
    click.secho(f"✓ Reply deleted", fg="green")


# ── GBP Performance commands ─────────────────────────────────

DEFAULT_PERF_METRICS = "BUSINESS_DIRECTION_REQUESTS,CALL_CLICKS,WEBSITE_CLICKS"


def _normalize_location(loc):
    """Prepend 'locations/' if only an ID is provided."""
    if not loc.startswith("locations/"):
        loc = f"locations/{loc}"
    return loc


def _today_date():
    """Today as a date object in the configured timezone."""
    from zoneinfo import ZoneInfo
    from .config import TZ_NAME
    return datetime.now(ZoneInfo(TZ_NAME)).date()


@gbp.command("perf")
@click.option("-l", "--location", required=True, help="Location ID or full name.")
@click.option("-d", "--days", default=14, help="Days to look back.")
@click.option("-m", "--metrics", default=DEFAULT_PERF_METRICS, help="Comma-separated daily metrics.")
@click.option("--json", "as_json", is_flag=True)
def gbp_perf(location, days, metrics, as_json):
    """Daily performance metrics for a GBP location."""
    enforce_allowed_caller()
    creds = get_credentials()
    loc = _normalize_location(location)
    metric_list = [m.strip() for m in metrics.split(",")]
    end = _today_date() - timedelta(days=1)
    start = end - timedelta(days=days - 1)

    data = gbp_multi_daily_metrics(creds, loc, metric_list, start, end)
    if as_json:
        return print_json(data)

    all_dates = set()
    for vals in data.values():
        for v in vals:
            all_dates.add(v["date"])

    rows = []
    for d in sorted(all_dates):
        row = {"date": d}
        for m in metric_list:
            vals = {v["date"]: v["value"] for v in data.get(m, [])}
            row[m[:20]] = vals.get(d, 0)
        rows.append(row)

    cols = ["date"] + [m[:20] for m in metric_list]
    print_table(rows, cols)


@gbp.command("perf-all")
@click.option("-d", "--days", default=14, help="Days to look back.")
@click.option("-m", "--metrics", default=DEFAULT_PERF_METRICS, help="Comma-separated daily metrics.")
@click.option("--json", "as_json", is_flag=True)
def gbp_perf_all(days, metrics, as_json):
    """Daily performance metrics for ALL GBP locations."""
    enforce_allowed_caller()
    creds = get_credentials()
    metric_list = [m.strip() for m in metrics.split(",")]
    end = _today_date() - timedelta(days=1)
    start = end - timedelta(days=days - 1)

    accts = gbp_list_accounts(creds, as_json=as_json)
    all_results = {}
    for acct in accts.get("accounts", []):
        if acct.get("type") != "LOCATION_GROUP":
            continue
        locs = gbp_list_locations(creds, acct["name"], read_mask="name,title", as_json=as_json)
        for loc in locs.get("locations", []):
            title = loc.get("title", loc["name"])
            click.echo(f"  Fetching {title}...", err=True)
            data = gbp_multi_daily_metrics(creds, loc["name"], metric_list, start, end)
            all_results[title] = data

    if as_json:
        return print_json(all_results)

    all_dates = set()
    for loc_data in all_results.values():
        for vals in loc_data.values():
            for v in vals:
                all_dates.add(v["date"])

    loc_names = list(all_results.keys())
    # Create short unique names for columns
    short_names = {}
    for name in loc_names:
        # Extract the location suffix (e.g. "Al Quoz", "Sajaa", "Industrial Area 4")
        parts = name.replace("Talas Tesla Auto Parts - ", "").replace("Talas Tesla Auto Parts", "")
        short_names[name] = parts.strip() or name[:15]

    for metric in metric_list:
        click.secho(f"\n  {metric}", fg="white", bold=True)
        rows = []
        for d in sorted(all_dates):
            row = {"date": d}
            total = 0
            for loc_title in loc_names:
                vals = {v["date"]: v["value"] for v in all_results[loc_title].get(metric, [])}
                v = vals.get(d, 0)
                row[short_names[loc_title]] = v
                total += v
            row["TOTAL"] = total
            rows.append(row)
        cols = ["date"] + [short_names[t] for t in loc_names] + ["TOTAL"]
        print_table(rows, cols)


@gbp.command("search-keywords")
@click.option("-l", "--location", required=True, help="Location ID or full name.")
@click.option("--months", default=3, help="Months to look back.")
@click.option("--limit", default=50, help="Max keywords.")
@click.option("--json", "as_json", is_flag=True)
def gbp_search_keywords(location, months, limit, as_json):
    """Monthly search keyword impressions for a GBP location."""
    enforce_allowed_caller()
    creds = get_credentials()
    loc = _normalize_location(location)
    now = _today_date()
    end_month = (now.year, now.month)
    start_y, start_m = now.year, now.month - months + 1
    while start_m < 1:
        start_m += 12
        start_y -= 1
    keywords = gbp_search_keywords_monthly(creds, loc, (start_y, start_m), end_month, page_size=limit, as_json=as_json)
    if as_json:
        return print_json(keywords)
    print_table(keywords[:limit], ["keyword", "impressions"])


@gbp.command("metrics-list")
def gbp_metrics_list():
    """List all available GBP daily metrics."""
    for m in DAILY_METRICS:
        click.echo(f"  {m}")


@gbp.command("ads-perf")
@click.option("-d", "--days", default=30, type=click.IntRange(1, 90), help="Lookback days (default 30)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def gbp_ads_perf(days, as_json):
    """Location asset performance in Google Ads (per-branch breakdown).

    Shows how each GBP location performs as a location extension
    across all campaigns. Matches the Ads UI Asset Report > Associations > Location view.
    """
    enforce_allowed_caller()
    creds = get_credentials()

    # Find the active LOCATION_SYNC asset set
    sets = run_gaql(creds, """
        SELECT asset_set.id, asset_set.name
        FROM asset_set
        WHERE asset_set.type = LOCATION_SYNC
          AND asset_set.status = ENABLED
    """)
    if not sets:
        click.secho("✗ No active LOCATION_SYNC asset set found", fg="red")
        raise SystemExit(1)
    asset_set_id = sets[0]["assetSet"]["id"]

    end = _today_date() - timedelta(days=1)
    start = end - timedelta(days=days - 1)

    rows = run_gaql(creds, f"""
        SELECT asset.location_asset.place_id,
               asset.location_asset.business_profile_locations,
               metrics.clicks, metrics.impressions, metrics.cost_micros,
               metrics.conversions, metrics.all_conversions
        FROM asset_set_asset
        WHERE asset_set.id = {asset_set_id}
          AND segments.date BETWEEN "{start}" AND "{end}"
        ORDER BY metrics.clicks DESC
    """)

    if as_json:
        click.echo(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    if not rows:
        click.echo("  No location asset data found.")
        return

    result_rows = []
    for r in rows:
        m = r["metrics"]
        loc = r.get("asset", {}).get("locationAsset", {})
        bpl = loc.get("businessProfileLocations", [])
        code = bpl[0].get("storeCode", "?") if bpl else loc.get("placeId", "?")[:12]
        clicks = int(m.get("clicks", 0))
        impr = int(m.get("impressions", 0))
        cost = int(m.get("costMicros", 0)) / 1e6
        ctr = (clicks / impr * 100) if impr > 0 else 0
        avg_cpc = (cost / clicks) if clicks > 0 else 0
        conv = float(m.get("conversions", 0))
        allconv = float(m.get("allConversions", 0))
        result_rows.append({
            "location": code,
            "clicks": clicks,
            "impr": impr,
            "ctr": f"{ctr:.2f}%",
            "avg_cpc": f"{CURRENCY}{avg_cpc:.2f}",
            "cost": f"{CURRENCY}{cost:.2f}",
            "conv": f"{conv:.0f}",
            "all_conv": f"{allconv:.0f}",
        })

    print_table(result_rows, ["location", "clicks", "impr", "ctr", "avg_cpc", "cost", "conv", "all_conv"])


@gbp.command("ads-daily")
@click.option("-d", "--days", default=14, type=click.IntRange(1, 90), help="Lookback days (default 14)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
def gbp_ads_daily(days, as_json):
    """Daily location asset performance in Google Ads (per-branch per-day).

    Shows daily clicks, impressions, cost for each GBP location as ad extension.
    """
    enforce_allowed_caller()
    creds = get_credentials()

    sets = run_gaql(creds, """
        SELECT asset_set.id
        FROM asset_set
        WHERE asset_set.type = LOCATION_SYNC
          AND asset_set.status = ENABLED
    """)
    if not sets:
        click.secho("✗ No active LOCATION_SYNC asset set found", fg="red")
        raise SystemExit(1)
    asset_set_id = sets[0]["assetSet"]["id"]

    end = _today_date() - timedelta(days=1)
    start = end - timedelta(days=days - 1)

    rows = run_gaql(creds, f"""
        SELECT asset.location_asset.business_profile_locations,
               segments.date,
               metrics.clicks, metrics.impressions, metrics.cost_micros,
               metrics.conversions
        FROM asset_set_asset
        WHERE asset_set.id = {asset_set_id}
          AND segments.date BETWEEN "{start}" AND "{end}"
        ORDER BY segments.date DESC
    """)

    if as_json:
        click.echo(json.dumps(rows, indent=2, ensure_ascii=False))
        return

    if not rows:
        click.echo("  No data found.")
        return

    # Group by date → location
    from collections import defaultdict
    by_date = defaultdict(dict)
    locations = set()
    for r in rows:
        m = r["metrics"]
        bpl = r.get("asset", {}).get("locationAsset", {}).get("businessProfileLocations", [])
        code = bpl[0].get("storeCode", "?") if bpl else "?"
        locations.add(code)
        d = r["segments"]["date"]
        by_date[d][code] = {
            "clicks": int(m.get("clicks", 0)),
            "impr": int(m.get("impressions", 0)),
            "cost": int(m.get("costMicros", 0)) / 1e6,
            "conv": float(m.get("conversions", 0)),
        }

    locations = sorted(locations)
    result_rows = []
    for d in sorted(by_date.keys()):
        row = {"date": d}
        total_clk = total_cost = total_conv = 0
        for loc in locations:
            data = by_date[d].get(loc, {})
            clk = data.get("clicks", 0)
            cost = data.get("cost", 0)
            conv = data.get("conv", 0)
            row[loc] = clk
            total_clk += clk
            total_cost += cost
            total_conv += conv
        row["total_clk"] = total_clk
        row[f"cost_{CURRENCY}"] = f"{total_cost:.2f}"
        row["conv"] = f"{total_conv:.0f}"
        result_rows.append(row)

    cols = ["date"] + locations + ["total_clk", f"cost_{CURRENCY}", "conv"]
    print_table(result_rows, cols)


# ── Search Console commands ──────────────────────────────────

@cli.group()
def gsc():
    """Google Search Console commands."""
    pass


@gsc.command("sites")
@click.option("--json", "as_json", is_flag=True)
def gsc_sites_cmd(as_json):
    """List verified Search Console sites."""
    enforce_allowed_caller()
    data = gsc_list_sites(get_credentials(), as_json=as_json)
    sites = data.get("siteEntry", [])
    if as_json:
        return print_json(sites)
    rows = [{"url": s.get("siteUrl", ""), "level": s.get("permissionLevel", "")} for s in sites]
    print_table(rows, ["url", "level"])


@gsc.command("queries")
@click.option("-s", "--site", required=True, help="Site URL (e.g. https://shop.talas.ae/).")
@click.option("-d", "--days", default=28, help="Days to look back.")
@click.option("--limit", default=25, help="Max rows.")
@click.option("--json", "as_json", is_flag=True)
def gsc_queries_cmd(site, days, limit, as_json):
    """Top search queries from Search Console."""
    enforce_allowed_caller()
    creds = get_credentials()
    end = (_today_date() - timedelta(days=3)).strftime("%Y-%m-%d")
    start = (_today_date() - timedelta(days=days)).strftime("%Y-%m-%d")
    data = gsc_search_analytics(creds, site, start, end, dimensions=["query"], row_limit=limit, as_json=as_json)
    rows_raw = data.get("rows", [])
    if as_json:
        return print_json(rows_raw)
    rows = [{"query": r["keys"][0], "clicks": int(r.get("clicks", 0)),
             "impressions": int(r.get("impressions", 0)),
             "ctr": f"{r.get('ctr', 0) * 100:.1f}%",
             "position": f"{r.get('position', 0):.1f}"} for r in rows_raw]
    print_table(rows, ["query", "clicks", "impressions", "ctr", "position"])


@gsc.command("pages")
@click.option("-s", "--site", required=True, help="Site URL.")
@click.option("-d", "--days", default=28, help="Days to look back.")
@click.option("--limit", default=25, help="Max rows.")
@click.option("--json", "as_json", is_flag=True)
def gsc_pages_cmd(site, days, limit, as_json):
    """Top pages from Search Console."""
    enforce_allowed_caller()
    creds = get_credentials()
    end = (_today_date() - timedelta(days=3)).strftime("%Y-%m-%d")
    start = (_today_date() - timedelta(days=days)).strftime("%Y-%m-%d")
    data = gsc_search_analytics(creds, site, start, end, dimensions=["page"], row_limit=limit, as_json=as_json)
    rows_raw = data.get("rows", [])
    if as_json:
        return print_json(rows_raw)
    rows = [{"page": r["keys"][0], "clicks": int(r.get("clicks", 0)),
             "impressions": int(r.get("impressions", 0)),
             "ctr": f"{r.get('ctr', 0) * 100:.1f}%",
             "position": f"{r.get('position', 0):.1f}"} for r in rows_raw]
    print_table(rows, ["page", "clicks", "impressions", "ctr", "position"])


@gsc.command("performance")
@click.option("-s", "--site", required=True, help="Site URL.")
@click.option("-d", "--days", default=28, help="Days to look back.")
@click.option("--json", "as_json", is_flag=True)
def gsc_perf_cmd(site, days, as_json):
    """Daily performance from Search Console."""
    enforce_allowed_caller()
    creds = get_credentials()
    end = (_today_date() - timedelta(days=3)).strftime("%Y-%m-%d")
    start = (_today_date() - timedelta(days=days)).strftime("%Y-%m-%d")
    data = gsc_search_analytics(creds, site, start, end, dimensions=["date"], row_limit=1000, as_json=as_json)
    rows_raw = data.get("rows", [])
    if as_json:
        return print_json(rows_raw)
    rows = [{"date": r["keys"][0], "clicks": int(r.get("clicks", 0)),
             "impressions": int(r.get("impressions", 0)),
             "ctr": f"{r.get('ctr', 0) * 100:.1f}%",
             "position": f"{r.get('position', 0):.1f}"}
            for r in sorted(rows_raw, key=lambda x: x["keys"][0])]
    print_table(rows, ["date", "clicks", "impressions", "ctr", "position"])


@gsc.command("sitemaps")
@click.option("-s", "--site", required=True, help="Site URL (e.g. https://shop.talas.ae/).")
@click.option("--json", "as_json", is_flag=True)
def gsc_sitemaps_cmd(site, as_json):
    """List submitted sitemaps for a Search Console property."""
    enforce_allowed_caller()
    data = gsc_list_sitemaps(get_credentials(), site, as_json=as_json)
    sitemaps = data.get("sitemap", [])
    if as_json:
        return print_json(sitemaps)
    rows = [{"path": s.get("path", ""), "last_submitted": s.get("lastSubmitted", ""),
             "type": s.get("type", ""), "is_index": s.get("isSitemapIndex", False),
             "warnings": s.get("warnings", "0"), "errors": s.get("errors", "0")} for s in sitemaps]
    print_table(rows, ["path", "last_submitted", "type", "is_index", "warnings", "errors"])


@gsc.command("inspect")
@click.argument("url")
@click.option("-s", "--site", required=True, help="Verified Search Console property URL.")
@click.option("--lang", default="en-US", help="Language code (default en-US).")
@click.option("--json", "as_json", is_flag=True)
def gsc_inspect_cmd(url, site, lang, as_json):
    """Inspect a URL's index status via Search Console URL Inspection API."""
    enforce_allowed_caller()
    data = gsc_url_inspect(get_credentials(), url, site, language_code=lang, as_json=as_json)
    if as_json:
        return print_json(data)
    result = data.get("inspectionResult", {})
    index = result.get("indexStatusResult", {})
    click.secho(f"\n  URL Inspection: {url}\n", bold=True)
    fields = [
        ("verdict", index.get("verdict", "")),
        ("coverage_state", index.get("coverageState", "")),
        ("indexing_state", index.get("indexingState", "")),
        ("page_fetch_state", index.get("pageFetchState", "")),
        ("robots_txt_state", index.get("robotsTxtState", "")),
        ("last_crawl", index.get("lastCrawlTime", "")),
        ("crawled_as", index.get("crawledAs", "")),
        ("canonical_google", index.get("googleCanonical", "")),
        ("canonical_user", index.get("userCanonical", "")),
        ("mobile_usability", (result.get("mobileUsabilityResult") or {}).get("verdict", "")),
    ]
    rows = [{"field": k, "value": v} for k, v in fields if v]
    print_table(rows, ["field", "value"])


# ── Merchant commands ────────────────────────────────────────

@merchant.command("account")
@click.option("--json", "as_json", is_flag=True)
def merchant_account(as_json):
    """Account info."""
    enforce_allowed_caller()
    data = mc_get_account(get_credentials(), as_json=as_json)
    if as_json: return print_json(data)
    rows = [{"field": k, "value": v} for k, v in data.items() if not isinstance(v, (dict, list))]
    print_table(rows, ["field", "value"])

@merchant.command("status")
@click.option("--json", "as_json", is_flag=True)
def merchant_status(as_json):
    """Account issues."""
    enforce_allowed_caller()
    data = mc_get_account_status(get_credentials(), as_json=as_json)
    if as_json: return print_json(data)
    issues = data.get("accountIssues", [])
    if not issues: return click.secho("  No issues.", fg="green")
    rows = [{"id": (i.get("name","").split("/")[-1] if i.get("name") else ""),
             "severity": i.get("severity",""), "title": i.get("title",""),
             "detail": (i.get("detail","")[:80]+"…") if len(i.get("detail",""))>80 else i.get("detail","")}
            for i in issues]
    print_table(rows, ["id", "severity", "title", "detail"])

@merchant.command("products")
@click.option("--limit", "-l", type=int, default=20)
@click.option("--json", "as_json", is_flag=True)
def merchant_products(limit, as_json):
    """List products."""
    enforce_allowed_caller()
    data = mc_list_products(get_credentials(), max_results=limit, as_json=as_json)
    products = data.get("products", [])
    if as_json: return print_json(products)
    def _price(attrs):
        pr = attrs.get("price") or {}
        micros = pr.get("amountMicros")
        if micros in (None, ""):
            return ""
        try:
            return f"{int(micros)/1_000_000:.2f} {pr.get('currencyCode','')}".strip()
        except (TypeError, ValueError):
            return f"{micros} {pr.get('currencyCode','')}".strip()
    rows = []
    for p in products:
        attrs = p.get("productAttributes") or {}
        title = attrs.get("title","")
        rows.append({"id": p.get("offerId",""),
                     "title": (title[:50]+"…") if len(title)>50 else title,
                     "availability": attrs.get("availability",""),
                     "price": _price(attrs)})
    print_table(rows, ["id", "title", "availability", "price"])

@merchant.command("product-status")
@click.option("--limit", "-l", type=int, default=20)
@click.option("--json", "as_json", is_flag=True)
def merchant_product_status(limit, as_json):
    """Product approval statuses."""
    enforce_allowed_caller()
    data = mc_list_product_statuses(get_credentials(), max_results=limit, as_json=as_json)
    statuses = data.get("products", [])
    if as_json: return print_json(statuses)
    rows = []
    for s in statuses:
        attrs = s.get("productAttributes") or {}
        status = s.get("productStatus") or {}
        title = attrs.get("title","")
        dests = status.get("destinationStatuses", [])
        rows.append({"product_id": s.get("offerId",""),
                     "title": (title[:40]+"…") if len(title)>40 else title,
                     "destinations": ", ".join(d.get("reportingContext", d.get("destination","")) for d in dests[:3]),
                     "issues": len(status.get("itemLevelIssues", []))})
    print_table(rows, ["product_id", "title", "destinations", "issues"])

@merchant.command("feeds")
@click.option("--json", "as_json", is_flag=True)
def merchant_feeds(as_json):
    """Data feeds."""
    enforce_allowed_caller()
    data = mc_list_datafeeds(get_credentials(), as_json=as_json)
    feeds = data.get("dataSources", [])
    if as_json: return print_json(feeds)
    def _ds_type(f):
        for k in ("primaryProductDataSource", "supplementalProductDataSource",
                  "localInventoryDataSource", "regionalInventoryDataSource",
                  "promotionDataSource", "merchantReviewDataSource", "productReviewDataSource"):
            if k in f:
                return k
        return f.get("input", "")
    rows = [{"id": f.get("dataSourceId",""), "name": f.get("displayName",""),
             "type": _ds_type(f), "file_name": (f.get("fileInput") or {}).get("fileName","")} for f in feeds]
    print_table(rows, ["id", "name", "type", "file_name"])

@merchant.command("shipping")
@click.option("--json", "as_json", is_flag=True)
def merchant_shipping(as_json):
    """Shipping settings."""
    enforce_allowed_caller()
    data = mc_get_shipping(get_credentials(), as_json=as_json)
    if as_json: return print_json(data)
    rows = [{"name": s.get("serviceName",""),
             "country": ", ".join(s.get("deliveryCountries", [])),
             "currency": s.get("currencyCode",""), "active": s.get("active","")} for s in data.get("services",[])]
    print_table(rows, ["name", "country", "currency", "active"])

@merchant.command("returns")
@click.option("--json", "as_json", is_flag=True)
def merchant_returns(as_json):
    """Return policy."""
    enforce_allowed_caller()
    data = mc_get_return_policy(get_credentials(), as_json=as_json)
    if as_json: return print_json(data)
    policies = data.get("onlineReturnPolicies", [])
    rows = [{"name": (p.get("name","").split("/")[-1] if p.get("name") else ""),
             "country": ", ".join(p.get("countries", [])),
             "label": p.get("label",""),
             "days": (p.get("policy") or {}).get("days", (p.get("policy") or {}).get("numberOfDays",""))} for p in policies]
    print_table(rows, ["name", "country", "label", "days"])


@merchant.command("register-gcp")
@click.option("--developer-email", "-e", required=True,
              help="Email address of the GCP project developer to register with the Merchant account.")
@click.option("--account", "account_id", default=None,
              help="Merchant Center account ID (default: MERCHANT_CENTER_ID from config).")
@click.option("--json", "as_json", is_flag=True)
def merchant_register_gcp(developer_email, account_id, as_json):
    """Register the GCP project with a Merchant Center account (fixes GCP_NOT_REGISTERED errors).

    Calls POST /accounts/v1/accounts/{account}/developerRegistration:registerGcp
    with {"developerEmail": EMAIL}.  This resolves the auth/gcp_unknown error
    that blocks merchant API reads when your GCP OAuth project has not been
    associated with the MC account.

    \\b
    Examples:
      gads merchant register-gcp --developer-email admin@example.com
      gads merchant register-gcp -e admin@example.com --account 12345678 --json

    After success: wait ~5 minutes before retrying merchant commands.
    This is a one-time setup step per GCP project + MC account pair.
    """
    enforce_allowed_caller()
    creds = get_credentials()
    effective_account = account_id or MERCHANT_CENTER_ID
    if not effective_account:
        if as_json:
            print_json({"error": {"code": "VALIDATION", "message": "No Merchant Center account ID — set GOOGLE_MERCHANT_CENTER_ID or pass --account."}})
        else:
            click.secho("  Error: No Merchant Center account ID configured.", fg="red")
            click.echo("  Set GOOGLE_MERCHANT_CENTER_ID in your .env or pass --account ACCOUNT_ID.")
        raise SystemExit(EXIT_CODES["VALIDATION"])

    data = mc_register_gcp(creds, developer_email=developer_email,
                           account_id=effective_account, as_json=as_json)

    if as_json:
        # Success: emit the API response + metadata
        return print_json({
            "status": "registered",
            "account": effective_account,
            "developer_email": developer_email,
            "response": data,
            "next_step": "Wait ~5 minutes then retry merchant commands.",
        })

    # Human-readable success
    click.secho("\n  GCP project registered with Merchant Center account.", fg="green", bold=True)
    click.echo(f"  Account:          {effective_account}")
    click.echo(f"  Developer email:  {developer_email}")
    click.secho("\n  Next step: wait ~5 minutes, then retry:", fg="yellow")
    click.echo("    gads merchant account")
    click.echo("    gads merchant status")


# ── GA4 commands ─────────────────────────────────────────────

@ga4.command("metadata")
@click.option("--property", "property_id", default=None)
@click.option("--json", "as_json", is_flag=True)
def ga4_metadata_cmd(property_id, as_json):
    """Available dimensions and metrics."""
    enforce_allowed_caller()
    data = ga4_get_metadata(get_credentials(), property_id=property_id, as_json=as_json)
    if as_json: return print_json(data)
    dims, mets = data.get("dimensions",[]), data.get("metrics",[])
    click.secho(f"\n  Dimensions: {len(dims)}   Metrics: {len(mets)}\n", bold=True)
    for d in dims[:15]: click.echo(f"    {d.get('apiName','')} — {d.get('uiName','')}")
    click.echo()
    for m in mets[:15]: click.echo(f"    {m.get('apiName','')} — {m.get('uiName','')}")

@ga4.command("report")
@click.option("--property", "property_id", default=None)
@click.option("--dimensions", "-d", default="date")
@click.option("--metrics", "-m", default="activeUsers,sessions")
@click.option("--start", "start_date", default="7daysAgo")
@click.option("--end", "end_date", default="yesterday")
@click.option("--limit", "-l", type=int, default=100)
@click.option("--json", "as_json", is_flag=True)
def ga4_report_cmd(property_id, dimensions, metrics, start_date, end_date, limit, as_json):
    """Run a GA4 report."""
    enforce_allowed_caller()
    dims = [d.strip() for d in dimensions.split(",")]
    mets = [m.strip() for m in metrics.split(",")]
    data = ga4_run_report(get_credentials(), dims, mets,
        [{"startDate": start_date, "endDate": end_date}], property_id=property_id, limit=limit, as_json=as_json)
    if as_json: return print_json(data)
    dim_h = [h.get("name","") for h in data.get("dimensionHeaders",[])]
    met_h = [h.get("name","") for h in data.get("metricHeaders",[])]
    rows = []
    for row in data.get("rows",[]):
        r = {dim_h[i]: dv.get("value","") for i, dv in enumerate(row.get("dimensionValues",[]))}
        r.update({met_h[i]: mv.get("value","") for i, mv in enumerate(row.get("metricValues",[]))})
        rows.append(r)
    print_table(rows, dim_h + met_h)
    click.echo(f"\n  {len(rows)} row(s)")

@ga4.command("realtime")
@click.option("--property", "property_id", default=None)
@click.option("--dimensions", "-d", default="country")
@click.option("--metrics", "-m", default="activeUsers")
@click.option("--json", "as_json", is_flag=True)
def ga4_realtime_cmd(property_id, dimensions, metrics, as_json):
    """Realtime report (last 30 min)."""
    enforce_allowed_caller()
    dims = [d.strip() for d in dimensions.split(",")]
    mets = [m.strip() for m in metrics.split(",")]
    data = ga4_run_realtime_report(get_credentials(), dims, mets, property_id=property_id, as_json=as_json)
    if as_json: return print_json(data)
    dim_h = [h.get("name","") for h in data.get("dimensionHeaders",[])]
    met_h = [h.get("name","") for h in data.get("metricHeaders",[])]
    rows = []
    for row in data.get("rows",[]):
        r = {dim_h[i]: dv.get("value","") for i, dv in enumerate(row.get("dimensionValues",[]))}
        r.update({met_h[i]: mv.get("value","") for i, mv in enumerate(row.get("metricValues",[]))})
        rows.append(r)
    print_table(rows, dim_h + met_h)
    click.echo(f"\n  {len(rows)} row(s)")


@ga4.command("batch-report")
@click.option("--property", "property_id", default=None)
@click.option("--requests-file", "requests_file", default=None, help="JSON file with list of report requests.")
@click.option("--json", "as_json", is_flag=True)
def ga4_batch_report_cmd(property_id, requests_file, as_json):
    """Run multiple GA4 reports in one API call (batchRunReports)."""
    enforce_allowed_caller()
    import json as _json
    if requests_file:
        with open(requests_file) as f:
            requests_list = _json.load(f)
    else:
        # Default: two reports — sessions by source, and events by date
        requests_list = [
            {"dimensions": [{"name": "sessionSource"}], "metrics": [{"name": "sessions"}],
             "dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}], "limit": 10},
            {"dimensions": [{"name": "date"}], "metrics": [{"name": "keyEvents"}],
             "dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}], "limit": 30},
        ]
    data = ga4_batch_run_reports(get_credentials(), requests_list, property_id=property_id, as_json=as_json)
    if as_json:
        return print_json(data)
    reports = data.get("reports", [])
    for i, report in enumerate(reports):
        click.secho(f"\n  Report {i+1}:", fg="white", bold=True)
        dim_h = [h.get("name", "") for h in report.get("dimensionHeaders", [])]
        met_h = [h.get("name", "") for h in report.get("metricHeaders", [])]
        rows = []
        for row in report.get("rows", []):
            r = {dim_h[j]: dv.get("value", "") for j, dv in enumerate(row.get("dimensionValues", []))}
            r.update({met_h[j]: mv.get("value", "") for j, mv in enumerate(row.get("metricValues", []))})
            rows.append(r)
        print_table(rows, dim_h + met_h)
        click.echo(f"  {len(rows)} row(s)")


@ga4.command("pivot-report")
@click.option("--property", "property_id", default=None)
@click.option("--dimensions", "-d", default="sessionSource,deviceCategory")
@click.option("--metrics", "-m", default="sessions")
@click.option("--start", "start_date", default="7daysAgo")
@click.option("--end", "end_date", default="yesterday")
@click.option("--pivot-dimension", "pivot_dim", default="deviceCategory", help="Dimension to pivot on.")
@click.option("--json", "as_json", is_flag=True)
def ga4_pivot_report_cmd(property_id, dimensions, metrics, start_date, end_date, pivot_dim, as_json):
    """Run a GA4 pivot report (cross-tabulation)."""
    enforce_allowed_caller()
    dims = [d.strip() for d in dimensions.split(",")]
    mets = [m.strip() for m in metrics.split(",")]
    pivots = [{"fieldNames": [pivot_dim], "limit": 10, "orderBys": [{"metric": {"metricName": mets[0]}, "desc": True}]}]
    data = ga4_run_pivot_report(get_credentials(), dims, mets,
        [{"startDate": start_date, "endDate": end_date}], pivots, property_id=property_id, as_json=as_json)
    if as_json:
        return print_json(data)
    rows_raw = data.get("rows", [])
    dim_h = [h.get("name", "") for h in data.get("dimensionHeaders", [])]
    met_h = [h.get("name", "") for h in data.get("metricHeaders", [])]
    rows = []
    for row in rows_raw:
        r = {dim_h[i]: dv.get("value", "") for i, dv in enumerate(row.get("dimensionValues", []))}
        r.update({met_h[i]: mv.get("value", "") for i, mv in enumerate(row.get("metricValues", []))})
        rows.append(r)
    print_table(rows, dim_h + met_h)
    click.echo(f"\n  {len(rows)} row(s)")


@ga4.command("check-compatibility")
@click.option("--property", "property_id", default=None)
@click.option("--dimensions", "-d", default="date,sessionSource")
@click.option("--metrics", "-m", default="sessions,totalRevenue")
@click.option("--json", "as_json", is_flag=True)
def ga4_check_compatibility_cmd(property_id, dimensions, metrics, as_json):
    """Check which GA4 dimension+metric combinations are compatible."""
    enforce_allowed_caller()
    dims = [d.strip() for d in dimensions.split(",")]
    mets = [m.strip() for m in metrics.split(",")]
    data = ga4_check_compatibility(get_credentials(), dims, mets, property_id=property_id, as_json=as_json)
    if as_json:
        return print_json(data)
    click.secho("\n  Dimension Compatibility\n", bold=True)
    dim_compat = data.get("dimensionCompatibilities", [])
    dim_rows = [{"dimension": (d.get("dimensionMetadata") or {}).get("apiName", ""),
                 "compatibility": d.get("compatibility", "")} for d in dim_compat]
    print_table(dim_rows, ["dimension", "compatibility"])
    click.echo()
    click.secho("  Metric Compatibility\n", bold=True)
    met_compat = data.get("metricCompatibilities", [])
    met_rows = [{"metric": (m.get("metricMetadata") or {}).get("apiName", ""),
                 "compatibility": m.get("compatibility", "")} for m in met_compat]
    print_table(met_rows, ["metric", "compatibility"])


# ── GA4 Key Events (Admin API) ───────────────────────────────

_COUNTING_CHOICES = ["once-per-session", "once-per-event"]


def _counting_to_api(value):
    """Map CLI-friendly kebab value to the API enum."""
    return {
        "once-per-session": "ONCE_PER_SESSION",
        "once-per-event": "ONCE_PER_EVENT",
    }[value]


@ga4.group("key-events")
def ga4_key_events():
    """Manage GA4 key events (conversions). Write ops need analytics.edit scope."""
    pass


@ga4_key_events.command("list")
@click.option("--property", "property_id", default=None, help="GA4 property id (default: GOOGLE_GA4_PROPERTY_ID)")
@click.option("--json", "as_json", is_flag=True)
def ga4_key_events_list_cmd(property_id, as_json):
    """List all key events on the property."""
    enforce_allowed_caller()
    events = list_key_events(property_id, get_credentials())
    if as_json:
        return print_json(events)
    rows = [
        {
            "event_name": e.get("eventName", ""),
            "counting_method": e.get("countingMethod", ""),
            "custom": e.get("custom", False),
            "create_time": e.get("createTime", ""),
        }
        for e in events
    ]
    print_table(rows, ["event_name", "counting_method", "custom", "create_time"])
    click.echo(f"\n  {len(rows)} key event(s)")


@ga4_key_events.command("create")
@click.argument("event_name")
@click.option(
    "--counting-method",
    type=click.Choice(_COUNTING_CHOICES, case_sensitive=False),
    default="once-per-session",
    show_default=True,
)
@click.option("--property", "property_id", default=None)
@click.option("--json", "as_json", is_flag=True)
def ga4_key_events_create_cmd(event_name, counting_method, property_id, as_json):
    """Mark a single event as a key event. Idempotent."""
    enforce_allowed_caller()
    cm = _counting_to_api(counting_method.lower())
    result = create_key_event(property_id, get_credentials(), event_name, counting_method=cm)
    already = result.get("_already_exists", False)
    if as_json:
        return print_json(result)
    if already:
        click.secho(f"  = {event_name} already a key event", fg="yellow")
    else:
        click.secho(f"  \u2713 {event_name} marked as key event ({cm})", fg="green")


@ga4_key_events.command("bulk")
@click.argument("event_names")
@click.option(
    "--counting-method",
    type=click.Choice(_COUNTING_CHOICES, case_sensitive=False),
    default="once-per-session",
    show_default=True,
)
@click.option("--property", "property_id", default=None)
@click.option("--json", "as_json", is_flag=True)
def ga4_key_events_bulk_cmd(event_names, counting_method, property_id, as_json):
    """Mark several events as key events in one call. EVENT_NAMES is comma-separated.

    Idempotent — existing events are reported and skipped, not errored on.
    """
    enforce_allowed_caller()
    names = [n.strip() for n in event_names.split(",") if n.strip()]
    if not names:
        click.secho("  no event names provided", fg="red", err=True)
        raise SystemExit(1)
    cm = _counting_to_api(counting_method.lower())
    creds = get_credentials()
    results = []
    for name in names:
        try:
            data = create_key_event(property_id, creds, name, counting_method=cm)
            status = "exists" if data.get("_already_exists") else "created"
            results.append({"event_name": name, "status": status, "counting_method": cm})
            if not as_json:
                tag = "=" if status == "exists" else "\u2713"
                colour = "yellow" if status == "exists" else "green"
                click.secho(f"  {tag} {name:25s} {status}", fg=colour)
        except SystemExit as exc:
            results.append({"event_name": name, "status": "error", "error": str(exc)})
            if not as_json:
                click.secho(f"  \u2717 {name:25s} {exc}", fg="red", err=True)
    if as_json:
        return print_json(results)
    created = sum(1 for r in results if r["status"] == "created")
    exists = sum(1 for r in results if r["status"] == "exists")
    errors = sum(1 for r in results if r["status"] == "error")
    click.echo(f"\n  {created} created, {exists} already existed, {errors} error(s)")


@ga4_key_events.command("delete")
@click.argument("event_name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
@click.option("--property", "property_id", default=None)
@click.option("--json", "as_json", is_flag=True)
def ga4_key_events_delete_cmd(event_name, yes, property_id, as_json):
    """Remove a key event (the underlying event keeps flowing; it just stops being a conversion)."""
    enforce_allowed_caller()
    if not yes:
        click.confirm(f"  Remove key event '{event_name}'?", abort=True)
    removed = delete_key_event(property_id, get_credentials(), event_name)
    if as_json:
        return print_json({"event_name": event_name, "removed": removed})
    if removed:
        click.secho(f"  \u2713 {event_name} removed as key event", fg="green")
    else:
        click.secho(f"  = {event_name} was not a key event (nothing to do)", fg="yellow")


# ── New command groups ───────────────────────────────────────

@cli.group()
def campaign():
    """Campaign management commands."""
    pass

@cli.group()
def adgroup():
    """Ad group management commands."""
    pass

@cli.group("ad")
def ad_group():
    """Ad management commands."""
    pass

@cli.group()
def keyword():
    """Keyword management and research."""
    pass

@cli.group("asset")
def asset_group():
    """Asset management (images, sitelinks, callouts)."""
    pass

@cli.group("conversion")
def conversion_group():
    """Conversion tracking and upload."""
    pass

@cli.group("audience")
def audience_group():
    """Audience and user list management."""
    pass

@cli.group("report")
def report_group():
    """Specialized reports (geo, hourly, devices, search terms)."""
    pass

@cli.group("data-manager")
def data_manager_group():
    """Data Manager API — modern events/audience ingestion (events:ingest, audienceMembers:ingest)."""
    pass


# ── Helpers ──────────────────────────────────────────────────

def _confirm_and_log(action, details, dry_run=False, yes=False):
    if dry_run:
        click.secho(f"  DRY RUN: {action} — {details}", fg="yellow")
        return False
    if not yes:
        click.confirm(f"  Execute: {action}?", abort=True)
    return True

def _auto_log(action, details, campaign_name="", campaign_id=""):
    """Best-effort changelog write; must never abort an already-successful mutation.

    Note: `get_db()` raises `SystemExit(1)` (not a plain `Exception`) when the
    local SQLite DB is missing — caught explicitly here alongside `Exception`
    so a missing/not-yet-initialized DB (or any other local-logging failure)
    never masks a live API mutation that already succeeded.
    """
    try:
        import json as _json
        conn = get_db()
        ts = now_local()
        raw = {"timestamp": ts, "action": action, "details": details, "campaign": campaign_name, "campaign_id": campaign_id, "agent": "gads-cli"}
        conn.execute(
            "INSERT INTO changelog (timestamp, action, campaign, campaign_id, details, reason, agent, snapshot_ref, script, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, action, campaign_name, campaign_id, details, "", "gads-cli", "", "", _json.dumps(raw)))
        conn.commit()
        conn.close()
    except (Exception, SystemExit):
        pass


# ── Campaign commands ────────────────────────────────────────

@campaign.command("list")
@click.option("--json", "as_json", is_flag=True)
def campaign_list(as_json):
    """List all campaigns with status and budget."""
    creds = get_credentials()
    results = run_gaql(creds, """
        SELECT campaign.name, campaign.id, campaign.status,
               campaign.advertising_channel_type, campaign_budget.amount_micros,
               campaign.bidding_strategy_type
        FROM campaign WHERE campaign.status != 'REMOVED' ORDER BY campaign.name""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        c, b = r.get("campaign", {}), r.get("campaignBudget", {})
        rows.append({"name": c.get("name",""), "id": c.get("id",""), "status": c.get("status",""),
                     "type": c.get("advertisingChannelType",""),
                     "budget": round(int(b.get("amountMicros",0))/1e6, 2),
                     "bidding": c.get("biddingStrategyType","")})
    print_table(rows, ["name", "id", "status", "type", "budget", "bidding"])

@campaign.command("status")
@click.argument("campaign_id")
@click.argument("status", type=click.Choice(["ENABLED", "PAUSED"], case_sensitive=False))
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def campaign_status_cmd(campaign_id, status, dry_run, yes, as_json):
    """Enable or pause a campaign."""
    enforce_allowed_caller()
    status = status.upper()
    op = {"update": {"resourceName": f"customers/{CUSTOMER_ID}/campaigns/{campaign_id}", "status": status}, "updateMask": "status"}
    if not _confirm_and_log(f"campaign {campaign_id} → {status}", f"status change", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "campaigns", [op])
    _auto_log("campaign_status", f"{campaign_id} → {status}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Campaign {campaign_id} → {status}", fg="green")

@campaign.command("budget")
@click.argument("campaign_id")
@click.argument("amount", type=float)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def campaign_budget_cmd(campaign_id, amount, dry_run, yes, as_json):
    """Change campaign daily budget."""
    enforce_allowed_caller()
    creds = get_credentials()
    # Lookup budget resource name
    results = run_gaql(creds, f"SELECT campaign.id, campaign_budget.resource_name FROM campaign WHERE campaign.id = {campaign_id}")
    if not results:
        click.secho(f"✗ Campaign {campaign_id} not found", fg="red", err=True)
        raise SystemExit(1)
    budget_rn = results[0].get("campaignBudget", {}).get("resourceName", "")
    if not budget_rn:
        click.secho("✗ No budget resource found", fg="red", err=True)
        raise SystemExit(1)
    micros = str(int(amount * 1_000_000))
    op = {"update": {"resourceName": budget_rn, "amountMicros": micros}, "updateMask": "amountMicros"}
    if not _confirm_and_log(f"budget → {amount} {CURRENCY}", f"campaign {campaign_id}", dry_run, yes):
        return
    result = ads_mutate(creds, "campaignBudgets", [op])
    _auto_log("campaign_budget", f"{campaign_id} budget → {amount} {CURRENCY}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Campaign {campaign_id} budget → {amount} {CURRENCY}", fg="green")

@campaign.command("perf")
@click.option("--days", "-d", type=int, default=7)
@click.option("--json", "as_json", is_flag=True)
def campaign_perf(days, as_json):
    """Campaign performance from API (last N days)."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    results = run_gaql(get_credentials(), f"""
        SELECT campaign.name, campaign.id, metrics.impressions, metrics.clicks,
               metrics.conversions, metrics.cost_micros, metrics.ctr,
               metrics.conversions_from_interactions_rate
        FROM campaign WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
          AND campaign.status != 'REMOVED'
        ORDER BY metrics.conversions DESC""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        c, m = r.get("campaign", {}), r.get("metrics", {})
        conv = float(m.get("conversions", 0))
        cost = int(m.get("costMicros", 0)) / 1e6
        rows.append({"name": c.get("name",""), "impr": m.get("impressions",0),
                     "clicks": m.get("clicks",0), "conv": conv,
                     "cost": round(cost, 2),
                     "cpa": round(cost/conv, 2) if conv > 0 else "—",
                     "ctr": m.get("ctr",""), "cvr": m.get("conversionsFromInteractionsRate","")})
    print_table(rows, ["name", "impr", "clicks", "conv", "cost", "cpa", "ctr", "cvr"])


# ── Ad Group commands ────────────────────────────────────────

@adgroup.command("list")
@click.option("--campaign", "-c", "campaign_id", required=True)
@click.option("--json", "as_json", is_flag=True)
def adgroup_list(campaign_id, as_json):
    """List ad groups in a campaign."""
    results = run_gaql(get_credentials(), f"""
        SELECT ad_group.name, ad_group.id, ad_group.status, ad_group.type
        FROM ad_group WHERE campaign.id = {campaign_id} ORDER BY ad_group.name""")
    if as_json:
        return print_json(results)
    rows = [{"name": r.get("adGroup",{}).get("name",""), "id": r.get("adGroup",{}).get("id",""),
             "status": r.get("adGroup",{}).get("status",""), "type": r.get("adGroup",{}).get("type","")}
            for r in results]
    print_table(rows, ["name", "id", "status", "type"])

@adgroup.command("status")
@click.argument("adgroup_id")
@click.argument("status", type=click.Choice(["ENABLED", "PAUSED"], case_sensitive=False))
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def adgroup_status_cmd(adgroup_id, status, dry_run, yes, as_json):
    """Enable or pause an ad group."""
    enforce_allowed_caller()
    status = status.upper()
    op = {"update": {"resourceName": f"customers/{CUSTOMER_ID}/adGroups/{adgroup_id}", "status": status}, "updateMask": "status"}
    if not _confirm_and_log(f"ad group {adgroup_id} → {status}", "status change", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "adGroups", [op])
    _auto_log("adgroup_status", f"{adgroup_id} → {status}")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Ad group {adgroup_id} → {status}", fg="green")

@adgroup.command("create")
@click.argument("campaign_id")
@click.argument("name")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def adgroup_create_cmd(campaign_id, name, dry_run, yes, as_json):
    """Create an ad group."""
    enforce_allowed_caller()
    op = {"create": {"campaign": f"customers/{CUSTOMER_ID}/campaigns/{campaign_id}", "name": name, "status": "ENABLED"}}
    if not _confirm_and_log(f"create ad group '{name}' in campaign {campaign_id}", "create", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "adGroups", [op])
    _auto_log("adgroup_create", f"'{name}' in campaign {campaign_id}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Created ad group '{name}'", fg="green")


# ── Ad commands ──────────────────────────────────────────────

@ad_group.command("list")
@click.option("--campaign", "-c", "campaign_id", default=None)
@click.option("--adgroup", "-a", "adgroup_id", default=None)
@click.option("--json", "as_json", is_flag=True)
def ad_list(campaign_id, adgroup_id, as_json):
    """List ads with creatives."""
    where = "WHERE ad_group_ad.status != 'REMOVED'"
    if campaign_id:
        where += f" AND campaign.id = {campaign_id}"
    if adgroup_id:
        where += f" AND ad_group.id = {adgroup_id}"
    results = run_gaql(get_credentials(), f"""
        SELECT ad_group.name, ad_group_ad.ad.id, ad_group_ad.status,
               ad_group_ad.ad.type, ad_group_ad.ad.responsive_search_ad.headlines,
               ad_group_ad.ad.responsive_search_ad.descriptions
        FROM ad_group_ad {where} ORDER BY ad_group.name""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        ag = r.get("adGroup", {})
        aga = r.get("adGroupAd", {})
        ad = aga.get("ad", {})
        rows.append({"ad_group": ag.get("name",""), "ad_id": ad.get("id",""),
                     "status": aga.get("status",""), "type": ad.get("type","")})
    print_table(rows, ["ad_group", "ad_id", "status", "type"])

@ad_group.command("status")
@click.argument("adgroup_id")
@click.argument("ad_id")
@click.argument("status", type=click.Choice(["ENABLED", "PAUSED"], case_sensitive=False))
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def ad_status_cmd(adgroup_id, ad_id, status, dry_run, yes, as_json):
    """Enable or pause an ad."""
    enforce_allowed_caller()
    status = status.upper()
    op = {"update": {"resourceName": f"customers/{CUSTOMER_ID}/adGroupAds/{adgroup_id}~{ad_id}", "status": status}, "updateMask": "status"}
    if not _confirm_and_log(f"ad {ad_id} → {status}", "status change", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "adGroupAds", [op])
    _auto_log("ad_status", f"ad {ad_id} in adgroup {adgroup_id} → {status}")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Ad {ad_id} → {status}", fg="green")

@ad_group.command("perf")
@click.option("--days", "-d", type=int, default=7)
@click.option("--campaign", "-c", "campaign_id", default=None)
@click.option("--json", "as_json", is_flag=True)
def ad_perf(days, campaign_id, as_json):
    """Ad-level performance."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    where = f"WHERE segments.date BETWEEN '{d_from}' AND '{d_to}' AND ad_group_ad.status != 'REMOVED'"
    if campaign_id:
        where += f" AND campaign.id = {campaign_id}"
    results = run_gaql(get_credentials(), f"""
        SELECT ad_group.name, ad_group_ad.ad.id, ad_group_ad.ad.type,
               metrics.impressions, metrics.clicks, metrics.conversions, metrics.cost_micros
        FROM ad_group_ad {where} ORDER BY metrics.conversions DESC""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        ag, aga, m = r.get("adGroup",{}), r.get("adGroupAd",{}).get("ad",{}), r.get("metrics",{})
        conv = float(m.get("conversions",0))
        cost = int(m.get("costMicros",0))/1e6
        rows.append({"ad_group": ag.get("name",""), "ad_id": aga.get("id",""), "type": aga.get("type",""),
                     "impr": m.get("impressions",0), "clicks": m.get("clicks",0), "conv": conv,
                     "cost": round(cost,2), "cpa": round(cost/conv,2) if conv>0 else "—"})
    print_table(rows, ["ad_group", "ad_id", "type", "impr", "clicks", "conv", "cost", "cpa"])


# ── Keyword commands ─────────────────────────────────────────

@keyword.command("list")
@click.option("--campaign", "-c", "campaign_id", required=True)
@click.option("--days", "-d", type=int, default=30)
@click.option("--json", "as_json", is_flag=True)
def keyword_list(campaign_id, days, as_json):
    """List keywords with performance."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    results = run_gaql(get_credentials(), f"""
        SELECT ad_group.name, ad_group_criterion.keyword.text,
               ad_group_criterion.keyword.match_type, ad_group_criterion.criterion_id,
               metrics.impressions, metrics.clicks, metrics.conversions, metrics.cost_micros
        FROM keyword_view WHERE campaign.id = {campaign_id}
          AND segments.date BETWEEN '{d_from}' AND '{d_to}'
        ORDER BY metrics.clicks DESC""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        ag, kw, m = r.get("adGroup",{}), r.get("adGroupCriterion",{}).get("keyword",{}), r.get("metrics",{})
        conv = float(m.get("conversions",0))
        cost = int(m.get("costMicros",0))/1e6
        rows.append({"ad_group": ag.get("name",""), "keyword": kw.get("text",""),
                     "match": kw.get("matchType",""), "impr": m.get("impressions",0),
                     "clicks": m.get("clicks",0), "conv": conv, "cost": round(cost,2),
                     "cpa": round(cost/conv,2) if conv>0 else "—"})
    print_table(rows, ["ad_group", "keyword", "match", "impr", "clicks", "conv", "cost", "cpa"])

@keyword.command("add")
@click.argument("adgroup_id")
@click.argument("text")
@click.option("--match-type", "-m", type=click.Choice(["EXACT", "PHRASE", "BROAD"], case_sensitive=False), default="PHRASE")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def keyword_add(adgroup_id, text, match_type, dry_run, yes, as_json):
    """Add a keyword to an ad group."""
    enforce_allowed_caller()
    op = {"create": {"adGroup": f"customers/{CUSTOMER_ID}/adGroups/{adgroup_id}",
                     "keyword": {"text": text, "matchType": match_type.upper()}, "status": "ENABLED"}}
    if not _confirm_and_log(f"add keyword '{text}' [{match_type}] to adgroup {adgroup_id}", "add keyword", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "adGroupCriteria", [op])
    _auto_log("keyword_add", f"'{text}' [{match_type}] → adgroup {adgroup_id}")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Added keyword '{text}' [{match_type}]", fg="green")

@keyword.command("remove")
@click.argument("adgroup_id")
@click.argument("criterion_id")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def keyword_remove(adgroup_id, criterion_id, dry_run, yes, as_json):
    """Remove a keyword from an ad group."""
    enforce_allowed_caller()
    # Tilde format for ad group criteria
    rn = f"customers/{CUSTOMER_ID}/adGroupCriteria/{adgroup_id}~{criterion_id}"
    op = {"remove": rn}
    if not _confirm_and_log(f"remove criterion {criterion_id} from adgroup {adgroup_id}", "remove keyword", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "adGroupCriteria", [op])
    _auto_log("keyword_remove", f"criterion {criterion_id} from adgroup {adgroup_id}")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Removed criterion {criterion_id}", fg="green")

@keyword.command("negative")
@click.argument("campaign_id")
@click.argument("text")
@click.option("--match-type", "-m", type=click.Choice(["EXACT", "PHRASE", "BROAD"], case_sensitive=False), default="PHRASE")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def keyword_negative(campaign_id, text, match_type, dry_run, yes, as_json):
    """Add a negative keyword to a campaign."""
    enforce_allowed_caller()
    op = {"create": {"campaign": f"customers/{CUSTOMER_ID}/campaigns/{campaign_id}",
                     "keyword": {"text": text, "matchType": match_type.upper()}, "negative": True}}
    if not _confirm_and_log(f"add negative '{text}' [{match_type}] to campaign {campaign_id}", "add negative", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "campaignCriteria", [op])
    _auto_log("keyword_negative", f"negative '{text}' [{match_type}] → campaign {campaign_id}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Added negative '{text}' [{match_type}]", fg="green")

@keyword.command("search-terms")
@click.option("--days", "-d", type=int, default=7)
@click.option("--campaign", "-c", "campaign_id", default=None)
@click.option("--min-clicks", type=int, default=0)
@click.option("--json", "as_json", is_flag=True)
def keyword_search_terms(days, campaign_id, min_clicks, as_json):
    """Search terms report."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    where = f"WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'"
    if campaign_id:
        where += f" AND campaign.id = {campaign_id}"
    if min_clicks > 0:
        where += f" AND metrics.clicks >= {min_clicks}"
    results = run_gaql(get_credentials(), f"""
        SELECT search_term_view.search_term, campaign.name,
               metrics.impressions, metrics.clicks, metrics.conversions, metrics.cost_micros
        FROM search_term_view {where} ORDER BY metrics.clicks DESC""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        st, c, m = r.get("searchTermView",{}), r.get("campaign",{}), r.get("metrics",{})
        conv = float(m.get("conversions",0))
        cost = int(m.get("costMicros",0))/1e6
        rows.append({"search_term": st.get("searchTerm",""), "campaign": c.get("name",""),
                     "impr": m.get("impressions",0), "clicks": m.get("clicks",0),
                     "conv": conv, "cost": round(cost,2),
                     "cpa": round(cost/conv,2) if conv>0 else "—"})
    print_table(rows, ["search_term", "campaign", "impr", "clicks", "conv", "cost", "cpa"])

# ISO code → Google Ads language_constant ID
# Verified live via: SELECT language_constant.id, language_constant.code FROM language_constant WHERE language_constant.code IN ('en','ar')
_LANGUAGE_IDS = {"en": "1000", "ar": "1019"}

# ISO country code → geo_target_constant ID (country-level only)
# Verified live via: SELECT geo_target_constant.id, geo_target_constant.country_code FROM geo_target_constant WHERE geo_target_constant.country_code = 'AE' AND geo_target_constant.target_type = 'Country'
_GEO_IDS = {"AE": "2784"}


def _resolve_language(value):
    """Accept an ISO code (e.g. 'en') or a raw numeric language_constant ID."""
    if value is None:
        return value
    v = str(value).strip()
    if v.isdigit():
        return v
    resolved = _LANGUAGE_IDS.get(v.lower())
    if resolved:
        return resolved
    return v  # pass through; API will return a clear error if unknown


def _resolve_geo(value):
    """Accept an ISO country code (e.g. 'AE') or a raw numeric geo_target_constant ID."""
    if value is None:
        return value
    v = str(value).strip()
    if v.isdigit():
        return v
    resolved = _GEO_IDS.get(v.upper())
    if resolved:
        return resolved
    return v  # pass through; API will return a clear error if unknown


@keyword.command("ideas")
@click.option("--keywords", "-k", default=None, help="Comma-separated seed keywords.")
@click.option("--url", "-u", default=None, help="Seed URL for ideas.")
@click.option("--language", default="1000", help="ISO code (e.g. 'en', 'ar') or numeric language_constant ID (default: 1000=English).")
@click.option("--geo", default=None, help="Comma-separated ISO country codes (e.g. 'AE') or numeric geo_target_constant IDs (e.g. 2784=UAE).")
@click.option("--json", "as_json", is_flag=True)
def keyword_ideas_cmd(keywords, url, language, geo, as_json):
    """Generate keyword ideas (requires Standard Access dev token)."""
    kw_list = [k.strip() for k in keywords.split(",")] if keywords else None
    resolved_language = _resolve_language(language)
    geo_list = [_resolve_geo(g.strip()) for g in geo.split(",")] if geo else None
    result = generate_keyword_ideas(get_credentials(), keywords=kw_list, url=url, language_id=resolved_language, geo_ids=geo_list)
    if as_json:
        return print_json(result)
    ideas = result.get("results", [])
    rows = []
    for idea in ideas[:50]:
        kw = idea.get("keywordIdeaMetrics", {})
        rows.append({"keyword": idea.get("text",""),
                     "avg_monthly": kw.get("avgMonthlySearches",""),
                     "competition": kw.get("competition",""),
                     "low_cpc": kw.get("lowTopOfPageBidMicros",""),
                     "high_cpc": kw.get("highTopOfPageBidMicros","")})
    print_table(rows, ["keyword", "avg_monthly", "competition", "low_cpc", "high_cpc"])
    click.echo(f"\n  {len(ideas)} idea(s)")

@keyword.command("forecast")
@click.option("--keywords", "-k", required=True, help="Comma-separated keywords.")
@click.option("--language", default="1000", help="ISO code (e.g. 'en', 'ar') or numeric language_constant ID (default: 1000=English).")
@click.option("--geo", default=None, help="Comma-separated ISO country codes (e.g. 'AE') or numeric geo_target_constant IDs (e.g. 2784=UAE).")
@click.option("--json", "as_json", is_flag=True)
def keyword_forecast_cmd(keywords, language, geo, as_json):
    """Keyword traffic/cost forecast (requires Standard Access dev token)."""
    kw_list = [k.strip() for k in keywords.split(",")]
    resolved_language = _resolve_language(language)
    geo_list = [_resolve_geo(g.strip()) for g in geo.split(",")] if geo else None
    result = generate_keyword_forecast(get_credentials(), keywords=kw_list, language_id=resolved_language, geo_ids=geo_list)
    if as_json:
        return print_json(result)
    print_json(result)


# ── Asset commands ───────────────────────────────────────────

@asset_group.command("list")
@click.option("--type", "asset_type", default=None, help="Filter by type (IMAGE, SITELINK, etc).")
@click.option("--json", "as_json", is_flag=True)
def asset_list(asset_type, as_json):
    """List assets."""
    where = "WHERE asset.type != 'UNSPECIFIED'"
    if asset_type:
        where += f" AND asset.type = '{asset_type.upper()}'"
    results = run_gaql(get_credentials(), f"""
        SELECT asset.id, asset.name, asset.type, asset.resource_name
        FROM asset {where} ORDER BY asset.type, asset.name""")
    if as_json:
        return print_json(results)
    rows = [{"id": r.get("asset",{}).get("id",""), "name": r.get("asset",{}).get("name",""),
             "type": r.get("asset",{}).get("type","")} for r in results]
    print_table(rows, ["id", "name", "type"])

@asset_group.command("sitelink")
@click.argument("campaign_id")
@click.option("--link-text", required=True)
@click.option("--desc1", default="")
@click.option("--desc2", default="")
@click.option("--url", required=True)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def asset_sitelink(campaign_id, link_text, desc1, desc2, url, dry_run, yes, as_json):
    """Add a sitelink to a campaign (two-step: create asset + link)."""
    enforce_allowed_caller()
    if not _confirm_and_log(f"add sitelink '{link_text}' → {url} to campaign {campaign_id}", "sitelink", dry_run, yes):
        return
    creds = get_credentials()
    # Step 1: Create the sitelink asset — finalUrls at top level, NOT inside sitelinkAsset
    asset_op = {"create": {"sitelinkAsset": {"linkText": link_text, "description1": desc1, "description2": desc2}, "finalUrls": [url]}}
    asset_result = ads_mutate(creds, "assets", [asset_op])
    asset_rn = asset_result.get("results", [{}])[0].get("resourceName", "")
    if not asset_rn:
        click.secho("✗ Failed to create sitelink asset", fg="red", err=True)
        raise SystemExit(1)
    # Step 2: Link to campaign
    link_op = {"create": {"asset": asset_rn, "campaign": f"customers/{CUSTOMER_ID}/campaigns/{campaign_id}", "fieldType": "SITELINK"}}
    result = ads_mutate(creds, "campaignAssets", [link_op])
    _auto_log("asset_sitelink", f"'{link_text}' → campaign {campaign_id}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Sitelink '{link_text}' added to campaign {campaign_id}", fg="green")

@asset_group.command("callout")
@click.argument("campaign_id")
@click.option("--text", required=True)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def asset_callout(campaign_id, text, dry_run, yes, as_json):
    """Add a callout extension to a campaign."""
    enforce_allowed_caller()
    if not _confirm_and_log(f"add callout '{text}' to campaign {campaign_id}", "callout", dry_run, yes):
        return
    creds = get_credentials()
    asset_op = {"create": {"calloutAsset": {"calloutText": text}}}
    asset_result = ads_mutate(creds, "assets", [asset_op])
    asset_rn = asset_result.get("results", [{}])[0].get("resourceName", "")
    link_op = {"create": {"asset": asset_rn, "campaign": f"customers/{CUSTOMER_ID}/campaigns/{campaign_id}", "fieldType": "CALLOUT"}}
    result = ads_mutate(creds, "campaignAssets", [link_op])
    _auto_log("asset_callout", f"'{text}' → campaign {campaign_id}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Callout '{text}' added", fg="green")

@asset_group.command("call")
@click.argument("campaign_id")
@click.option("--phone", required=True)
@click.option("--country-code", default="US")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def asset_call(campaign_id, phone, country_code, dry_run, yes, as_json):
    """Add a call extension to a campaign."""
    enforce_allowed_caller()
    if not _confirm_and_log(f"add call {phone} ({country_code}) to campaign {campaign_id}", "call ext", dry_run, yes):
        return
    creds = get_credentials()
    asset_op = {"create": {"callAsset": {"phoneNumber": phone, "countryCode": country_code.upper()}}}
    asset_result = ads_mutate(creds, "assets", [asset_op])
    asset_rn = asset_result.get("results", [{}])[0].get("resourceName", "")
    link_op = {"create": {"asset": asset_rn, "campaign": f"customers/{CUSTOMER_ID}/campaigns/{campaign_id}", "fieldType": "CALL"}}
    result = ads_mutate(creds, "campaignAssets", [link_op])
    _auto_log("asset_call", f"{phone} ({country_code}) → campaign {campaign_id}", campaign_id=campaign_id)
    if as_json:
        return print_json(result)
    click.secho(f"✓ Call extension {phone} added", fg="green")


# ── Conversion commands ──────────────────────────────────────

@conversion_group.command("list")
@click.option("--json", "as_json", is_flag=True)
def conversion_list(as_json):
    """List conversion actions."""
    results = run_gaql(get_credentials(), """
        SELECT conversion_action.name, conversion_action.id, conversion_action.type,
               conversion_action.status, conversion_action.category
        FROM conversion_action ORDER BY conversion_action.name""")
    if as_json:
        return print_json(results)
    rows = [{"name": r.get("conversionAction",{}).get("name",""),
             "id": r.get("conversionAction",{}).get("id",""),
             "type": r.get("conversionAction",{}).get("type",""),
             "status": r.get("conversionAction",{}).get("status",""),
             "category": r.get("conversionAction",{}).get("category","")}
            for r in results]
    print_table(rows, ["name", "id", "type", "status", "category"])

@conversion_group.command("create")
@click.argument("name")
@click.option("--type", "conv_type", default="WEBPAGE", type=click.Choice(["WEBPAGE", "UPLOAD_CLICKS", "UPLOAD_CALLS", "AD_CALL", "CLICK_TO_CALL"]))
@click.option("--category", default="DEFAULT")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def conversion_create(name, conv_type, category, dry_run, yes, as_json):
    """Create a conversion action."""
    enforce_allowed_caller()
    op = {"create": {"name": name, "type": conv_type, "category": category, "status": "ENABLED"}}
    if not _confirm_and_log(f"create conversion action '{name}' [{conv_type}]", "create conversion", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), "conversionActions", [op])
    _auto_log("conversion_create", f"'{name}' [{conv_type}]")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Created conversion action '{name}'", fg="green")

@conversion_group.command("set-primary")
@click.argument("action")
@click.option("--primary", "make_primary", flag_value="primary", help="Mark the conversion action as Primary (drives Smart Bidding).")
@click.option("--secondary", "make_primary", flag_value="secondary", help="Mark the conversion action as Secondary (observation-only; reported but not bid on).")
@click.option("--customer-id", "customer_id_opt", default=None, help="Customer ID to target. Defaults to GOOGLE_ADS_CUSTOMER_ID.")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def conversion_set_primary(action, make_primary, customer_id_opt, dry_run, yes, as_json):
    """Toggle a conversion action's primary_for_goal flag (Primary ↔ Secondary).

    ACTION may be a full resource_name (customers/.../conversionActions/123)
    or just the numeric conversion_action ID.
    """
    # Require exactly one of --primary / --secondary
    if make_primary not in ("primary", "secondary"):
        click.secho("✗ Must specify exactly one of --primary or --secondary.", fg="red", err=True)
        raise SystemExit(2)
    target_primary = (make_primary == "primary")

    # Resolve customer ID (flag > env default from config)
    cid = (customer_id_opt or CUSTOMER_ID or "").strip()
    if not cid:
        click.secho("✗ No customer ID — pass --customer-id or set GOOGLE_ADS_CUSTOMER_ID.", fg="red", err=True)
        raise SystemExit(1)

    # Normalize action → resource_name + numeric id
    action = action.strip()
    if action.startswith("customers/"):
        resource_name = action
        try:
            action_id = resource_name.rsplit("/", 1)[-1]
        except Exception:
            action_id = ""
    elif action.isdigit():
        action_id = action
        resource_name = f"customers/{cid}/conversionActions/{action_id}"
    else:
        click.secho(
            f"✗ Unrecognised ACTION '{action}'. Expected a numeric ID or a full "
            f"resource_name like customers/{cid}/conversionActions/12345.",
            fg="red", err=True,
        )
        raise SystemExit(2)

    creds = get_credentials()

    # Look up current state
    results = run_gaql(creds, f"""
        SELECT conversion_action.resource_name, conversion_action.name,
               conversion_action.id, conversion_action.primary_for_goal
        FROM conversion_action
        WHERE conversion_action.resource_name = '{resource_name}'""")
    if not results:
        click.secho(f"✗ Conversion action not found: {resource_name}", fg="red", err=True)
        raise SystemExit(1)
    ca = results[0].get("conversionAction", {})
    before_primary = bool(ca.get("primaryForGoal", False))
    before_state = {
        "name": ca.get("name", ""),
        "resource_name": ca.get("resourceName", resource_name),
        "primary_for_goal": before_primary,
    }

    new_label = "Primary" if target_primary else "Secondary"
    old_label = "Primary" if before_primary else "Secondary"

    if before_primary == target_primary:
        click.secho(
            f"  No change needed — '{before_state['name']}' is already {new_label}.",
            fg="yellow",
        )
        if as_json:
            return print_json({"before": before_state, "after": before_state, "changed": False})
        return

    enforce_allowed_caller()

    summary = f"conversion action {action_id} '{before_state['name']}': {old_label} → {new_label}"
    if not _confirm_and_log(summary, "set primary_for_goal", dry_run, yes):
        if as_json:
            return print_json({"before": before_state, "after": None, "dry_run": True})
        return

    op = {
        "update": {"resourceName": resource_name, "primaryForGoal": target_primary},
        "updateMask": "primary_for_goal",
    }
    result = ads_mutate(creds, "conversionActions", [op])
    _auto_log("conversion_set_primary", summary)

    # Re-query for confirmed after-state
    results_after = run_gaql(creds, f"""
        SELECT conversion_action.resource_name, conversion_action.name,
               conversion_action.id, conversion_action.primary_for_goal
        FROM conversion_action
        WHERE conversion_action.resource_name = '{resource_name}'""")
    after_state = before_state
    if results_after:
        ca2 = results_after[0].get("conversionAction", {})
        after_state = {
            "name": ca2.get("name", ""),
            "resource_name": ca2.get("resourceName", resource_name),
            "primary_for_goal": bool(ca2.get("primaryForGoal", False)),
        }

    if as_json:
        return print_json({"before": before_state, "after": after_state, "result": result})
    click.secho(f"✓ {before_state['name']} ({action_id}): {old_label} → {new_label}", fg="green")
    click.echo(f"  before: primary_for_goal={before_state['primary_for_goal']}")
    click.echo(f"  after:  primary_for_goal={after_state['primary_for_goal']}")


@conversion_group.command("tag")
@click.argument("conversion_id")
@click.option("--json", "as_json", is_flag=True)
def conversion_tag(conversion_id, as_json):
    """Get conversion tracking tag/snippet."""
    results = run_gaql(get_credentials(), f"""
        SELECT conversion_action.name, conversion_action.id,
               conversion_action.tag_snippets
        FROM conversion_action WHERE conversion_action.id = {conversion_id}""")
    if as_json:
        return print_json(results)
    if results:
        ca = results[0].get("conversionAction", {})
        click.secho(f"\n  {ca.get('name', '')} (ID: {ca.get('id', '')})\n", bold=True)
        snippets = ca.get("tagSnippets", [])
        for s in snippets:
            click.secho(f"  Type: {s.get('type','')}", fg="cyan")
            click.echo(f"  {s.get('eventSnippet','')}\n")
    else:
        click.echo("  (not found)")

@conversion_group.command("perf")
@click.option("--days", "-d", type=int, default=7)
@click.option("--json", "as_json", is_flag=True)
def conversion_perf(days, as_json):
    """Conversion performance by action."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    results = run_gaql(get_credentials(), f"""
        SELECT segments.conversion_action_name, metrics.conversions,
               metrics.all_conversions, metrics.conversions_value
        FROM campaign WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
          AND metrics.conversions > 0
        ORDER BY metrics.conversions DESC""")
    if as_json:
        return print_json(results)
    # Aggregate by conversion action
    agg = {}
    for r in results:
        name = r.get("segments",{}).get("conversionActionName","")
        m = r.get("metrics",{})
        if name not in agg:
            agg[name] = {"name": name, "conv": 0, "all_conv": 0, "value": 0}
        agg[name]["conv"] += float(m.get("conversions",0))
        agg[name]["all_conv"] += float(m.get("allConversions",0))
        agg[name]["value"] += float(m.get("conversionsValue",0))
    rows = sorted(agg.values(), key=lambda x: x["conv"], reverse=True)
    print_table(rows, ["name", "conv", "all_conv", "value"])

@conversion_group.command("upload")
@click.option("--gclid", required=True)
@click.option("--action-id", required=True, help="Conversion action resource name.")
@click.option("--time", "conv_time", required=True, help="Conversion time (ISO 8601).")
@click.option("--value", type=float, default=None)
@click.option("--currency", default=None)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def conversion_upload_cmd(gclid, action_id, conv_time, value, currency, dry_run, yes, as_json):
    """Upload an offline conversion."""
    enforce_allowed_caller()
    conv = {"gclid": gclid, "conversionDateTime": conv_time}
    if value is not None:
        conv["conversionValue"] = value
    if currency:
        conv["currencyCode"] = currency
    if not _confirm_and_log(f"upload conversion gclid={gclid}", "upload conversion", dry_run, yes):
        return
    result = ads_upload_click_conversions(get_credentials(), [conv], action_id)
    _auto_log("conversion_upload", f"gclid={gclid}")

    # Check for partial failures (API returns 200 but some conversions failed)
    partial_error = result.get("partialFailureError")
    if partial_error:
        if as_json:
            return print_json({"status": "partial_failure", "partialFailureError": partial_error, "result": result})
        click.secho("⚠ Partial failure: some conversions were not uploaded", fg="yellow", err=True)
        # Extract per-conversion errors from partial failure details
        details = partial_error.get("details", [])
        for detail in details:
            for error in detail.get("errors", []):
                loc = error.get("location", {})
                field_path = ".".join(
                    str(op.get("fieldName", op.get("index", "?")))
                    for op in loc.get("fieldPathElements", [])
                ) or "unknown"
                msg = error.get("errorCode", {})
                click.secho(f"  ✗ [{field_path}] {msg}", fg="red", err=True)
        raise SystemExit(1)

    if as_json:
        return print_json(result)
    click.secho("✓ Conversion uploaded", fg="green")


# ── Audience commands ────────────────────────────────────────

@audience_group.command("list")
@click.option("--json", "as_json", is_flag=True)
def audience_list(as_json):
    """List user lists / audiences."""
    results = run_gaql(get_credentials(), """
        SELECT user_list.name, user_list.id, user_list.type,
               user_list.size_for_search, user_list.size_for_display,
               user_list.membership_status, user_list.match_rate_percentage
        FROM user_list ORDER BY user_list.name""")
    if as_json:
        return print_json(results)
    rows = [{"name": r.get("userList",{}).get("name",""),
             "id": r.get("userList",{}).get("id",""),
             "type": r.get("userList",{}).get("type",""),
             "search_size": r.get("userList",{}).get("sizeForSearch",""),
             "display_size": r.get("userList",{}).get("sizeForDisplay",""),
             "match_rate": r.get("userList",{}).get("matchRatePercentage","")}
            for r in results]
    print_table(rows, ["name", "id", "type", "search_size", "display_size", "match_rate"])

@audience_group.command("create")
@click.argument("name")
@click.option("--description", "-d", default="", help="List description.")
@click.option("--life-span", type=int, default=540, help="Membership life span in days (default: 540).")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def audience_create_cmd(name, description, life_span, dry_run, yes, as_json):
    """Create a Customer Match user list."""
    enforce_allowed_caller()
    if not _confirm_and_log(f"create audience list '{name}'", "create audience", dry_run, yes):
        return
    from gads_lib.ads import audience_create_list
    result = audience_create_list(get_credentials(), name, description=description, life_span=life_span)
    _auto_log("audience_create", f"'{name}' (life_span={life_span}d)")
    if as_json:
        return print_json(result)
    rn = result.get("results", [{}])[0].get("resourceName", "")
    click.secho(f"✓ Created audience list '{name}' → {rn}", fg="green")

@audience_group.command("upload")
@click.argument("csv_path", type=click.Path(exists=True))
@click.option("--list-name", required=True, help="Name of the target user list (must exist or use --create).")
@click.option("--create", "create_if_missing", is_flag=True, help="Create the list if it doesn't exist.")
@click.option("--description", default="", help="Description for new list (with --create).")
@click.option("--life-span", type=int, default=540, help="Membership life span for new list (default: 540 days).")
@click.option("--batch-size", type=int, default=100, help="Upload batch size (default: 100).")
@click.option("--max-rows", type=int, default=None, help="Max rows to upload (for testing).")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def audience_upload(csv_path, list_name, create_if_missing, description, life_span, batch_size, max_rows, dry_run, yes, as_json):
    """Upload a CSV to a Customer Match list.

    CSV format: Phone,Email,First Name,Last Name,Country

    \b
    All PII is SHA-256 hashed before upload.
    Phone numbers are normalized to E.164 format.
    Invalid names (companies, garbage, special chars) are skipped — phone-only upload.
    Consent fields (adUserData + adPersonalization = GRANTED) are included automatically.

    \b
    Example:
      gads audience upload data/audiences/my_list.csv --list-name "My Audience" --create
      gads audience upload contacts.csv --list-name "Existing List" --max-rows 10
    """
    enforce_allowed_caller()
    from gads_lib.ads import audience_find_list, audience_create_list, audience_upload_csv

    creds = get_credentials()

    # Find or create the list
    list_rn = audience_find_list(creds, list_name)
    if not list_rn:
        if create_if_missing:
            if not _confirm_and_log(f"create list '{list_name}' + upload {csv_path}", "create + upload", dry_run, yes):
                return
            result = audience_create_list(creds, list_name, description=description, life_span=life_span)
            list_rn = result.get("results", [{}])[0].get("resourceName", "")
            click.secho(f"  ✓ Created list: {list_rn}", fg="green")
        else:
            click.secho(f"✗ List '{list_name}' not found. Use --create to create it.", fg="red", err=True)
            raise SystemExit(1)
    else:
        click.echo(f"  Found list: {list_rn}")
        if not _confirm_and_log(f"upload {csv_path} → '{list_name}'", "upload audience", dry_run, yes):
            return

    if dry_run:
        return

    # Upload
    job_rn, stats = audience_upload_csv(creds, list_rn, csv_path, batch_size=batch_size, max_rows=max_rows)
    _auto_log("audience_upload", f"'{list_name}': {stats['rows_uploaded']} rows, job={job_rn}")

    if as_json:
        return print_json(stats)
    click.secho(f"\n  ✓ Upload complete", fg="green")
    click.echo(f"    List:     {list_name}")
    click.echo(f"    Rows:     {stats['rows_uploaded']}")
    click.echo(f"    Job:      {job_rn}")
    if stats.get("phone_dropped"):
        click.secho(f"    Phone numbers dropped: {stats['phone_dropped']} (unparseable -- see warning above)", fg="yellow")
    click.echo(f"\n  Check job status:  gads query \"SELECT offline_user_data_job.id, offline_user_data_job.status FROM offline_user_data_job WHERE offline_user_data_job.resource_name = '{job_rn}'\"")
    click.echo(f"  Check list sizes:  gads audience list --json | grep '{list_name}'")

@audience_group.command("job-status")
@click.argument("job_id")
@click.option("--json", "as_json", is_flag=True)
def audience_job_status(job_id, as_json):
    """Check status of a Customer Match upload job."""
    results = run_gaql(get_credentials(), f"""
        SELECT offline_user_data_job.id, offline_user_data_job.status,
               offline_user_data_job.failure_reason,
               offline_user_data_job.operation_metadata.match_rate_range,
               offline_user_data_job.customer_match_user_list_metadata.user_list
        FROM offline_user_data_job WHERE offline_user_data_job.id = {job_id}""")
    if as_json:
        return print_json(results)
    if not results:
        click.echo(f"  Job {job_id} not found")
        return
    j = results[0].get("offlineUserDataJob", {})
    meta = j.get("customerMatchUserListMetadata", {})
    op_meta = j.get("operationMetadata", {})
    click.echo(f"  Job ID:      {j.get('id','')}")
    click.echo(f"  Status:      {j.get('status','')}")
    click.echo(f"  Match range: {op_meta.get('matchRateRange','')}")
    click.echo(f"  User list:   {meta.get('userList','')}")
    if j.get("failureReason"):
        click.secho(f"  Failure:     {j['failureReason']}", fg="red")


# ── Data Manager API commands ────────────────────────────────

def _load_and_validate_events(events_path):
    """Parse a JSON-lines events file for `data-manager conversion-ingest`.

    Returns the list of event dicts. Exits with SystemExit(VALIDATION) on
    malformed JSON, a non-object line, an empty file, or any event missing
    the de-facto-required `eventTimestamp` field -- this is the "structural"
    validation `--dry-run` performs with zero network calls, and it also
    runs before a live call so a bad batch never reaches the API.
    """
    import json as _json

    events = []
    with open(events_path, encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except _json.JSONDecodeError as exc:
                click.secho(f"✗ Line {i}: invalid JSON — {exc}", fg="red", err=True)
                raise SystemExit(EXIT_CODES["VALIDATION"])
            if not isinstance(obj, dict):
                click.secho(f"✗ Line {i}: expected a JSON object, got {type(obj).__name__}", fg="red", err=True)
                raise SystemExit(EXIT_CODES["VALIDATION"])
            events.append(obj)

    if not events:
        click.secho("✗ No events found in file", fg="red", err=True)
        raise SystemExit(EXIT_CODES["VALIDATION"])

    missing_timestamp = [i for i, e in enumerate(events, start=1) if not e.get("eventTimestamp")]
    if missing_timestamp:
        shown = missing_timestamp[:10]
        suffix = "..." if len(missing_timestamp) > 10 else ""
        click.secho(
            f"✗ {len(missing_timestamp)} event(s) missing required field 'eventTimestamp' "
            f"(lines: {shown}{suffix})",
            fg="red", err=True,
        )
        raise SystemExit(EXIT_CODES["VALIDATION"])

    return events


@data_manager_group.command("conversion-ingest")
@click.argument("events_path", type=click.Path(exists=True))
@click.option("--action-id", required=True, help="Google Ads conversion action ID (bare ID, not a full resource name) -- becomes the Destination's productDestinationId.")
@click.option("--batch-size", type=int, default=MAX_EVENTS_PER_REQUEST, help=f"Max events per API call (default/max: {MAX_EVENTS_PER_REQUEST}).")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def data_manager_conversion_ingest(events_path, action_id, batch_size, dry_run, yes, as_json):
    """Ingest conversion events via the Data Manager API (events:ingest).

    EVENTS_PATH is a JSON-lines file: one Event object per line, e.g.:
    \b
      {"eventTimestamp": "2026-01-01T10:00:00+04:00", "transactionId": "abc123",
       "adIdentifiers": {"gclid": "Cj0..."}, "conversionValue": 30.0, "currency": "AED"}

    \b
    NOTE: The Data Manager API response is asynchronous. A 200 with a
    requestId means the request was accepted -- NOT that every event was
    successfully matched or recorded. There is no per-event success/failure
    detail in this response (unlike the legacy `conversion upload` command's
    partialFailureError).
    """
    enforce_allowed_caller()

    if batch_size < 1 or batch_size > MAX_EVENTS_PER_REQUEST:
        click.secho(f"✗ --batch-size must be between 1 and {MAX_EVENTS_PER_REQUEST}", fg="red", err=True)
        raise SystemExit(EXIT_CODES["VALIDATION"])

    events = _load_and_validate_events(events_path)
    batches = [events[i:i + batch_size] for i in range(0, len(events), batch_size)]
    action_desc = f"ingest {len(events)} conversion events ({len(batches)} batch(es)) → action-id {action_id}"

    if dry_run:
        # Structural validation is already complete (parsing + eventTimestamp
        # check above) with zero network calls. Handled directly here (rather
        # than via _confirm_and_log's shared dry-run branch) so --json mode
        # emits clean, parseable JSON with no interleaved yellow text.
        if as_json:
            return print_json({
                "status": "dry_run",
                "event_count": len(events),
                "batch_size": batch_size,
                "batch_count": len(batches),
            })
        click.secho(f"  DRY RUN: {action_desc}", fg="yellow")
        return

    if not _confirm_and_log(action_desc, "data-manager conversion-ingest", False, yes):
        return

    creds = get_credentials()
    batch_results = []
    for batch in batches:
        result = datamanager_ingest_events(creds, batch, action_id, as_json=as_json)
        request_id = result.get("requestId", "")
        batch_results.append({"requestId": request_id, "event_count": len(batch)})
        if not as_json:
            click.echo(f"  Batch requestId: {request_id}  ({len(batch)} events)")

    note = (
        f"Submitted {len(events)} events in {len(batches)} batch(es) — "
        "ingestion is asynchronous, no per-event status available in this response."
    )
    _auto_log(
        "datamanager_conversion_ingest",
        f"{len(events)} events in {len(batches)} batch(es) → action-id={action_id}",
    )

    if as_json:
        return print_json({
            "status": "submitted",
            "event_count": len(events),
            "batch_count": len(batches),
            "batches": batch_results,
            "note": note,
        })
    click.secho(f"\n✓ {note}", fg="green")


@data_manager_group.command("audience-upload")
@click.argument("csv_path", type=click.Path(exists=True))
@click.option("--list-resource-name", required=True, help="Google Ads Customer Match user-list ID (bare ID) -- becomes the Destination's productDestinationId.")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def data_manager_audience_upload(csv_path, list_resource_name, dry_run, yes, as_json):
    """Upload a CSV of contacts to a Customer Match audience via the Data Manager API.

    CSV format: Phone,Email,First Name,Last Name,Country (same shape as `gads audience upload`).

    \b
    Only phone and email identifiers are hashed and sent — Data Manager's
    address-based identifier requires a postal code this CSV shape does not
    carry, so the name/country columns are read but not used for matching.
    All PII is SHA-256 hashed (hex) before upload.

    \b
    This is a NEW, parallel path alongside the existing `audience upload`
    command (OfflineUserDataJobService) — it does not replace it.

    \b
    NOTE: The Data Manager API response is asynchronous. A 200 with a
    requestId means the request was accepted -- NOT that every member was
    matched. There is no per-row success/failure detail in this response.
    """
    enforce_allowed_caller()

    import csv as _csv

    members = []
    skipped = 0
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for row in _csv.DictReader(f):
            ids = build_user_identifiers(phone=row.get("Phone", ""), email=row.get("Email", ""))
            if ids:
                members.append({"userData": {"userIdentifiers": ids}})
            else:
                skipped += 1

    if not members:
        click.secho("✗ No valid phone/email identifiers found in CSV", fg="red", err=True)
        raise SystemExit(EXIT_CODES["VALIDATION"])

    if len(members) > MAX_AUDIENCE_MEMBERS_PER_REQUEST:
        click.secho(
            f"✗ {len(members)} members exceeds the {MAX_AUDIENCE_MEMBERS_PER_REQUEST}/request "
            "Data Manager limit — split the CSV before retrying.",
            fg="red", err=True,
        )
        raise SystemExit(EXIT_CODES["VALIDATION"])

    action_desc = f"upload {len(members)} audience members ({skipped} skipped) → {list_resource_name}"

    if dry_run:
        # Structural validation (identifier extraction + row-count) is already
        # complete above with zero network calls. Handled directly here
        # (rather than via _confirm_and_log's shared dry-run branch) so
        # --json mode emits clean, parseable JSON with no interleaved text.
        if as_json:
            return print_json({"status": "dry_run", "member_count": len(members), "skipped_rows": skipped})
        click.secho(f"  DRY RUN: {action_desc}", fg="yellow")
        return

    if not _confirm_and_log(action_desc, "data-manager audience-upload", False, yes):
        return

    creds = get_credentials()
    result = datamanager_ingest_audience_members(creds, members, list_resource_name, as_json=as_json)
    request_id = result.get("requestId", "")

    note = "Ingestion is asynchronous — no per-member match status available in this response."
    _auto_log(
        "datamanager_audience_upload",
        f"{len(members)} members ({skipped} skipped) → {list_resource_name}, requestId={request_id}",
    )

    if as_json:
        return print_json({
            "status": "submitted",
            "member_count": len(members),
            "skipped_rows": skipped,
            "requestId": request_id,
            "note": note,
        })
    click.secho(
        f"\n✓ Submitted {len(members)} audience members ({skipped} skipped, requestId={request_id}) — {note}",
        fg="green",
    )


# ── Report commands ──────────────────────────────────────────

@report_group.command("geo")
@click.option("--days", "-d", type=int, default=7)
@click.option("--json", "as_json", is_flag=True)
def report_geo(days, as_json):
    """Geographic performance report."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    results = run_gaql(get_credentials(), f"""
        SELECT geographic_view.country_criterion_id, geographic_view.location_type,
               metrics.impressions, metrics.clicks, metrics.conversions, metrics.cost_micros
        FROM geographic_view WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
        ORDER BY metrics.clicks DESC""")
    if as_json:
        return print_json(results)
    rows = []
    for r in results:
        gv, m = r.get("geographicView",{}), r.get("metrics",{})
        conv = float(m.get("conversions",0))
        cost = int(m.get("costMicros",0))/1e6
        rows.append({"country_id": gv.get("countryCriterionId",""), "type": gv.get("locationType",""),
                     "impr": m.get("impressions",0), "clicks": m.get("clicks",0),
                     "conv": conv, "cost": round(cost,2)})
    print_table(rows, ["country_id", "type", "impr", "clicks", "conv", "cost"])

@report_group.command("hourly")
@click.option("--days", "-d", type=int, default=7)
@click.option("--json", "as_json", is_flag=True)
def report_hourly(days, as_json):
    """Hourly performance breakdown."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    results = run_gaql(get_credentials(), f"""
        SELECT segments.hour, metrics.impressions, metrics.clicks,
               metrics.conversions, metrics.cost_micros
        FROM campaign WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
        ORDER BY segments.hour""")
    if as_json:
        return print_json(results)
    # Aggregate by hour
    hours = {}
    for r in results:
        h = r.get("segments",{}).get("hour","")
        m = r.get("metrics",{})
        if h not in hours:
            hours[h] = {"hour": h, "impr": 0, "clicks": 0, "conv": 0, "cost": 0}
        hours[h]["impr"] += int(m.get("impressions",0))
        hours[h]["clicks"] += int(m.get("clicks",0))
        hours[h]["conv"] += float(m.get("conversions",0))
        hours[h]["cost"] += int(m.get("costMicros",0))/1e6
    rows = [{"hour": v["hour"], "impr": v["impr"], "clicks": v["clicks"],
             "conv": round(v["conv"],1), "cost": round(v["cost"],2)} for v in sorted(hours.values(), key=lambda x: int(x["hour"]))]
    print_table(rows, ["hour", "impr", "clicks", "conv", "cost"])

@report_group.command("devices")
@click.option("--days", "-d", type=int, default=7)
@click.option("--json", "as_json", is_flag=True)
def report_devices(days, as_json):
    """Device performance breakdown."""
    from datetime import datetime, timedelta
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    results = run_gaql(get_credentials(), f"""
        SELECT segments.device, metrics.impressions, metrics.clicks,
               metrics.conversions, metrics.cost_micros
        FROM campaign WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
        ORDER BY metrics.clicks DESC""")
    if as_json:
        return print_json(results)
    devs = {}
    for r in results:
        d = r.get("segments",{}).get("device","")
        m = r.get("metrics",{})
        if d not in devs:
            devs[d] = {"device": d, "impr": 0, "clicks": 0, "conv": 0, "cost": 0}
        devs[d]["impr"] += int(m.get("impressions",0))
        devs[d]["clicks"] += int(m.get("clicks",0))
        devs[d]["conv"] += float(m.get("conversions",0))
        devs[d]["cost"] += int(m.get("costMicros",0))/1e6
    rows = [{"device": v["device"], "impr": v["impr"], "clicks": v["clicks"],
             "conv": round(v["conv"],1), "cost": round(v["cost"],2)} for v in sorted(devs.values(), key=lambda x: x["clicks"], reverse=True)]
    print_table(rows, ["device", "impr", "clicks", "conv", "cost"])

@report_group.command("search-terms")
@click.option("--days", "-d", type=int, default=7)
@click.option("--campaign", "-c", "campaign_id", default=None)
@click.option("--min-clicks", type=int, default=0)
@click.option("--json", "as_json", is_flag=True)
def report_search_terms(days, campaign_id, min_clicks, as_json):
    """Search terms report (alias for keyword search-terms)."""
    # Delegate to keyword search-terms
    ctx = click.get_current_context()
    ctx.invoke(keyword_search_terms, days=days, campaign_id=campaign_id, min_clicks=min_clicks, as_json=as_json)


# ── Generic mutate commands (escape hatch) ───────────────────

@cli.command("mutate")
@click.argument("resource_type")
@click.argument("operations_json")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def mutate_single(resource_type, operations_json, dry_run, yes, as_json):
    """Generic single-resource mutate (escape hatch)."""
    enforce_allowed_caller()
    import json as _json
    try:
        ops = _json.loads(operations_json)
    except _json.JSONDecodeError as e:
        click.secho(f"✗ Invalid JSON: {e}", fg="red", err=True)
        raise SystemExit(1)
    if not isinstance(ops, list):
        ops = [ops]
    if not _confirm_and_log(f"mutate {resource_type} ({len(ops)} ops)", f"generic mutate", dry_run, yes):
        return
    result = ads_mutate(get_credentials(), resource_type, ops)
    _auto_log("mutate", f"{resource_type}: {len(ops)} operations")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Mutated {resource_type}", fg="green")
    print_json(result)

@cli.command("batch-mutate")
@click.argument("operations_json")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", "-y", is_flag=True)
@click.option("--json", "as_json", is_flag=True)
def batch_mutate_cmd(operations_json, dry_run, yes, as_json):
    """Generic cross-resource batch mutate (escape hatch)."""
    enforce_allowed_caller()
    import json as _json
    try:
        ops = _json.loads(operations_json)
    except _json.JSONDecodeError as e:
        click.secho(f"✗ Invalid JSON: {e}", fg="red", err=True)
        raise SystemExit(1)
    if not isinstance(ops, list):
        ops = [ops]
    if not _confirm_and_log(f"batch mutate ({len(ops)} ops)", f"batch mutate", dry_run, yes):
        return
    result = ads_batch_mutate(get_credentials(), ops)
    _auto_log("batch_mutate", f"{len(ops)} operations")
    if as_json:
        return print_json(result)
    click.secho(f"✓ Batch mutate complete", fg="green")
    print_json(result)


# ── Standalone commands ──────────────────────────────────────

@cli.command("accounts")
@click.option("--json", "as_json", is_flag=True)
def accounts_cmd(as_json):
    """List accessible Google Ads accounts."""
    results = run_gaql(get_credentials(), """
        SELECT customer_client.id, customer_client.descriptive_name,
               customer_client.status, customer_client.manager
        FROM customer_client ORDER BY customer_client.descriptive_name""")
    if as_json:
        return print_json(results)
    rows = [{"id": r.get("customerClient",{}).get("id",""),
             "name": r.get("customerClient",{}).get("descriptiveName",""),
             "status": r.get("customerClient",{}).get("status",""),
             "manager": r.get("customerClient",{}).get("manager","")}
            for r in results]
    print_table(rows, ["id", "name", "status", "manager"])


# ── analyze: read-only analysis commands ────────────────────
@cli.group()
def analyze():
    """Read-only analysis: landing pages, wasted spend, n-grams, ad copy, competition."""
    pass


@analyze.command("landing-page")
@click.option("--branch", "-b", type=click.Choice(["qz3", "sja", "ind4"]), default="qz3",
              help="Branch landing page to score.")
@click.option("--url", "-u", default=None, help="Override URL (otherwise branch default).")
@click.option("--timeout", type=int, default=20, help="HTTP timeout (seconds).")
@click.option("--json", "as_json", is_flag=True)
def analyze_landing_page(branch, url, timeout, as_json):
    """Score a branch landing page for conversion readiness (read-only HTTP fetch)."""
    from gads_lib.analyze.lp_score import score_landing_page, render_lp_score
    result = score_landing_page(branch, url=url, timeout=timeout)
    render_lp_score(result, as_json=as_json)


@analyze.command("wasted-spend")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--min-cost", type=float, default=1.0, help="Ignore items below this AED cost.")
@click.option("--cpa-multiple", type=float, default=2.0,
              help="Flag below-average items whose CPA exceeds N x account avg CPA.")
@click.option("--limit", "-l", type=int, default=25, help="Rows per table.")
@click.option("--json", "as_json", is_flag=True)
def analyze_wasted_spend_cmd(days, min_cost, cpa_multiple, limit, as_json):
    """AED-ranked wasted spend on zero/low-conversion search terms and campaigns."""
    from gads_lib.analyze.wasted_spend import analyze_wasted_spend, render_wasted_spend
    result = analyze_wasted_spend(get_credentials(), days=days, min_cost=min_cost,
                                  cpa_multiple=cpa_multiple)
    render_wasted_spend(result, as_json=as_json, limit=limit)


@analyze.command("ngrams")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("-n", "n", type=int, default=3, help="Max n-gram size (produces 1..n).")
@click.option("--min-cost", type=float, default=1.0, help="Ignore n-grams below this AED cost.")
@click.option("--top", "-t", type=int, default=25, help="Rows per table.")
@click.option("--json", "as_json", is_flag=True)
def analyze_ngrams_cmd(days, n, min_cost, top, as_json):
    """N-gram clustering of search terms (Arabic + English) with negative candidates."""
    from gads_lib.analyze.ngrams import analyze_ngrams, render_ngrams
    result = analyze_ngrams(get_credentials(), days=days, n=n, min_cost=min_cost, top=top)
    render_ngrams(result, as_json=as_json, top=top)


@analyze.command("ad-copy")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--top", "-t", type=int, default=25, help="Rows in the ranked table.")
@click.option("--violations-only", is_flag=True, help="Only show ads with rule violations.")
@click.option("--json", "as_json", is_flag=True)
def analyze_ad_copy_cmd(days, top, violations_only, as_json):
    """Performance-ranked RSA ads, validated against PARTS-ONLY business rules."""
    from gads_lib.analyze.adcopy import analyze_adcopy, render_adcopy
    result = analyze_adcopy(get_credentials(), days=days, top=max(top, 50))
    render_adcopy(result, as_json=as_json, top=top, violations_only=violations_only)


@analyze.command("competition")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--top", "-t", type=int, default=25, help="Rows in the pressure table.")
@click.option("--json", "as_json", is_flag=True)
def analyze_competition_cmd(days, top, as_json):
    """Competitive pressure via impression-share + auction-insights (best-effort)."""
    from gads_lib.analyze.competitive import analyze_competitive, render_competitive
    result = analyze_competitive(get_credentials(), days=days, top=max(top, 50))
    render_competitive(result, as_json=as_json, top=top)


@analyze.command("audit")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_audit_cmd(days, as_json):
    """12-section structural-compliance audit: scoring 0/50/100 per section, weighted overall.

    Checks: RSA headline/description length, intra-ad duplicate headlines,
    ad strength, DKI presence, ad schedule, attribution model, budget-lost IS,
    Quality Score distribution, negative keyword coverage, primary conversion
    action, and sitelink coverage.
    """
    from gads_lib.analyze.audit import analyze_audit, render_audit
    result = analyze_audit(get_credentials(), days=days)
    render_audit(result, as_json=as_json)


@analyze.command("rsa-lengths")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_rsa_lengths_cmd(days, as_json):
    """Flag RSA headlines < 20 chars or descriptions < 60 chars (too-short copy).

    Short ad copy reduces ad strength and relevance signals. This check identifies
    headlines and descriptions that are below the recommended minimum length.
    """
    from gads_lib.analyze.checks import check_rsa_lengths
    result = check_rsa_lengths(get_credentials(), days=days)
    if as_json:
        return print_json(result)
    import click as _click
    w = result["window"]
    _click.secho(
        f"\nRSA length check — {w['from']} → {w['to']} ({w['days']}d)  "
        f"impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(
        f"  {result['total_ads']} ads  |  "
        f"{result['total_headlines']} headlines  |  "
        f"{result['total_descriptions']} descriptions"
    )
    if result["short_headlines"]:
        _click.secho(f"\nShort headlines ({len(result['short_headlines'])}):", fg="red", bold=True)
        print_table(result["short_headlines"][:20], ["ad_id", "campaign", "headline", "length"])
    else:
        _click.secho("\nNo short headlines found.", fg="green")
    if result["short_descriptions"]:
        _click.secho(f"\nShort descriptions ({len(result['short_descriptions'])}):", fg="red", bold=True)
        print_table(result["short_descriptions"][:20], ["ad_id", "campaign", "description", "length"])
    else:
        _click.secho("No short descriptions found.", fg="green")


@analyze.command("rsa-duplicates")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_rsa_duplicates_cmd(days, as_json):
    """Detect intra-RSA duplicate headlines (same text twice in one ad, case-insensitive).

    Duplicate headlines within an RSA waste a slot and reduce message diversity,
    lowering ad strength. This check flags any such ads.
    """
    from gads_lib.analyze.checks import check_rsa_duplicates
    result = check_rsa_duplicates(get_credentials(), days=days)
    if as_json:
        return print_json(result)
    import click as _click
    w = result["window"]
    _click.secho(
        f"\nRSA duplicate-headline check — {w['from']} → {w['to']} ({w['days']}d)  "
        f"impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(f"  {result['total_ads']} ads checked  |  {result['count_affected']} with duplicates")
    if result["ads_with_duplicates"]:
        _click.secho(f"\nAds with duplicate headlines:", fg="red", bold=True)
        rows = [
            {
                "ad_id": ad["ad_id"],
                "campaign": ad["campaign"][:30],
                "ad_group": ad["ad_group"][:20],
                "duplicates": ", ".join(ad["duplicate_headlines"][:3]),
            }
            for ad in result["ads_with_duplicates"][:20]
        ]
        print_table(rows, ["ad_id", "campaign", "ad_group", "duplicates"])
    else:
        _click.secho("\nNo intra-RSA duplicate headlines found.", fg="green")


@analyze.command("dki")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_dki_cmd(days, as_json):
    """Check for Dynamic Keyword Insertion ({KeyWord:} syntax) in RSA ads.

    DKI dynamically replaces the placeholder with the user's search query,
    improving ad relevance for Search campaigns. This check reports usage (or absence).
    """
    from gads_lib.analyze.checks import check_dki_presence
    result = check_dki_presence(get_credentials(), days=days)
    if as_json:
        return print_json(result)
    import click as _click
    w = result["window"]
    _click.secho(
        f"\nDKI presence check — {w['from']} → {w['to']} ({w['days']}d)  "
        f"impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(f"  {result['total_ads_checked']} ads checked  |  DKI found: {result['dki_found']}")
    if result["ads_with_dki"]:
        _click.secho(f"\nAds using DKI ({len(result['ads_with_dki'])}):", fg="green", bold=True)
        print_table(result["ads_with_dki"][:10], ["ad_id", "campaign", "snippet"])
    else:
        _click.secho(f"\n{result['recommendation']}", fg="yellow")


@analyze.command("ad-schedule")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_ad_schedule_cmd(days, as_json):
    """Check ad-schedule criteria coverage per active SEARCH campaign.

    Campaigns without ad schedules serve ads 24/7, which can waste budget in
    off-hours. This check flags campaigns missing dayparting rules.
    """
    from gads_lib.analyze.checks import check_ad_schedule
    result = check_ad_schedule(get_credentials(), days=days)
    if as_json:
        return print_json(result)
    import click as _click
    w = result["window"]
    _click.secho(
        f"\nAd-schedule check — {w['from']} → {w['to']} ({w['days']}d)  "
        f"impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(
        f"  {result['scheduled_campaigns']}/{result['total_search_campaigns']} SEARCH campaigns "
        f"have ad schedules ({result['coverage_pct']:.1f}%)"
    )
    if result["unscheduled_campaigns"]:
        _click.secho("\nCampaigns missing ad schedule:", fg="red", bold=True)
        for name in result["unscheduled_campaigns"][:20]:
            _click.echo(f"  - {name}")
    else:
        _click.secho("\nAll active SEARCH campaigns have ad schedules.", fg="green")


@analyze.command("attribution")
@click.option("--json", "as_json", is_flag=True)
def analyze_attribution_cmd(as_json):
    """Check conversion-action attribution models; flag Last-Click usage.

    Last-Click attribution under-credits upper-funnel touchpoints. Data-Driven
    attribution is recommended when the account has ≥300 conversions/month.
    """
    from gads_lib.analyze.checks import check_attribution_model
    result = check_attribution_model(get_credentials())
    if as_json:
        return print_json(result)
    import click as _click
    _click.secho(
        f"\nConversion attribution check  impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(
        f"  {result['total_conversion_actions']} enabled conversion actions  |  "
        f"Last-Click: {len(result['last_click_actions'])}  |  "
        f"Data-Driven/Other: {len(result['data_driven_actions']) + len(result['other_actions'])}"
    )
    if result["last_click_actions"]:
        _click.secho("\nLast-Click conversion actions (recommend switching):", fg="red", bold=True)
        print_table(result["last_click_actions"][:10], ["name", "model"])
    _click.echo(f"\n  {result['recommendation']}")


@analyze.command("budget-is")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_budget_is_cmd(days, as_json):
    """Report campaign budget-lost impression share for SEARCH campaigns.

    search_budget_lost_impression_share shows the fraction of auctions missed
    due to insufficient budget. > 10% signals under-budgeting.
    """
    from gads_lib.analyze.checks import check_budget_lost_is
    result = check_budget_lost_is(get_credentials(), days=days)
    if as_json:
        return print_json(result)
    import click as _click
    w = result["window"]
    avg = result.get("avg_budget_lost_is_pct")
    _click.secho(
        f"\nBudget-lost IS check — {w['from']} → {w['to']} ({w['days']}d)  "
        f"impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(
        f"  Avg budget-lost IS: {avg:.1f}%  |  "
        f"Flagged campaigns (>10%): {result['flagged_count']}"
        if avg is not None
        else "  No data available in window"
    )
    if result["campaigns"]:
        print_table(result["campaigns"][:20], ["name", "budget_lost_is_pct", "flag"])


@analyze.command("qs-distribution")
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--json", "as_json", is_flag=True)
def analyze_qs_distribution_cmd(days, as_json):
    """Quality Score sub-signal distribution across keywords (post-click, creative, predicted CTR).

    Shows the % of keywords in ABOVE_AVERAGE / AVERAGE / BELOW_AVERAGE bands for
    each QS sub-signal, plus overall average QS and band distribution.
    """
    from gads_lib.analyze.checks import check_qs_distribution
    result = check_qs_distribution(get_credentials(), days=days)
    if as_json:
        return print_json(result)
    import click as _click
    w = result["window"]
    avg_qs = result.get("avg_qs")
    _click.secho(
        f"\nQuality Score distribution — {w['from']} → {w['to']} ({w['days']}d)  "
        f"impact: {result['impact']}",
        fg="yellow", bold=True,
    )
    _click.echo(
        f"  {result['total_keywords']} unique keywords  |  "
        f"Avg QS: {avg_qs:.2f}" if avg_qs is not None
        else f"  {result['total_keywords']} unique keywords  |  Avg QS: N/A"
    )
    qs_dist = result.get("qs_distribution", {})
    _click.echo(
        f"  QS bands — 1-3: {qs_dist.get('1-3', 0)}  "
        f"4-6: {qs_dist.get('4-6', 0)}  "
        f"7-10: {qs_dist.get('7-10', 0)}"
    )
    sub = result.get("sub_signals", {})
    if sub:
        _click.secho("\nSub-signal distribution:", fg="white", bold=True)
        rows = []
        label_map = {
            "post_click": "Post-Click Quality",
            "creative": "Creative Quality (CTR)",
            "predicted_ctr": "Predicted CTR",
        }
        for key, label in label_map.items():
            s = sub.get(key, {})
            rows.append({
                "signal": label,
                "ABOVE_AVG": s.get("ABOVE_AVERAGE", 0),
                "AVERAGE": s.get("AVERAGE", 0),
                "BELOW_AVG": s.get("BELOW_AVERAGE", 0),
                "UNKNOWN": s.get("UNKNOWN", 0),
            })
        print_table(rows, ["signal", "ABOVE_AVG", "AVERAGE", "BELOW_AVG", "UNKNOWN"])


# ── Top-level audit command (alias to analyze audit) ─────────────

@cli.command()
@click.option("--days", "-d", type=int, default=30, help="Lookback window (ends yesterday).")
@click.option("--format", "fmt", type=click.Choice(["md", "json"]), default="md",
              help="Output format: md (human-readable markdown) or json.")
def audit(days, fmt):
    """12-section structural-compliance audit with weighted scoring.

    Runs all compliance checks (RSA lengths, duplicate headlines, DKI, ad schedule,
    attribution model, budget-lost IS, Quality Score, negative keywords, conversions,
    sitelinks) and produces an overall score (0-100) + grade (A-F).

    \\b
    Examples:
      gads audit                   # Human-readable report, 30-day window
      gads audit --days 14         # Shorter window
      gads audit --format json     # Machine-readable JSON for agents
      gads audit --format md       # Explicit human-readable mode
    """
    from gads_lib.analyze.audit import analyze_audit, render_audit
    result = analyze_audit(get_credentials(), days=days)
    as_json = fmt == "json"
    render_audit(result, as_json=as_json)


# ── Catalog (machine-readable command manifest) ─────────────

@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Emit the full command manifest as JSON.")
def catalog(as_json):
    """Emit a machine-readable manifest of every command, param, and help string.

    Lets an agent discover the CLI's full capabilities without parsing --help.
    """
    manifest = build_catalog(cli, __version__)
    if as_json:
        print_json(manifest)
        return
    # Human-readable fallback: list commands + one-line help.
    click.secho("\n  gads command catalog\n", fg="white", bold=True)

    def _emit(commands, indent=2):
        for name in sorted(commands):
            entry = commands[name]
            help_txt = (entry.get("help") or "").strip().splitlines()
            help_one = help_txt[0] if help_txt else ""
            click.echo(f"{' ' * indent}{name:<18} {help_one}")
            if entry.get("subcommands"):
                _emit(entry["subcommands"], indent + 4)

    _emit(manifest["commands"])
    click.echo(f"\n  Use 'gads catalog --json' for the full machine-readable manifest.\n")


# ── Read-only history DB access ─────────────────────────────

@cli.command(name="db")
@click.argument("sql")
@click.option("--limit", type=int, default=None, help="Cap the number of returned rows.")
@click.option("--json", "as_json", is_flag=True)
def db_query(sql, limit, as_json):
    """Run a read-only SELECT against the local history database.

    Only single SELECT/WITH queries are allowed; any mutating statement is rejected.
    """
    try:
        rows = dbread.run_select(sql, limit=limit)
    except dbread.UnsafeSQLError as e:
        raise SystemExit(print_error(str(e), code="VALIDATION", as_json=as_json))
    if as_json:
        print_json(rows)
        return
    print_table([flatten(r) for r in rows] if rows else rows)
    click.echo(f"\n  {len(rows)} row(s)")


@cli.command()
@click.option("--limit", "-n", type=int, default=50)
@click.option("--json", "as_json", is_flag=True)
def changelog(limit, as_json):
    """Read the local changelog (append-only action history)."""
    rows = dbread.read_changelog(limit=limit)
    if as_json:
        print_json(rows)
        return
    print_table([flatten(r) for r in rows] if rows else rows)
    click.echo(f"\n  {len(rows)} entry(ies)")


@cli.command()
@click.option("--limit", "-n", type=int, default=50)
@click.option("--json", "as_json", is_flag=True)
def decisions(limit, as_json):
    """Read the local decisions log."""
    rows = dbread.read_decisions(limit=limit)
    if as_json:
        print_json(rows)
        return
    print_table([flatten(r) for r in rows] if rows else rows)
    click.echo(f"\n  {len(rows)} decision(s)")


@cli.command()
@click.option("--limit", "-n", type=int, default=50)
@click.option("--json", "as_json", is_flag=True)
def milestones(limit, as_json):
    """Read the local milestones log."""
    rows = dbread.read_milestones(limit=limit)
    if as_json:
        print_json(rows)
        return
    print_table([flatten(r) for r in rows] if rows else rows)
    click.echo(f"\n  {len(rows)} milestone(s)")


# ── KB commands ──────────────────────────────────────────────

@cli.group()
def kb():
    """Knowledge Base — API version drift detection and KB surfacing."""
    pass


@kb.command("check")
@click.option("--json", "as_json", is_flag=True)
def kb_check_cmd(as_json):
    """Compare code API versions against kb/manifest.json. Exits non-zero on drift."""
    import sys
    results = check_drift()
    if as_json:
        return print_json(results)
    click.secho("\n  KB Drift Check\n", fg="white", bold=True)
    for r in results:
        status = r["status"]
        color = "red" if r["drift"] else "green"
        click.secho(
            f"  [{status}] {r['slug']:15s} manifest={r['manifest_version']:8s} code={r['code_version']:8s}  {r['api']}",
            fg=color,
        )
    drifts = [r for r in results if r["drift"]]
    click.echo()
    if drifts:
        click.secho(f"  {len(drifts)} DRIFT(S) detected. Update kb/<api>.md + manifest.json when bumping API versions.", fg="red")
        sys.exit(1)
    else:
        click.secho("  All API versions aligned with KB manifest.", fg="green")


@kb.command("list")
@click.option("--json", "as_json", is_flag=True)
def kb_list_cmd(as_json):
    """List all KB files with their API coverage."""
    files = list_kb_files()
    if as_json:
        return print_json(files)
    rows = [{"file": f["file"], "api": f["api"][:40], "exists": f["exists"], "size_bytes": f["size_bytes"]} for f in files]
    print_table(rows, ["file", "api", "exists", "size_bytes"])


@kb.command("show")
@click.argument("api")
def kb_show_cmd(api):
    """Show KB documentation for an API (by slug or filename)."""
    try:
        content = show_kb_file(api)
        click.echo(content)
    except FileNotFoundError as e:
        click.secho(f"✗ {e}", fg="red", err=True)
        manifest = load_manifest()
        slugs = sorted(set(e["slug"] for e in manifest))
        click.echo(f"  Available slugs: {', '.join(slugs)}", err=True)
        raise SystemExit(1)


# ── Register grouped aliases ────────────────────────────────
ads.add_command(query, name="query")
ads.add_command(perf, name="perf")
ads.add_command(config, name="config")
ads.add_command(refresh, name="refresh")
ads.add_command(snapshot, name="snapshot")
ads.add_command(log, name="log")


def main():
    """Entry point with a structured error envelope and stable exit codes.

    On failure, emits {"error": {...}} JSON to stderr when --json was requested,
    otherwise a colored message. Honors meaningful exit codes from EXIT_CODES.
    """
    # Detect whether the invocation asked for JSON output (best-effort, for the
    # top-level catch only — individual commands handle their own --json output).
    want_json = "--json" in sys.argv
    try:
        cli(standalone_mode=False)
    except SystemExit as e:
        # Honor explicit exit codes raised by commands (already printed).
        raise
    except click.exceptions.Abort:
        raise SystemExit(EXIT_CODES["GENERAL"])
    except click.exceptions.UsageError as e:
        # Preserve Click's own formatting on stderr, then exit with USAGE code.
        e.show()
        raise SystemExit(EXIT_CODES["USAGE"])
    except click.ClickException as e:
        raise SystemExit(print_error(e.format_message(), code="GENERAL", as_json=want_json))
    except Exception as e:  # noqa: BLE001 — top-level safety net
        code = "GENERAL"
        msg = str(e).lower()
        if "auth" in msg or "credential" in msg or "token" in msg or "401" in msg:
            code = "AUTH"
        elif "not found" in msg or "404" in msg:
            code = "NOT_FOUND"
        elif "403" in msg or "api" in msg or "quota" in msg:
            code = "API"
        raise SystemExit(print_error(f"{type(e).__name__}: {e}", code=code, as_json=want_json))
