"""Configuration for gads-cli.

Scope detection (determines where credentials, data, and .env live):
  1. GADS_PROJECT_ROOT env var set       → project scope (that directory)
  2. CWD has data/, credentials/, or .env → project scope (CWD)
  3. Otherwise                            → global scope (~/.config/gads/)

Within any scope, .env is loaded and all paths resolve relative to the scope root.
Environment variables always override detected paths.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

# ── Scope detection ──────────────────────────────────────────
GLOBAL_HOME = Path.home() / ".config" / "gads"


def _detect_scope():
    """Determine scope root and whether we're global or project-local."""
    explicit = os.environ.get("GADS_PROJECT_ROOT")
    if explicit:
        return Path(explicit), "project"

    cwd = Path.cwd()
    if (cwd / "data").is_dir() or (cwd / "credentials").is_dir() or (cwd / ".env").exists():
        return cwd, "project"

    # Check if we're inside a submodule layout (gads-cli/ inside a project)
    pkg_dir = Path(__file__).resolve().parent.parent  # gads-cli/
    parent = pkg_dir.parent
    if (parent / "data").is_dir() or (parent / "credentials").is_dir():
        return parent, "project"

    return GLOBAL_HOME, "global"


SCOPE_ROOT, SCOPE_TYPE = _detect_scope()

# ── Load .env ────────────────────────────────────────────────
if load_dotenv is not None:
    # Load scope-specific .env first (highest priority)
    load_dotenv(SCOPE_ROOT / ".env")
    # If project scope, also check global as fallback for shared secrets
    if SCOPE_TYPE == "project":
        load_dotenv(GLOBAL_HOME / ".env", override=False)

# ── Paths (all overridable, default to scope root) ───────────
PROJECT_ROOT = SCOPE_ROOT  # alias for backward compat
CONFIG_HOME = GLOBAL_HOME

def _scoped_path(env_var, default):
    """Resolve a path env var, anchoring RELATIVE values to the scope root.

    .env files in this project set relative values (e.g.
    GADS_DB_PATH=data/talas_ads.db). Passing those straight to Path() resolves
    them against the CURRENT WORKING DIRECTORY, so the CLI found the database
    only when invoked from the project root and reported it missing from
    anywhere else -- including cron, which is why `gads doctor` intermittently
    showed a database FAIL against a database that was present the whole time.
    An absolute value is always honoured as given.
    """
    raw = os.environ.get(env_var)
    if not raw:
        return Path(default)
    p = Path(raw).expanduser()
    return p if p.is_absolute() else SCOPE_ROOT / p


DB_PATH = _scoped_path("GADS_DB_PATH", SCOPE_ROOT / "data" / "gads.db")
CREDS_PATH = _scoped_path("GADS_CREDENTIALS_PATH", SCOPE_ROOT / "credentials" / "google-ads-oauth.json")
SNAPSHOTS_DIR = _scoped_path("GADS_SNAPSHOTS_DIR", SCOPE_ROOT / "snapshots")

# ── Google Ads ───────────────────────────────────────────────
DEV_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN", "")
LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
CUSTOMER_ID = os.environ.get("GOOGLE_ADS_CUSTOMER_ID", "")
API_VERSION = os.environ.get("GOOGLE_ADS_API_VERSION", "v24")

# ── Google Merchant Center ───────────────────────────────────
MERCHANT_CENTER_ID = os.environ.get("GOOGLE_MERCHANT_CENTER_ID", "")

# ── Google Analytics / GA4 ───────────────────────────────────
GA4_PROPERTY_ID = os.environ.get("GOOGLE_GA4_PROPERTY_ID", "")

# ── Timezone (IANA format, e.g. "Asia/Dubai", "America/New_York") ──
TZ_NAME = os.environ.get("GADS_TIMEZONE", "UTC")

# ── Currency (ISO 4217 code, e.g. "USD", "AED", "EUR") ──────
CURRENCY = os.environ.get("GADS_CURRENCY", "USD")
