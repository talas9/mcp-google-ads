"""KB (Knowledge Base) helpers — version drift detection and KB surfacing."""

import json
import re
from pathlib import Path

# Path to kb/ directory — relative to this file's location
_KB_DIR = Path(__file__).resolve().parent.parent / "kb"
_MANIFEST_PATH = _KB_DIR / "manifest.json"


def load_manifest():
    """Load and return the KB manifest as a list of dicts."""
    with open(_MANIFEST_PATH) as f:
        return json.load(f)


def get_code_versions():
    """Extract actual API version strings used in the code.

    Returns a dict keyed by a stable slug string -> actual version string in code.
    """
    from .config import API_VERSION
    from . import ga4, gsc, gbp

    versions = {}

    # Google Ads
    versions["google-ads"] = API_VERSION  # e.g. "v24"

    # GA4 Data API — extract version from GA4_DATA_BASE URL
    m = re.search(r'/(v[\w]+)$', ga4.GA4_DATA_BASE)
    versions["ga4-data"] = m.group(1) if m else "unknown"

    # GA4 Admin API — extract version from GA4_ADMIN_BASE URL
    m = re.search(r'/(v[\w]+)$', ga4.GA4_ADMIN_BASE)
    versions["ga4-admin"] = m.group(1) if m else "unknown"

    # GSC — extract version from GSC_BASE URL
    m = re.search(r'/(v[\w]+)$', gsc.GSC_BASE)
    versions["search-console"] = m.group(1) if m else "unknown"

    # GBP — extract versions from each base URL constant
    for attr, key in [
        ("GBP_ACCOUNT_BASE", "gbp-account"),
        ("GBP_INFO_BASE", "gbp-info"),
        ("GBP_PERF_BASE", "gbp-perf"),
        ("GBP_V4_BASE", "gbp-v4"),
    ]:
        base = getattr(gbp, attr, "")
        m = re.search(r'/(v[\w]+)$', base)
        versions[key] = m.group(1) if m else "unknown"

    return versions


def _normalize_version(v):
    """Normalize version for comparison.

    Strips dot-separated minor versions but preserves pre-release suffixes:
      'v24.1'  -> 'v24'
      'v1beta' -> 'v1beta'
      'v1alpha'-> 'v1alpha'
      'v3'     -> 'v3'

    This means 'v24' and 'v24.1' compare equal (patch bump, not a code change),
    but 'v1beta' and 'v1alpha' compare as different (distinct API surfaces).
    """
    # Strip trailing dot-minor: "v24.1" -> "v24"
    return re.sub(r'^(v\d+)\.\d+$', r'\1', v)


def _manifest_entry_to_code_key(entry):
    """Map a manifest entry to the code_versions dict key.

    Returns None for entries whose version is not tracked in code (e.g. Merchant API,
    which uses per-sub-API paths rather than a single versioned base URL).
    """
    slug = entry["slug"]
    api_name = entry["api"]

    if slug == "google-ads":
        return "google-ads"

    if slug == "ga4":
        if "Admin" in api_name:
            return "ga4-admin"
        return "ga4-data"

    if slug == "gbp":
        if "Performance" in api_name:
            return "gbp-perf"
        if "Legacy" in api_name or "v4" in api_name.lower():
            return "gbp-v4"
        if "Account Management" in api_name:
            return "gbp-account"
        if "Business Information" in api_name:
            return "gbp-info"
        # Fallback for any other GBP entry — use account base
        return "gbp-account"

    if slug == "search-console":
        return "search-console"

    # merchant-api and any future slugs without a single versioned code constant
    return None


def check_drift():
    """Compare code versions against manifest.json.

    Returns a list of result dicts, one per manifest entry:
      {api, slug, manifest_version, code_version, drift, status}
    where drift=True means the normalized versions do not match.
    """
    manifest = load_manifest()
    code_versions = get_code_versions()

    results = []
    for entry in manifest:
        manifest_version = entry["current_version"]
        code_key = _manifest_entry_to_code_key(entry)
        code_version = code_versions.get(code_key, "n/a") if code_key else "n/a"

        has_drift = False
        if code_version != "n/a":
            has_drift = _normalize_version(manifest_version) != _normalize_version(code_version)

        results.append({
            "api": entry["api"],
            "slug": entry["slug"],
            "manifest_version": manifest_version,
            "code_version": code_version,
            "drift": has_drift,
            "status": "DRIFT" if has_drift else "OK",
        })

    return results


def list_kb_files():
    """Return list of KB files with their metadata."""
    manifest = load_manifest()
    seen = set()
    files = []
    for entry in manifest:
        kb_file = entry.get("kb_file", "")
        if kb_file and kb_file not in seen:
            seen.add(kb_file)
            path = _KB_DIR / kb_file
            files.append({
                "file": kb_file,
                "api": entry["api"],
                "slug": entry["slug"],
                "exists": path.exists(),
                "size_bytes": path.stat().st_size if path.exists() else 0,
            })
    return files


def show_kb_file(slug_or_file):
    """Return the contents of a KB file by slug or filename."""
    # Try as filename directly
    path = _KB_DIR / slug_or_file
    if not path.exists():
        # Try adding .md extension
        path = _KB_DIR / f"{slug_or_file}.md"
    if not path.exists():
        # Try finding by slug in manifest
        manifest = load_manifest()
        for entry in manifest:
            if entry.get("slug") == slug_or_file:
                path = _KB_DIR / entry["kb_file"]
                break
    if not path.exists():
        raise FileNotFoundError(f"KB file not found for: {slug_or_file}")
    return path.read_text()


def api_version_currency():
    """Compare the pinned Google Ads major version against the manifest's upstream latest.

    `check_drift` only proves the KB and the code agree — both can be a major
    version behind Google and still report zero drift. This answers the other
    question: is the pin itself stale?

    Returns a dict: {"status": "ok"|"warn"|"unknown", "pinned", "latest_upstream",
    "detail"}. Never raises — a malformed or missing manifest degrades to
    "unknown" rather than breaking `gads doctor`.
    """
    from .config import API_VERSION

    pinned = API_VERSION
    try:
        entry = next(e for e in load_manifest() if e.get("slug") == "google-ads")
        latest = entry.get("latest_upstream_version")
    except Exception:
        return {"status": "unknown", "pinned": pinned, "latest_upstream": None,
                "detail": "manifest unreadable — cannot compare against upstream"}

    if not latest:
        return {"status": "unknown", "pinned": pinned, "latest_upstream": None,
                "detail": "manifest has no latest_upstream_version"}

    def major(v):
        m = re.match(r'^v(\d+)', v or "")
        return int(m.group(1)) if m else None

    pm, lm = major(pinned), major(latest)
    if pm is None or lm is None:
        return {"status": "unknown", "pinned": pinned, "latest_upstream": latest,
                "detail": f"unparseable version ({pinned} vs {latest})"}

    if pm < lm:
        return {"status": "warn", "pinned": pinned, "latest_upstream": latest,
                "detail": (f"pinned {pinned} is {lm - pm} major version(s) behind upstream "
                           f"{latest} — set GOOGLE_ADS_API_VERSION or bump config.py")}

    return {"status": "ok", "pinned": pinned, "latest_upstream": latest,
            "detail": f"{pinned} is current with upstream {latest}"}
