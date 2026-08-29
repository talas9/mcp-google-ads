"""Google Ads REST API client.

API: Google Ads REST API
KB reference: kb/google-ads.md (relative to gads-cli root)
Official docs: https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/
"""
import re
import unicodedata
import click
import requests

from .config import API_VERSION, CUSTOMER_ID, DEV_TOKEN, LOGIN_CUSTOMER_ID
from .http import request_json
from .output import EXIT_CODES, classify_api_error


# Canonical mapping: snake_case aliases → Google Ads REST camelCase plural resource names.
# The REST API requires camelCase plural (e.g. "campaignCriteria"), NOT snake_case singular
# (e.g. "campaign_criterion"). Passing the wrong form produces HTTP 404 from Google's servers
# (HTML error page, not a JSON API error) — which is the P0 bug this map fixes.
# Keep this list sorted; add new entries as resources are added to the CLI.
_RESOURCE_ALIASES: dict[str, str] = {
    # snake_case singular → camelCase plural (REST endpoint segment)
    "ad_group": "adGroups",
    "ad_group_ad": "adGroupAds",
    "ad_group_bid_modifier": "adGroupBidModifiers",
    "ad_group_criterion": "adGroupCriteria",
    "ad_group_feed": "adGroupFeeds",
    "asset": "assets",
    "campaign": "campaigns",
    "campaign_asset": "campaignAssets",
    "campaign_bid_modifier": "campaignBidModifiers",
    "campaign_budget": "campaignBudgets",
    "campaign_criterion": "campaignCriteria",
    "campaign_feed": "campaignFeeds",
    "conversion_action": "conversionActions",
    "customer_negative_criterion": "customerNegativeCriteria",
    "feed": "feeds",
    "feed_item": "feedItems",
    "keyword_plan": "keywordPlans",
    "label": "labels",
    "remarketing_action": "remarketingActions",
    "shared_criterion": "sharedCriteria",
    "shared_set": "sharedSets",
    "user_list": "userLists",
}


def _canonicalize_resource(resource_path: str) -> str:
    """Normalize a resource path segment to the Google Ads REST camelCase plural form.

    Accepts either the canonical form (passthrough) or snake_case aliases from
    _RESOURCE_ALIASES. Raises ValueError if the input is not recognized.

    Examples:
        "campaignCriteria"     → "campaignCriteria"  (passthrough, already canonical)
        "campaign_criterion"   → "campaignCriteria"  (alias → canonical)
        "adGroupCriteria"      → "adGroupCriteria"   (passthrough)
        "ad_group_criterion"   → "adGroupCriteria"   (alias → canonical)
    """
    # Already canonical (camelCase or any known non-alias form) — check alias table first
    canonical = _RESOURCE_ALIASES.get(resource_path)
    if canonical:
        return canonical
    # If it contains an underscore and wasn't found in the alias table, it's an unknown alias —
    # reject it with a clear message rather than silently building a 404 URL.
    if "_" in resource_path:
        known = ", ".join(sorted(_RESOURCE_ALIASES.keys()))
        raise ValueError(
            f"Unknown resource alias '{resource_path}'. "
            f"Use the camelCase plural REST form (e.g. 'campaignCriteria') "
            f"or one of the known aliases: {known}"
        )
    # Assume caller passed the camelCase form directly — pass through unchanged.
    return resource_path


def get_ads_headers(creds):
    return {
        "Authorization": f"Bearer {creds.token}",
        "developer-token": DEV_TOKEN,
        "login-customer-id": LOGIN_CUSTOMER_ID,
        "Content-Type": "application/json",
    }


def sanitize_keyword(keyword):
    """Remove special characters and collapse whitespace.
    
    Removes: ! @ % , * '
    Collapses multiple spaces to single space.
    """
    # Remove special chars
    sanitized = re.sub(r'[!@%,*\']', '', keyword)
    # Collapse whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    return sanitized


# KB: kb/google-ads.md § searchStream | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/searchStream
def run_gaql(creds, query):
    """Execute a GAQL query via the REST searchStream endpoint."""
    url = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}/googleAds:searchStream"
    )
    data = request_json("POST", url, headers=get_ads_headers(creds), json_body={"query": query})

    results = []
    for batch in (data if isinstance(data, list) else [data]):
        results.extend(batch.get("results", []))
    return results


# ── Campaign bidding target extraction ────────────────────────
# KB: kb/google-ads.md § DG-2 (Bidding Strategy Types)
#
# A campaign's target CPA/ROAS can live in different sub-messages depending
# on its bidding strategy: TARGET_CPA/TARGET_ROAS carry theirs directly, but
# MAXIMIZE_CONVERSIONS/MAXIMIZE_CONVERSION_VALUE also carry an OPTIONAL
# target under maximize_conversions/maximize_conversion_value instead (used
# to constrain spend/value rather than define it). Checking only
# targetCpa/targetRoas misses every MAXIMIZE_CONVERSIONS(_VALUE) campaign
# with a target set -- which was silently misreporting "no target" as a
# real AED 3.84 tCPA on a live campaign (talas-ads 2026-08-29 incident).
# Both helpers return None (not 0) when neither sub-message has the field,
# so "no target set" is never confused with "target is zero" -- callers
# must render None as "none"/an em dash, not "0.00".
def extract_target_cpa(camp):
    """Extract a campaign's target CPA in account currency, or None if unset.

    `camp` is the `campaign` object from a GAQL row requesting
    campaign.target_cpa.target_cpa_micros AND
    campaign.maximize_conversions.target_cpa_micros.
    """
    for key in ("targetCpa", "maximizeConversions"):
        val = camp.get(key, {}).get("targetCpaMicros")
        if val is not None:
            return int(val) / 1_000_000
    return None


def extract_target_roas(camp):
    """Extract a campaign's target ROAS, or None if unset.

    `camp` is the `campaign` object from a GAQL row requesting
    campaign.target_roas.target_roas AND
    campaign.maximize_conversion_value.target_roas.
    """
    for key in ("targetRoas", "maximizeConversionValue"):
        val = camp.get(key, {}).get("targetRoas")
        if val is not None:
            return float(val)
    return None


# KB: kb/google-ads.md § search | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/search
def ads_search(creds, query):
    """Execute a GAQL query via the REST search endpoint (paginated).
    
    Uses pageToken loop instead of searchStream.
    Returns list of all results across pages.
    """
    url = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}/googleAds:search"
    )
    headers = get_ads_headers(creds)
    results = []
    page_token = None
    
    while True:
        payload = {"query": query}
        if page_token:
            payload["pageToken"] = page_token
        
        data = request_json("POST", url, headers=headers, json_body=payload)
        results.extend(data.get("results", []))
        
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    
    return results


# KB: kb/google-ads.md § mutate | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/mutate
def ads_mutate(creds, resource_path, operations):
    """Single-resource mutate operation.

    POST to /{resource_path}:mutate with {"operations": operations}
    resource_path is canonicalized via _canonicalize_resource() so that callers
    may pass either the camelCase plural REST form ("campaignCriteria") or a
    snake_case alias ("campaign_criterion") — both route to the correct URL.
    Passing an unknown snake_case alias raises ValueError before any HTTP call.
    Returns response JSON.
    """
    canonical = _canonicalize_resource(resource_path)
    url = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}/{canonical}:mutate"
    )
    headers = get_ads_headers(creds)
    payload = {"operations": operations}

    return request_json("POST", url, headers=headers, json_body=payload)


# KB: kb/google-ads.md § batch-mutate | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/mutate
def ads_batch_mutate(creds, mutate_operations):
    """Cross-resource batch mutate operation.
    
    POST to /googleAds:mutate with {"mutateOperations": mutate_operations}
    KEY: use "mutateOperations" NOT "operations"
    Returns response JSON.
    """
    url = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}/googleAds:mutate"
    )
    headers = get_ads_headers(creds)
    payload = {"mutateOperations": mutate_operations}
    
    return request_json("POST", url, headers=headers, json_body=payload)


# KB: kb/google-ads.md § conversion-upload | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/uploadClickConversions
def ads_upload_click_conversions(creds, conversions, conversion_action_id):
    """Upload click conversions.
    
    POST to /customers/{CID}:uploadClickConversions
    Injects conversion_action_id into each conversion object.
    """
    url = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}:uploadClickConversions"
    )
    headers = get_ads_headers(creds)
    
    # Inject conversion_action_id into each conversion
    enriched_conversions = []
    for conv in conversions:
        enriched = dict(conv)
        enriched["conversionAction"] = conversion_action_id
        enriched_conversions.append(enriched)
    
    payload = {
        "conversions": enriched_conversions,
        "partialFailure": True,
    }
    
    return request_json("POST", url, headers=headers, json_body=payload)


# KB: kb/google-ads.md § keyword-ideas | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/generateKeywordIdeas
def generate_keyword_ideas(creds, keywords=None, url=None, language_id="1000", geo_ids=None, as_json=False):
    """Generate keyword ideas.

    POST to /customers/{CID}:generateKeywordIdeas
    Supports keywordSeed, urlSeed, or keywordAndUrlSeed (when both given).
    Seeds are mutually exclusive per the API contract.
    Sanitizes keywords before sending.
    """
    if not keywords and not url:
        click.secho("✗ Must provide either keywords or url", fg="red", err=True)
        raise SystemExit(1)

    url_endpoint = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}:generateKeywordIdeas"
    )
    headers = get_ads_headers(creds)

    payload = {}

    # Seeds are mutually exclusive: use keywordAndUrlSeed when both are provided
    if keywords and url:
        sanitized = [sanitize_keyword(kw) for kw in keywords]
        payload["keywordAndUrlSeed"] = {"url": url, "keywords": sanitized}
    elif keywords:
        sanitized = [sanitize_keyword(kw) for kw in keywords]
        payload["keywordSeed"] = {"keywords": sanitized}
    else:
        payload["urlSeed"] = {"url": url}

    # Language: single resource-name string (not a numeric id field)
    payload["language"] = f"languageConstants/{language_id}"
    # Geo targets: array of plain resource-name strings (not objects)
    if geo_ids:
        payload["geoTargetConstants"] = [f"geoTargetConstants/{geo_id}" for geo_id in geo_ids]
    # Network: restrict to Google Search (recommended; avoids schema rejection)
    payload["keywordPlanNetwork"] = "GOOGLE_SEARCH"

    return request_json("POST", url_endpoint, headers=headers, json_body=payload, as_json=as_json)


# KB: kb/google-ads.md § keyword-forecast | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers/generateKeywordForecastMetrics
def generate_keyword_forecast(creds, keywords, language_id="1000", geo_ids=None, as_json=False):
    """Generate keyword forecast metrics.

    POST to /customers/{CID}:generateKeywordForecastMetrics (v24 body schema).
    v24: top-level key is ``campaign`` (not ``campaignToForecast``); keywords
    move into ``campaign.adGroups[0].keywords`` as {text, matchType} objects;
    ``keywordPlanNetwork`` is removed; ``biddingStrategy`` is required; and a
    forward-looking ``forecastPeriod`` (start no earlier than tomorrow) with
    ``YYYY-MM-DD`` dates is required. Sanitizes keywords before sending.
    """
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo
    from .config import TZ_NAME

    url_endpoint = (
        f"https://googleads.googleapis.com/{API_VERSION}"
        f"/customers/{CUSTOMER_ID}:generateKeywordForecastMetrics"
    )
    headers = get_ads_headers(creds)

    # Sanitize keywords
    sanitized_keywords = [sanitize_keyword(kw) for kw in keywords]

    # Forecast period must be in the future: tomorrow through +30 days.
    _today = datetime.now(ZoneInfo(TZ_NAME)).date()
    _start = _today + timedelta(days=1)
    _end = _today + timedelta(days=31)

    payload = {
        "campaign": {
            "languageConstants": [f"languageConstants/{language_id}"],
            "biddingStrategy": {
                "manualCpcBiddingStrategy": {"maxCpcBidMicros": "1000000"}
            },
            "adGroups": [
                {
                    "keywords": [
                        {"text": kw, "matchType": "BROAD"}
                        for kw in sanitized_keywords
                    ]
                }
            ],
        },
        "forecastPeriod": {
            "startDate": _start.strftime("%Y-%m-%d"),
            "endDate": _end.strftime("%Y-%m-%d"),
        },
    }

    if geo_ids:
        payload["campaign"]["geoTargetConstants"] = [
            f"geoTargetConstants/{geo_id}" for geo_id in geo_ids
        ]

    return request_json("POST", url_endpoint, headers=headers, json_body=payload, as_json=as_json)


# ── Customer Match / Audience Upload ─────────────────────────

import csv
import hashlib
import time


def _sha256(val):
    """SHA-256 hash a string (stripped, encoded UTF-8)."""
    return hashlib.sha256(val.strip().encode("utf-8")).hexdigest()


def _is_valid_name(n):
    """Return True only if name looks like a real person name, not company/garbage."""
    if not n or not n.strip():
        return False
    n = n.strip()
    if len(n) > 30:
        return False
    if re.search(r'[*(),\[\]{}|/\\]', n):
        return False
    if re.search(r'\d', n):
        return False
    if len(n.split()) > 4:
        return False
    return True


def _normalize_phone(raw):
    """Normalize phone to E.164 format. Returns normalized string or None.

    Real-world exports (Zoho CRM in particular) contaminate phone values in
    ways that don't just fail to parse -- they parse into a WRONG number that
    silently hashes to something Google's Customer Match will never match,
    with no error to signal it. All of the following must be cleaned up
    BEFORE the country-code branching below runs, because a single leftover
    leading character (e.g. a spreadsheet text-guard apostrophe) breaks every
    startswith() check and produces a number missing its country code rather
    than None -- worse than a rejected value, since nothing flags it:
      - Leading `'`/`"` (Excel/Zoho spreadsheet text-guard on numeric cells,
        e.g. Zoho's MobilePhone export: "'+971527935444").
      - Unicode dash variants (en dash, em dash, minus sign, etc.) beyond the
        plain ASCII hyphen already handled.
      - Non-ASCII decimal digits (Arabic-Indic, fullwidth, etc.) -- plausible
        for a UAE CRM with Arabic-locale data entry -- converted to their
        ASCII value rather than left as literal Unicode digit characters
        that would silently survive into the hash.
    (Ordinary whitespace, including non-breaking space, was already handled
    by \\s below -- Python's \\s is Unicode-aware.)
    """
    if not raw:
        return None
    raw = str(raw).strip()
    raw = raw.lstrip("'\"").strip()
    if not raw:
        return None
    raw = "".join(
        str(unicodedata.digit(ch)) if ch.isdigit() and not ch.isascii() else ch
        for ch in raw
    )
    # Remove common prefixes/formatting, including Unicode dash punctuation
    # (‐-―: hyphen, non-breaking hyphen, figure/en/em dash,
    # horizontal bar; −: minus sign) an export/autocorrect tool can
    # introduce in place of a plain ASCII hyphen.
    raw = re.sub(r'[\s\-‐-―−\.\(\)]', '', raw)
    if not raw:
        return None
    if raw.startswith('00'):
        raw = '+' + raw[2:]
    elif raw.startswith('05') and len(raw) == 10:
        raw = '+971' + raw[1:]
    elif raw.startswith('5') and len(raw) == 9:
        raw = '+971' + raw
    elif raw.startswith('971') and not raw.startswith('+'):
        raw = '+' + raw
    elif not raw.startswith('+'):
        raw = '+' + raw
    # Must have + and at least 8 digits
    digits = re.sub(r'[^\d]', '', raw)
    if len(digits) < 8:
        return None
    return '+' + digits


def _build_user_op(phone=None, email=None, first_name=None, last_name=None, country=""):
    """Build one Customer Match userDataOperation with SHA-256 hashed identifiers.

    Returns (op_or_None, phone_dropped). `phone_dropped` is True when `phone`
    was provided but _normalize_phone() couldn't make a usable number of it
    -- the caller should surface this rather than let it vanish silently, per
    the same "a value that cannot be made valid should be visible, not
    vanish" rule as (now-fixed) phone normalization itself. Note an op can
    still come back non-None via email/name even when its phone was dropped,
    which would otherwise hide the loss completely (the row "succeeds" while
    quietly missing its phone-match signal).
    """
    ids = []
    phone_dropped = False
    if phone:
        normalized = _normalize_phone(phone)
        if normalized:
            ids.append({"hashedPhoneNumber": _sha256(normalized)})
        else:
            phone_dropped = True
    if email and "@" in email:
        ids.append({"hashedEmail": _sha256(email.strip().lower())})
    if _is_valid_name(first_name) and _is_valid_name(last_name):
        addr = {
            "hashedFirstName": _sha256(first_name.strip().lower()),
            "hashedLastName": _sha256(last_name.strip().lower()),
        }
        if country:
            addr["countryCode"] = country.strip().upper()
        ids.append({"addressInfo": addr})
    if not ids:
        return None, phone_dropped
    return {"create": {"userIdentifiers": ids}}, phone_dropped


# KB: kb/google-ads.md § customer-match | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers.userLists
def audience_find_list(creds, name):
    """Find a user list by name. Returns resource_name or None."""
    results = run_gaql(creds, f"SELECT user_list.resource_name FROM user_list WHERE user_list.name = '{name}'")
    if results:
        return results[0].get("userList", {}).get("resourceName")
    return None


# KB: kb/google-ads.md § customer-match | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers.userLists/mutate
def audience_create_list(creds, name, description="", life_span=540):
    """Create a CRM-based Customer Match user list."""
    op = {"create": {
        "name": name,
        "description": description,
        "membershipStatus": "OPEN",
        "membershipLifeSpan": life_span,
        "crmBasedUserList": {
            "uploadKeyType": "CONTACT_INFO",
            "dataSourceType": "FIRST_PARTY",
        },
    }}
    return ads_mutate(creds, "userLists", [op])


# KB: kb/google-ads.md § offline-user-data-jobs | https://developers.google.com/google-ads/api/docs/rest/reference/rest/v24/customers.offlineUserDataJobs
def audience_upload_csv(creds, list_resource_name, csv_path, batch_size=100, max_rows=None):
    """Upload a CSV file to a Customer Match list.

    CSV format: Phone,Email,First Name,Last Name,Country
    All PII is SHA-256 hashed before upload.
    Names are validated — garbage/company names are skipped (phone-only).
    Consent (adUserData + adPersonalization = GRANTED) is included.

    Returns: (job_resource_name, stats_dict)
    """
    headers = get_ads_headers(creds)
    base = f"https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}"

    # 1. Create offline user data job
    job_url = f"{base}/offlineUserDataJobs:create"
    job_payload = {"job": {
        "type": "CUSTOMER_MATCH_USER_LIST",
        "customerMatchUserListMetadata": {
            "userList": list_resource_name,
            "consent": {
                "adUserData": "GRANTED",
                "adPersonalization": "GRANTED",
            }
        }
    }}
    result = request_json("POST", job_url, headers=headers, json_body=job_payload, timeout=120)
    job_rn = result["resourceName"]
    click.echo(f"  Job created: {job_rn}")

    # 2. Read CSV and build operations
    rows = []
    phone_dropped = 0
    with open(csv_path, newline="", encoding="utf-8-sig", errors="replace") as f:
        for i, row in enumerate(csv.DictReader(f)):
            if max_rows and i >= max_rows:
                break
            op, dropped = _build_user_op(
                phone=row.get("Phone", ""),
                email=row.get("Email", ""),
                first_name=row.get("First Name", ""),
                last_name=row.get("Last Name", ""),
                country=row.get("Country", ""),
            )
            if dropped:
                phone_dropped += 1
            if op:
                rows.append(op)

    click.echo(f"  Rows: {len(rows)} valid operations from CSV")
    if phone_dropped:
        click.secho(
            f"  WARNING: {phone_dropped} phone number(s) could not be normalized "
            f"and were dropped (row still uploaded via email/name if present)",
            fg="yellow",
        )

    # 3. Upload in batches with retry
    add_url = f"https://googleads.googleapis.com/{API_VERSION}/{job_rn}:addOperations"
    uploaded = 0
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        for attempt in range(5):
            resp = requests.post(
                add_url, headers=headers,
                json={"operations": batch, "enableWarnings": True},
                timeout=120,
            )
            if resp.status_code == 200:
                uploaded += len(batch)
                break
            elif resp.status_code == 429:
                delay = 10 * (attempt + 1)
                click.echo(f"  Rate limited — waiting {delay}s (attempt {attempt + 1}/5)")
                time.sleep(delay)
            else:
                click.secho(f"✗ Upload batch failed: {resp.text[:500]}", fg="red", err=True)
                classified = classify_api_error(resp.status_code, resp.text)
                if classified:
                    click.secho(f"  {classified.get('message', '')}", fg="yellow", err=True)
                raise SystemExit(EXIT_CODES["API"])
        else:
            click.secho("✗ Upload failed after 5 retries (429)", fg="red", err=True)
            raise SystemExit(EXIT_CODES["API"])

    click.echo(f"  Uploaded: {uploaded} operations in {(len(rows) + batch_size - 1) // batch_size} batches")

    # 4. Run the job
    run_url = f"https://googleads.googleapis.com/{API_VERSION}/{job_rn}:run"
    request_json("POST", run_url, headers=headers, json_body={}, timeout=120)

    stats = {
        "job": job_rn,
        "rows_uploaded": uploaded,
        "total_csv_ops": len(rows),
        "phone_dropped": phone_dropped,
    }
    return job_rn, stats
