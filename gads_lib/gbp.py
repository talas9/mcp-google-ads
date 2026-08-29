"""Google Business Profile API client.

API: Google Business Profile (Account Management, Business Information, Legacy v4, Performance)
KB reference: kb/gbp.md (relative to gads-cli root)
Official docs: https://developers.google.com/my-business/reference/businessprofile/rest
"""
from .http import get_bearer_headers, request_json

GBP_ACCOUNT_BASE = "https://mybusinessaccountmanagement.googleapis.com/v1"
GBP_INFO_BASE = "https://mybusinessbusinessinformation.googleapis.com/v1"
GBP_V4_BASE = "https://mybusiness.googleapis.com/v4"

# Safety valve for gbp_list_reviews' pagination loop — a location with this many
# pages (at page_size=50, up to 5,000 reviews) would be extraordinary; stop
# rather than spin forever if the API ever misbehaves.
MAX_REVIEW_PAGES = 100


# KB: kb/gbp.md § accounts | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts/list
def gbp_list_accounts(creds, as_json=False):
    return request_json("GET", f"{GBP_ACCOUNT_BASE}/accounts", headers=get_bearer_headers(creds), as_json=as_json)


# Cache of the auto-resolved GBP account resource name, per process, so repeated
# review calls in the same invocation (e.g. gbp_batch_get_reviews) don't each
# re-fetch the accounts list.
_resolved_account_cache = {"name": None}


def _resolve_gbp_account(creds, account_name=None):
    """Resolve the "accounts/{id}" resource name to prefix onto bare v4 names.

    The legacy GBP v4 reviews API (mybusiness.googleapis.com/v4) requires the
    parent account in the path (accounts/{A}/locations/{L}/reviews), unlike the
    newer Account Management / Business Information APIs which accept a bare
    "locations/{L}". If account_name is given explicitly, it's used as-is.
    Otherwise this auto-discovers the account via gbp_list_accounts, preferring
    the LOCATION_GROUP account (the one that actually owns locations).
    """
    if account_name:
        return account_name
    if _resolved_account_cache["name"]:
        return _resolved_account_cache["name"]
    data = gbp_list_accounts(creds)
    accounts = data.get("accounts", [])
    location_groups = [a for a in accounts if a.get("type") == "LOCATION_GROUP"]
    if len(location_groups) == 1:
        resolved = location_groups[0]["name"]
    elif len(accounts) == 1:
        resolved = accounts[0]["name"]
    else:
        raise ValueError(
            "Could not auto-resolve a single GBP account (found "
            f"{len(accounts)} accounts, {len(location_groups)} of type "
            "LOCATION_GROUP). Pass account_name explicitly (--account accounts/{id})."
        )
    _resolved_account_cache["name"] = resolved
    return resolved


def _qualify_gbp_name(creds, name, account_name=None):
    """Ensure a v4 resource name (location or review) is account-qualified.

    Accepts either a bare name ("locations/{L}" or "locations/{L}/reviews/{R}")
    or an already-qualified one ("accounts/{A}/locations/{L}[...]"), which is
    returned unchanged to avoid double-prefixing.
    """
    if name.startswith("accounts/"):
        return name
    account = _resolve_gbp_account(creds, account_name)
    return f"{account}/{name}"


# KB: kb/gbp.md § locations | https://developers.google.com/my-business/reference/businessinformation/rest/v1/accounts.locations/list
def gbp_list_locations(creds, account_name, page_size=100, read_mask=None, as_json=False):
    params = {"pageSize": page_size}
    if read_mask:
        params["readMask"] = read_mask
    return request_json(
        "GET",
        f"{GBP_INFO_BASE}/{account_name}/locations",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )


# KB: kb/gbp.md § locations | https://developers.google.com/my-business/reference/businessinformation/rest/v1/accounts.locations/get
def gbp_get_location(creds, location_name, read_mask=None, as_json=False):
    params = {}
    if read_mask:
        params["readMask"] = read_mask
    return request_json(
        "GET",
        f"{GBP_INFO_BASE}/{location_name}",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )


# KB: kb/gbp.md § reviews | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list
def gbp_list_reviews(creds, location_name, page_size=50, account_name=None, as_json=False, limit=None):
    """Fetch ALL reviews for a location, following nextPageToken to exhaustion.

    The raw v4 API paginates (page_size caps each page, default/max 50), so a
    single request silently returns only the first page. This accumulates
    every page into one `reviews` list and returns it alongside the API's own
    `averageRating` / `totalReviewCount` fields (computed over ALL reviews,
    not just the fetched page) plus two fields this function adds:
    `fetchedReviewCount` (len of what was actually accumulated) and
    `complete` (True iff fetchedReviewCount == totalReviewCount) — so a
    partial fetch (loop cut short by MAX_REVIEW_PAGES, a repeated token, or
    an explicit `limit`) is visible in the return value instead of silently
    under-reporting.

    limit: optional cap on the number of reviews to accumulate before
    stopping early (a caller deliberately fetching fewer, e.g. for a quick
    sample). None (default) fetches everything.
    """
    qualified = _qualify_gbp_name(creds, location_name, account_name)
    params = {"pageSize": page_size}
    all_reviews = []
    result = {}
    seen_tokens = set()
    for _ in range(MAX_REVIEW_PAGES):
        data = request_json(
            "GET",
            f"{GBP_V4_BASE}/{qualified}/reviews",
            headers=get_bearer_headers(creds),
            params=params,
            as_json=as_json,
        )
        if not result:
            # Capture the API's own top-level fields (averageRating, etc.)
            # from the first page only; reviews/nextPageToken are handled below.
            result = {k: v for k, v in data.items() if k not in ("reviews", "nextPageToken")}
        all_reviews.extend(data.get("reviews", []))
        if limit is not None and len(all_reviews) >= limit:
            all_reviews = all_reviews[:limit]
            break
        token = data.get("nextPageToken")
        if not token or token in seen_tokens:
            break
        seen_tokens.add(token)
        params["pageToken"] = token
    result["reviews"] = all_reviews
    result.setdefault("totalReviewCount", len(all_reviews))
    result["fetchedReviewCount"] = len(all_reviews)
    result["complete"] = result["fetchedReviewCount"] >= int(result["totalReviewCount"])
    return result


# KB: kb/gbp.md § reviews | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/updateReply
def gbp_reply_review(creds, review_name, comment, account_name=None, as_json=False):
    qualified = _qualify_gbp_name(creds, review_name, account_name)
    return request_json(
        "PUT",
        f"{GBP_V4_BASE}/{qualified}/reply",
        headers=get_bearer_headers(creds),
        json_body={"comment": comment},
        as_json=as_json,
    )


# KB: kb/gbp.md § reviews | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/deleteReply
def gbp_delete_reply(creds, review_name, account_name=None, as_json=False):
    qualified = _qualify_gbp_name(creds, review_name, account_name)
    return request_json(
        "DELETE",
        f"{GBP_V4_BASE}/{qualified}/reply",
        headers=get_bearer_headers(creds),
        as_json=as_json,
    )


# ── GBP Performance API ─────────────────────────────────────

GBP_PERF_BASE = "https://businessprofileperformance.googleapis.com/v1"

# All available daily metrics
DAILY_METRICS = [
    "BUSINESS_IMPRESSIONS_DESKTOP_MAPS",
    "BUSINESS_IMPRESSIONS_DESKTOP_SEARCH",
    "BUSINESS_IMPRESSIONS_MOBILE_MAPS",
    "BUSINESS_IMPRESSIONS_MOBILE_SEARCH",
    "BUSINESS_CONVERSATIONS",
    "BUSINESS_DIRECTION_REQUESTS",
    "CALL_CLICKS",
    "WEBSITE_CLICKS",
    "BUSINESS_BOOKINGS",
    "BUSINESS_FOOD_ORDERS",
    "BUSINESS_FOOD_MENU_CLICKS",
]


# KB: kb/gbp.md § performance | https://developers.google.com/my-business/reference/businessprofileperformance/rest/v1/locations/getDailyMetricsTimeSeries
def gbp_daily_metrics(creds, location_name, metric, start_date, end_date, as_json=False):
    """Fetch a single daily metric time series for a location.

    start_date/end_date: date objects or (year, month, day) tuples.
    Returns list of {date: "YYYY-MM-DD", value: int}.
    """
    if hasattr(start_date, "year"):
        sy, sm, sd = start_date.year, start_date.month, start_date.day
    else:
        sy, sm, sd = start_date
    if hasattr(end_date, "year"):
        ey, em, ed = end_date.year, end_date.month, end_date.day
    else:
        ey, em, ed = end_date

    params = {
        "dailyMetric": metric,
        "dailyRange.startDate.year": sy,
        "dailyRange.startDate.month": sm,
        "dailyRange.startDate.day": sd,
        "dailyRange.endDate.year": ey,
        "dailyRange.endDate.month": em,
        "dailyRange.endDate.day": ed,
    }
    data = request_json(
        "GET",
        f"{GBP_PERF_BASE}/{location_name}:getDailyMetricsTimeSeries",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )
    results = []
    for dv in data.get("timeSeries", {}).get("datedValues", []):
        d = dv["date"]
        results.append({
            "date": f"{d['year']}-{d['month']:02d}-{d['day']:02d}",
            "value": int(dv.get("value", 0)),
        })
    return results


# KB: kb/gbp.md § performance | https://developers.google.com/my-business/reference/businessprofileperformance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries
def gbp_multi_daily_metrics(creds, location_name, metrics, start_date, end_date):
    """Fetch multiple daily metrics in a single API call.

    Returns dict of {metric_name: [{date, value}, ...]}.
    """
    if hasattr(start_date, "year"):
        sy, sm, sd = start_date.year, start_date.month, start_date.day
    else:
        sy, sm, sd = start_date
    if hasattr(end_date, "year"):
        ey, em, ed = end_date.year, end_date.month, end_date.day
    else:
        ey, em, ed = end_date

    params = {
        "dailyRange.startDate.year": sy,
        "dailyRange.startDate.month": sm,
        "dailyRange.startDate.day": sd,
        "dailyRange.endDate.year": ey,
        "dailyRange.endDate.month": em,
        "dailyRange.endDate.day": ed,
    }
    # fetchMultiDailyMetricsTimeSeries uses repeated dailyMetrics param which
    # can't be expressed as a dict (duplicate keys), so we pre-build the URL.
    param_str = "&".join(f"dailyMetrics={m}" for m in metrics)
    base_str = "&".join(f"{k}={v}" for k, v in params.items())
    full_url = f"{GBP_PERF_BASE}/{location_name}:fetchMultiDailyMetricsTimeSeries?{param_str}&{base_str}"

    data = request_json("GET", full_url, headers=get_bearer_headers(creds), timeout=30)

    result = {}
    for group in data.get("multiDailyMetricTimeSeries", []):
        for series in group.get("dailyMetricTimeSeries", []):
            metric_name = series.get("dailyMetric", "UNKNOWN")
            values = []
            for dv in series.get("timeSeries", {}).get("datedValues", []):
                d = dv["date"]
                # The API omits the "value" key entirely for a date this metric
                # hasn't backfilled yet (GBP Performance backfills on a staggered
                # per-metric schedule -- some metrics land in ~3 days, others take
                # ~8). That's the ONLY signal that a date is "not landed yet" --
                # every date in the requested range gets an entry either way, so
                # a missing date never occurs; only a missing "value" key does.
                # A genuinely-measured zero is indistinguishable from "not
                # landed" at a single location in isolation (the API omits
                # "value" for both), so this returns None here rather than
                # guessing, and leaves the zero-vs-not-landed decision to the
                # caller, which can disambiguate using data other locations
                # provide for the same date (see fetch_daily.py's
                # fetch_gbp_performance). Do NOT default this to 0 -- doing so
                # is what silently turned "not landed yet" into a permanent
                # false zero (2026-08-29 incident).
                raw_value = dv.get("value")
                values.append({
                    "date": f"{d['year']}-{d['month']:02d}-{d['day']:02d}",
                    "value": None if raw_value is None else int(raw_value),
                })
            result[metric_name] = values
    return result


# KB: kb/gbp.md § performance | https://developers.google.com/my-business/reference/businessprofileperformance/rest/v1/locations.searchkeywords.impressions.monthly/list
def gbp_search_keywords_monthly(creds, location_name, start_month, end_month, page_size=100, as_json=False):
    """Fetch monthly search keyword impressions.

    start_month/end_month: (year, month) tuples.
    Returns list of {keyword, impressions}.
    """
    sy, sm = start_month
    ey, em = end_month
    params = {
        "monthlyRange.startMonth.year": sy,
        "monthlyRange.startMonth.month": sm,
        "monthlyRange.endMonth.year": ey,
        "monthlyRange.endMonth.month": em,
        "pageSize": page_size,
    }

    all_keywords = []
    while True:
        data = request_json(
            "GET",
            f"{GBP_PERF_BASE}/{location_name}/searchkeywords/impressions/monthly",
            headers=get_bearer_headers(creds),
            params=params,
            as_json=as_json,
        )
        for kw in data.get("searchKeywordsCounts", []):
            all_keywords.append({
                "keyword": kw.get("searchKeyword", ""),
                "impressions": int(kw.get("insightsValue", {}).get("value", 0)),
            })
        token = data.get("nextPageToken")
        if not token:
            break
        params["pageToken"] = token

    return sorted(all_keywords, key=lambda x: -x["impressions"])


# ── Reviews batch helper ─────────────────────────────────────

# KB: kb/gbp.md § reviews | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list
def gbp_batch_get_reviews(creds, account_name, location_names, page_size=50, as_json=False, limit=None):
    """Collect reviews for multiple locations.

    GBP v4 has no true batch-reviews endpoint, so this iterates over each
    location and calls gbp_list_reviews (which itself paginates through
    nextPageToken to fetch every review, not just the first page), returning
    a dict keyed by location resource name.

    Args:
        creds: OAuth credentials.
        account_name: e.g. "accounts/123456789". Optional — if omitted (or
            falsy), each location is auto-qualified via gbp_list_reviews'
            own account resolution (accounts/X/locations/Y).
        location_names: list of location resource names, either bare
            ("locations/Y") or already-qualified ("accounts/X/locations/Y").
        page_size: passed through to gbp_list_reviews for each location.
        limit: optional cap on reviews fetched per location (see
            gbp_list_reviews). None (default) fetches everything.

    Returns:
        {location_name: {reviews, averageRating, totalReviewCount,
                          fetchedReviewCount, complete}} — the full
        gbp_list_reviews() result per location, so callers (and the CLI)
        can see whether the fetch was complete.
    """
    results = {}
    for location_name in location_names:
        resp = gbp_list_reviews(creds, location_name, page_size=page_size,
                                 account_name=account_name, limit=limit, as_json=as_json)
        results[location_name] = resp
    return results


# ── Local Posts CRUD ─────────────────────────────────────────

# KB: kb/gbp.md § local-posts | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/list
def gbp_list_local_posts(creds, account_name, location_id, page_size=20, as_json=False):
    """List local posts for a location.

    GET /v4/{parent=accounts/X/locations/Y}/localPosts

    Returns raw API response.
    """
    parent = f"{account_name}/locations/{location_id}"
    return request_json(
        "GET",
        f"{GBP_V4_BASE}/{parent}/localPosts",
        headers=get_bearer_headers(creds),
        params={"pageSize": page_size},
        as_json=as_json,
    )


# KB: kb/gbp.md § local-posts | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/create
def gbp_create_local_post(creds, account_name, location_id, post_body, as_json=False):
    """Create a local post for a location.

    POST /v4/{parent=accounts/X/locations/Y}/localPosts

    Args:
        post_body: LocalPost resource dict (caller provides full body).

    Returns raw API response.
    """
    parent = f"{account_name}/locations/{location_id}"
    return request_json(
        "POST",
        f"{GBP_V4_BASE}/{parent}/localPosts",
        headers=get_bearer_headers(creds),
        json_body=post_body,
        as_json=as_json,
    )


# KB: kb/gbp.md § local-posts | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/delete
def gbp_delete_local_post(creds, account_name, location_id, post_id, as_json=False):
    """Delete a local post.

    DELETE /v4/accounts/{X}/locations/{Y}/localPosts/{postId}

    Returns raw API response.
    """
    parent = f"{account_name}/locations/{location_id}"
    return request_json(
        "DELETE",
        f"{GBP_V4_BASE}/{parent}/localPosts/{post_id}",
        headers=get_bearer_headers(creds),
        as_json=as_json,
    )
