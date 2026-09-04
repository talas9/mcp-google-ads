"""Google Analytics 4 Data and Admin API client.

API: GA4 Data API (v1beta) + GA4 Admin API (v1beta)
KB reference: kb/ga4.md (relative to gads-cli root)
Official docs: https://developers.google.com/analytics/devguides/reporting/data/v1/rest
"""
import json
import sys

import click

from .config import GA4_PROPERTY_ID
from .http import _send_with_retry, get_bearer_headers, request_json
from .output import EXIT_CODES, classify_api_error

GA4_DATA_BASE = "https://analyticsdata.googleapis.com/v1beta"
GA4_ADMIN_BASE = "https://analyticsadmin.googleapis.com/v1beta"

VALID_COUNTING_METHODS = ("ONCE_PER_EVENT", "ONCE_PER_SESSION")


def _require_property():
    if not GA4_PROPERTY_ID:
        import click
        click.secho("✗ GOOGLE_GA4_PROPERTY_ID not set in .env", fg="red", err=True)
        raise SystemExit(1)
    return GA4_PROPERTY_ID


# KB: kb/ga4.md § metadata | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/getMetadata
def ga4_get_metadata(creds, property_id=None, as_json=False):
    pid = property_id or _require_property()
    return request_json(
        "GET",
        f"{GA4_DATA_BASE}/properties/{pid}/metadata",
        headers=get_bearer_headers(creds),
        as_json=as_json,
    )


# KB: kb/ga4.md § run-report | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport
def ga4_run_report(creds, dimensions, metrics, date_ranges, property_id=None, limit=10000, as_json=False):
    pid = property_id or _require_property()
    body = {
        "dimensions": [{"name": d} for d in dimensions],
        "metrics": [{"name": m} for m in metrics],
        "dateRanges": date_ranges,
        "limit": limit,
    }
    return request_json(
        "POST",
        f"{GA4_DATA_BASE}/properties/{pid}:runReport",
        headers=get_bearer_headers(creds),
        json_body=body,
        as_json=as_json,
    )


# KB: kb/ga4.md § realtime-report | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport
def ga4_run_realtime_report(creds, dimensions, metrics, property_id=None, as_json=False):
    pid = property_id or _require_property()
    body = {
        "dimensions": [{"name": d} for d in dimensions],
        "metrics": [{"name": m} for m in metrics],
    }
    return request_json(
        "POST",
        f"{GA4_DATA_BASE}/properties/{pid}:runRealtimeReport",
        headers=get_bearer_headers(creds),
        json_body=body,
        as_json=as_json,
    )


# ── Admin API: Key Events ────────────────────────────────────
#
# Key Events are the GA4 successor to "conversions". Toggling an event to
# a key event needs the analytics.edit scope; listing is covered by
# analytics.readonly.
#
# API: https://developers.google.com/analytics/devguides/config/admin/v1


def _normalise_property(property_id):
    """Return the bare numeric property id, stripping any 'properties/' prefix."""
    pid = (property_id or _require_property()).strip()
    if pid.startswith("properties/"):
        pid = pid.split("/", 1)[1]
    if not pid.isdigit():
        raise SystemExit(
            f"GA4 property id must be numeric (or 'properties/<id>'), got: {pid!r}"
        )
    return pid


def _raise_for_admin_status(resp, action):
    """Translate GA4 Admin API failures into actionable human-readable errors.

    Emits a message to stderr then raises SystemExit with EXIT_CODES["API"] (5).

    403 → scope likely missing, point user to generate_token.py.
    404 → property id wrong.

    This helper is used in human (non-JSON) mode only. Under --json, callers
    should use _raise_for_admin_status_json() instead.
    """
    if resp.status_code == 403:
        click.secho(
            f"✗ 403 Forbidden while {action}. The OAuth token almost certainly "
            "lacks the analytics.edit scope — re-run tools/generate_token.py "
            "(or gads-cli/generate_token.py) to refresh it, then retry.",
            fg="red",
            err=True,
        )
        raise SystemExit(EXIT_CODES["API"])
    if resp.status_code == 404:
        click.secho(
            f"✗ 404 Not Found while {action}. Check GOOGLE_GA4_PROPERTY_ID — "
            "it must be the numeric GA4 property id (not a Measurement ID).",
            fg="red",
            err=True,
        )
        raise SystemExit(EXIT_CODES["API"])
    if resp.status_code >= 400:
        click.secho(
            f"✗ GA4 Admin API error while {action} ({resp.status_code}): "
            f"{resp.text[:600]}",
            fg="red",
            err=True,
        )
        raise SystemExit(EXIT_CODES["API"])


def _handle_admin_error(resp, action, url, as_json=False):
    """Handle a GA4 Admin API error response, respecting --json mode.

    Under --json: emit a JSON envelope to stdout, exit EXIT_CODES["API"] (5).
    Under human mode: emit GA4-specific helpful message to stderr, exit EXIT_CODES["API"] (5).

    Only call this when resp.status_code >= 400.
    """
    if as_json:
        classified = classify_api_error(resp.status_code, resp.text, url=url)
        envelope = classified if classified is not None else {
            "code": "API_ERROR",
            "message": resp.text[:600],
            "action": None,
            "service": None,
            "scope": None,
            "url": None,
            "project_id": None,
        }
        sys.stdout.write(json.dumps({"error": envelope}) + "\n")
        sys.stdout.flush()
        raise SystemExit(EXIT_CODES["API"])
    else:
        _raise_for_admin_status(resp, action)


# KB: kb/ga4.md § key-events | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/list
def list_key_events(property_id, creds, as_json=False):
    """Return all keyEvents on a GA4 property.

    Each item has keys: eventName, countingMethod, name (full resource path),
    plus createTime / custom flags from the API response.
    """
    pid = _normalise_property(property_id)
    url = f"{GA4_ADMIN_BASE}/properties/{pid}/keyEvents"
    items = []
    page_token = None
    while True:
        params = {"pageSize": 200}
        if page_token:
            params["pageToken"] = page_token
        resp = _send_with_retry("GET", url, headers=get_bearer_headers(creds), params=params, timeout=30)
        if resp.status_code >= 400:
            _handle_admin_error(resp, "listing keyEvents", url, as_json=as_json)
        data = resp.json() if resp.text else {}
        items.extend(data.get("keyEvents", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return items


# KB: kb/ga4.md § key-events | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/create
def create_key_event(property_id, creds, event_name, counting_method="ONCE_PER_SESSION", as_json=False):
    """Create (mark) an event as a key event. Idempotent.

    Returns the API response dict on success. If the event is already a key
    event (409 Conflict), returns the existing entry from a preceding list
    call so callers still get a well-formed dict.
    """
    if counting_method not in VALID_COUNTING_METHODS:
        raise ValueError(
            f"counting_method must be one of {VALID_COUNTING_METHODS}, got {counting_method!r}"
        )
    pid = _normalise_property(property_id)
    url = f"{GA4_ADMIN_BASE}/properties/{pid}/keyEvents"
    body = {"eventName": event_name, "countingMethod": counting_method}
    # Explicit, in addition to the URL-shape default: this creates a keyEvent,
    # so correctness must not depend on http.py's URL classification alone.
    resp = _send_with_retry(
        "POST", url, headers=get_bearer_headers(creds), json_body=body, timeout=30,
        idempotent=False,
    )
    if resp.status_code == 409:
        # Already exists — look it up from the list so we still return a dict.
        for existing in list_key_events(pid, creds, as_json=False):
            if existing.get("eventName") == event_name:
                existing = dict(existing)
                existing["_already_exists"] = True
                return existing
        return {"eventName": event_name, "countingMethod": counting_method, "_already_exists": True}
    if resp.status_code >= 400:
        _handle_admin_error(resp, f"creating keyEvent {event_name!r}", url, as_json=as_json)
    data = resp.json() if resp.text else {}
    data["_already_exists"] = False
    return data


# KB: kb/ga4.md § key-events | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/delete
def delete_key_event(property_id, creds, event_name, as_json=False):
    """Delete a keyEvent by event name. Returns True if deleted, False if not found."""
    pid = _normalise_property(property_id)
    target = None
    for existing in list_key_events(pid, creds, as_json=False):
        if existing.get("eventName") == event_name:
            target = existing
            break
    if target is None:
        return False
    resource_name = target.get("name")
    if not resource_name:
        raise SystemExit(
            f"keyEvent {event_name!r} found but has no resource name — cannot delete."
        )
    url = f"{GA4_ADMIN_BASE}/{resource_name}"
    resp = _send_with_retry("DELETE", url, headers=get_bearer_headers(creds), timeout=30)
    if resp.status_code in (200, 204):
        return True
    _handle_admin_error(resp, f"deleting keyEvent {event_name!r}", url, as_json=as_json)
    return True  # unreachable — _handle_admin_error exits on any >=400


# ── Data API: Batch / Pivot / Compatibility ──────────────────────────────────
#
# These three endpoints extend the core runReport surface:
#   batchRunReports  — run up to 5 reports in a single round-trip
#   runPivotReport   — cross-tab / pivot report
#   checkCompatibility — discover which dimensions/metrics can be combined
#
# API: https://developers.google.com/analytics/devguides/reporting/data/v1/rest


# KB: kb/ga4.md § batch-run-reports | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/batchRunReports
def ga4_batch_run_reports(creds, requests_list, property_id=None, as_json=False):
    """Run multiple GA4 reports in a single API call.

    POST /v1beta/properties/{pid}:batchRunReports

    Args:
        creds: OAuth credentials object.
        requests_list: list of report request dicts.  Each dict has the same
            shape as the body accepted by ga4_run_report (dimensions, metrics,
            dateRanges, limit, offset, …).  Up to 5 requests per batch.
        property_id: GA4 numeric property id.  Falls back to
            GOOGLE_GA4_PROPERTY_ID env var if omitted.

    Returns:
        Raw API response dict containing a ``reports`` list where each element
        corresponds to the matching entry in ``requests_list``.
    """
    pid = property_id or _require_property()
    body = {"requests": requests_list}
    return request_json(
        "POST",
        f"{GA4_DATA_BASE}/properties/{pid}:batchRunReports",
        headers=get_bearer_headers(creds),
        json_body=body,
        as_json=as_json,
    )


# KB: kb/ga4.md § pivot-report | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runPivotReport
def ga4_run_pivot_report(creds, dimensions, metrics, date_ranges, pivots, property_id=None, as_json=False):
    """Run a GA4 pivot report.

    POST /v1beta/properties/{pid}:runPivotReport

    Args:
        creds: OAuth credentials object.
        dimensions: list of dimension name strings, e.g. ["date", "country"].
        metrics: list of metric name strings, e.g. ["sessions", "activeUsers"].
        date_ranges: list of dateRange dicts, e.g.
            [{"startDate": "7daysAgo", "endDate": "yesterday"}].
        pivots: list of pivot objects.  Each pivot dict may contain:
            fieldNames (list[str]), limit (int), offset (int),
            orderBys (list), metricAggregations (list[str]).
        property_id: GA4 numeric property id.  Falls back to
            GOOGLE_GA4_PROPERTY_ID env var if omitted.

    Returns:
        Raw API response dict with ``pivotHeaders``, ``rows``, ``aggregates``,
        ``metadata``, and ``kind`` fields.
    """
    pid = property_id or _require_property()
    body = {
        "dimensions": [{"name": d} for d in dimensions],
        "metrics": [{"name": m} for m in metrics],
        "dateRanges": date_ranges,
        "pivots": pivots,
    }
    return request_json(
        "POST",
        f"{GA4_DATA_BASE}/properties/{pid}:runPivotReport",
        headers=get_bearer_headers(creds),
        json_body=body,
        as_json=as_json,
    )


# KB: kb/ga4.md § check-compatibility | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/checkCompatibility
def ga4_check_compatibility(creds, dimensions, metrics, property_id=None, as_json=False):
    """Check which dimensions and metrics are compatible with each other.

    POST /v1beta/properties/{pid}:checkCompatibility

    Useful for discovering valid dimension/metric combinations before running a
    report — the API returns a compatibility enum for every field so you can
    filter to COMPATIBLE ones only.

    Args:
        creds: OAuth credentials object.
        dimensions: list of dimension name strings to check.
        metrics: list of metric name strings to check.
        property_id: GA4 numeric property id.  Falls back to
            GOOGLE_GA4_PROPERTY_ID env var if omitted.

    Returns:
        Raw API response dict containing:
        - ``dimensionCompatibilities``: list of {dimensionMetadata, compatibility}
        - ``metricCompatibilities``:   list of {metricMetadata, compatibility}
        where ``compatibility`` is one of "COMPATIBLE", "INCOMPATIBLE",
        or "COMPATIBILITY_UNSPECIFIED".
    """
    pid = property_id or _require_property()
    body = {
        "dimensions": [{"name": d} for d in dimensions],
        "metrics": [{"name": m} for m in metrics],
    }
    return request_json(
        "POST",
        f"{GA4_DATA_BASE}/properties/{pid}:checkCompatibility",
        headers=get_bearer_headers(creds),
        json_body=body,
        as_json=as_json,
    )
