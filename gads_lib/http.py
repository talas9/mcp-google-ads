import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import click
import requests

from .config import DEV_TOKEN, LOGIN_CUSTOMER_ID
from .output import EXIT_CODES, classify_api_error, offer_gcloud_enable

# ── Retry / backoff / session configuration ─────────────────────────────────
#
# GADS_HTTP_RETRIES / GADS_HTTP_TIMEOUT are read from the environment at call
# time (not import time) so tests can monkeypatch os.environ mid-run.

_DEFAULT_RETRIES = 4
_DEFAULT_TIMEOUT = 30.0
_MAX_RETRY_WAIT = 60.0  # cap on any single backoff/Retry-After sleep

# HTTP status codes worth retrying (rate limit + transient server errors).
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# A POST to one of these colon-RPC suffixes performs a mutation and must not
# be retried after a response is received (retrying could double-apply it).
# Reads (searchStream, search, GET, etc.) are unaffected -- see _is_idempotent.
_NON_IDEMPOTENT_SUFFIXES = (
    ":mutate",
    ":mutateAll",
    ":uploadClickConversions",
    ":ingest",
    ":run",
    ":addOperations",
    ":create",
)

_session = None


def _get_session():
    """Return the process-wide requests.Session, creating it lazily."""
    global _session
    if _session is None:
        _session = requests.Session()
    return _session


def _get_retries_config():
    raw = os.environ.get("GADS_HTTP_RETRIES")
    if raw is None:
        return _DEFAULT_RETRIES
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_RETRIES
    return max(1, value)


def _get_timeout_config():
    raw = os.environ.get("GADS_HTTP_TIMEOUT")
    if raw is None:
        return _DEFAULT_TIMEOUT
    try:
        return float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_TIMEOUT


def _is_idempotent(method, url):
    """True if it is safe to retry this request after an error response.

    Every non-POST method (GET/DELETE/PUT/...) is treated as idempotent.
    A POST is idempotent unless its URL path ends in one of the mutate-style
    colon-RPC suffixes (searchStream/search and other read POSTs still count
    as idempotent since they don't end in those suffixes).
    """
    if (method or "").upper() != "POST":
        return True
    path = (url or "").split("?", 1)[0]
    return not path.endswith(_NON_IDEMPOTENT_SUFFIXES)


def _parse_retry_after(value):
    """Parse a Retry-After header (seconds form or HTTP-date form) to seconds.

    Returns None if the value is missing or unparseable.
    """
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = (dt - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, delta)


def _backoff_delay(attempt, retry_after=None):
    """Seconds to sleep before the next attempt (attempt = attempts made so far)."""
    if retry_after is not None:
        return min(retry_after, _MAX_RETRY_WAIT)
    base = min(2 ** (attempt - 1), _MAX_RETRY_WAIT)
    jitter = random.uniform(0, base * 0.25)
    return min(base + jitter, _MAX_RETRY_WAIT)


def _send_with_retry(method, url, *, headers=None, params=None, json_body=None,
                      timeout=None, retries=None, idempotent=None):
    """Send an HTTP request via the shared session, retrying on transient failures.

    Returns the raw requests.Response -- does NOT raise or interpret status
    codes; callers (request_json, ga4.py's admin-API helpers) decide how to
    handle 4xx/5xx. Only re-raises the underlying requests exception once
    retries are exhausted (or immediately, if the failure isn't retryable).
    """
    session = _get_session()
    effective_timeout = timeout if timeout is not None else _get_timeout_config()
    max_attempts = max(1, int(retries if retries is not None else _get_retries_config()))
    is_idempotent = _is_idempotent(method, url) if idempotent is None else idempotent

    attempt = 0
    while True:
        attempt += 1
        try:
            resp = session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=effective_timeout,
            )
        except requests.exceptions.ConnectionError:
            # Includes ConnectTimeout (a ConnectionError subclass): the request
            # never reached the server, so retrying is always safe, even for
            # non-idempotent mutate calls.
            if attempt >= max_attempts:
                raise
            time.sleep(_backoff_delay(attempt))
            continue
        except requests.exceptions.Timeout:
            # A plain/ReadTimeout: the request may have been received and
            # applied server-side, so only retry idempotent calls.
            if not is_idempotent or attempt >= max_attempts:
                raise
            time.sleep(_backoff_delay(attempt))
            continue

        if (
            is_idempotent
            and resp.status_code in _RETRYABLE_STATUS
            and attempt < max_attempts
        ):
            retry_after = _parse_retry_after(
                (getattr(resp, "headers", None) or {}).get("Retry-After")
            )
            time.sleep(_backoff_delay(attempt, retry_after))
            continue

        return resp


def _wants_json(as_json):
    """True if the response should be emitted as a JSON error envelope.

    Honours an explicit as_json=True from the caller. Otherwise, falls back
    to the active click command's --json flag (and its parent contexts) so
    call sites that don't thread as_json through (e.g. run_gaql) still emit
    JSON errors under `gads ... --json`. Never raises when there is no click
    context (e.g. direct/offline calls, or click's own None-context state).
    """
    if as_json:
        return True
    try:
        ctx = click.get_current_context(silent=True)
    except Exception:
        return False
    while ctx is not None:
        try:
            if ctx.params.get("as_json"):
                return True
        except Exception:
            pass
        ctx = getattr(ctx, "parent", None)
    return False


def request_json(method, url, *, headers=None, params=None, json_body=None,
                  timeout=None, as_json=False, retries=None, idempotent=None):
    resp = _send_with_retry(
        method,
        url,
        headers=headers,
        params=params,
        json_body=json_body,
        timeout=timeout,
        retries=retries,
        idempotent=idempotent,
    )
    if resp.status_code >= 400:
        wants_json = _wants_json(as_json)
        classified = classify_api_error(resp.status_code, resp.text, url=url)
        if classified:
            if wants_json:
                sys.stdout.write(json.dumps({"error": classified}) + "\n")
                sys.stdout.flush()
                raise SystemExit(EXIT_CODES["API"])
            code = classified["code"]  # noqa: F841
            msg = classified["message"]
            action = classified.get("action")
            if action == "run_gcloud":
                service = classified.get("service", "unknown")
                project_id = classified.get("project_id")
                click.secho(f"✗ {msg}", fg="red", err=True)
                click.secho(f"  API not enabled: {service}.googleapis.com", fg="yellow", err=True)
                offer_gcloud_enable(service, project_id=project_id, yes=False)
            elif action == "regen_token":
                scope = classified.get("scope", "")
                click.secho("✗ Insufficient OAuth scope.", fg="red", err=True)
                click.secho(f"  Missing scope: {scope}", fg="yellow", err=True)
                click.secho(
                    "  Fix: python generate_token.py  (re-consent to add the scope)",
                    fg="cyan",
                    err=True,
                )
            elif action == "register_merchant":
                click.secho(f"✗ {msg}", fg="red", err=True)
                click.secho(
                    "  Merchant Center not registered as API developer.", fg="yellow", err=True
                )
                click.secho(
                    f"  Register at: {classified.get('url', '')}", fg="cyan", err=True
                )
            elif action == "request_allowlist":
                click.secho(f"✗ {msg}", fg="red", err=True)
                click.secho(
                    f"  Request access/allowlist at: {classified.get('url', '')}",
                    fg="cyan",
                    err=True,
                )
            raise SystemExit(EXIT_CODES["API"])
        else:
            detail = resp.text[:1200]
            if wants_json:
                sys.stdout.write(json.dumps({
                    "error": {
                        "code": "API_ERROR",
                        "message": detail,
                        "action": None,
                        "service": None,
                        "scope": None,
                        "url": None,
                        "project_id": None,
                    }
                }) + "\n")
                sys.stdout.flush()
                raise SystemExit(EXIT_CODES["API"])
            click.secho(f"✗ API Error {resp.status_code}: {detail}", fg="red", err=True)
            raise SystemExit(EXIT_CODES["API"])
    if not resp.text:
        return {}
    return resp.json()


def get_bearer_headers(creds):
    return {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }


def get_ads_headers(creds):
    return {
        **get_bearer_headers(creds),
        "developer-token": DEV_TOKEN,
        "login-customer-id": LOGIN_CUSTOMER_ID,
    }
