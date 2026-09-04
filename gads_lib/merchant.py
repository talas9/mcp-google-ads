"""Google Merchant Center API client (Merchant API v1).

API: Merchant API v1 (accounts, products, datasources sub-APIs)
KB reference: kb/merchant-api.md (relative to gads-cli root)
Official docs: https://developers.google.com/merchant/api
"""
from .config import MERCHANT_CENTER_ID
from .http import get_bearer_headers, request_json

# Merchant API v1 — per-sub-API host with versioned path segments.
# Each sub-API has its OWN version segment before the resource name.
MA_ACCOUNTS = "https://merchantapi.googleapis.com/accounts/v1"
MA_PRODUCTS = "https://merchantapi.googleapis.com/products/v1"
MA_DATASOURCES = "https://merchantapi.googleapis.com/datasources/v1"
MA_REPORTS = "https://merchantapi.googleapis.com/reports/v1"


# KB: kb/merchant-api.md § accounts | https://developers.google.com/merchant/api/reference/rest/accounts_v1beta/accounts/get
def mc_get_account(creds, as_json=False):
    """Fetch the Merchant Center account.

    Response shape (single object):
      name            — "accounts/{ID}"
      accountId       — numeric string
      accountName     — display name
      testAccount     — bool
      timeZone        — {id, version}
      languageCode    — BCP-47 string
      adultContent    — bool
    """
    return request_json(
        "GET",
        f"{MA_ACCOUNTS}/accounts/{MERCHANT_CENTER_ID}",
        headers=get_bearer_headers(creds),
        as_json=as_json,
    )


# KB: kb/merchant-api.md § account-issues | https://developers.google.com/merchant/api/reference/rest/accounts_v1beta/accounts.issues/list
def mc_get_account_status(creds, as_json=False):
    """List account-level issues for the Merchant Center account.

    In Merchant API v1, account status is surfaced as a paginated list of
    AccountIssue resources under accounts/{ID}/issues.

    Response shape:
      accountIssues[] — array of issue objects, each with:
        name                  — resource name
        title                 — human-readable title
        severity              — CRITICAL | ERROR | SUGGESTION
        impactedDestinations[]— affected destinations
        detail                — detailed description string
        documentationUri      — link to help docs
    """
    params = {"pageSize": 50}
    return request_json(
        "GET",
        f"{MA_ACCOUNTS}/accounts/{MERCHANT_CENTER_ID}/issues",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )


# KB: kb/merchant-api.md § products | https://developers.google.com/merchant/api/reference/rest/products_v1beta/accounts.products/list
def mc_list_products(creds, max_results=50, page_token=None, as_json=False):
    """List products in the Merchant Center account.

    Response shape:
      products[] — array of product objects, each with:
        name                              — resource name "accounts/{ID}/products/{product_id}"
        offerId                           — merchant-assigned product id
        contentLanguage                   — BCP-47 language code
        feedLabel                         — country/feed label
        dataSource                        — data source resource name
        productStatus.destinationStatuses[]   — per-destination approval statuses
        productStatus.itemLevelIssues[]       — item-level issues
        productAttributes.title           — product title
        productAttributes.description     — product description
        productAttributes.link            — canonical URL
        productAttributes.brand           — brand string
        productAttributes.condition       — condition enum
        productAttributes.availability    — availability enum
        productAttributes.gtins[]         — list of GTINs
        productAttributes.price.amountMicros   — price as micros (divide by 1e6)
        productAttributes.price.currencyCode   — ISO 4217 currency
    """
    params = {"pageSize": max_results}
    if page_token:
        params["pageToken"] = page_token
    return request_json(
        "GET",
        f"{MA_PRODUCTS}/accounts/{MERCHANT_CENTER_ID}/products",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )


# KB: kb/merchant-api.md § products | https://developers.google.com/merchant/api/reference/rest/products_v1beta/accounts.products/list
def mc_list_product_statuses(creds, max_results=50, page_token=None, as_json=False):
    """List product statuses for the Merchant Center account.

    NOTE: Merchant API v1 has NO standalone productstatuses endpoint.
    Product status (approval state, item-level issues, destination statuses)
    is folded directly into the products resource.  This function delegates
    to the same products list endpoint as mc_list_products and returns the
    identical response so callers continue to work without change.

    Response shape: same as mc_list_products — top-level key is `products[]`.
    Status fields per product are under productStatus.*
    """
    params = {"pageSize": max_results}
    if page_token:
        params["pageToken"] = page_token
    return request_json(
        "GET",
        f"{MA_PRODUCTS}/accounts/{MERCHANT_CENTER_ID}/products",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )


# KB: kb/merchant-api.md § datasources | https://developers.google.com/merchant/api/reference/rest/datasources_v1beta/accounts.dataSources/list
def mc_list_datafeeds(creds, as_json=False):
    """List data sources (formerly datafeeds) in the Merchant Center account.

    Response shape:
      dataSources[] — array of DataSource objects, each with:
        name           — resource name "accounts/{ID}/dataSources/{dataSourceId}"
        dataSourceId   — numeric string
        displayName    — human-readable display name
        input          — input type enum (e.g. API, FILE, CRAWL, MANUAL)
        fileInput.fileName      — filename for file-based sources
        fileInput.fileInputType — file input type enum
        (additional union-type fields present depending on source type)
    """
    return request_json(
        "GET",
        f"{MA_DATASOURCES}/accounts/{MERCHANT_CENTER_ID}/dataSources",
        headers=get_bearer_headers(creds),
        as_json=as_json,
    )


# KB: kb/merchant-api.md § shipping | https://developers.google.com/merchant/api/reference/rest/accounts_v1beta/accounts.shippingSettings/get
def mc_get_shipping(creds, as_json=False):
    """Fetch shipping settings for the Merchant Center account.

    Response shape (single ShippingSettings object):
      services[] — array of Service objects, each with:
        serviceName        — display name for the service
        active             — bool
        deliveryCountries[]— list of country codes
        currencyCode       — ISO 4217 currency for this service
        deliveryTime       — DeliveryTime message with min/max transit days etc.
        rateGroups[]       — array of RateGroup objects with shipping rates
    """
    return request_json(
        "GET",
        f"{MA_ACCOUNTS}/accounts/{MERCHANT_CENTER_ID}/shippingSettings",
        headers=get_bearer_headers(creds),
        as_json=as_json,
    )


# KB: kb/merchant-api.md § return-policies | https://developers.google.com/merchant/api/reference/rest/accounts_v1beta/accounts.onlineReturnPolicies/list
def mc_get_return_policy(creds, as_json=False):
    """List online return policies for the Merchant Center account.

    Response shape:
      onlineReturnPolicies[] — array of OnlineReturnPolicy objects, each with:
        name           — resource name
        returnPolicyId — policy ID string
        label          — policy label
        countries[]    — list of country codes this policy applies to
        policy         — Policy message with type and days fields
    """
    params = {"pageSize": 10}
    return request_json(
        "GET",
        f"{MA_ACCOUNTS}/accounts/{MERCHANT_CENTER_ID}/onlineReturnPolicies",
        headers=get_bearer_headers(creds),
        params=params,
        as_json=as_json,
    )


# KB: kb/merchant-api.md § reports | https://developers.google.com/merchant/api/reference/rest/reports_v1/accounts.reports/search
# Verified 2026-09-04 via the reports_v1 discovery doc
# (https://merchantapi.googleapis.com/$discovery/rest?version=reports_v1): method id
# merchantapi.accounts.reports.search, path "reports/v1/{+parent}/reports:search",
# request schema SearchRequest {query, pageSize, pageToken}, response schema
# SearchResponse {results[] of ReportRow, nextPageToken}.
def mc_reports_search(creds, query, page_size=1000, page_token=None, as_json=False):
    """Execute a Merchant reports query.

    IMPORTANT: the Merchant reports query language is its own SQL-like dialect
    (SELECT/FROM/WHERE/ORDER BY/LIMIT over tables like product_performance_view) --
    it is NOT GAQL (Google Ads Query Language) and the two are not interchangeable.
    See kb/merchant-api.md "Reports Sub-API" for the supported tables and columns.

    POST /reports/v1/accounts/{merchantId}/reports:search
    Body: {"query": <str>, "pageSize": <int>, "pageToken": <str, optional>}

    Response shape:
      results[]      -- array of ReportRow objects. Each ReportRow is a typed
                         union -- only the key matching the queried table is
                         populated, e.g. a query against product_performance_view
                         returns rows shaped {"productPerformanceView": {...}}.
      nextPageToken   -- pagination cursor; absent/empty on the last page.
    """
    body = {"query": query, "pageSize": page_size}
    if page_token:
        body["pageToken"] = page_token
    return request_json(
        "POST",
        f"{MA_REPORTS}/accounts/{MERCHANT_CENTER_ID}/reports:search",
        headers=get_bearer_headers(creds),
        json_body=body,
        as_json=as_json,
    )


# KB: kb/merchant-api.md § developer-registration
def mc_register_gcp(creds, developer_email: str, account_id: str | None = None,
                    as_json: bool = False):
    """Register the caller's GCP project with a Merchant Center account.

    Calls the Developer Registration API:
      POST /accounts/v1/accounts/{account}/developerRegistration:registerGcp
    with body {"developerEmail": developer_email}.

    This resolves the ``auth/gcp_unknown`` / ``GCP_NOT_REGISTERED`` error that
    occurs when a GCP project has not been explicitly associated with the MC
    account.  After a successful registration, wait ~5 minutes before retrying
    merchant API calls.

    Args:
        creds:            OAuth credentials (scope: content).
        developer_email:  Email address of the GCP project developer to register.
        account_id:       Merchant Center account ID (default: MERCHANT_CENTER_ID
                          from config).
        as_json:          Route errors through the JSON error envelope (--json mode).

    Returns:
        The raw API response dict on success.  On error, behaviour depends on
        ``as_json`` — see ``request_json`` error routing.

    Response shape:
        On success the API returns an empty object ``{}`` or a simple ack.
        The CLI prints a success message with next steps.
    """
    account = account_id or MERCHANT_CENTER_ID
    return request_json(
        "POST",
        f"{MA_ACCOUNTS}/accounts/{account}/developerRegistration:registerGcp",
        headers=get_bearer_headers(creds),
        json_body={"developerEmail": developer_email},
        as_json=as_json,
        # Explicit, in addition to the URL-shape default: this registers a
        # GCP project, so correctness must not depend on http.py's URL
        # classification alone.
        idempotent=False,
    )
