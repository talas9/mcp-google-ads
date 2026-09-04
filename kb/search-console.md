# Google Search Console API

## Status & Versions

The Search Console API has two co-existing API surface names that point to the same underlying service:

| Surface | Discovery name | Base URL | Status |
|---|---|---|---|
| **Canonical (per discovery doc, 2026-09-04)** | `searchconsole` v1 | `https://searchconsole.googleapis.com/webmasters/v3` (Search Analytics / Sites / Sitemaps) | Active — this is now the documented host |
| **Legacy host, still working** | `searchconsole` v1 | `https://www.googleapis.com/webmasters/v3` (Search Analytics / Sites / Sitemaps) | Active, no deprecation notice found |
| **Current** | `searchconsole` v1 | `https://searchconsole.googleapis.com/v1` (URL Inspection only) | Active |
| **Legacy name** | `webmasters` v3 | same endpoints | Still functional; discovery document support ended 2020-12-31 |

**Key finding, updated 2026-09-04 — the host moved in the discovery doc.** The `webmasters` v3 → `searchconsole` v1 rename was originally discovery-level only, and the *paths* are still `webmasters/v3/...`. But the live discovery document (revision `20260902`, fetched 2026-09-04 — the previous revision recorded here was `20260630`) now sets `rootUrl`/`baseUrl` to `https://searchconsole.googleapis.com/` for **every** resource, including `searchanalytics`, `sites` and `sitemaps` — not just URL Inspection. The canonical Search Analytics endpoint is therefore now:

```
POST https://searchconsole.googleapis.com/webmasters/v3/sites/{siteUrl}/searchAnalytics/query
```

**gads-cli is not broken.** Its `GSC_BASE = "https://www.googleapis.com/webmasters/v3"` still works: both hosts were probed unauthenticated on 2026-09-04 and both returned HTTP 401 "Login Required" (not 404), i.e. both route to a live service. The constant simply no longer matches the canonical discovery doc. **No deprecation notice for the `www.googleapis.com` host was found on any official page fetched today — whether or when it is retired is [unverified].** Examples further down this file still show the legacy host; they are functionally correct, and the canonical form is the one above.

Python client library callers should use `build('searchconsole', 'v1')` rather than `build('webmasters', 'v3')`.

The **URL Inspection API** (added January 2022) uses a different base host: `https://searchconsole.googleapis.com/v1`.

**No v2 exists.** Fetched the live discovery document directly (`https://www.googleapis.com/discovery/v1/apis/searchconsole/v1/rest`) on 2026-07-01: `"version": "v1"`, `"revision": "20260630"` (i.e. Google republished/re-validated this same v1 discovery doc as recently as 2026-06-30, one day before this refresh — there is still no `v2` and no announced successor). This confirms the API surface documented below is the current, actively-maintained one — not stale. [verified: live discovery doc, fetched 2026-07-01]

**Discovery doc also lists a `urlTestingTools.mobileFriendlyTest.run` method** (`POST v1/urlTestingTools/mobileFriendlyTest:run`) that is **not** in the endpoint tables below. Do not implement it: Google officially retired the entire Mobile-Friendly Test tool and API on 2023-12-01 (https://searchengineland.com/google-officially-drops-mobile-usability-report-mobile-friendly-test-tool-and-mobile-friendly-test-api-435377). The method definition is a leftover schema stub in the discovery doc; calling it does not return live results. [verified: live discovery doc schema, fetched 2026-07-01]

Sources:
- https://developers.google.com/webmaster-tools/v1/api_reference_index
- https://developers.google.com/search/blog/2020/08/search-console-api-announcements
- https://developers.google.com/search/blog/2020/12/search-console-api-updates
- https://www.googleapis.com/discovery/v1/apis/searchconsole/v1/rest (live discovery doc, revision 20260630, fetched 2026-07-01)

---

## Base URLs

| API group | Base URL |
|---|---|
| Search Analytics, Sites, Sitemaps (canonical, per discovery doc 2026-09-04) | `https://searchconsole.googleapis.com/webmasters/v3` |
| Search Analytics, Sites, Sitemaps (legacy host, still live — what gads-cli sends) | `https://www.googleapis.com/webmasters/v3` |
| URL Inspection | `https://searchconsole.googleapis.com/v1` |

Source: https://developers.google.com/webmaster-tools/v1/api_reference_index

---

## Auth / OAuth Scopes

All requests require OAuth 2.0. No API-key access is supported for the main API.

| Scope URI | Access |
|---|---|
| `https://www.googleapis.com/auth/webmasters` | Read + write |
| `https://www.googleapis.com/auth/webmasters.readonly` | Read-only |

The scope URIs retain the `webmasters` name even under the `searchconsole` v1 discovery name — there are no new scope URIs.

For read-only operations (analytics queries, listing sites, listing sitemaps) the `.readonly` scope is sufficient.

**Required headers on every request:**
```
Authorization: Bearer {access_token}
Content-Type: application/json   # only on POST/PUT with a body
```

Sources:
- https://developers.google.com/webmaster-tools/v1/how-tos/authorizing (last updated 2025-08-28 UTC)
- https://developers.google.com/webmaster-tools/v1/sites/list

---

## URL Encoding for siteUrl Path Parameter

**This is the #1 source of bugs when building new subcommands.**

The `{siteUrl}` segment in all path templates must be **percent-encoded**. The raw site URL is used as a key value, so every special character — especially `:`, `/`, and `.` — must be escaped.

```python
import urllib.parse
encoded = urllib.parse.quote(site_url, safe='')
# "https://shop.talas.ae/"  →  "https%3A%2F%2Fshop.talas.ae%2F"
# "sc-domain:talas.ae"      →  "sc-domain%3Atalas.ae"
```

### URL-prefix properties vs domain properties

| Property type | Raw siteUrl | Encoded for path |
|---|---|---|
| URL-prefix | `https://shop.talas.ae/` | `https%3A%2F%2Fshop.talas.ae%2F` |
| URL-prefix | `http://www.example.com/` | `http%3A%2F%2Fwww.example.com%2F` |
| Domain property | `sc-domain:talas.ae` | `sc-domain%3Atalas.ae` |
| Domain property | `sc-domain:example.com` | `sc-domain%3Aexample.com` |

- **URL-prefix** properties cover a specific URL and its subpaths (old-style verification)
- **Domain properties** (`sc-domain:` prefix) cover all protocols, subdomains, and paths — requires DNS TXT record verification. These return aggregated data across all URLs under the domain.

The `siteUrl` value returned by `sites.list` is always in its **un-encoded raw form** — store it as-is and encode only when building the request path.

---

## Resources & Endpoints

| Resource | Method | Path (relative to webmasters/v3 base) | Purpose | Source URL |
|---|---|---|---|---|
| sites | list | `GET /sites` | List all verified properties | https://developers.google.com/webmaster-tools/v1/sites/list |
| sites | get | `GET /sites/{siteUrl*}` | Get a single property | https://developers.google.com/webmaster-tools/v1/sites/get |
| sites | add | `PUT /sites/{siteUrl*}` | Add a property | https://developers.google.com/webmaster-tools/v1/api_reference_index |
| sites | delete | `DELETE /sites/{siteUrl*}` | Remove a property | https://developers.google.com/webmaster-tools/v1/api_reference_index |
| searchAnalytics | query | `POST /sites/{siteUrl*}/searchAnalytics/query` | Query search traffic data | https://developers.google.com/webmaster-tools/v1/searchanalytics/query |
| sitemaps | list | `GET /sites/{siteUrl*}/sitemaps` | List submitted sitemaps | https://developers.google.com/webmaster-tools/v1/sitemaps/list |
| sitemaps | get | `GET /sites/{siteUrl*}/sitemaps/{feedpath*}` | Get a single sitemap | https://developers.google.com/webmaster-tools/v1/api_reference_index |
| sitemaps | submit | `PUT /sites/{siteUrl*}/sitemaps/{feedpath*}` | Submit a sitemap | https://developers.google.com/webmaster-tools/v1/api_reference_index |
| sitemaps | delete | `DELETE /sites/{siteUrl*}/sitemaps/{feedpath*}` | Delete a sitemap | https://developers.google.com/webmaster-tools/v1/api_reference_index |
| urlInspection | index.inspect | `POST /urlInspection/index:inspect` | URL index inspection (**different base**: searchconsole.googleapis.com/v1) | https://developers.google.com/search/blog/2020/08/search-console-api-announcements |

> `*` = value must be percent-encoded in the URL path

---

## Endpoint Details with Concrete Examples

### GET /sites — sites.list

**Full URL:** `GET https://www.googleapis.com/webmasters/v3/sites`

No request body. No query parameters.

**Request:**
```http
GET https://www.googleapis.com/webmasters/v3/sites
Authorization: Bearer ya29.a0AfB_byC...
```

**Response:**
```json
{
  "siteEntry": [
    {
      "siteUrl": "https://shop.talas.ae/",
      "permissionLevel": "siteOwner"
    },
    {
      "siteUrl": "sc-domain:talas.ae",
      "permissionLevel": "siteOwner"
    },
    {
      "siteUrl": "https://talas.ae/",
      "permissionLevel": "siteRestrictedUser"
    }
  ]
}
```

**permissionLevel values:**

| Value | Meaning |
|---|---|
| `siteOwner` | Full owner — can add/remove users, verify, see all data |
| `siteFullUser` | Full data access, cannot manage verification |
| `siteRestrictedUser` | Limited data access |
| `siteUnverifiedUser` | Listed but not yet verified |

**Edge cases:**
- If the authenticated user has no verified sites, `siteEntry` is absent (not an empty array — the key is omitted entirely). Code must use `.get('siteEntry', [])`.
- `siteUrl` for a domain property always starts with `sc-domain:`.

Source: https://developers.google.com/webmaster-tools/v1/sites/list

---

### POST /sites/{siteUrl}/searchAnalytics/query — searchAnalytics.query

**Full URL:**
```
POST https://www.googleapis.com/webmasters/v3/sites/{percent-encoded-siteUrl}/searchAnalytics/query
```

**Concrete URL for shop.talas.ae:**
```
POST https://www.googleapis.com/webmasters/v3/sites/https%3A%2F%2Fshop.talas.ae%2F/searchAnalytics/query
```

#### Request Body Fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `startDate` | string (YYYY-MM-DD) | **Yes** | — | Pacific Time. Must be ≤ endDate |
| `endDate` | string (YYYY-MM-DD) | **Yes** | — | Pacific Time. Must be ≥ startDate |
| `dimensions[]` | list of string | No | (none — property-level aggregate) | Grouping: `country`, `device`, `page`, `query`, `searchAppearance`, `date`, `hour` |
| `type` | string | No | `"web"` | Search type: `"web"`, `"image"`, `"video"`, `"news"`, `"discover"`, `"googleNews"` |
| `dimensionFilterGroups[]` | list of object | No | — | Server-side filter groups (see examples below) |
| `aggregationType` | string | No | `"auto"` | `"auto"`, `"byPage"`, `"byProperty"`, `"byNewsShowcasePanel"`. Cannot use `byPage` when filtering/grouping by page |
| `rowLimit` | integer | No | 1,000 | Max **25,000** per request |
| `startRow` | integer | No | 0 | Zero-based row offset for pagination |
| `dataState` | string | No | `"final"` | `"final"` = confirmed only (~3 day lag); `"all"` = includes fresh/unconfirmed; `"hourly_all"` = hourly breakdown (requires `hour` dimension, added April 2025) |

#### Example 1 — Query + Page breakdown (most common)

**Request:**
```http
POST https://www.googleapis.com/webmasters/v3/sites/https%3A%2F%2Fshop.talas.ae%2F/searchAnalytics/query
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "startDate": "2026-05-25",
  "endDate": "2026-06-20",
  "dimensions": ["query", "page"],
  "type": "web",
  "rowLimit": 100,
  "startRow": 0,
  "dataState": "final"
}
```

**Response:**
```json
{
  "rows": [
    {
      "keys": ["tesla model 3 door panel uae", "https://shop.talas.ae/products/tesla-m3-door-panel"],
      "clicks": 47.0,
      "impressions": 312.0,
      "ctr": 0.1506,
      "position": 3.2
    },
    {
      "keys": ["tesla spare parts dubai", "https://shop.talas.ae/collections/tesla"],
      "clicks": 38.0,
      "impressions": 890.0,
      "ctr": 0.0427,
      "position": 7.8
    },
    {
      "keys": ["used tesla parts", "https://shop.talas.ae/"],
      "clicks": 21.0,
      "impressions": 450.0,
      "ctr": 0.0467,
      "position": 5.1
    }
  ],
  "responseAggregationType": "byPage"
}
```

- `keys[0]` = query string, `keys[1]` = page URL (matches `dimensions` order)
- `ctr` is a decimal fraction (0.1506 = 15.06%)
- `position` is 1-based average rank (lower = better)
- Sort: descending by clicks (unless `date` is in dimensions)

#### Example 2 — dimensionFilterGroups (filter to a specific query)

Use `dimensionFilterGroups` for server-side filtering so you only receive rows matching a condition. This avoids fetching all rows and filtering client-side.

**Request:**
```http
POST https://www.googleapis.com/webmasters/v3/sites/https%3A%2F%2Fshop.talas.ae%2F/searchAnalytics/query
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "startDate": "2026-05-01",
  "endDate": "2026-06-20",
  "dimensions": ["query", "page", "device"],
  "type": "web",
  "dimensionFilterGroups": [
    {
      "groupType": "and",
      "filters": [
        {
          "dimension": "query",
          "operator": "contains",
          "expression": "tesla"
        }
      ]
    }
  ],
  "rowLimit": 500,
  "dataState": "final"
}
```

**Filter object fields:**

| Field | Type | Values |
|---|---|---|
| `dimension` | string | `country`, `device`, `page`, `query`, `searchAppearance` |
| `operator` | string | `equals`, `notEquals`, `contains`, `notContains`, `includingRegex`, `excludingRegex` |
| `expression` | string | The filter value (case-insensitive for contains/equals) |

Multiple `filters[]` within one group are ANDed. Multiple `dimensionFilterGroups[]` are ORed.

#### Example 3 — Date breakdown with dataState: "all"

```http
POST https://www.googleapis.com/webmasters/v3/sites/https%3A%2F%2Fshop.talas.ae%2F/searchAnalytics/query
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "startDate": "2026-06-01",
  "endDate": "2026-06-22",
  "dimensions": ["date"],
  "type": "web",
  "rowLimit": 25000,
  "dataState": "all"
}
```

`dataState: "all"` includes data from the last 2-3 days that hasn't been finalized yet. Useful for monitoring recent trends but values will change as data is confirmed. **Do not use for decision-making** (aligns with project 24-48h attribution lag rule).

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

## Pagination

The API returns at most `rowLimit` rows (hard cap: 25,000) per request. To retrieve all rows for a large dataset, paginate using `startRow`.

### Pagination algorithm

```python
import urllib.parse
import requests

def fetch_all_rows(session, site_url, body):
    """Fetch all rows for a searchAnalytics query, paginating automatically."""
    encoded = urllib.parse.quote(site_url, safe='')
    url = f"https://www.googleapis.com/webmasters/v3/sites/{encoded}/searchAnalytics/query"
    
    page_size = 25_000
    start_row = 0
    all_rows = []
    
    while True:
        page_body = {**body, "rowLimit": page_size, "startRow": start_row}
        resp = session.post(url, json=page_body)
        resp.raise_for_status()
        data = resp.json()
        
        rows = data.get("rows", [])
        all_rows.extend(rows)
        
        # Stop when fewer rows than requested — we've reached the end
        if len(rows) < page_size:
            break
        
        start_row += page_size
    
    return all_rows
```

### Concrete page 1 → page 2 body change

**Page 1 request body:**
```json
{
  "startDate": "2026-05-01",
  "endDate": "2026-06-20",
  "dimensions": ["query"],
  "rowLimit": 25000,
  "startRow": 0
}
```

**Page 2 request body (only startRow changes):**
```json
{
  "startDate": "2026-05-01",
  "endDate": "2026-06-20",
  "dimensions": ["query"],
  "rowLimit": 25000,
  "startRow": 25000
}
```

**Stop condition:** `len(response["rows"]) < rowLimit` — if the response returns fewer rows than requested, you have all the data.

**Note:** If `rows` key is absent in the response (zero results), treat as empty — do not raise an error.

---

## Error Handling

### Common error shapes

**403 — Site not verified / no access:**
```json
{
  "error": {
    "code": 403,
    "message": "User does not have sufficient permission for site 'https://shop.talas.ae/'.",
    "status": "PERMISSION_DENIED",
    "errors": [
      {
        "message": "User does not have sufficient permission for site 'https://shop.talas.ae/'.",
        "domain": "youtube.quota",
        "reason": "forbidden"
      }
    ]
  }
}
```
Cause: The OAuth token's user doesn't have Search Console access to this property, or the property isn't verified. Also triggered if `siteUrl` in the path doesn't exactly match a verified property (including trailing slash differences).

**400 — Invalid dimension or request body:**
```json
{
  "error": {
    "code": 400,
    "message": "Invalid value at 'search_analytics_query_request.dimensions[0]' (type.googleapis.com/google.webmasters.v3.SearchAnalyticsQueryRequest.Dimension), \"badDimension\"",
    "status": "INVALID_ARGUMENT"
  }
}
```
Cause: Unknown dimension value, invalid `type`, `rowLimit` > 25000, or `startDate` > `endDate`.

**429 — Quota exceeded:**
```json
{
  "error": {
    "code": 429,
    "message": "Quota exceeded for quota metric 'webmasters.googleapis.com/default_requests' and limit 'DEFAULT-1MIN-SITE' of service 'webmasters.googleapis.com'.",
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "RATE_LIMIT_EXCEEDED",
        "domain": "googleapis.com",
        "metadata": {
          "quota_metric": "webmasters.googleapis.com/default_requests",
          "quota_limit": "DEFAULT-1MIN-SITE"
        }
      }
    ]
  }
}
```
Cause: Exceeding 1,200 QPM per site or 40,000 QPM per project for searchAnalytics. Backoff with exponential retry.

**401 — Token expired:**
```json
{
  "error": {
    "code": 401,
    "message": "Request had invalid authentication credentials.",
    "status": "UNAUTHENTICATED"
  }
}
```
Cause: Access token expired (typically 1-hour lifetime). Refresh using the refresh token.

---

## URL Inspection API

**Implemented in `gads_lib/gsc.py` as `gsc_url_inspect()`.**

Uses a **different base URL**: `https://searchconsole.googleapis.com/v1`

### POST /urlInspection/index:inspect

**Full URL:**
```
POST https://searchconsole.googleapis.com/v1/urlInspection/index:inspect
```

**Auth scopes required:**
- `https://www.googleapis.com/auth/webmasters` (read-write)
- `https://www.googleapis.com/auth/webmasters.readonly` (read-only, sufficient for inspection)

**Request:**
```http
POST https://searchconsole.googleapis.com/v1/urlInspection/index:inspect
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "inspectionUrl": "https://shop.talas.ae/products/tesla-m3-door-panel",
  "siteUrl": "https://shop.talas.ae/",
  "languageCode": "en-US"
}
```

**Request body fields:**

| Field | Type | Required | Notes |
|---|---|---|---|
| `inspectionUrl` | string | **Yes** | The specific page URL to inspect — must be within `siteUrl` |
| `siteUrl` | string | **Yes** | The verified Search Console property (raw, NOT encoded — it goes in the JSON body, not the URL path) |
| `languageCode` | string | No | BCP-47 language code for the response (e.g., `"en-US"`) |

**Note:** Unlike `searchAnalytics`, `siteUrl` here goes in the **JSON body** — it is NOT percent-encoded. Only path parameters need encoding.

**Response:**
```json
{
  "inspectionResult": {
    "inspectionResultLink": "https://search.google.com/search-console/inspect?resource_id=...",
    "indexStatusResult": {
      "verdict": "PASS",
      "coverageState": "Submitted and indexed",
      "robotsTxtState": "ALLOWED",
      "indexingState": "INDEXING_ALLOWED",
      "lastCrawlTime": "2026-06-18T14:32:00Z",
      "pageFetchState": "SUCCESSFUL",
      "googleCanonical": "https://shop.talas.ae/products/tesla-m3-door-panel",
      "userCanonical": "https://shop.talas.ae/products/tesla-m3-door-panel",
      "sitemap": ["https://shop.talas.ae/sitemap.xml"],
      "referringUrls": ["https://shop.talas.ae/collections/tesla"],
      "crawledAs": "DESKTOP"
    },
    "mobileUsabilityResult": {
      "verdict": "PASS"
    },
    "richResultsResult": {
      "verdict": "NEUTRAL"
    }
  }
}
```

**Key verdict values:** `PASS`, `FAIL`, `NEUTRAL`, `VERDICT_UNSPECIFIED`

**Key indexingState values:** `INDEXING_ALLOWED`, `BLOCKED_BY_META_TAG`, `BLOCKED_BY_HTTP_HEADER`, `BLOCKED_BY_ROBOTS_TXT`

**Key pageFetchState values:** `SUCCESSFUL`, `SOFT_404`, `BLOCKED_ROBOTS_TXT`, `NOT_FOUND`, `SERVER_ERROR`, `REDIRECT_ERROR`, `ACCESS_DENIED`, `BLOCKED_4XX`

**Quotas for URL Inspection:**
- 2,000 requests/day per site
- 600 requests/minute per site
- 10,000,000 QPD per project

**Implementation note for new `gsc inspect` subcommand:**
This endpoint requires a second `requests.Session` or at minimum a different base URL in `gsc.py`. The auth token is the same OAuth token — no additional credential setup needed as long as the `webmasters.readonly` scope is already granted.

Source: https://developers.google.com/search/blog/2020/08/search-console-api-announcements (URL Inspection API announcement, January 2022)

---

## sitemaps.list

**Full URL:**
```
GET https://www.googleapis.com/webmasters/v3/sites/{percent-encoded-siteUrl}/sitemaps
```

**Optional query parameter:** `sitemapIndex` (string) — filter to sitemaps nested under a specific sitemap index URL.

**Request:**
```http
GET https://www.googleapis.com/webmasters/v3/sites/https%3A%2F%2Fshop.talas.ae%2F/sitemaps
Authorization: Bearer ya29.a0AfB_byC...
```

**Response:**
```json
{
  "sitemap": [
    {
      "path": "https://shop.talas.ae/sitemap.xml",
      "lastSubmitted": "2026-04-10T08:12:00.000Z",
      "isPending": false,
      "isSitemapIndex": true,
      "type": "sitemap",
      "lastDownloaded": "2026-06-21T03:44:00.000Z",
      "warnings": "0",
      "errors": "0",
      "contents": [
        {
          "type": "web",
          "submitted": "1240",
          "indexed": "987"
        }
      ]
    }
  ]
}
```

Source: https://developers.google.com/webmaster-tools/v1/sitemaps/list

---

## Pagination & Quotas

### Pagination
Paginate `searchAnalytics.query` by incrementing `startRow` by `rowLimit`:
- `startRow: 0`, `rowLimit: 25000` → first page
- `startRow: 25000`, `rowLimit: 25000` → second page
- Stop when `len(rows) < rowLimit`
- Maximum 25,000 rows per single API response

### Rate Limits / Quotas

| Resource | Limit type | Limit |
|---|---|---|
| Search Analytics | Per-site QPM | 1,200 |
| Search Analytics | Per-user QPM | 1,200 |
| Search Analytics | Per-project QPD | 30,000,000 |
| Search Analytics | Per-project QPM | 40,000 |
| URL Inspection | Per-site QPD | 2,000 |
| URL Inspection | Per-site QPM | 600 |
| URL Inspection | Per-project QPD | 10,000,000 |
| URL Inspection | Per-project QPM | 15,000 |
| All other resources (sites, sitemaps) | Per-user QPS | 20 |
| All other resources (sites, sitemaps) | Per-user QPM | 200 |
| All other resources (sites, sitemaps) | Per-project QPD | 100,000,000 |

Source: https://developers.google.com/webmaster-tools/limits

---

## Gotchas

### URL encoding for siteUrl
The `{siteUrl}` path parameter must be **percent-encoded** when used in the URL path. For example:
- `https://shop.talas.ae/` → `https%3A%2F%2Fshop.talas.ae%2F`
- `sc-domain:talas.ae` → `sc-domain%3Atalas.ae`
- Use `urllib.parse.quote(site_url, safe='')` in Python
- **Exception:** For URL Inspection API, `siteUrl` goes in the JSON body — do NOT encode it there

### sc-domain: prefix for domain properties
Domain-wide properties (not URL-prefix properties) use the `sc-domain:` prefix:
- `sc-domain:talas.ae` (not `https://talas.ae`)
This prefix must also be URL-encoded when used in path parameters.
Domain properties aggregate across all subdomains and protocols — useful for total-site visibility.

### Trailing slashes matter
`https://shop.talas.ae/` and `https://shop.talas.ae` are different property identifiers. The value returned by `sites.list` is authoritative — use it exactly as returned.

### siteEntry key may be absent
When a user has no verified sites, the response is `{}` — the `siteEntry` key is missing entirely, not an empty array. Always use `.get('siteEntry', [])`.

### rows key may be absent
When a `searchAnalytics.query` returns zero results (valid date range with no data), the response is `{"responseAggregationType": "byProperty"}` with no `rows` key. Always use `.get('rows', [])`.

### Data freshness and attribution lag
- Default `dataState: "final"` excludes data that hasn't been confirmed by Google (~2-3 day lag typical)
- Use `dataState: "all"` to include unconfirmed recent data, but expect it to change
- **Never use same-day data** for decision-making (aligns with project rule: 24-48h attribution lag)

### Hourly data (added April 2025)
- Requires `dataState: "hourly_all"` and `"hour"` in `dimensions[]`
- Only available for recent date ranges (unverified — doc fetch returned no explicit cutoff)

### FAQ search appearance deprecated August 2026
- FAQ rich results stopped appearing in Google Search as of **2026-05-07**; the `searchAppearance` dimension value for FAQ rich results in the API is scheduled for full deprecation in **August 2026** (confirmed via web search against 2026 SEO/Search-Central coverage — Google's own dated blog post for this specific removal was not directly fetched, so treat the exact August 2026 date as **(unverified — third-party corroborated, not confirmed on an official dated Google page)**)
- Other `searchAppearance` values remain valid
- Structured-data support for practice-problem markup and a few lesser-used schemas was removed from Search Console (and its API-reported rich-result types) starting January 2026 (unverified — third-party summary only, no official dated source fetched)

### mobileFriendlyTest.run is a dead endpoint (do not implement)
- The live discovery document (`https://www.googleapis.com/discovery/v1/apis/searchconsole/v1/rest`, revision `20260630`, fetched 2026-07-01) still defines `urlTestingTools.mobileFriendlyTest.run` (`POST v1/urlTestingTools/mobileFriendlyTest:run`)
- Google officially retired the whole Mobile-Friendly Test tool + API on 2023-12-01 (https://searchengineland.com/google-officially-drops-mobile-usability-report-mobile-friendly-test-tool-and-mobile-friendly-test-api-435377) — the schema stub still shows up in discovery, but the service behind it is gone
- Do not build a `gsc mobile-friendly-test` subcommand against this; it will not return real results

### 2026 Search Console UI features are NOT new API fields
- Late-2025/2026 additions like the branded-vs-non-branded queries filter, "Query Groups", AI natural-language report configuration, weekly/monthly Performance-report aggregation, and Social Channels in Insights are **Search Console web-app (UI) features only**
- The live discovery document (revision `20260630`) shows **no new `dimensions[]` values, no new `type` values, and no new request/response fields** to support these — the `SearchAnalyticsQueryRequest`/`SearchAnalyticsQueryResponse` schemas are unchanged from what's documented in this file
- Several third-party SEO blogs describe these as "new API dimensions" — that claim is **not corroborated by the live discovery doc and should be treated as incorrect** for API-integration purposes [verified: live discovery doc schema dump, fetched 2026-07-01]

### rowLimit maximum is 25,000
- Values above 25,000 will be rejected with HTTP 400.
- The CLI currently uses whatever `rowLimit` is passed — caller must validate.

### aggregationType cannot combine byPage with page filtering
- If `dimensions` includes `"page"` or `dimensionFilterGroups` filters on `page`, you cannot set `aggregationType: "byPage"` — the API returns 400. Use `"auto"` or `"byProperty"` instead.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

## Coverage vs Current gads CLI

Current `gads_lib/gsc.py` uses:

| Feature | Used in CLI | Notes |
|---|---|---|
| `sites.list` (GET /sites) | Yes | Lists verified properties |
| `searchAnalytics.query` | Yes | Core analytics pull |
| `dimensions[]` parameter | Yes | Passed through from CLI args |
| `type` / search_type | Yes | Passed as `"web"` by default |
| `rowLimit` | Yes | Configurable |
| `startRow` pagination | Unknown — check source | If not implemented, queries are capped at rowLimit rows |
| `dataState` parameter | Unknown — check source | Omitted = `"final"`; adding `"all"` would include fresher data |
| `aggregationType` | Unknown — check source | Default is `"auto"` |
| `dimensionFilterGroups[]` | Likely not used | Allows server-side filtering before aggregation |
| Hourly data (`dataState: "hourly_all"`) | No | Added April 2025; needs `hour` dimension |
| `sitemaps.*` | Yes | `gsc_list_sitemaps()` implemented in `gads_lib/gsc.py` |
| `sites.get / add / delete` | No | Not implemented |
| URL Inspection API | Yes | `gsc_url_inspect()` in `gads_lib/gsc.py`; base URL `searchconsole.googleapis.com/v1`; 2,000 QPD per site limit |

**Coverage gaps worth noting for future work:**
1. **No pagination** — queries returning exactly `rowLimit` rows are silently truncated; add `startRow` loop
2. **`dataState` not configurable** — cannot request fresher data when needed; default is `"final"` (~3 day lag)
3. **No `dimensionFilterGroups`** — all filtering is done client-side after fetching; server-side filtering is cheaper and avoids rowLimit truncation

---

## Sources

All claims in this document are sourced from the URLs below. Re-verified 2026-07-01 (previous pass: June 2026); per-page "last updated" dates as fetched are noted where the doc shows one:

- https://developers.google.com/webmaster-tools/v1/api_reference_index (no v2/deprecation notice; last updated 2024-07-23 UTC as displayed on the page, re-fetched 2026-07-01)
- https://developers.google.com/webmaster-tools/v1/searchanalytics/query (last updated 2026-05-20 UTC — newer than the previous KB pass; content re-checked, no breaking changes found)
- https://developers.google.com/webmaster-tools/v1/sites/list (last updated 2024-07-23 UTC, unchanged)
- https://developers.google.com/webmaster-tools/v1/sitemaps/list (last updated 2024-07-23 UTC, unchanged)
- https://developers.google.com/webmaster-tools/v1/how-tos/authorizing (last updated 2025-08-28 UTC, unchanged — scopes identical)
- https://developers.google.com/webmaster-tools/limits (last updated 2025-08-28 UTC, unchanged — quotas identical)
- https://developers.google.com/search/blog/2020/08/search-console-api-announcements
- https://developers.google.com/search/blog/2020/12/search-console-api-updates
- https://developers.google.com/webmaster-tools/search-console-api-original/v3/sites/get
- https://www.googleapis.com/discovery/v1/apis/searchconsole/v1/rest — live discovery document, revision `20260630`, fetched + parsed directly (not summarized) on 2026-07-01; authoritative source for exact enum values (`type`, `dimensions`, `dataState`, `aggregationType`, filter `operator`/`dimension`) and the full method list, including the confirmation that no `v2` exists and that `urlTestingTools.mobileFriendlyTest.run` is a stale/dead schema entry
- https://searchengineland.com/google-officially-drops-mobile-usability-report-mobile-friendly-test-tool-and-mobile-friendly-test-api-435377 — confirms Mobile-Friendly Test API retirement effective 2023-12-01
- WebSearch results (2026-07-01, not an official Google page) corroborating: FAQ rich results stopped 2026-05-07 / API deprecation slated August 2026; practice-problem structured-data removal January 2026; 2026 Search Console UI additions (branded queries filter, Query Groups, AI report config) — all flagged `(unverified)` above where no dated official Google page was directly fetched

---

## Developer Guide

Reference: https://developers.google.com/webmaster-tools

### Search Analytics API — Request Schema

`POST /sites/{siteUrl*}/searchAnalytics/query`

Full request body schema:

```json
{
  "startDate":              "YYYY-MM-DD",
  "endDate":                "YYYY-MM-DD",
  "dimensions":             ["query", "page", "country", "device", "searchAppearance", "date"],
  "type":                   "web",
  "aggregationType":        "AUTO",
  "rowLimit":               25000,
  "startRow":               0,
  "dataState":              "final",
  "dimensionFilterGroups":  []
}
```

| Field | Type | Required | Default | Constraints |
|---|---|---|---|---|
| `startDate` | string (YYYY-MM-DD) | Yes | — | Pacific Time; must be <= endDate |
| `endDate` | string (YYYY-MM-DD) | Yes | — | Pacific Time; must be >= startDate |
| `dimensions` | string[] | No | (none) | Zero or more dimension values; order determines `keys[]` order in response |
| `type` | string | No | `"web"` | SearchType enum; see SearchType Values section |
| `aggregationType` | string | No | `"AUTO"` | `"AUTO"`, `"BY_PROPERTY"`, `"BY_PAGE"`, `"BY_NEWS_SHOWCASE_PANEL"` |
| `rowLimit` | integer | No | 1000 | Hard maximum: 25000 |
| `startRow` | integer | No | 0 | Zero-based row offset for pagination |
| `dataState` | string | No | `"final"` | `"final"`, `"all"`, `"hourly_all"` |
| `dimensionFilterGroups` | object[] | No | (none) | Server-side filter groups; see dimensionFilterGroups section |

**Response shape:**

```json
{
  "rows": [
    {
      "keys":        ["<dim1-value>", "<dim2-value>"],
      "clicks":      0.0,
      "impressions": 0.0,
      "ctr":         0.0,
      "position":    0.0
    }
  ],
  "responseAggregationType": "byPage"
}
```

- `rows` key is absent (not an empty array) when there is no data — always use `.get("rows", [])`.
- `keys[]` order mirrors the `dimensions[]` order in the request.
- `ctr` is a decimal fraction (0.15 = 15%).
- `position` is 1-based average rank; lower is better.
- `responseAggregationType` reports what aggregation the server actually applied.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### Dimensions

Valid dimension values for `dimensions[]`:

| Dimension | Description | Combinable |
|---|---|---|
| `query` | Search query string | Yes |
| `page` | URL of the page that appeared in results | Yes |
| `country` | ISO 3166-1 alpha-3 country code (e.g., `"ARE"`) | Yes |
| `device` | `"DESKTOP"`, `"MOBILE"`, `"TABLET"` | Yes |
| `searchAppearance` | Rich result type, AMP, etc. (see docs for current enum values) | No — cannot be combined with other dimensions |
| `date` | Calendar date (YYYY-MM-DD) | Yes |
| `hour` | Hour of day (0–23); requires `dataState: "hourly_all"` | Yes |

**Behavior when combined:**
When multiple dimensions are specified, each unique combination of dimension values produces a separate row. For example, `["query", "page"]` returns one row per (query, page) pair. The `keys[]` array in each row contains values in the same order as `dimensions[]`.

**Behavior when no dimensions are specified:**
The API returns a single aggregated row for the entire site across the date range. No `keys[]` in the row.

**searchAppearance restriction:**
`searchAppearance` cannot be combined with any other dimension in a single request. Request it alone if you need rich-result breakdown.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### SearchType Values

The `type` field (also seen as `searchType` in older docs) controls which index the query runs against.

| Value | Data covered |
|---|---|
| `web` | Standard web search results (default) |
| `image` | Google Image Search results |
| `video` | Google Video Search results |
| `news` | Google News tab results |
| `googleNews` | news.google.com and Google News app |
| `discover` | Google Discover feed (no query data — query dimension is unsupported) |

**Correction (2026-07-01):** A previous version of this document listed `chromeNotifications` as a valid `type` value. That value does **not** appear in the live discovery document's `SearchAnalyticsQueryRequest.type` enum (`WEB`, `IMAGE`, `VIDEO`, `NEWS`, `DISCOVER`, `GOOGLE_NEWS` only — fetched and dumped directly from `https://www.googleapis.com/discovery/v1/apis/searchconsole/v1/rest`, revision `20260630`) and no independent web source corroborates it ever being a documented, callable value. Treat `chromeNotifications` as incorrect/unverified and do not implement it. [verified: live discovery doc schema, fetched 2026-07-01]

**Notes:**
- `discover` does not support the `query` dimension — omit it or the API returns 400.
- `googleNews` and `news` are distinct: `news` = news tab in web search; `googleNews` = the standalone News product.
- Default is `web` if `type` is omitted.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query; enum cross-checked against https://www.googleapis.com/discovery/v1/apis/searchconsole/v1/rest (revision 20260630)

---

### AggregationType

Controls how data is aggregated when a URL appears in search results under multiple properties.

| Value | Behavior | Use case |
|---|---|---|
| `AUTO` | Server chooses: `BY_PAGE` when `page` is in dimensions, otherwise `BY_PROPERTY` | Default; safe for most queries |
| `BY_PROPERTY` | Aggregates impressions/clicks at the property level; a page counted once per property per query | Site-level performance totals |
| `BY_PAGE` | Aggregates at the URL level; each URL counted separately | URL-level analysis, finding which pages rank |
| `BY_NEWS_SHOWCASE_PANEL` | Aggregates for News Showcase panels | News Showcase-specific reporting |

**Constraint:** Cannot use `BY_PAGE` when the `page` dimension is included or when filtering on `page` in `dimensionFilterGroups`. The API returns HTTP 400. Use `AUTO` instead — it will apply `BY_PAGE` automatically.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### DataState

Controls which data maturity level to include in the response.

| Value | Description | Typical lag | Use case |
|---|---|---|---|
| `final` | Only confirmed, fully processed data | ~3 days | Decision-making, reporting |
| `all` | Confirmed + unconfirmed recent data | ~0 days (but values change) | Trend monitoring; do not use for decisions |
| `hourly_all` | Hourly granularity (unconfirmed) | <1 day | Real-time monitoring; requires `hour` in dimensions |

**Date range effects:**
- With `dataState: "final"`, the most recent 2-3 days are excluded even if included in `startDate`/`endDate`.
- With `dataState: "all"`, recent data is present but values will change as Google finalizes it.
- `hourly_all` was added in April 2025 and requires the `hour` dimension. Historical hourly data availability varies.

**Project rule alignment:** Per the talas-ads project rule (24-48h attribution lag), always use `dataState: "final"` for performance analysis and decision-making. Only use `"all"` for trend-spotting with explicit acknowledgment that values will change.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### Pagination

The API enforces a hard maximum of **25,000 rows per request**. Large datasets (high-volume sites, wide date ranges, many dimensions) will be truncated if not paginated.

**Pattern:** Increment `startRow` by `rowLimit` on each subsequent request. Stop when the response returns fewer rows than `rowLimit`.

```python
def fetch_all_rows(session, encoded_site_url, body):
    """Paginate searchAnalytics.query to retrieve all rows."""
    url = f"https://www.googleapis.com/webmasters/v3/sites/{encoded_site_url}/searchAnalytics/query"
    page_size = 25_000
    start_row = 0
    all_rows = []

    while True:
        page_body = {**body, "rowLimit": page_size, "startRow": start_row}
        resp = session.post(url, json=page_body)
        resp.raise_for_status()
        data = resp.json()

        rows = data.get("rows", [])  # absent key = zero results
        all_rows.extend(rows)

        if len(rows) < page_size:
            break  # fewer rows than requested = last page

        start_row += page_size

    return all_rows
```

**Detecting truncation without full pagination:**
If you only want to detect whether results were truncated (not fetch all), check `len(response["rows"]) == rowLimit`. If true, there may be more rows.

**rowLimit max:** 25,000. Values above this return HTTP 400.

**startRow offset:** Zero-based. Page 1 = `startRow: 0`; page 2 = `startRow: 25000`; page N = `startRow: (N-1) * 25000`.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### dimensionFilterGroups

Server-side filtering applied before aggregation and before `rowLimit` is enforced. Use this to avoid fetching all rows and filtering client-side — critical for large sites where unfiltered results exceed 25,000 rows.

**Top-level structure:**

```json
"dimensionFilterGroups": [
  {
    "groupType": "AND",
    "filters": [
      {
        "dimension":  "query",
        "operator":   "contains",
        "expression": "tesla"
      },
      {
        "dimension":  "device",
        "operator":   "equals",
        "expression": "MOBILE"
      }
    ]
  },
  {
    "groupType": "AND",
    "filters": [
      {
        "dimension":  "page",
        "operator":   "includingRegex",
        "expression": ".*/collections/.*"
      }
    ]
  }
]
```

**Logic:**
- Filters within a single group are **ANDed** together (`groupType: "AND"` is the only supported value).
- Multiple groups in `dimensionFilterGroups[]` are **ORed** together (a row matches if it satisfies any group).

**Filter object fields:**

| Field | Type | Valid values |
|---|---|---|
| `dimension` | string | `"country"`, `"device"`, `"page"`, `"query"`, `"searchAppearance"` |
| `operator` | string | `"equals"`, `"notEquals"`, `"contains"`, `"notContains"`, `"includingRegex"`, `"excludingRegex"` |
| `expression` | string | The filter value; case-insensitive for `contains`/`equals`/`notContains`/`notEquals`; RE2 syntax for regex operators |

**Operator notes:**
- `equals` / `notEquals` — exact match (case-insensitive).
- `contains` / `notContains` — substring match (case-insensitive).
- `includingRegex` / `excludingRegex` — RE2 regex; partial match (anchoring with `^`/`$` if needed).
- `dimension` in a filter does not need to be listed in `dimensions[]` — you can filter on a dimension you are not grouping by.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### Sites API

Manages which properties (sites) are verified in Search Console.

**Base URL:** `https://www.googleapis.com/webmasters/v3`

| Operation | Method + Path | Auth |
|---|---|---|
| List all properties | `GET /sites` | readonly |
| Get a single property | `GET /sites/{siteUrl*}` | readonly |
| Add a property | `PUT /sites/{siteUrl*}` | write |
| Delete a property | `DELETE /sites/{siteUrl*}` | write |

`*` = `siteUrl` must be percent-encoded in the path.

**siteEntry schema (from list response):**

```json
{
  "siteUrl":         "https://shop.talas.ae/",
  "permissionLevel": "siteOwner"
}
```

**permissionLevel enum:**

| Value | Description |
|---|---|
| `siteOwner` | Full owner — can manage users, verification, all data |
| `siteFullUser` | Full data access; cannot manage verification |
| `siteRestrictedUser` | Limited data access |
| `siteUnverifiedUser` | Site listed but not verified |

**Edge cases:**
- `sites.list` response has no `siteEntry` key (not an empty array) when the user has no verified sites. Always use `.get("siteEntry", [])`.
- `sites.add` (PUT) does not verify the property — it only registers the intent. Actual verification happens through the Search Console UI or DNS/HTML methods.
- `sites.delete` removes the property from the user's Search Console account. It does NOT remove other users' access.

Source: https://developers.google.com/webmaster-tools/v1/sites/list

---

### Sitemaps API

Manages submitted sitemaps for a verified property.

**Base URL:** `https://www.googleapis.com/webmasters/v3`

| Operation | Method + Path | Auth |
|---|---|---|
| List sitemaps | `GET /sites/{siteUrl*}/sitemaps` | readonly |
| Get a sitemap | `GET /sites/{siteUrl*}/sitemaps/{feedpath*}` | readonly |
| Submit a sitemap | `PUT /sites/{siteUrl*}/sitemaps/{feedpath*}` | write |
| Delete a sitemap | `DELETE /sites/{siteUrl*}/sitemaps/{feedpath*}` | write |

`*` = percent-encoded in the path. `{feedpath}` is the full URL of the sitemap (e.g., `https%3A%2F%2Fshop.talas.ae%2Fsitemap.xml`).

**Sitemap entry schema:**

```json
{
  "path":           "https://shop.talas.ae/sitemap.xml",
  "lastSubmitted":  "2026-04-10T08:12:00.000Z",
  "isPending":      false,
  "isSitemapIndex": true,
  "type":           "sitemap",
  "lastDownloaded": "2026-06-21T03:44:00.000Z",
  "warnings":       "0",
  "errors":         "0",
  "contents": [
    {
      "type":      "web",
      "submitted": "1240",
      "indexed":   "987"
    }
  ]
}
```

**Fields:**
- `warnings` and `errors` are string-encoded integers (not numbers).
- `contents[].submitted` and `contents[].indexed` are also strings.
- `isSitemapIndex: true` means this is a sitemap index file pointing to child sitemaps.
- `isPending: true` means Google has not yet downloaded/processed the sitemap.
- `type` on the root object is always `"sitemap"`.
- `contents[].type` values: `"web"`, `"image"`, `"video"`, `"news"`.

**Optional query parameter for list:**
`sitemapIndex` (string, URL-encoded) — filters to sitemaps nested under a specific sitemap index.

Source: https://developers.google.com/webmaster-tools/v1/sitemaps/list

---

### URL Inspection API

Inspects the index status, AMP validity, mobile usability, and rich result eligibility of a specific URL.

**Base URL:** `https://searchconsole.googleapis.com/v1` (different from all other GSC endpoints)

**Endpoint:** `POST /urlInspection/index:inspect`

**Request schema:**

```json
{
  "inspectionUrl": "https://shop.talas.ae/products/tesla-m3-door-panel",
  "siteUrl":       "https://shop.talas.ae/",
  "languageCode":  "en-US"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `inspectionUrl` | string | Yes | Full URL of the page to inspect; must be within `siteUrl` property |
| `siteUrl` | string | Yes | Verified Search Console property; goes in JSON body — NOT percent-encoded |
| `languageCode` | string | No | BCP-47 (e.g., `"en-US"`, `"ar"`); affects response language |

**Response schema:**

```json
{
  "inspectionResult": {
    "inspectionResultLink": "https://search.google.com/search-console/inspect?resource_id=...",
    "indexStatusResult": {
      "verdict":        "PASS",
      "coverageState":  "Submitted and indexed",
      "robotsTxtState": "ALLOWED",
      "indexingState":  "INDEXING_ALLOWED",
      "lastCrawlTime":  "2026-06-18T14:32:00Z",
      "pageFetchState": "SUCCESSFUL",
      "googleCanonical":"https://shop.talas.ae/products/tesla-m3-door-panel",
      "userCanonical":  "https://shop.talas.ae/products/tesla-m3-door-panel",
      "sitemap":        ["https://shop.talas.ae/sitemap.xml"],
      "referringUrls":  ["https://shop.talas.ae/collections/tesla"],
      "crawledAs":      "DESKTOP"
    },
    "ampResult": {
      "verdict": "NOT_APPLICABLE"
    },
    "mobileUsabilityResult": {
      "verdict": "PASS",
      "issues":  []
    },
    "richResultsResult": {
      "verdict":    "NEUTRAL",
      "detectedItems": []
    }
  }
}
```

**coverageState enum (indexStatusResult.coverageState):** Human-readable string; key states include:
- `"Submitted and indexed"` — indexed and in sitemap
- `"Crawled - currently not indexed"` — crawled but Google chose not to index
- `"Discovered - currently not indexed"` — known but not yet crawled
- `"Excluded by 'noindex' tag"` — blocked by meta/header
- `"Blocked by robots.txt"` — blocked by robots
- `"Redirect error"` — redirect chain issue
- `"Soft 404"` — page returns 200 but appears to have no content

**verdict enum:** `"PASS"`, `"FAIL"`, `"NEUTRAL"`, `"VERDICT_UNSPECIFIED"`

**indexingState enum:** `"INDEXING_ALLOWED"`, `"BLOCKED_BY_META_TAG"`, `"BLOCKED_BY_HTTP_HEADER"`, `"BLOCKED_BY_ROBOTS_TXT"`

**pageFetchState enum:** `"SUCCESSFUL"`, `"SOFT_404"`, `"BLOCKED_ROBOTS_TXT"`, `"NOT_FOUND"`, `"SERVER_ERROR"`, `"REDIRECT_ERROR"`, `"ACCESS_DENIED"`, `"BLOCKED_4XX"`

**crawledAs enum:** `"DESKTOP"`, `"MOBILE"`, `"CRAWLED_AS_UNSPECIFIED"`

Source: https://developers.google.com/webmaster-tools/v1/urlInspection.index/inspect

---

### OAuth Requirements

| Scope | Required for |
|---|---|
| `https://www.googleapis.com/auth/webmasters.readonly` | All read operations: searchAnalytics.query, sites.list, sites.get, sitemaps.list, sitemaps.get, urlInspection.index.inspect |
| `https://www.googleapis.com/auth/webmasters` | All write operations: sites.add, sites.delete, sitemaps.submit, sitemaps.delete |

**Notes:**
- The scope URIs retain the `webmasters` name even under the `searchconsole` v1 discovery name — there are no new scope URIs.
- Both scopes can be requested simultaneously; the broader `webmasters` scope implicitly grants `webmasters.readonly` access.
- For the URL Inspection API, `webmasters.readonly` is sufficient (inspection is a read operation despite using POST).
- If only `webmasters.readonly` is granted, any mutating call (`sites.add`, `sitemaps.submit`, etc.) returns HTTP 403.

The `gads-cli/generate_token.py` requests `webmasters.readonly` (as of v3.4.0+). To enable write operations, add `webmasters` to SCOPES and regenerate the token.

Source: https://developers.google.com/webmaster-tools/v1/how-tos/authorizing

---

### Rate Limits

| Resource | Quota dimension | Limit |
|---|---|---|
| Search Analytics | Per-site QPM | 1,200 |
| Search Analytics | Per-user QPM | 1,200 |
| Search Analytics | Per-project QPM | 40,000 |
| Search Analytics | Per-project QPD | 30,000,000 |
| URL Inspection | Per-site QPD | 2,000 |
| URL Inspection | Per-site QPM | 600 |
| URL Inspection | Per-project QPM | 15,000 |
| URL Inspection | Per-project QPD | 10,000,000 |
| Sites, Sitemaps | Per-user QPS | 20 |
| Sites, Sitemaps | Per-user QPM | 200 |
| Sites, Sitemaps | Per-project QPD | 100,000,000 |

**429 handling pattern:**

```python
import time

def post_with_retry(session, url, body, max_retries=5):
    backoff = 1.0
    for attempt in range(max_retries):
        resp = session.post(url, json=body)
        if resp.status_code == 429:
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError(f"Exceeded {max_retries} retries due to rate limiting")
```

Key points:
- Exponential backoff with cap (60 seconds is a reasonable ceiling).
- 429 `Retry-After` header may be present; use it if provided.
- The quota limit name in the 429 body (e.g., `DEFAULT-1MIN-SITE`) identifies which dimension was exceeded.

Source: https://developers.google.com/webmaster-tools/limits

---

### Date Range Limits

| Aspect | Detail |
|---|---|
| Maximum historical range | ~16 months (data older than ~16 months is not returned) |
| Most recent data with `dataState: "final"` | ~3 days lag (data from last 2-3 days excluded) |
| Most recent data with `dataState: "all"` | Near-real-time (within hours) but values will change |
| Hourly data (`dataState: "hourly_all"`) | Available for recent dates only; exact cutoff not documented |
| Date field format | YYYY-MM-DD (Pacific Time) |

**Practical implications:**
- `startDate` more than ~16 months ago: API returns data only from within the 16-month window, silently ignoring older dates (does not return an error).
- Date comparisons (YoY, MoM) are reliable only within the 16-month window.
- For freshness-sensitive use cases (e.g., "did my page disappear from results today?"), use `dataState: "all"` and treat values as preliminary.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query

---

### Best Practices

**1. Always paginate with rowLimit=25000 + startRow loop.**
Never assume a single request returns all data. For any query with broad dimensions (especially `query` alone over a busy site), results can exceed 25,000 rows. Use the pagination pattern in the Pagination section above.

```python
# Correct pattern
body = {"startDate": "...", "endDate": "...", "dimensions": ["query"], "rowLimit": 25000, "startRow": 0}
all_rows = fetch_all_rows(session, encoded_site_url, body)
```

**2. Use `BY_PAGE` aggregationType for URL-level analysis.**
When you need to know how individual pages perform (which URLs rank, for which queries), set `aggregationType: "BY_PAGE"` — but only when `page` is NOT in `dimensions[]`. If `page` is in dimensions, the API applies `BY_PAGE` automatically (or use `AUTO`).

**3. Use `BY_PROPERTY` for site-level totals.**
When computing site-wide click/impression totals for reporting, use `aggregationType: "BY_PROPERTY"` to avoid double-counting pages that appear under multiple sub-properties.

**4. Use server-side `dimensionFilterGroups` instead of client-side filtering.**
Filtering client-side after fetching all rows wastes quota and hits the 25,000-row truncation limit. Apply `dimensionFilterGroups` to get only the rows you need, then paginate only what passes the filter.

```python
# Prefer this (server-side)
body["dimensionFilterGroups"] = [{"groupType": "AND", "filters": [{"dimension": "query", "operator": "contains", "expression": "tesla"}]}]

# Over this (client-side)
rows = [r for r in all_rows if "tesla" in r["keys"][0]]
```

**5. Percent-encode `siteUrl` in path parameters; never encode in JSON bodies.**
- Path parameter (`/sites/{siteUrl}`): always `urllib.parse.quote(site_url, safe='')`.
- JSON body (`inspectionUrl` request): use the raw URL string, no encoding.

**6. Handle absent keys defensively.**
- `rows` key is absent when zero results: use `.get("rows", [])`.
- `siteEntry` key is absent when no sites: use `.get("siteEntry", [])`.
- `mobileUsabilityResult.issues` may be absent or empty: use `.get("issues", [])`.

**7. Respect `dataState: "final"` for decisions.**
Use `dataState: "final"` (the default) for all performance analysis and budget/bid decisions. The 3-day lag is expected behavior, not a data problem. Only use `"all"` for trend-spotting with explicit caveat.

**8. Match `siteUrl` exactly as returned by `sites.list`.**
Trailing slashes, protocol, and subdomain matter. `https://shop.talas.ae/` and `https://shop.talas.ae` are different properties. Retrieve the authoritative form via `sites.list` and store it verbatim.

Source: https://developers.google.com/webmaster-tools/v1/searchanalytics/query
