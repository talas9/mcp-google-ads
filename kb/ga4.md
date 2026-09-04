# Google Analytics 4 APIs

## Status & Versions

_Last verified against official docs: **2026-09-04** (previous pass 2026-07-01)._

**2026-09-04 re-verification result: no drift.** Checked against the live discovery directory and
discovery documents fetched that day: Data API has only `v1beta` (`preferred: true`, revision
`20260902`, `baseUrl https://analyticsdata.googleapis.com/`) — no `v1` GA release exists. Admin API
exposes both `v1alpha` and `v1beta` with `v1beta` `preferred: true` (revision `20260901`), and
`properties.keyEvents` on v1beta carries `get / patch / delete / list / create`. The Data API quota
table later in this file (200,000 tokens/property/day, 40,000/property/hour, 14,000/project/property/hour,
10 concurrent, 10 server errors/hour, 120 potentially-thresholded/hour; Analytics 360 at 10x on
tokens/concurrency/errors) matches the official quotas page exactly. Scopes `analytics.readonly`
(reads) and `analytics.edit` (Admin key-event writes) confirmed on the OAuth scopes page.

### Data API
- **v1beta** — stable, production-ready; the primary version used for reporting
- **v1alpha** — experimental; adds funnel reports, audience lists, recurring audience lists, report tasks, property quota snapshots, and (new, 2026-04-23) **Conversion Reporting** via `runReport` — see Developer Guide §16
- No separate `v1` (fully GA) release found; `v1beta` is still the current stable channel as of 2026-07-01 — re-confirmed against the live REST resource listing (no `v1` resource group exists, only `v1beta` and `v1alpha`)
- Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest

### Admin API
- **v1beta** — stable; "No breaking changes are expected in this channel" — covers account/property management, **key events** (used by gads CLI, see below), custom dimensions/metrics, service links, data retention settings, and (new, 2026-06-18) `UpdateReportingIdentitySettings` + `can_edit` field on `PropertySummary`
- **v1alpha** — early preview; adds audiences, BigQuery links, Search Ads 360, channel groups, event edit rules, subproperties, data redaction, SKAdNetwork conversion value schemas, Google Signals settings, and (new, 2026-04-14) `GetUserProvidedDataSettings`
- Source: https://developers.google.com/analytics/devguides/config/admin/v1, changelog: https://developers.google.com/analytics/devguides/config/admin/v1/changelog

### Admin API v1alpha vs v1beta — Key Events specifically

The `properties.keyEvents` resource exists in **both** v1alpha and v1beta with identical method sets (create, delete, get, list, patch). No behavioral differences are documented between the two versions for key events.

**gads CLI status: MIGRATED.** As of gads-cli **v3.8.2**, `GA4_ADMIN_BASE` in `gads_lib/ga4.py` points at `https://analyticsadmin.googleapis.com/v1beta` (previously `v1alpha`). All key-events calls (`list`, `create`, `delete`) now run on the stable v1beta channel — confirmed against source (`gads_lib/ga4.py:18`), `kb/manifest.json`, `kb/INDEX.md`, and `gads kb check` (all report `ga4 Admin API: v1beta`). This section previously described the CLI as still using v1alpha with a migration "recommended" — that has been corrected below and throughout this file: v1beta is what the CLI actually calls today.

**v1alpha sunset:** No sunset date has been announced (as of 2026-07-01). Google typically promotes features from v1alpha → v1beta when they stabilize, rather than removing v1alpha.

Sources: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents, https://developers.google.com/analytics/devguides/config/admin/v1

---

## Base URLs

| API | Base URL |
|-----|----------|
| Data API (v1beta) | `https://analyticsdata.googleapis.com/v1beta` |
| Data API (v1alpha) | `https://analyticsdata.googleapis.com/v1alpha` |
| Admin API (v1beta) | `https://analyticsadmin.googleapis.com/v1beta` |
| Admin API (v1alpha) | `https://analyticsadmin.googleapis.com/v1alpha` |

Sources: https://developers.google.com/analytics/devguides/reporting/data/v1/rest, https://developers.google.com/analytics/devguides/config/admin/v1/rest

---

## Auth / OAuth Scopes

| Scope | URI | What it Covers |
|-------|-----|----------------|
| `analytics.readonly` | `https://www.googleapis.com/auth/analytics.readonly` | Read all Data API endpoints (`runReport`, `runRealtimeReport`, `getMetadata`, etc.) and read Admin API resources (key events list/get) |
| `analytics.edit` | `https://www.googleapis.com/auth/analytics.edit` | Mutate Admin API resources: create, patch, delete key events, custom dimensions, etc. |
| `analytics` | `https://www.googleapis.com/auth/analytics` | Full access (superset of `analytics.readonly`); also accepted by `runReport` and `getMetadata` |

The gads CLI project's `generate_token.py` already includes both `analytics.readonly` and `analytics.edit`. If a `403 Forbidden` appears on write calls, the token was generated before `analytics.edit` was added — regenerate it.

Sources: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport, https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/list

---

## Resources & Endpoints

### Data API (v1beta)

| Resource | Method | HTTP | Path | Purpose | Source URL |
|----------|--------|------|------|---------|------------|
| properties | runReport | POST | `/v1beta/{property=properties/*}:runReport` | Standard customized report of GA4 event data | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport |
| properties | runRealtimeReport | POST | `/v1beta/{property=properties/*}:runRealtimeReport` | Real-time event data (last 30 min, up to 60 min for 360) | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport |
| properties | runPivotReport | POST | `/v1beta/{property=properties/*}:runPivotReport` | Pivot-format report of GA4 event data | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties | batchRunReports | POST | `/v1beta/{property=properties/*}:batchRunReports` | Multiple standard reports in one request | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties | batchRunPivotReports | POST | `/v1beta/{property=properties/*}:batchRunPivotReports` | Multiple pivot reports in one request | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties | checkCompatibility | POST | `/v1beta/{property=properties/*}:checkCompatibility` | Check which dimensions/metrics can be added together | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.metadata | get | GET | `/v1beta/{name=properties/*/metadata}` | Dimension/metric catalog for a property | https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/getMetadata |
| properties.audienceExports | create | POST | `/v1beta/{parent=properties/*}/audienceExports` | Create an audience export for later retrieval | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.audienceExports | get | GET | `/v1beta/{name=properties/*/audienceExports/*}` | Get audience export metadata | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.audienceExports | list | GET | `/v1beta/{parent=properties/*}/audienceExports` | List all audience exports for a property | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.audienceExports | query | POST | `/v1beta/{name=properties/*/audienceExports/*}:query` | Retrieve audience export user rows | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |

### Data API (v1alpha — experimental)

| Resource | Method | HTTP | Path | Purpose | Source URL |
|----------|--------|------|------|---------|------------|
| properties | runFunnelReport | POST | `/v1alpha/{property=properties/*}:runFunnelReport` | Funnel report (alpha only) | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties | getPropertyQuotasSnapshot | GET | `/v1alpha/{name=properties/*/propertyQuotasSnapshot}` | All quota categories for a property | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.audienceLists | create/get/list/query | POST/GET | `/v1alpha/{parent=properties/*}/audienceLists` | Audience lists (alpha predecessor to audienceExports) | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.recurringAudienceLists | create/get/list | POST/GET | `/v1alpha/{parent=properties/*}/recurringAudienceLists` | Scheduled recurring audience list snapshots | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |
| properties.reportTasks | create/get/list/query | POST/GET | `/v1alpha/{parent=properties/*}/reportTasks` | Async large report tasks | https://developers.google.com/analytics/devguides/reporting/data/v1/rest |

### Admin API (v1beta — key events used by current gads CLI)

`GA4_ADMIN_BASE = https://analyticsadmin.googleapis.com/v1beta` (`gads_lib/ga4.py:18`, migrated from v1alpha in gads-cli v3.8.2).

| Resource | Method | HTTP | Path | Purpose | Source URL |
|----------|--------|------|------|---------|------------|
| properties.keyEvents | list | GET | `/v1beta/{parent=properties/*}/keyEvents` | List all key events for a property (paginated) | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/list |
| properties.keyEvents | create | POST | `/v1beta/{parent=properties/*}/keyEvents` | Create a new key event | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents |
| properties.keyEvents | get | GET | `/v1beta/{name=properties/*/keyEvents/*}` | Get a single key event | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents |
| properties.keyEvents | patch | PATCH | `/v1beta/{keyEvent.name=properties/*/keyEvents/*}` | Update key event fields (e.g. countingMethod) | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents |
| properties.keyEvents | delete | DELETE | `/v1beta/{name=properties/*/keyEvents/*}` | Delete a key event | https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents |

### Admin API (v1alpha — same resource, early-preview channel)

The `properties.keyEvents` resource exposes the same five methods (create, delete, get, list, patch) in v1alpha too. No documented behavioral differences vs v1beta for key events. This is the version the gads CLI used **before** v3.8.2; kept here only for historical/compatibility reference — do not build new code against it.

To use it: replace `analyticsadmin.googleapis.com/v1beta` with `analyticsadmin.googleapis.com/v1alpha` in the base URL. No other changes needed for key events.

Source: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1alpha/properties.keyEvents

---

## Concrete Examples — Priority Endpoints

All examples use:
- Property ID: `271773771` (from `GOOGLE_GA4_PROPERTY_ID`)
- Token: obtained via `google-auth` library — `credentials.token` after `credentials.refresh(Request())`

---

### POST /v1beta/properties/{pid}:runReport

**Full HTTP request:**

```
POST https://analyticsdata.googleapis.com/v1beta/properties/271773771:runReport
Authorization: Bearer ya29.a0ARrdaM...{token}
Content-Type: application/json

{
  "dimensions": [
    {"name": "sessionSource"},
    {"name": "sessionMedium"}
  ],
  "metrics": [
    {"name": "sessions"},
    {"name": "keyEvents"},
    {"name": "totalRevenue"}
  ],
  "dateRanges": [
    {"startDate": "7daysAgo", "endDate": "yesterday"}
  ],
  "orderBys": [
    {"metric": {"metricName": "sessions"}, "desc": true}
  ],
  "limit": 100,
  "offset": 0,
  "returnPropertyQuota": true
}
```

**All request fields:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `dimensions[]` | array of `{name: string}` | optional | Max ~9 dimensions per request |
| `metrics[]` | array of `{name: string}` | optional | At least one dimension or metric required |
| `dateRanges[]` | array of `{startDate, endDate}` | optional (default: none) | Accepts `"today"`, `"yesterday"`, `"NdaysAgo"`, `"YYYY-MM-DD"`. Up to 4 ranges. |
| `dimensionFilter` | `FilterExpression` | optional | SQL WHERE equivalent on dimensions |
| `metricFilter` | `FilterExpression` | optional | SQL HAVING equivalent, applied post-aggregation |
| `offset` | integer | optional | 0-indexed row offset for pagination (default: 0) |
| `limit` | integer | optional | Max rows to return (default: 10,000; max: 250,000) |
| `orderBys[]` | array | optional | Each element is `{metric: {metricName}, desc: bool}` or `{dimension: {dimensionName}, desc: bool}` |
| `metricAggregations[]` | array of enum | optional | `"TOTAL"`, `"MINIMUM"`, `"MAXIMUM"`, `"COUNT"` — appends aggregate rows |
| `keepEmptyRows` | boolean | optional | Include rows with zero metric values (default: false) |
| `returnPropertyQuota` | boolean | optional | Include quota state in response (default: false) |
| `currencyCode` | string | optional | ISO 4217; overrides property default |
| `comparisons[]` | array | optional | Side-by-side comparison columns |
| `cohortSpec` | object | optional | Cohort analysis configuration |

**Example response:**

```json
{
  "dimensionHeaders": [
    {"name": "sessionSource"},
    {"name": "sessionMedium"}
  ],
  "metricHeaders": [
    {"name": "sessions", "type": "TYPE_INTEGER"},
    {"name": "keyEvents", "type": "TYPE_INTEGER"},
    {"name": "totalRevenue", "type": "TYPE_CURRENCY"}
  ],
  "rows": [
    {
      "dimensionValues": [
        {"value": "google"},
        {"value": "cpc"}
      ],
      "metricValues": [
        {"value": "1842"},
        {"value": "37"},
        {"value": "4120.50"}
      ]
    },
    {
      "dimensionValues": [
        {"value": "google"},
        {"value": "organic"}
      ],
      "metricValues": [
        {"value": "923"},
        {"value": "11"},
        {"value": "890.00"}
      ]
    },
    {
      "dimensionValues": [
        {"value": "(direct)"},
        {"value": "(none)"}
      ],
      "metricValues": [
        {"value": "511"},
        {"value": "8"},
        {"value": "630.00"}
      ]
    }
  ],
  "rowCount": 12,
  "metadata": {
    "currencyCode": "AED",
    "timeZone": "Asia/Dubai",
    "dataLossFromOtherRow": false,
    "schemaRestrictionResponse": {
      "activeMetricRestrictions": []
    }
  },
  "propertyQuota": {
    "tokensPerDay": {"consumed": 14, "remaining": 199986},
    "tokensPerHour": {"consumed": 14, "remaining": 39986},
    "concurrentRequests": {"consumed": 0, "remaining": 10},
    "serverErrorsPerProjectPerHour": {"consumed": 0, "remaining": 10},
    "potentiallyThresholdedRequestsPerHour": {"consumed": 0, "remaining": 120}
  },
  "kind": "analyticsData#runReport"
}
```

**Key response field notes:**
- `rows[i].dimensionValues[j].value` — always a string, even for numeric dimension values
- `rows[i].metricValues[j].value` — always a string; parse to int/float as needed based on `metricHeaders[j].type`
- `rowCount` — total rows matching the query, NOT the number of rows returned (used to compute whether more pages exist: `if offset + len(rows) < rowCount: fetch next page`)
- Metric types: `TYPE_INTEGER`, `TYPE_FLOAT`, `TYPE_CURRENCY`, `TYPE_SECONDS`, `TYPE_MILLISECONDS`, `TYPE_MINUTES`, `TYPE_HOURS`, `TYPE_STANDARD`, `TYPE_CURRENCY`, `TYPE_FEET`, `TYPE_MILES`, `TYPE_METERS`, `TYPE_KILOMETERS`

**Pagination pattern:**
```python
offset = 0
limit = 10000
all_rows = []
while True:
    body["offset"] = offset
    body["limit"] = limit
    resp = requests.post(url, json=body, headers=headers).json()
    rows = resp.get("rows", [])
    all_rows.extend(rows)
    row_count = resp.get("rowCount", 0)
    offset += len(rows)
    if offset >= row_count or not rows:
        break
```

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport

---

### POST /v1beta/properties/{pid}:runRealtimeReport

**Full HTTP request:**

```
POST https://analyticsdata.googleapis.com/v1beta/properties/271773771:runRealtimeReport
Authorization: Bearer ya29.a0ARrdaM...{token}
Content-Type: application/json

{
  "dimensions": [
    {"name": "city"},
    {"name": "deviceCategory"}
  ],
  "metrics": [
    {"name": "activeUsers"}
  ],
  "minuteRanges": [
    {"name": "last_30_min", "startMinutesAgo": 29, "endMinutesAgo": 0}
  ],
  "orderBys": [
    {"metric": {"metricName": "activeUsers"}, "desc": true}
  ],
  "limit": 50,
  "returnPropertyQuota": true
}
```

**All request fields:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `dimensions[]` | array of `{name: string}` | optional | Realtime-specific dimensions available (e.g. `"city"`, `"country"`, `"deviceCategory"`, `"platform"`, `"unifiedScreenName"`) |
| `metrics[]` | array of `{name: string}` | optional | Realtime metrics: `"activeUsers"`, `"screenPageViews"`, `"eventCount"` |
| `minuteRanges[]` | array of `{name?, startMinutesAgo, endMinutesAgo}` | optional | Default = last 30 min. Max 2 ranges. Values: 0 (now) to 29 (standard) / 59 (360). `name` is optional label for multi-range responses. |
| `dimensionFilter` | `FilterExpression` | optional | Same structure as runReport |
| `metricFilter` | `FilterExpression` | optional | Same structure as runReport |
| `limit` | integer | optional | Max rows (default 10,000; max 250,000) |
| `metricAggregations[]` | array of enum | optional | Same as runReport |
| `orderBys[]` | array | optional | Same as runReport |
| `returnPropertyQuota` | boolean | optional | Include realtime quota state |

**NOT valid in runRealtimeReport** (will cause 400 error):
- `dateRanges` — use `minuteRanges` instead
- `offset` — realtime has no pagination
- `keepEmptyRows`
- `cohortSpec`
- `comparisons`

**Example response:**

```json
{
  "dimensionHeaders": [
    {"name": "city"},
    {"name": "deviceCategory"}
  ],
  "metricHeaders": [
    {"name": "activeUsers", "type": "TYPE_INTEGER"}
  ],
  "rows": [
    {
      "dimensionValues": [{"value": "Dubai"}, {"value": "mobile"}],
      "metricValues": [{"value": "23"}]
    },
    {
      "dimensionValues": [{"value": "Abu Dhabi"}, {"value": "mobile"}],
      "metricValues": [{"value": "7"}]
    },
    {
      "dimensionValues": [{"value": "Dubai"}, {"value": "desktop"}],
      "metricValues": [{"value": "4"}]
    }
  ],
  "rowCount": 8,
  "propertyQuota": {
    "tokensPerDay": {"consumed": 3, "remaining": 199997},
    "tokensPerHour": {"consumed": 3, "remaining": 39997},
    "concurrentRequests": {"consumed": 0, "remaining": 10},
    "serverErrorsPerProjectPerHour": {"consumed": 0, "remaining": 10}
  },
  "kind": "analyticsData#runRealtimeReport"
}
```

**Realtime-specific notes:**
- `rowCount` may be less than `limit`; there is no more data to page through
- Data reflects events received within the last 30 minutes (standard) or 60 minutes (360)
- Events appear typically within seconds of firing; some latency is expected
- Realtime dimensions are a subset of standard dimensions — not all standard dimensions work in realtime

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport

---

### GET /v1beta/properties/{pid}/metadata

**Full HTTP request:**

```
GET https://analyticsdata.googleapis.com/v1beta/properties/271773771/metadata
Authorization: Bearer ya29.a0ARrdaM...{token}
```

No request body. No query parameters except the path parameter.

- Use `properties/0/metadata` to get only universal dimensions/metrics (no property-specific custom ones)

**Example response (abbreviated — real response has 200+ entries):**

```json
{
  "name": "properties/271773771/metadata",
  "dimensions": [
    {
      "apiName": "city",
      "uiName": "City",
      "description": "The city from which the user activity originated.",
      "category": "Geography"
    },
    {
      "apiName": "country",
      "uiName": "Country",
      "description": "The country from which the user activity originated.",
      "category": "Geography"
    },
    {
      "apiName": "sessionSource",
      "uiName": "Session source",
      "description": "The source that initiated a session.",
      "category": "Traffic source"
    },
    {
      "apiName": "sessionMedium",
      "uiName": "Session medium",
      "description": "The medium that initiated a session.",
      "category": "Traffic source"
    },
    {
      "apiName": "deviceCategory",
      "uiName": "Device category",
      "description": "The type of device: Desktop, Tablet, or Mobile.",
      "category": "Platform / Device"
    },
    {
      "apiName": "customEvent:branch",
      "uiName": "branch (custom event)",
      "description": "Custom event parameter 'branch'",
      "category": "Custom",
      "customDefinition": true
    }
  ],
  "metrics": [
    {
      "apiName": "activeUsers",
      "uiName": "Active users",
      "description": "The number of distinct users who visited your site or app.",
      "type": "TYPE_INTEGER",
      "category": "User"
    },
    {
      "apiName": "sessions",
      "uiName": "Sessions",
      "description": "The number of sessions that began on your site or app.",
      "type": "TYPE_INTEGER",
      "category": "Session"
    },
    {
      "apiName": "keyEvents",
      "uiName": "Key events",
      "description": "The number of times users triggered a key event.",
      "type": "TYPE_INTEGER",
      "category": "Conversions"
    },
    {
      "apiName": "keyEvents:purchase",
      "uiName": "Purchase key events",
      "description": "The number of times users triggered the 'purchase' key event.",
      "type": "TYPE_INTEGER",
      "category": "Conversions",
      "customDefinition": true
    },
    {
      "apiName": "keyEvents:whatsapp_click",
      "uiName": "whatsapp_click key events",
      "description": "The number of times users triggered the 'whatsapp_click' key event.",
      "type": "TYPE_INTEGER",
      "category": "Conversions",
      "customDefinition": true
    },
    {
      "apiName": "totalRevenue",
      "uiName": "Total revenue",
      "description": "The sum of revenue from purchases, subscriptions, and advertising.",
      "type": "TYPE_CURRENCY",
      "category": "Revenue"
    }
  ]
}
```

**Key notes:**
- `customDefinition: true` marks property-specific dimensions/metrics (custom events, key event metrics)
- Key event metrics have `apiName` prefix `keyEvents:` followed by the event name
- Custom event parameters have prefix `customEvent:` (event-scoped) or `customUser:` (user-scoped)
- Use this endpoint first to discover available dimension/metric names before building runReport requests
- No pagination — returns all entries in one call (can be large; cache it)

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/getMetadata

---

### GET /v1beta/properties/{pid}/keyEvents (list)

**Full HTTP request** (as issued by `gads_lib/ga4.py::list_key_events`, `GA4_ADMIN_BASE = v1beta`):

```
GET https://analyticsadmin.googleapis.com/v1beta/properties/271773771/keyEvents?pageSize=200
Authorization: Bearer ya29.a0ARrdaM...{token}
```

No request body. Query parameters:

| Parameter | Type | Required | Notes |
|-----------|------|----------|-------|
| `pageSize` | integer | optional | Max 200 (default 50). The gads CLI uses `pageSize=200`. |
| `pageToken` | string | optional | Opaque token from previous response's `nextPageToken` |

**Example response:**

```json
{
  "keyEvents": [
    {
      "name": "properties/271773771/keyEvents/11111111",
      "eventName": "purchase",
      "createTime": "2024-03-15T08:22:14.000000Z",
      "deletable": true,
      "custom": false,
      "countingMethod": "ONCE_PER_EVENT",
      "defaultValue": {
        "numericValue": 0.0,
        "currencyCode": "AED"
      }
    },
    {
      "name": "properties/271773771/keyEvents/22222222",
      "eventName": "whatsapp_click",
      "createTime": "2024-06-01T11:45:00.000000Z",
      "deletable": true,
      "custom": true,
      "countingMethod": "ONCE_PER_EVENT"
    },
    {
      "name": "properties/271773771/keyEvents/33333333",
      "eventName": "begin_checkout",
      "createTime": "2024-06-01T11:45:01.000000Z",
      "deletable": true,
      "custom": false,
      "countingMethod": "ONCE_PER_SESSION"
    }
  ]
}
```

When there are more pages:
```json
{
  "keyEvents": [...],
  "nextPageToken": "Cg8KDXByb3BlcnRpZXMv..."
}
```

**Pagination pattern:**
```python
page_token = None
all_events = []
while True:
    params = {"pageSize": 200}
    if page_token:
        params["pageToken"] = page_token
    resp = requests.get(url, params=params, headers=headers).json()
    all_events.extend(resp.get("keyEvents", []))
    page_token = resp.get("nextPageToken")
    if not page_token:
        break
```

Source: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/list

---

### POST /v1beta/properties/{pid}/keyEvents (create)

**Full HTTP request** (as issued by `gads_lib/ga4.py::create_key_event`):

```
POST https://analyticsadmin.googleapis.com/v1beta/properties/271773771/keyEvents
Authorization: Bearer ya29.a0ARrdaM...{token}
Content-Type: application/json

{
  "eventName": "form_submit",
  "countingMethod": "ONCE_PER_EVENT"
}
```

**All request body fields:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `eventName` | string | **required** | GA4 event name exactly as tracked (e.g. `"form_submit"`, `"whatsapp_click"`). Immutable after creation. Must match an event that GA4 actually receives. |
| `countingMethod` | enum | **required** | `"ONCE_PER_EVENT"` or `"ONCE_PER_SESSION"` |
| `defaultValue.numericValue` | number | optional | Default monetary value for this key event |
| `defaultValue.currencyCode` | string | optional | ISO 4217 (e.g. `"AED"`) |

**Do NOT send:** `name`, `createTime`, `deletable`, `custom` — these are output-only and will be ignored or cause an error.

**Success response (201 Created):**

```json
{
  "name": "properties/271773771/keyEvents/44444444",
  "eventName": "form_submit",
  "createTime": "2026-06-23T10:30:00.000000Z",
  "deletable": true,
  "custom": true,
  "countingMethod": "ONCE_PER_EVENT"
}
```

**409 Conflict — event already exists as a key event:**

```json
{
  "error": {
    "code": 409,
    "message": "Key event already exists: form_submit",
    "status": "ALREADY_EXISTS",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ResourceInfo",
        "resourceType": "analyticsadmin.googleapis.com/KeyEvent",
        "resourceName": "properties/271773771/keyEvents/44444444",
        "description": "A Key Event already exists with this event name."
      }
    ]
  }
}
```

**Handling 409 in the CLI:** `ga4.py::create_key_event` treats 409 as "already exists" — it re-looks up the existing entry via `list_key_events` and returns it with `_already_exists: True` instead of raising.

Source: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents

---

### DELETE /v1beta/{keyEvent.name}

**Critical:** The path uses the **full resource name** from the `name` field of the KeyEvent object — NOT the `eventName` string. The `keyEventId` segment is the numeric ID from `name` (e.g. `"44444444"` from `"properties/271773771/keyEvents/44444444"`).

**Full HTTP request** (as issued by `gads_lib/ga4.py::delete_key_event`):

```
DELETE https://analyticsadmin.googleapis.com/v1beta/properties/271773771/keyEvents/44444444
Authorization: Bearer ya29.a0ARrdaM...{token}
```

No request body. No query parameters.

**Success response:** HTTP 200 with empty body `{}`

**404 — key event not found or wrong ID:**

```json
{
  "error": {
    "code": 404,
    "message": "Key event not found.",
    "status": "NOT_FOUND"
  }
}
```

**403 — wrong scope (analytics.readonly instead of analytics.edit):**

```json
{
  "error": {
    "code": 403,
    "message": "Request had insufficient authentication scopes.",
    "status": "PERMISSION_DENIED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
        "domain": "googleapis.com",
        "metadata": {
          "method": "google.analytics.admin.v1beta.AnalyticsAdminService.DeleteKeyEvent",
          "service": "analyticsadmin.googleapis.com"
        }
      }
    ]
  }
}
```

**Pattern in gads CLI:** The CLI lists key events first (to get the `name` field), then calls delete using the `name`. The `eventName` string alone is NOT sufficient to delete — you must resolve it to a `name` first via list.

```python
# Correct delete pattern (mirrors gads_lib/ga4.py::delete_key_event):
# 1. List to find name
events = list_key_events(pid)  # returns [{name: "properties/X/keyEvents/Y", eventName: "foo", ...}]
match = next((e for e in events if e["eventName"] == target_event_name), None)
if match:
    delete_url = f"https://analyticsadmin.googleapis.com/v1beta/{match['name']}"
    requests.delete(delete_url, headers=headers)
```

Source: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents

---

## Key Request/Response Fields — Reference

### runReport — complete field reference

**Request body** (`POST /v1beta/properties/{pid}:runReport`):

```json
{
  "dimensions": [{"name": "city"}],
  "metrics": [{"name": "totalUsers"}],
  "dateRanges": [{"startDate": "2025-01-01", "endDate": "today"}],
  "dimensionFilter": {
    "filter": {
      "fieldName": "country",
      "stringFilter": {"matchType": "EXACT", "value": "United Arab Emirates"}
    }
  },
  "metricFilter": {
    "filter": {
      "fieldName": "totalUsers",
      "numericFilter": {"operation": "GREATER_THAN", "value": {"int64Value": "100"}}
    }
  },
  "offset": 0,
  "limit": 10000,
  "orderBys": [{"metric": {"metricName": "totalUsers"}, "desc": true}],
  "metricAggregations": ["TOTAL", "MAXIMUM", "MINIMUM"],
  "keepEmptyRows": false,
  "returnPropertyQuota": true,
  "currencyCode": "AED",
  "comparisons": []
}
```

- `limit` default: 10,000; max: 250,000
- `offset` is 0-indexed (not pageToken-based)
- `dateRanges` supports up to 4 ranges; use `startDate`/`endDate` with values like `"today"`, `"yesterday"`, `"7daysAgo"`, or `"YYYY-MM-DD"`

**FilterExpression structures:**

```json
// Single filter
{"filter": {"fieldName": "city", "stringFilter": {"value": "Dubai"}}}

// AND of multiple filters
{"andGroup": {"expressions": [
  {"filter": {"fieldName": "country", "stringFilter": {"value": "United Arab Emirates"}}},
  {"filter": {"fieldName": "deviceCategory", "stringFilter": {"value": "mobile"}}}
]}}

// OR of multiple filters
{"orGroup": {"expressions": [...]}}

// NOT
{"notExpression": {"filter": {...}}}

// inListFilter (any of N values)
{"filter": {"fieldName": "city", "inListFilter": {"values": ["Dubai", "Abu Dhabi", "Sharjah"]}}}

// betweenFilter (numeric range)
{"filter": {"fieldName": "sessions", "betweenFilter": {
  "fromValue": {"int64Value": "10"},
  "toValue": {"int64Value": "100"}
}}}
```

**stringFilter matchType values:** `EXACT`, `BEGINS_WITH`, `ENDS_WITH`, `CONTAINS`, `FULL_REGEXP`, `PARTIAL_REGEXP`

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport

---

### runRealtimeReport — field reference

**Request body** (`POST /v1beta/properties/{pid}:runRealtimeReport`):

```json
{
  "dimensions": [{"name": "country"}],
  "metrics": [{"name": "activeUsers"}],
  "minuteRanges": [{"startMinutesAgo": 29, "endMinutesAgo": 0}],
  "dimensionFilter": {},
  "metricFilter": {},
  "limit": 10000,
  "metricAggregations": ["TOTAL"],
  "orderBys": [],
  "returnPropertyQuota": true
}
```

- `minuteRanges` instead of `dateRanges`; default = last 30 minutes; max 2 ranges per request
- 360 properties: up to 60 minutes of realtime data
- No `offset`; no pagination — realtime is a snapshot
- `dateRanges` is NOT a valid field (realtime-only uses `minuteRanges`)

**Response body**: same shape as `runReport` but with `kind: "analyticsData#runRealtimeReport"` and `propertyQuota` reflects realtime quota.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport

---

### getMetadata — field reference

**Request** (`GET /v1beta/properties/{pid}/metadata`):

- Path parameter `name` = `properties/{propertyId}/metadata`
- Use `properties/0/metadata` to get universal dimensions/metrics (excludes custom ones)
- Empty request body

**Response fields per dimension:**
- `apiName` — string to use in `dimensions[].name`
- `uiName` — human-readable label
- `description` — what it means
- `category` — grouping category
- `customDefinition` — boolean, true if property-specific
- `deprecatedApiNames[]` — old names (may be absent)
- `blockedReasons[]` — if access-controlled

**Response fields per metric:**
- `apiName`, `uiName`, `description`, `category` — same as dimensions
- `type` — `TYPE_INTEGER`, `TYPE_FLOAT`, `TYPE_CURRENCY`, `TYPE_SECONDS`, `TYPE_MINUTES`, `TYPE_HOURS`, `TYPE_STANDARD`, `TYPE_FEET`, `TYPE_MILES`, `TYPE_METERS`, `TYPE_KILOMETERS`
- `expression` — formula for calculated metrics
- `customDefinition` — boolean

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/getMetadata

---

### keyEvents (Admin API) — field reference

**KeyEvent resource object:**

```json
{
  "name": "properties/271773771/keyEvents/44444444",
  "eventName": "purchase",
  "createTime": "2025-01-15T10:30:00.000000Z",
  "deletable": true,
  "custom": true,
  "countingMethod": "ONCE_PER_EVENT",
  "defaultValue": {
    "numericValue": 0.0,
    "currencyCode": "AED"
  }
}
```

**Field details:**

| Field | Type | R/W | Notes |
|-------|------|-----|-------|
| `name` | string | output-only | Full resource path: `properties/{property}/keyEvents/{keyEvent}` — use as the DELETE URL path |
| `eventName` | string | create-only (immutable) | GA4 event name — cannot be changed after creation; must match an event being tracked |
| `createTime` | string | output-only | RFC 3339 timestamp |
| `custom` | boolean | output-only | `false` for built-in GA4 events (purchase, first_visit, etc.), `true` for custom events |
| `deletable` | boolean | output-only | `false` for events that GA4 protects from deletion |
| `countingMethod` | enum | required on create; patchable | `ONCE_PER_EVENT` or `ONCE_PER_SESSION` |
| `defaultValue.numericValue` | number | optional | Default monetary value assigned when the event doesn't include a `value` parameter |
| `defaultValue.currencyCode` | string | optional | ISO 4217; required when `defaultValue.numericValue` is set |

**countingMethod:**
- `ONCE_PER_EVENT` — every event instance counts as a key event (e.g. each WhatsApp click counted separately)
- `ONCE_PER_SESSION` — at most one key event per session per user (e.g. if purchase fires 3× in one session, it only counts once)

**list request parameters:**
- `pageSize`: max 200, default 50 (gads CLI uses 200)
- `pageToken`: opaque token from previous `nextPageToken`
- `parent`: `properties/{propertyId}` (path param, not query param)

**list response:**
```json
{
  "keyEvents": [...],
  "nextPageToken": "Cg8KDXByb3BlcnRpZXMv..."
}
```
`nextPageToken` is omitted (not null) when there are no more pages.

Sources: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents, https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/list

---

## Error Responses — Common Patterns

### 400 — Invalid dimension or metric name

```json
{
  "error": {
    "code": 400,
    "message": "Field dimension[0] has unknown name 'sessions'. Did you mean metric[0] sessions?",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.analytics.data.v1beta.QuotaFailure"
      }
    ]
  }
}
```

Also occurs when trying to combine incompatible dimensions and metrics. Use `checkCompatibility` to pre-validate, or call `getMetadata` to verify `apiName` values.

### 403 — Missing analytics.edit scope (write operations)

```json
{
  "error": {
    "code": 403,
    "message": "Request had insufficient authentication scopes.",
    "status": "PERMISSION_DENIED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "ACCESS_TOKEN_SCOPE_INSUFFICIENT",
        "domain": "googleapis.com",
        "metadata": {
          "method": "google.analytics.admin.v1beta.AnalyticsAdminService.CreateKeyEvent",
          "service": "analyticsadmin.googleapis.com"
        }
      }
    ]
  }
}
```

**Fix:** Regenerate the OAuth token to include `analytics.edit` scope. The gads CLI's `generate_token.py` already includes it — if you see this, the token is stale.

### 403 — Wrong GA4 property ID or no access

```json
{
  "error": {
    "code": 403,
    "message": "The caller does not have permission",
    "status": "PERMISSION_DENIED"
  }
}
```

**Note:** A 403 for "no access to this property" looks identical to "insufficient scopes" — check both. The property ID in `GOOGLE_GA4_PROPERTY_ID` must be the numeric GA4 property ID, not the Measurement ID (`G-XXXXXXXX`).

### 404 — Wrong property ID format

If the Measurement ID (`G-XXXXXXXX`) is used instead of the numeric property ID, the API returns 404:

```json
{
  "error": {
    "code": 404,
    "message": "Property G-XXXXXXXX not found or it may not be a GA4 property.",
    "status": "NOT_FOUND"
  }
}
```

**Fix:** Use the numeric property ID found in GA4 Admin > Property Settings > Property ID (a 9-digit number like `271773771`).

### 429 — Quota exhausted

```json
{
  "error": {
    "code": 429,
    "message": "Quota exceeded for quota metric 'analyticsdata.googleapis.com/tokens' and limit 'Tokens per project per property per hour' of service 'analyticsdata.googleapis.com'.",
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
        "violations": [
          {
            "subject": "project:my-gcp-project",
            "description": "Quota exceeded for quota metric 'analyticsdata.googleapis.com/tokens' and limit 'Tokens per project per property per hour' of service 'analyticsdata.googleapis.com'."
          }
        ]
      }
    ]
  }
}
```

**Fix:** Wait for hourly quota refresh (within ~60 minutes). Use `returnPropertyQuota: true` proactively to monitor remaining tokens before hitting the limit. For high-volume workloads, use `batchRunReports` to combine multiple report requests and reduce per-request overhead.

### 409 — Key event already exists

```json
{
  "error": {
    "code": 409,
    "message": "Key event already exists: whatsapp_click",
    "status": "ALREADY_EXISTS"
  }
}
```

Treat as success (idempotent) in bulk create operations.

---

## Pagination & Quotas

### Data API Pagination

- `runReport` and `runPivotReport` use **offset-based pagination** (`offset` + `limit`), NOT page tokens
- `batchRunReports`, `checkCompatibility` — same offset approach per report
- `audienceExports.list` — uses `pageToken` / `pageSize`
- `runRealtimeReport` — no pagination (snapshot; use `limit` to cap rows)
- `getMetadata` — no pagination (returns all dimensions/metrics in one call)

### Admin API Pagination

- `keyEvents.list`: `pageSize` (max 200), `pageToken` / `nextPageToken`

### Data API Quota Limits

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/quotas

| Quota Category | Standard Property | Analytics 360 |
|---------------|-------------------|---------------|
| Tokens per day | 200,000 | 2,000,000 |
| Tokens per hour (property) | 40,000 | 400,000 |
| Tokens per hour (project, per property) | 14,000 | 140,000 |
| Concurrent requests | 10 | 50 |
| Server errors per hour | 10 | 50 |

- Token cost depends on row count, column count, date range span, filter complexity, and dimension cardinality
- Quota refreshes: daily at midnight PST; hourly within the hour (not necessarily on the hour boundary)
- Use `"returnPropertyQuota": true` in requests to get remaining quota in the response

---

## Gotchas

1. **v1beta vs v1alpha split**: Data API `v1beta` is stable for all standard reporting; only use `v1alpha` if you need funnel reports, async report tasks, or recurring audience lists. Admin API `v1beta` covers key events stably; `v1alpha` is needed for audiences, BigQuery links, channel groups, etc.

2. **Key Events vs Conversion Events naming**: GA4 renamed "conversion events" to "key events" in the UI and API. The Admin API resource is `keyEvents` (not `conversionEvents`). The old `conversionEvents` resource still exists in some API versions for backward compatibility but `keyEvents` is the current name. The gads CLI correctly uses "Key Events" terminology.

3. **Property ID format**: The `{property}` path parameter must be the **numeric GA4 Property ID** (e.g. `properties/271773771`), NOT the Measurement ID (e.g. `G-XXXXXXXXXX`). These are different identifiers. Using the wrong format produces a 403 or 404 depending on the endpoint.

4. **DELETE path uses `keyEvent.name`**: The delete endpoint takes the full resource name from the `name` field of a KeyEvent object (e.g. `properties/271773771/keyEvents/44444444`), not just the event name string. Always list first to resolve `eventName` → `name`.

5. **`eventName` is immutable**: After creating a key event, the `eventName` cannot be changed. To rename, you must delete and recreate.

6. **`analytics` scope vs `analytics.readonly`**: The broader `analytics` scope is also accepted by Data API read endpoints, but `analytics.edit` is specifically required for Admin API mutations (create/delete/patch key events). A 403 with `ACCESS_TOKEN_SCOPE_INSUFFICIENT` on write calls = missing `analytics.edit`.

7. **Realtime window**: Standard properties get 30 minutes of realtime data; 360 properties get up to 60 minutes. Attempting to specify `minuteRanges` beyond these limits returns an error.

8. **`offset` not `pageToken` for runReport**: Unlike many Google APIs, `runReport` uses integer `offset` for pagination, not a page token string. Check `rowCount` in response to know when you have all rows.

9. **`dateRanges` vs `minuteRanges`**: These are mutually exclusive by endpoint. `runReport` uses `dateRanges`. `runRealtimeReport` uses `minuteRanges`. Sending `dateRanges` to the realtime endpoint returns a 400.

10. **`nextPageToken` absent vs null**: Admin API list endpoints omit `nextPageToken` entirely (key not present) when there are no more pages — they do NOT return `"nextPageToken": null`. Code must check `resp.get("nextPageToken")`, not `resp["nextPageToken"] is None`.

11. **Metric values are always strings**: Even `TYPE_INTEGER` metrics come back as `"value": "1842"` (a JSON string). Always cast: `int(row["metricValues"][0]["value"])`.

12. **409 on bulk create is safe to ignore**: When bulk-creating key events, a 409 means the event is already a key event. Treat as success/skip, not fatal error.

---

## Coverage vs Current gads CLI

The gads CLI (`gads_lib/ga4.py`) currently uses:

| What | Status |
|------|--------|
| `GET /v1beta/properties/{pid}/metadata` | Used — dimension/metric catalog |
| `POST /v1beta/properties/{pid}:runReport` | Used — standard reports |
| `POST /v1beta/properties/{pid}:runRealtimeReport` | Used — realtime reports |
| `POST /v1beta/properties/{pid}:batchRunReports` | Used — `gads ga4 batch-report` (added gads-cli v3.7.0) |
| `POST /v1beta/properties/{pid}:runPivotReport` | Used — `gads ga4 pivot-report` (added gads-cli v3.7.0) |
| `POST /v1beta/properties/{pid}:checkCompatibility` | Used — `gads ga4 check-compatibility` (added gads-cli v3.7.0) |
| `GET /v1beta/properties/{pid}/keyEvents` | Used — list key events (pageSize=200) — **migrated from v1alpha in gads-cli v3.8.2** |
| `POST /v1beta/properties/{pid}/keyEvents` | Used — create key event — **migrated from v1alpha in gads-cli v3.8.2** |
| `DELETE /v1beta/{keyEvent.name}` | Used — delete key event — **migrated from v1alpha in gads-cli v3.8.2** |

**Gaps — endpoints not yet used by gads CLI:**

| Endpoint | Notes |
|----------|-------|
| `batchRunPivotReports` | Batch version of pivot — not wired up (single `runPivotReport` is) |
| `audienceExports` (v1beta) | Export audience user lists for retargeting analysis |
| `runFunnelReport` (v1alpha) | Multi-step funnel analysis (checkout steps, etc.) |
| `reportTasks` (v1alpha) | Async large reports that exceed realtime API limits |
| Conversion Reporting via `runReport` `conversionSpec` (v1alpha, **new 2026-04-23**) | Paid+organic conversion-performance rows inside a normal `runReport` call — see Developer Guide §16. Availability is per-property (Google is rolling it out); check `properties.getMetadata`'s new `conversions` field first |
| Admin: `keyEvents.get` | Retrieve a single key event by name |
| Admin: `keyEvents.patch` | Update `countingMethod` or `defaultValue` without delete+recreate |
| Admin: Custom dimensions CRUD | `properties.customDimensions` — list/create/archive |
| Admin: Custom metrics CRUD | `properties.customMetrics` — list/create/archive |
| Admin: `accounts` / `properties` | Account-level listing and property provisioning |
| Admin: `runAccessReport` | Audit who accessed GA4 data |
| Admin: `dataRetentionSettings` get/update | Controls `eventDataRetention` / `userDataRetention` window (2mo/14mo/26-50mo on 360) |
| Admin: `UpdateReportingIdentitySettings` (**new 2026-06-18**) | Controls Blended/Observed/Device-based reporting identity |
| Admin: `GetUserProvidedDataSettings` (**new 2026-04-14**, v1alpha) | Enhanced Conversions / user-provided data collection config |

**Migration status:** `key-events` commands already run on `v1beta` Admin API (migrated from `v1alpha` in gads-cli v3.8.2 — see `gads_lib/ga4.py:18`). No further action needed for key events; this file previously described the switch as a pending "opportunity," which was stale.

---

## Sources

| URL | What It Documents |
|-----|-------------------|
| https://developers.google.com/analytics/devguides/reporting/data/v1/api-schema | Data API dimensions/metrics catalog overview |
| https://developers.google.com/analytics/devguides/reporting/data/v1/rest | Data API full endpoint reference (v1beta + v1alpha) |
| https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport | runReport request/response shape |
| https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport | runRealtimeReport request/response shape |
| https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/getMetadata | getMetadata request/response shape |
| https://developers.google.com/analytics/devguides/reporting/data/v1/quotas | Quota limits (tokens/day, tokens/hour, concurrency) |
| https://developers.google.com/analytics/devguides/config/admin/v1 | Admin API overview and version channels |
| https://developers.google.com/analytics/devguides/config/admin/v1/rest | Admin API endpoint reference (v1beta + v1alpha) |
| https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents | keyEvents resource (v1beta) — all methods; the version gads CLI actually calls (since v3.8.2) |
| https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents/list | keyEvents.list — pagination params and auth scopes |
| https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1alpha/properties.keyEvents | keyEvents resource (v1alpha) — same methods, kept for historical/compat reference only |
| https://developers.google.com/analytics/devguides/config/admin/v1/changelog | Admin API changelog — confirms latest additions (`UpdateReportingIdentitySettings`, `can_edit`, `GetUserProvidedDataSettings`) |
| https://developers.google.com/analytics/devguides/reporting/data/v1/changelog | Data API changelog — confirms Conversion Reporting addition (2026-04-23) |
| https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1alpha/properties/runReport | `conversionSpec` field, `attributionModel` enum (Conversion Reporting, v1alpha) |
| https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties/getDataRetentionSettings | `DataRetentionSettings` fields (`eventDataRetention`, `userDataRetention`, `resetUserDataOnNewActivity`) |

---

## Developer Guide

A deeper reference for building against the GA4 APIs. Supplements the concrete examples above with schema definitions, naming rules, advanced endpoints, and operational patterns.

Source references: https://developers.google.com/analytics/devguides/reporting/data/v1 and https://developers.google.com/analytics/devguides/config/admin/v1

---

### 1. Report Request Schema — Full Field Map

`POST /v1beta/properties/{property}:runReport` accepts the following top-level fields:

```json
{
  "dimensions":         [ { "name": "string" } ],
  "metrics":            [ { "name": "string" } ],
  "dateRanges":         [ { "startDate": "string", "endDate": "string", "name": "string?" } ],
  "dimensionFilter":    FilterExpression,
  "metricFilter":       FilterExpression,
  "orderBys":           [ OrderBy ],
  "limit":              integer,
  "offset":             integer,
  "metricAggregations": [ "TOTAL" | "MINIMUM" | "MAXIMUM" | "COUNT" ],
  "keepEmptyRows":      boolean,
  "returnPropertyQuota": boolean,
  "currencyCode":       "ISO-4217",
  "comparisons":        [ Comparison ],
  "cohortSpec":         CohortSpec
}
```

**Field-by-field notes:**

| Field | Default | Max | Notes |
|-------|---------|-----|-------|
| `dimensions` | none | ~9 per request | Each element: `{"name": "dimensionApiName"}` |
| `metrics` | none | ~10 per request | Each element: `{"name": "metricApiName"}` |
| `dateRanges` | none | 4 ranges | Multi-range adds a `dateRange` dimension automatically |
| `dimensionFilter` | none | — | Applied before aggregation (WHERE equivalent) |
| `metricFilter` | none | — | Applied after aggregation (HAVING equivalent) |
| `orderBys` | none | — | Array of `OrderBy` objects; see schema below |
| `limit` | 10,000 | 250,000 | Rows per page |
| `offset` | 0 | — | Zero-indexed row start for pagination |
| `keepEmptyRows` | false | — | When true, rows with all-zero metrics are included |
| `returnPropertyQuota` | false | — | Include token quota state in each response |

**OrderBy schema:**

```json
// Sort by metric (descending)
{"metric": {"metricName": "sessions"}, "desc": true}

// Sort by dimension (ascending)
{"dimension": {"dimensionName": "date"}, "desc": false}

// Sort by dimension value as a number (e.g. date string treated numerically)
{"dimension": {"dimensionName": "date", "orderType": "NUMERIC"}, "desc": false}
```

`orderType` values for dimension orderBys: `ALPHANUMERIC` (default), `CASE_INSENSITIVE_ALPHANUMERIC`, `NUMERIC`.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport

---

### 2. Dimension and Metric Naming

**Naming conventions:**

| Prefix | Meaning | Example |
|--------|---------|---------|
| (none) | Built-in GA4 dimension or metric | `sessions`, `date`, `country` |
| `customEvent:` | Event-scoped custom dimension (registered in Admin) | `customEvent:branch` |
| `customUser:` | User-scoped custom dimension | `customUser:loyalty_tier` |
| `keyEvents:` | Per-event-name key event metric | `keyEvents:whatsapp_click` |

**There is no `ga:` prefix in GA4.** The `ga:` prefix belongs to Universal Analytics (GA3) and is not used in the GA4 Data API. All GA4 API names are used bare (e.g. `sessions`, not `ga:sessions`).

**Common dimensions:**

| API Name | UI Name | Category |
|----------|---------|----------|
| `date` | Date | Time |
| `dateHour` | Date + hour | Time |
| `week` | Week (ISO week number) | Time |
| `month` | Month | Time |
| `year` | Year | Time |
| `sessionDefaultChannelGroup` | Session default channel group | Traffic source |
| `sessionSource` | Session source | Traffic source |
| `sessionMedium` | Session medium | Traffic source |
| `sessionCampaignName` | Session campaign | Traffic source |
| `firstUserSource` | First user source | User acquisition |
| `firstUserMedium` | First user medium | User acquisition |
| `firstUserCampaignName` | First user campaign | User acquisition |
| `deviceCategory` | Device category | Platform |
| `operatingSystem` | Operating system | Platform |
| `browser` | Browser | Platform |
| `country` | Country | Geography |
| `region` | Region | Geography |
| `city` | City | Geography |
| `landingPage` | Landing page + query string | Page / screen |
| `pagePath` | Page path + query string | Page / screen |
| `pageTitle` | Page title | Page / screen |
| `eventName` | Event name | Event |
| `platform` | Platform (Web / iOS / Android) | Platform |

**Common metrics:**

| API Name | UI Name | Type | Notes |
|----------|---------|------|-------|
| `sessions` | Sessions | INTEGER | Session count |
| `activeUsers` | Active users | INTEGER | Users with at least one engaged event |
| `totalUsers` | Total users | INTEGER | All users including bounced |
| `newUsers` | New users | INTEGER | First-time users |
| `screenPageViews` | Views | INTEGER | Page views + screen views |
| `engagedSessions` | Engaged sessions | INTEGER | Sessions with engagement >10s, 1+ conversion, 2+ views |
| `engagementRate` | Engagement rate | FLOAT | engagedSessions / sessions |
| `bounceRate` | Bounce rate | FLOAT | 1 − engagementRate |
| `averageSessionDuration` | Average session duration | SECONDS | |
| `conversions` | Conversions | INTEGER | Total key event count (all key events) |
| `keyEvents` | Key events | INTEGER | Synonym for `conversions` |
| `totalRevenue` | Total revenue | CURRENCY | Purchase + subscription + ad revenue |
| `purchaseRevenue` | Purchase revenue | CURRENCY | Ecommerce revenue only |
| `eventCount` | Event count | INTEGER | Total events fired |
| `eventCountPerUser` | Events per user | FLOAT | |
| `userEngagementDuration` | User engagement duration | SECONDS | |

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/api-schema

---

### 3. Date Range Patterns

**Accepted date formats for `startDate` / `endDate`:**

| Format | Example | Notes |
|--------|---------|-------|
| `YYYY-MM-DD` | `"2026-01-15"` | Absolute date in property timezone |
| `NdaysAgo` | `"7daysAgo"`, `"30daysAgo"` | N must be a positive integer; resolves relative to today in property timezone |
| `yesterday` | `"yesterday"` | Equivalent to `"1daysAgo"` |
| `today` | `"today"` | Current day (partial data — avoid for performance analysis) |

**Single range (most common):**
```json
"dateRanges": [{"startDate": "30daysAgo", "endDate": "yesterday"}]
```

**Multi-range comparison (period over period):**
```json
"dateRanges": [
  {"name": "this_period", "startDate": "7daysAgo", "endDate": "yesterday"},
  {"name": "prior_period", "startDate": "14daysAgo", "endDate": "8daysAgo"}
]
```

When multiple date ranges are specified, the response automatically adds a `dateRange` dimension column whose values are the `name` strings you supplied (or `date_range_0`, `date_range_1`, etc. if names are omitted). Each row is scoped to one date range, enabling side-by-side comparison in a single query.

Maximum 4 date ranges per request. Avoid using `today` in production queries — data for the current day is incomplete and results will change.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport

---

### 4. Filter Expressions — Full Schema

`dimensionFilter` and `metricFilter` both accept a `FilterExpression` object. The schemas are identical; only the valid field names differ (dimension names vs metric names).

**FilterExpression union type** — exactly one of these keys must be present:

```
FilterExpression =
  | { "filter": Filter }
  | { "andGroup": FilterExpressionList }
  | { "orGroup": FilterExpressionList }
  | { "notExpression": FilterExpression }
```

**Filter object:**
```json
{
  "fieldName": "country",
  "<filterType>": { ... }
}
```

**StringFilter:**
```json
{
  "fieldName": "sessionSource",
  "stringFilter": {
    "matchType": "EXACT",
    "value": "google",
    "caseSensitive": false
  }
}
```

`matchType` values:
- `EXACT` — full string equality
- `BEGINS_WITH` — prefix match
- `ENDS_WITH` — suffix match
- `CONTAINS` — substring search
- `FULL_REGEXP` — entire value must match the regex
- `PARTIAL_REGEXP` — any part of the value must match the regex

**NumericFilter:**
```json
{
  "fieldName": "sessions",
  "numericFilter": {
    "operation": "GREATER_THAN",
    "value": {"int64Value": "100"}
  }
}
```

`operation` values: `EQUAL`, `LESS_THAN`, `LESS_THAN_OR_EQUAL`, `GREATER_THAN`, `GREATER_THAN_OR_EQUAL`.
`value` is `{"int64Value": "N"}` or `{"doubleValue": N}`.

**BetweenFilter:**
```json
{
  "fieldName": "sessions",
  "betweenFilter": {
    "fromValue": {"int64Value": "10"},
    "toValue":   {"int64Value": "500"}
  }
}
```
Inclusive on both ends.

**InListFilter:**
```json
{
  "fieldName": "country",
  "inListFilter": {
    "values": ["United Arab Emirates", "Saudi Arabia", "Kuwait"],
    "caseSensitive": false
  }
}
```

**Compound expressions:**
```json
// AND: all conditions must match
{
  "andGroup": {
    "expressions": [
      {"filter": {"fieldName": "country", "stringFilter": {"matchType": "EXACT", "value": "United Arab Emirates"}}},
      {"filter": {"fieldName": "deviceCategory", "stringFilter": {"matchType": "EXACT", "value": "mobile"}}}
    ]
  }
}

// OR: at least one must match
{
  "orGroup": {
    "expressions": [
      {"filter": {"fieldName": "sessionMedium", "stringFilter": {"matchType": "EXACT", "value": "cpc"}}},
      {"filter": {"fieldName": "sessionMedium", "stringFilter": {"matchType": "EXACT", "value": "paidsearch"}}}
    ]
  }
}

// NOT
{
  "notExpression": {
    "filter": {
      "fieldName": "sessionSource",
      "stringFilter": {"matchType": "EXACT", "value": "(direct)"}
    }
  }
}
```

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport#FilterExpression

---

### 5. Key Events (Formerly Conversions)

GA4 renamed "conversion events" to "key events" in 2023. The Admin API resource is `properties.keyEvents`.

**Admin API methods (both v1alpha and v1beta):**

| Method | HTTP | Path |
|--------|------|------|
| `create` | POST | `/properties/{property}/keyEvents` |
| `list` | GET | `/properties/{property}/keyEvents` |
| `get` | GET | `/properties/{property}/keyEvents/{keyEvent}` |
| `patch` | PATCH | `/properties/{property}/keyEvents/{keyEvent}` |
| `delete` | DELETE | `/properties/{property}/keyEvents/{keyEvent}` |

**KeyEvent create request body:**
```json
{
  "eventName": "whatsapp_click",
  "countingMethod": "ONCE_PER_EVENT",
  "defaultValue": {
    "numericValue": 0.0,
    "currencyCode": "AED"
  }
}
```

**`countingMethod` enum:**

| Value | Behavior | When to use |
|-------|----------|-------------|
| `ONCE_PER_EVENT` | Every firing of the event counts as one key event | Clicks, form submits — each action is meaningful |
| `ONCE_PER_SESSION` | At most one key event per session per user | Purchases, signups — avoid double-counting within a visit |

**`custom` field (output-only):**
- `false` — GA4 built-in event (e.g. `purchase`, `first_visit`, `session_start`) promoted to key event
- `true` — developer-defined custom event promoted to key event

**`deletable` field (output-only):**
- `false` — protected by GA4; cannot be deleted via API. Typically `session_start` and `first_visit`.
- `true` — can be deleted

**`defaultValue`:**
- Optional. Assigns a monetary value to key event firings that do not include a `value` parameter.
- `currencyCode` is required when `numericValue` is set.

**Patch (update) example** — change counting method without delete+recreate:
```json
PATCH /v1beta/properties/271773771/keyEvents/44444444?updateMask=countingMethod
{
  "countingMethod": "ONCE_PER_SESSION"
}
```
`updateMask` is a comma-separated field path list. Only those fields are updated.

**Auto-collected events that can become key events:**
`purchase`, `add_to_cart`, `begin_checkout`, `add_payment_info`, `add_shipping_info`, `view_item`, `view_cart`, `first_visit`, `session_start`, `page_view`, `scroll`, `click`, `file_download`, `video_start`, `video_progress`, `video_complete`, `form_start`, `form_submit`, `search`.

Sources: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents, https://developers.google.com/analytics/devguides/config/admin/v1

---

### 6. Realtime Reports

`POST /v1beta/properties/{property}:runRealtimeReport`

**Key differences from `runReport`:**

| Aspect | runReport | runRealtimeReport |
|--------|-----------|-------------------|
| Time axis | `dateRanges` (days) | `minuteRanges` (minutes ago) |
| Window | Historical (yesterday and older) | Last 30 min (standard) / 60 min (360) |
| Pagination | `offset` + `limit` | `limit` only — no offset |
| `keepEmptyRows` | Supported | NOT supported |
| `cohortSpec` | Supported | NOT supported |
| `comparisons` | Supported | NOT supported |
| Dimension set | Full catalog | Reduced set (realtime-specific) |

**`minuteRanges` schema:**
```json
"minuteRanges": [
  {
    "name": "last_5_min",
    "startMinutesAgo": 4,
    "endMinutesAgo": 0
  },
  {
    "name": "prior_5_min",
    "startMinutesAgo": 9,
    "endMinutesAgo": 5
  }
]
```

- `startMinutesAgo` >= `endMinutesAgo` (start is further in the past)
- `endMinutesAgo` minimum: 0 (right now)
- `startMinutesAgo` maximum: 29 (standard) or 59 (360)
- Maximum 2 minute ranges per request

**Available realtime dimensions (subset of full catalog):**
`city`, `cityId`, `country`, `countryId`, `deviceCategory`, `eventName`, `minutesAgo`, `platform`, `region`, `streamId`, `streamName`, `unifiedScreenName` (current page/screen), `audienceId`, `audienceName`, `firstUserGoogleAdsAdGroupName`, `firstUserGoogleAdsCampaignName`, `firstUserMedium`, `firstUserSource`, `firstUserSourceMedium`.

**Available realtime metrics:**
`activeUsers`, `conversions`, `eventCount`, `keyEvents`, `screenPageViews`.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runRealtimeReport

---

### 7. batchRunReports

`POST /v1beta/properties/{property}:batchRunReports`

Sends up to 5 `runReport`-equivalent requests in a single HTTP call. Each sub-request shares the same property but can have independent dimensions, metrics, date ranges, and filters.

**Request shape:**
```json
{
  "requests": [
    {
      "dimensions": [{"name": "date"}],
      "metrics": [{"name": "sessions"}, {"name": "activeUsers"}],
      "dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}]
    },
    {
      "dimensions": [{"name": "country"}],
      "metrics": [{"name": "sessions"}],
      "dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}],
      "orderBys": [{"metric": {"metricName": "sessions"}, "desc": true}],
      "limit": 20
    }
  ]
}
```

**Response shape:**
```json
{
  "reports": [
    {
      "dimensionHeaders": [...],
      "metricHeaders": [...],
      "rows": [...],
      "rowCount": 7,
      "metadata": {...},
      "kind": "analyticsData#runReport"
    },
    {
      "dimensionHeaders": [...],
      "metricHeaders": [...],
      "rows": [...],
      "rowCount": 42,
      "metadata": {...},
      "kind": "analyticsData#runReport"
    }
  ],
  "kind": "analyticsData#batchRunReports"
}
```

- `reports[i]` corresponds to `requests[i]` — order is preserved.
- Each sub-report is independently paged; check `rowCount` per report.
- Quota cost: each sub-report consumes tokens independently, but the overhead is lower than 5 separate HTTP calls.
- Maximum 5 requests per batch call.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/batchRunReports

---

### 8. runPivotReport

`POST /v1beta/properties/{property}:runPivotReport`

Cross-tabulation report. Useful for campaign × device or channel × country breakdowns where you want values spread into columns rather than rows.

**Request shape:**
```json
{
  "dimensions": [
    {"name": "sessionDefaultChannelGroup"},
    {"name": "deviceCategory"}
  ],
  "metrics": [
    {"name": "sessions"},
    {"name": "conversions"}
  ],
  "dateRanges": [{"startDate": "30daysAgo", "endDate": "yesterday"}],
  "pivots": [
    {
      "fieldNames": ["sessionDefaultChannelGroup"],
      "limit": 10,
      "orderBys": [{"metric": {"metricName": "sessions"}, "desc": true}]
    },
    {
      "fieldNames": ["deviceCategory"],
      "limit": 5,
      "orderBys": [{"dimension": {"dimensionName": "deviceCategory"}, "desc": false}]
    }
  ]
}
```

**Pivot object fields:**

| Field | Type | Notes |
|-------|------|-------|
| `fieldNames` | string[] | Dimension name(s) to pivot on — must be in the top-level `dimensions` array |
| `limit` | integer | Max pivot columns; default 10 |
| `offset` | integer | Column offset (pagination within pivot) |
| `metricAggregations` | enum[] | `TOTAL`, `MINIMUM`, `MAXIMUM`, `COUNT` — per-pivot aggregates |
| `orderBys` | OrderBy[] | Sort order for pivot columns |

**Response shape** differs from `runReport`: instead of flat `rows`, the response contains `pivotHeaders` (column labels for each pivot) and `rows` where each row has `dimensionValues` and `metricValues` arranged in pivot order. Parsing is more complex; the `batchRunPivotReports` variant follows the same shape.

**PivotSelection** (in response): `pivotDimensionHeaders` lists the header values that were selected for each pivot, in order.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runPivotReport

---

### 9. checkCompatibility

`POST /v1beta/properties/{property}:checkCompatibility`

Validates which dimensions and metrics can be queried together before committing to a real report call. Use this when building dynamic report builders or debugging 400 errors from incompatible field combinations.

**Request shape:**
```json
{
  "dimensions": [{"name": "date"}, {"name": "sessionSource"}],
  "metrics": [{"name": "sessions"}, {"name": "totalRevenue"}],
  "dimensionFilter": {
    "filter": {"fieldName": "country", "stringFilter": {"matchType": "EXACT", "value": "United Arab Emirates"}}
  },
  "compatibilityFilter": "COMPATIBLE"
}
```

`compatibilityFilter` can be `"COMPATIBLE"` (return only compatible items), `"INCOMPATIBLE"`, or omitted (return all with their status).

**Response shape:**
```json
{
  "dimensionCompatibilities": [
    {
      "dimensionMetadata": {"apiName": "date", "uiName": "Date", ...},
      "compatibility": "COMPATIBLE"
    },
    {
      "dimensionMetadata": {"apiName": "cohort", "uiName": "Cohort", ...},
      "compatibility": "INCOMPATIBLE"
    }
  ],
  "metricCompatibilities": [
    {
      "metricMetadata": {"apiName": "sessions", "uiName": "Sessions", "type": "TYPE_INTEGER", ...},
      "compatibility": "COMPATIBLE"
    }
  ]
}
```

**`CompatibilityState` enum values:**
- `COMPATIBLE` — can be added to the current request without error
- `INCOMPATIBLE` — adding this field would cause a 400 error

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/checkCompatibility

---

### 10. Quota and Limits

**Token-based quota model:**

Each `runReport` request consumes a variable number of tokens depending on: row count returned, number of dimensions/metrics, date range span, filter complexity, and dimension cardinality. Simple queries on a small property cost ~1–5 tokens; large queries with many rows can cost hundreds.

**Standard property quota limits:**

| Quota bucket | Limit |
|-------------|-------|
| Tokens per property per day | 200,000 |
| Tokens per property per hour | 40,000 |
| Tokens per project per property per hour | 14,000 |
| Concurrent requests per property | 10 |
| Server errors per project per hour | 10 |
| Potentially thresholded requests per hour | 120 |

**Analytics 360 (paid tier) limits:** 10× higher on all token quotas; 50 concurrent requests.

**Quota in responses** — request `"returnPropertyQuota": true` to get the current state:

```json
"propertyQuota": {
  "tokensPerDay":                       {"consumed": 142, "remaining": 199858},
  "tokensPerHour":                      {"consumed": 42,  "remaining": 39958},
  "concurrentRequests":                 {"consumed": 1,   "remaining": 9},
  "serverErrorsPerProjectPerHour":      {"consumed": 0,   "remaining": 10},
  "potentiallyThresholdedRequestsPerHour": {"consumed": 3, "remaining": 117}
}
```

**Quota enforcement:**
- 429 `RESOURCE_EXHAUSTED` is returned when any quota bucket is exhausted.
- Hourly quota resets on the hour boundary (not a rolling window).
- Daily quota resets at midnight Pacific time.
- Concurrent request quota is released when the response is returned.

**Quota handling patterns:**
```python
def run_report_with_quota_check(payload, headers, url):
    payload["returnPropertyQuota"] = True
    resp = requests.post(url, json=payload, headers=headers)
    if resp.status_code == 429:
        # Wait and retry — quota exhausted
        time.sleep(60)
        return run_report_with_quota_check(payload, headers, url)
    data = resp.json()
    quota = data.get("propertyQuota", {})
    remaining_hour = quota.get("tokensPerHour", {}).get("remaining", 999)
    if remaining_hour < 100:
        print(f"Warning: only {remaining_hour} hourly tokens remaining")
    return data
```

Use `batchRunReports` to reduce per-request overhead when fetching multiple reports.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/quotas

---

### 11. Pagination

**runReport / runPivotReport / batchRunReports — offset-based pagination:**

```python
limit = 10000
offset = 0
all_rows = []

while True:
    body = {
        **base_payload,
        "limit": limit,
        "offset": offset
    }
    resp = requests.post(url, json=body, headers=headers).json()
    rows = resp.get("rows", [])
    all_rows.extend(rows)
    row_count = resp.get("rowCount", 0)
    offset += len(rows)
    if offset >= row_count or not rows:
        break
```

Key points:
- `rowCount` is the total number of matching rows in the full result set, NOT the count of rows in the current page.
- `rows` may be absent (not empty list) when there are no results — use `resp.get("rows", [])`.
- With `limit=250000` and `offset=0`, a single request fetches up to the maximum. For datasets larger than 250,000 rows, loop with offset increments.

**Admin API list endpoints — pageToken-based pagination:**

```python
page_token = None
all_items = []

while True:
    params = {"pageSize": 200}
    if page_token:
        params["pageToken"] = page_token
    resp = requests.get(url, params=params, headers=headers).json()
    all_items.extend(resp.get("keyEvents", []))  # or "customDimensions", etc.
    page_token = resp.get("nextPageToken")        # absent (not null) on last page
    if not page_token:
        break
```

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties/runReport

---

### 12. Admin API v1alpha vs v1beta

**Version comparison for key resources** (re-verified 2026-07-01):

| Resource | v1beta | v1alpha | Notes |
|----------|--------|---------|-------|
| `properties.keyEvents` | Stable | Stable | Identical method set. **gads CLI uses v1beta** (migrated from v1alpha in v3.8.2) |
| `properties.customDimensions` | Stable | Stable | Prefer v1beta |
| `properties.customMetrics` | Stable | Stable | Prefer v1beta |
| `properties.dataRetentionSettings` | Stable | Stable | `eventDataRetention` / `userDataRetention` / `resetUserDataOnNewActivity` — not used by gads CLI |
| `properties.dataStreams` | Stable | Stable | Data stream CRUD |
| `properties.measurementProtocolSecrets` | Stable | Stable | MP secret management |
| `properties.firebaseLinks` / `googleAdsLinks` | Stable | Stable | Firebase / Ads linking |
| `properties.reportingIdentitySettings` | Stable (**new method** `UpdateReportingIdentitySettings`, 2026-06-18) | — | Blended / Observed / Device-based reporting identity |
| `accountSummaries.propertySummaries` | Stable (**`can_edit` field added**, 2026-06-18) | — | Indicates whether the caller can change property settings |
| `accounts` | Stable | Stable | Account listing |
| `properties` | Stable | Stable | Property management |
| `properties.userProvidedDataSettings` | NOT present | Preview (**new method** `GetUserProvidedDataSettings`, 2026-04-14) | Enhanced Conversions config |
| `properties.audiences` | NOT present | Preview | Audience definition CRUD |
| `properties.bigQueryLinks` | NOT present | Preview | BigQuery export configuration |
| `properties.channelGroups` | NOT present | Preview | Custom channel grouping |
| `properties.eventCreateRules` / `eventEditRules` | NOT present | Preview | Server-side event modification |
| `properties.expandedDataSets` | NOT present | Preview | Audience-based data subsets |
| `properties.accessBindings` | NOT present | Preview | Fine-grained user access |
| `properties.subpropertyEventFilters` | NOT present | Preview | Subproperty provisioning + filters |
| `properties.skadNetworkConversionValueSchemas` | NOT present | Preview | iOS SKAdNetwork mapping |

**v1beta stability guarantee:** "No breaking changes are expected in this channel." v1alpha is an early-preview channel that may change without notice.

**gads CLI migration status — DONE, not a pending recommendation:** `GA4_ADMIN_BASE` in `gads_lib/ga4.py` was switched from v1alpha to v1beta in gads-cli **v3.8.2**. All key-events methods now hit v1beta:

```
# Before (pre-v3.8.2)
https://analyticsadmin.googleapis.com/v1alpha/properties/{pid}/keyEvents

# After (v3.8.2+, current)
https://analyticsadmin.googleapis.com/v1beta/properties/{pid}/keyEvents
```

No other code changes were needed — the method paths, request bodies, and response shapes are identical for these resources. `gads kb check` verifies `manifest.json` (`v1beta`) still matches the live `GA4_ADMIN_BASE` constant in code on every run.

Sources: https://developers.google.com/analytics/devguides/config/admin/v1, https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.keyEvents, https://developers.google.com/analytics/devguides/config/admin/v1/changelog

---

### 13. Custom Dimensions and Metrics CRUD

**Custom dimensions** allow you to collect event or user parameters as reportable dimensions.

**Admin API — `properties.customDimensions`:**

| Method | HTTP | Path |
|--------|------|------|
| `list` | GET | `/v1beta/{parent=properties/*}/customDimensions` |
| `create` | POST | `/v1beta/{parent=properties/*}/customDimensions` |
| `get` | GET | `/v1beta/{name=properties/*/customDimensions/*}` |
| `patch` | PATCH | `/v1beta/{name=properties/*/customDimensions/*}` |
| `archive` | POST | `/v1beta/{name=properties/*/customDimensions/*}:archive` |

**CustomDimension create request body:**
```json
{
  "parameterName": "branch",
  "displayName": "Branch",
  "description": "Store branch identifier (QZ3, IND4, SJA)",
  "scope": "EVENT",
  "disallowAdsPersonalization": false
}
```

**`scope` enum:**
- `EVENT` — dimension value is read from the event parameter named `parameterName` each time the event fires
- `USER` — dimension value is read from the user property named `parameterName` and attributed to all events for that user

**Create response:**
```json
{
  "name": "properties/271773771/customDimensions/cd1",
  "parameterName": "branch",
  "displayName": "Branch",
  "description": "Store branch identifier",
  "scope": "EVENT",
  "disallowAdsPersonalization": false
}
```

After creation, the dimension becomes available in reports as `customEvent:branch` (EVENT scope) or `customUser:branch` (USER scope). There is no delete — use `archive` to deactivate. Property limit: 50 event-scoped + 25 user-scoped custom dimensions.

**Custom metrics** follow the same CRUD pattern at `properties.customMetrics`:

```json
// Create request body
{
  "parameterName": "quote_value",
  "displayName": "Quote Value",
  "description": "Estimated value of a parts quote",
  "scope": "EVENT",
  "measurementUnit": "CURRENCY"
}
```

`measurementUnit` values: `STANDARD`, `CURRENCY`, `FEET`, `METERS`, `KILOMETERS`, `MILES`, `MILLISECONDS`, `SECONDS`, `MINUTES`, `HOURS`. Property limit: 50 event-scoped custom metrics.

Sources: https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.customDimensions, https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties.customMetrics

---

### 14. Audience Exports

Audience exports allow you to retrieve the list of users who belong to a GA4 audience, enabling retargeting analysis or CRM matching.

**v1beta endpoint (preferred):** `properties.audienceExports`

**Step 1 — Create the export:**
```
POST /v1beta/properties/{property}/audienceExports
```
```json
{
  "audience": "properties/271773771/audiences/123456",
  "dimensions": [
    {"dimensionName": "deviceId"},
    {"dimensionName": "userId"}
  ]
}
```

**Create response (operation — not immediately ready):**
```json
{
  "name": "properties/271773771/audienceExports/abc123",
  "audience": "properties/271773771/audiences/123456",
  "audienceDisplayName": "Converted Users",
  "dimensions": [{"dimensionName": "deviceId"}, {"dimensionName": "userId"}],
  "state": "CREATING",
  "creationQuotaTokensCharged": 30,
  "beginCreatingTime": "2026-06-23T10:00:00Z"
}
```

**Step 2 — Poll until state is `ACTIVE`:**
```
GET /v1beta/properties/{property}/audienceExports/{audienceExport}
```

Poll `state` field: `CREATING` → `ACTIVE` (or `FAILED`). Typically ready within minutes.

**Step 3 — Query the export:**
```
POST /v1beta/properties/{property}/audienceExports/{audienceExport}:query
```
```json
{"offset": 0, "limit": 10000}
```

Response:
```json
{
  "audienceExport": { ... },
  "audienceRows": [
    {"dimensionValues": [{"value": "device-uuid-1"}, {"value": "user-id-1"}]},
    {"dimensionValues": [{"value": "device-uuid-2"}, {"value": null}]}
  ],
  "rowCount": 4821
}
```

Use offset-based pagination (same pattern as `runReport`) on the `query` endpoint.

**Available export dimensions (limited set):**
`deviceId`, `userId`, `isLimitedAdTracking`, `ipAddress`, `city`, `cityId`, `country`, `countryId`, `region`, `firstSessionDate`, `ga_session_id`, `gender`, `interests`, `age_bracket`.

**v1alpha equivalent:** `properties.audienceLists` (predecessor; same concept but older resource name). Prefer v1beta `audienceExports` for new code.

Source: https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1beta/properties.audienceExports

---

### 15. Best Practices

**Property selection:**
- Always use the numeric GA4 Property ID (e.g. `271773771`), not the Measurement ID (`G-XXXXXXXXXX`). They are different identifiers. The numeric ID is found in GA4 Admin > Property Settings > Property ID.
- Use `properties/0/metadata` for the universal dimension/metric catalog when you don't have a specific property ID at build time.

**Date range selection:**
- Avoid `today` — data is partial and will change throughout the day.
- For performance analysis, use `yesterday` or older. Attribution lag is 24–48 hours for some metrics.
- When comparing periods, use explicit `YYYY-MM-DD` dates to avoid ambiguity during DST transitions or at month boundaries.
- Use multi-range date comparison (two `dateRanges`) for period-over-period analysis rather than two separate report calls.

**Sampling thresholds:**
- GA4 standard properties may apply data sampling when queries return large result sets. Sampling is indicated by `metadata.samplingMetadatas` in the response, which includes `samplesReadCount` and `samplingSpacesSize`. If both values are present, the data is sampled.
- To reduce sampling: narrow the date range, add more specific filters, or reduce the number of dimensions. Analytics 360 properties have higher sampling thresholds.
- The `potentiallyThresholdedRequestsPerHour` quota bucket tracks requests that triggered the sampling threshold.

**Cohort analysis:**
- Cohort reports use the `cohortSpec` field in `runReport`. A cohort groups users by their `firstSessionDate` and tracks them over subsequent periods.
- Cohorts require the `cohort` and `cohortNthDay` (or `cohortNthWeek`, `cohortNthMonth`) dimensions.
- The date range in `cohortSpec.cohortsRange` controls the cohort acquisition window; `cohortSpec.cohortReportSettings.accumulate` controls whether metrics accumulate across the cohort period.

**Dimension/metric discovery:**
- Always call `GET /v1beta/properties/{pid}/metadata` before building a dynamic report. Cache the result for the session — it doesn't change frequently.
- Custom dimensions appear with `customDefinition: true` and are prefixed `customEvent:` or `customUser:`.
- Key event metrics appear prefixed `keyEvents:` (e.g. `keyEvents:whatsapp_click`).

**Filter efficiency:**
- Apply `dimensionFilter` rather than `metricFilter` where possible — dimension filters reduce data scanned before aggregation.
- Use `inListFilter` for multi-value OR conditions on the same field rather than nested `orGroup` expressions — it is more readable and equally performant.

**Quota management:**
- Always use `"returnPropertyQuota": true` in production scripts to monitor consumption.
- Batch multiple reports with `batchRunReports` (up to 5) to reduce per-call overhead.
- For very large exports (> 250,000 rows), use `reportTasks` (v1alpha) for async execution, or paginate with `limit=250000` across multiple offset calls.
- The `serverErrorsPerProjectPerHour` quota (10/hour standard) limits how many 5xx responses you can receive before being throttled. Implement exponential backoff on 500/503 responses.

**Key event management:**
- `eventName` is immutable after creation. Plan event naming carefully — renaming requires delete + recreate.
- Use `countingMethod: ONCE_PER_SESSION` for high-frequency events that represent user intent (e.g. checkout start) to avoid inflated conversion counts.
- After creating a key event, allow 24–48 hours for historical data to be reprocessed with the new key event status.
- For bulk key event creation, handle 409 `ALREADY_EXISTS` as a no-op success, not a fatal error.

Sources: https://developers.google.com/analytics/devguides/reporting/data/v1, https://developers.google.com/analytics/devguides/config/admin/v1

---

### 16. Conversion Reporting via `runReport` (v1alpha, new — 2026-04-23)

**Not yet used by gads CLI.** Added to the Data API `v1alpha` on 2026-04-23 per the official changelog: `runReport` can now pull the same paid+organic "Conversion performance" rows shown in the GA4 UI's advertising section, inside a normal report request. **Availability is per-property** — the docs explicitly warn "this feature may not be available to your Google Analytics property" (Google is rolling it out gradually); check for it first via the new `conversions` field on `getMetadata`'s response before relying on it.

**New request field — `conversionSpec` on `RunReportRequest`:**

```json
{
  "dimensions": [{"name": "date"}],
  "metrics": [{"name": "conversions"}],
  "dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}],
  "conversionSpec": {
    "conversionActions": ["conversionActions/1234"],
    "attributionModel": "DATA_DRIVEN"
  }
}
```

| Field | Type | Notes |
|-------|------|-------|
| `conversionSpec.conversionActions` | string[] | Conversion action IDs to include, formatted `"conversionActions/{id}"`. Empty = all conversions. IDs come from the new `conversions` field in `getMetadata`'s response. |
| `conversionSpec.attributionModel` | enum | `DATA_DRIVEN` (default if unspecified), `LAST_CLICK`, or `ATTRIBUTION_MODEL_UNSPECIFIED` |

**New response field — `section` on `ResponseMetaData`:** distinguishes standard reporting rows (`SECTION_REPORT`) from conversion-reporting rows (`SECTION_ADVERTISING`) (unverified: exact enum member spelling — Google's own docs page did not render the full enum list when checked; treat as `SECTION_REPORT` / `SECTION_ADVERTISING` pending confirmation against a live response).

**`getMetadata` additions:**
- `conversions` field — array of `ConversionMetadata` objects mapping conversion action IDs to display names, so callers can discover valid `conversionActions` values.
- `sections` field added to `DimensionMetadata` and `MetricMetadata` — indicates whether a given dimension/metric is valid for `SECTION_REPORT`, `SECTION_ADVERTISING`, or both.

**Practical note for Talas:** this is v1alpha, per-property-gated, and overlaps ground the CLI already covers via Google Ads conversion data — no action needed unless GA4-native paid+organic conversion breakdowns (as opposed to Ads-API conversion data) become a specific requirement.

Sources: https://developers.google.com/analytics/devguides/reporting/data/v1/changelog (2026-04-23 entry), https://developers.google.com/analytics/devguides/reporting/data/v1/rest/v1alpha/properties/runReport

---

### 17. Recent Admin API Additions Not Yet Used by gads CLI

Confirmed via the official Admin API changelog (https://developers.google.com/analytics/devguides/config/admin/v1/changelog) as the most recent entries as of 2026-07-01:

| Date | Addition | What it does |
|------|----------|---------------|
| 2026-06-18 | `UpdateReportingIdentitySettings` method (v1beta) | Update a property's reporting identity (Blended / Observed / Device-based) — affects how user counts and deduplication are modeled in reports |
| 2026-06-18 | `can_edit` field on `PropertySummary` (v1beta, `accountSummaries.list`) | Indicates whether the calling credential has a role that permits changing settings on that property — useful for pre-flight permission checks before a mutation |
| 2026-04-14 | `GetUserProvidedDataSettings` method + `UserProvidedDataSettings` resource (v1alpha) | Retrieve a property's user-provided data collection configuration (Enhanced Conversions style first-party data matching) |

`properties.dataRetentionSettings` (get/update, v1beta — stable, exact addition date not confirmed by the changelog fetch) exposes `eventDataRetention` and `userDataRetention` as `RetentionDuration` enums (`TWO_MONTHS`, `FOURTEEN_MONTHS`, plus `TWENTY_SIX_MONTHS` / `THIRTY_EIGHT_MONTHS` / `FIFTY_MONTHS` for Analytics 360 event data only) and a `resetUserDataOnNewActivity` boolean. Not currently read or written by gads CLI; documented here since it surfaced during this refresh.

None of the above are wired into `gads_lib/ga4.py` today — listed for future "add support" consideration, not as something already implemented.

Sources: https://developers.google.com/analytics/devguides/config/admin/v1/changelog, https://developers.google.com/analytics/devguides/config/admin/v1/rest/v1beta/properties/getDataRetentionSettings
