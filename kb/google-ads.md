# Google Ads REST API

> Implementation-grade reference for building new gads-cli subcommands.
> Every concrete request/response example is derived from the live `gads_lib/ads.py`
> implementation + official doc pages fetched 2026-06-23, re-verified against
> official + primary-source-cited reporting on 2026-07-01, and re-verified against
> official developers.google.com pages fetched **2026-09-04**.

---

## Status & Versions

| Version | Release Date | Status |
|---------|-------------|--------|
| v26     | Tentative ~2026-10 (listed as upcoming on the release-notes page) | Not GA as of 2026-09-04 |
| v25.2   | Tentative ~2026-09 (listed as upcoming on the release-notes page) | Not GA as of 2026-09-04 |
| v25.1   | 2026-08-19 | **GA — current latest** |
| v25     | 2026-07-22 | GA |
| v24.2   | 2026-06-24 | GA |
| v24.1   | 2026-05-13 | GA |
| v24     | 2026-04-22 | GA |
| v23.3   | 2026-06-24 | GA |
| v23.2   | 2026-03-25 | GA |
| v23.1   | 2026-02-25 | GA |
| v23     | 2026-01-28 | GA |
| v22.2   | 2026-06-24 | GA |
| v22.1   | 2026-02-25 | GA |
| v22     | 2025-10-15 | GA |
| v21.1   | 2026-02-25 | GA |
| v21     | 2025-08-06 | GA — **sunsets 2026-08-05** [verified: ads-developers.googleblog.com/2026/06/google-ads-api-v21-sunset-reminder.html, fetched 2026-07-01] |

**Version status (re-verified 2026-09-04):** v25 went GA **2026-07-22** and v25.1 went GA **2026-08-19** — both confirmed from the static HTML of the official release-notes page (anchors `v25-2026-07-22` and `v25-1-2026-08-19`). **v25.1 is the current latest GA version.** v25.2 (~Sept 2026) and v26 (~Oct 2026) appear on that page as upcoming and are **not** GA today. The July-2026 projection recorded in the previous revision of this file has therefore been superseded by the official release notes; the third-party "monthly cadence" reporting cited below turned out to be directionally right but is no longer the basis for these dates.

**gads-cli is current with upstream.** The CLI pins `v25` — the URL segment for the v25 line, which is upstream GA (v25 2026-07-22, v25.1 2026-08-19). Bumped from `v24` on 2026-09-04 after a live A/B compatibility run: all 39 read-only CLI commands and all 22 GAQL field lists used by the talas-ads fetch scripts returned byte-identical result sets under `/v24/` and `/v25/`. `v25` sunsets **August 2027**.

**Current gads-cli default:** `v25` (env var `GOOGLE_ADS_API_VERSION`, falls back to `"v25"` in `gads_lib/config.py` — bumped 2026-09-04).

**Only the MAJOR is a URL path segment.** Minor versions (`v25.1`, `v25.2`) are non-breaking and ride the same `/v25/` REST URL segment — no code or env var change is needed to pick up their new fields (see DG-13). Setting `GOOGLE_ADS_API_VERSION=v25.1` builds `https://googleads.googleapis.com/v25.1/...`, which returns a **404 HTML error page** from Google, not a JSON API error (verified live against this account 2026-09-04). gads-cli already serves v25.1 fields for free because the path stays `/v25/`.

**Sunset schedule (re-verified 2026-09-04 — the per-version table IS present in static HTML today and was read directly, superseding the previous "client-rendered / not extractable" note):** Google's documented policy remains **"Google will sunset a version 1 year after its release"**, but the published per-version dates are rounded to a month rather than falling on the exact release anniversary. Official table as read on 2026-09-04 [verified: developers.google.com/google-ads/api/docs/sunset-dates]:

| Version | Sunset |
|---------|--------|
| v21     | 2026-08-05 (already sunset) |
| v22     | October 2026 (tentative) |
| v23     | February 2027 |
| v24     | May 2027 |
| v25     | **August 2027** ← the version gads-cli pins |

The v23/v24 estimates carried in the previous revision (2027-01-28 / 2027-04-22), derived by applying the 1-year rule to release dates, were each about a month early and have been replaced with the official values.

**Sources:**
- Release notes: https://developers.google.com/google-ads/api/docs/release-notes (fetched 2026-06-23, re-fetched 2026-07-01)
- Introduction: https://developers.google.com/google-ads/api/docs/get-started/introduction (fetched 2026-06-23)
- Sunset dates: https://developers.google.com/google-ads/api/docs/sunset-dates (fetched 2026-06-23 and 2026-07-01 — page exists; policy sentence extracted 2026-07-01, per-version table still not extracted, client-rendered)
- v21 sunset reminder: https://ads-developers.googleblog.com/2026/06/google-ads-api-v21-sunset-reminder.html (fetched 2026-07-01) — confirms 2026-08-05 exact sunset date
- v24.2 announcement: https://ads-developers.googleblog.com/2026/06/announcing-v242-of-google-ads-api.html (fetched 2026-07-01)
- v24.2 feature summary: https://ppc.land/google-ads-api-v24-2-ai-transparency-and-pmax-segmentation-finally-arrive/ (fetched 2026-07-01)
- Monthly release cadence: https://searchengineland.com/google-ads-api-to-switch-to-a-monthly-release-cycle-461596 (fetched 2026-07-01, third-party reporting — unverified against an official Google post in this session)
- Smart Campaign API creation sunset: https://searchengineland.com/google-ads-api-to-stop-supporting-new-smart-campaign-creation-480999 (fetched 2026-07-01, third-party reporting)
- DSA automigration delay: https://ads-developers.googleblog.com/2026/06/dynamic-search-ads-dsa-automigration.html (title/date confirmed via search 2026-07-01; body not directly fetchable)


---

## Base URL

```
https://googleads.googleapis.com/{API_VERSION: string}/customers/{CUSTOMER_ID: 10-digit-string}/
```

**Two path patterns — do not mix them:**

| Pattern | Example | Used for |
|---------|---------|---------|
| `customers/{CID}/{resource}:{method}` | `customers/3552856345/campaigns:mutate` | Resource-scoped operations |
| `customers/{CID}:{method}` | `customers/3552856345:generateKeywordIdeas` | Customer-level operations |

The `offlineUserDataJobs/{job_id}:addOperations` and `:run` paths are **not** prefixed with `customers/` — the full resource name returned from `:create` is used verbatim:

```
https://googleads.googleapis.com/v24/{job_resource_name}:addOperations
# e.g. https://googleads.googleapis.com/v24/customers/3552856345/offlineUserDataJobs/12345:addOperations
```

Source: confirmed from `gads_lib/ads.py` + introduction page.


---

## Auth / OAuth Scopes

| Scope | Services | How to pass |
|-------|---------|-------------|
| `https://www.googleapis.com/auth/adwords` | All Google Ads API endpoints | `Authorization: Bearer {token}` header |

### Required HTTP Headers (ALL Google Ads REST calls)

| Header | Type | Required? | Value |
|--------|------|-----------|-------|
| `Authorization` | string | Always | `Bearer {oauth2_access_token}` |
| `developer-token` | string | Always | 22-char alphanumeric from API Center |
| `login-customer-id` | string (10 digits) | When using MCC | Manager account ID, no dashes |
| `Content-Type` | string | Always for POST | `application/json` |

**Example headers block (used in every request below):**
```http
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json
```

### Developer Token Access Levels

| Level | Environments | Keyword Planner / Forecast |
|-------|-------------|---------------------------|
| Test Account | Test accounts only | No |
| Explorer | Production, some restrictions | No |
| Basic | Production | No |
| Standard | Production | Yes — required for `:generateKeywordIdeas` and `:generateKeywordForecastMetrics` |

Source:
- Developer token: https://developers.google.com/google-ads/api/docs/get-started/dev-token (fetched 2026-06-23)
- Account hierarchy / login-customer-id: https://developers.google.com/google-ads/api/docs/account-management/get-account-hierarchy (fetched 2026-06-23)
- `gads-cli/CLAUDE.md` confirms `adwords` scope and Standard Access requirement


---

## Endpoint Reference

Quick index:

| # | Endpoint | gads-cli function |
|---|----------|-------------------|
| 1 | `googleAds:searchStream` | `run_gaql()` |
| 2 | `googleAds:search` | `ads_search()` |
| 3 | `googleAds:mutate` (batch) | `ads_batch_mutate()` |
| 4 | `{resource}:mutate` (single) | `ads_mutate()` |
| 5 | `offlineUserDataJobs:create` | `audience_upload_csv()` |
| 6 | `{job}:addOperations` | `audience_upload_csv()` |
| 7 | `{job}:run` | `audience_upload_csv()` |
| 8 | `userLists:mutate` | `audience_create_list()` |
| 9 | `:generateKeywordIdeas` | `generate_keyword_ideas()` |
| 10 | `:generateKeywordForecastMetrics` | `generate_keyword_forecast()` |
| 11 | `:uploadClickConversions` | `ads_upload_click_conversions()` |


---

### 1. `googleAds:searchStream` — GAQL Streaming Query

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/googleAds:searchStream`

**When to use:** Bulk data pull — all matching rows returned in a single HTTP response body as an array of batch objects. No pagination. Faster than `search` for complete datasets. Used by `run_gaql()` throughout the CLI.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | GAQL query string |

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/googleAds:searchStream
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "query": "SELECT campaign.id, campaign.name, campaign.status, metrics.clicks, metrics.cost_micros, metrics.conversions FROM campaign WHERE segments.date DURING LAST_7_DAYS ORDER BY metrics.cost_micros DESC"
}
```

#### Response

The response is a **JSON array** of batch objects. Each batch has a `results` array and a `fieldMask`. Typically a single batch for normal result sets.

```json
[
  {
    "results": [
      {
        "campaign": {
          "resourceName": "customers/3552856345/campaigns/123456789",
          "id": "123456789",
          "name": "Search - Tesla Parts - QZ3",
          "status": "ENABLED"
        },
        "metrics": {
          "clicks": "142",
          "costMicros": "185340000",
          "conversions": 3.0
        }
      },
      {
        "campaign": {
          "resourceName": "customers/3552856345/campaigns/987654321",
          "id": "987654321",
          "name": "PMax - Tesla - IND4",
          "status": "ENABLED"
        },
        "metrics": {
          "clicks": "98",
          "costMicros": "112000000",
          "conversions": 1.0
        }
      }
    ],
    "fieldMask": "campaign.id,campaign.name,campaign.status,metrics.clicks,metrics.costMicros,metrics.conversions"
  }
]
```

**Important field conventions:**
- Numbers are returned as **strings** for integer IDs (e.g. `"id": "123456789"`)
- `cost_micros` in GAQL becomes `costMicros` in JSON response (camelCase)
- `metrics.cost_micros` value is in **micros** — divide by 1,000,000 for AED/USD amount
- `metrics.conversions` is a float, not a string

#### Python access pattern

```python
results = run_gaql(creds, query)
# results is already the flat list from all batch["results"]
for row in results:
    name = row["campaign"]["name"]
    cost_aed = int(row["metrics"].get("costMicros", 0)) / 1_000_000
```

#### Error Response

```json
{
  "error": {
    "code": 400,
    "message": "Request contains an invalid argument.",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
        "errors": [
          {
            "errorCode": {
              "queryError": "UNRECOGNIZED_FIELD"
            },
            "message": "Unrecognized field in the query: 'campaign.foo'.",
            "location": {
              "fieldPathElements": [{"fieldName": "query"}]
            }
          }
        ]
      }
    ]
  }
}
```

---

### 2. `googleAds:search` — Paginated GAQL Query

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/googleAds:search`

**When to use:** Large result sets requiring pagination, or when you need `returnTotalResultsCount`. Used by `ads_search()`.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `query` | string | Yes | GAQL query string |
| `pageToken` | string | No | Token from previous response's `nextPageToken` for subsequent pages |
| `returnTotalResultsCount` | bool | No | Include `totalResultsCount` in response |
| `validateOnly` | bool | No | Validate query without executing |

**Page size is fixed at 10,000 rows** (since v19). The `page_size` field was removed — do not send it.

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/googleAds:search
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "query": "SELECT keyword_view.resource_name, ad_group_criterion.keyword.text, ad_group_criterion.keyword.match_type, metrics.impressions, metrics.clicks FROM keyword_view WHERE segments.date DURING LAST_30_DAYS ORDER BY metrics.impressions DESC"
}
```

**Second page request** (add `pageToken` from previous response):
```json
{
  "query": "SELECT keyword_view.resource_name, ad_group_criterion.keyword.text, ad_group_criterion.keyword.match_type, metrics.impressions, metrics.clicks FROM keyword_view WHERE segments.date DURING LAST_30_DAYS ORDER BY metrics.impressions DESC",
  "pageToken": "CiQIABAAGAIiHQoZZ29vZ2xl..."
}
```

#### Response

```json
{
  "results": [
    {
      "keywordView": {
        "resourceName": "customers/3552856345/keywordViews/111~222"
      },
      "adGroupCriterion": {
        "keyword": {
          "text": "tesla model 3 parts",
          "matchType": "BROAD"
        }
      },
      "metrics": {
        "impressions": "4200",
        "clicks": "310"
      }
    }
  ],
  "nextPageToken": "CiQIABAAGAIiHQoZZ29vZ2xl...",
  "fieldMask": "keywordView.resourceName,adGroupCriterion.keyword.text,adGroupCriterion.keyword.matchType,metrics.impressions,metrics.clicks"
}
```

**Final page** — `nextPageToken` is absent or empty string:
```json
{
  "results": [ /* ... last batch ... */ ],
  "fieldMask": "..."
}
```

#### Pagination Loop Pattern

```python
page_token = None
results = []
while True:
    payload = {"query": query}
    if page_token:
        payload["pageToken"] = page_token
    resp = requests.post(url, headers=headers, json=payload)
    data = resp.json()
    results.extend(data.get("results", []))
    page_token = data.get("nextPageToken")
    if not page_token:
        break
```

**Rule:** The query string must be **byte-for-byte identical** across page requests to use the server-side cache and keep the result stable.

---

### 3. `googleAds:mutate` — Cross-Resource Batch Mutate

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/googleAds:mutate`

**When to use:** Creating or modifying multiple different resource types in a single atomic call (e.g., campaign + budget + ad group together). Uses **`mutateOperations`** key (plural). Used by `ads_batch_mutate()`.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mutateOperations` | array | Yes | Array of typed operation objects |
| `partialFailure` | bool | No | If true, successful ops commit even if others fail |
| `validateOnly` | bool | No | Validate without executing; useful for dry-run |
| `responseContentType` | string | No | `MUTABLE_RESOURCE` or `RESOURCE_NAME_ONLY` (default) |

Each element of `mutateOperations` is a **typed wrapper**: `{"{resourceType}Operation": {"create"|"update"|"remove": ...}}`.

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/googleAds:mutate
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "mutateOperations": [
    {
      "campaignBudgetOperation": {
        "create": {
          "name": "Tesla Parts Budget - QZ3 - 2026-06",
          "amountMicros": "35000000",
          "deliveryMethod": "STANDARD"
        }
      }
    },
    {
      "campaignOperation": {
        "update": {
          "resourceName": "customers/3552856345/campaigns/123456789",
          "campaignBudget": "customers/3552856345/campaignBudgets/-1"
        },
        "updateMask": "campaignBudget"
      }
    }
  ],
  "partialFailure": false
}
```

Note: Temporary resource names like `"-1"` can be used to reference resources created earlier in the same `mutateOperations` array.

#### Response

```json
{
  "mutateOperationResponses": [
    {
      "campaignBudgetResult": {
        "resourceName": "customers/3552856345/campaignBudgets/987654"
      }
    },
    {
      "campaignResult": {
        "resourceName": "customers/3552856345/campaigns/123456789"
      }
    }
  ]
}
```

**Operation type key names** (common ones):

| Resource | Operation key in mutateOperations |
|----------|----------------------------------|
| campaign | `campaignOperation` |
| campaign budget | `campaignBudgetOperation` |
| ad group | `adGroupOperation` |
| ad group ad | `adGroupAdOperation` |
| ad group criterion (keyword) | `adGroupCriterionOperation` |
| campaign criterion | `campaignCriterionOperation` |
| asset | `assetOperation` |
| campaign asset | `campaignAssetOperation` |
| conversion action | `conversionActionOperation` |

---

### 4. `{resource}:mutate` — Single-Resource Mutate

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/{resource}:mutate`

**When to use:** Mutating a single resource type — simpler shape than cross-resource batch. Uses **`operations`** key (singular). Used by `ads_mutate()`.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `operations` | array | Yes | Array of `create`/`update`/`remove` ops |
| `partialFailure` | bool | No | Allow partial success |
| `validateOnly` | bool | No | Dry-run validation |

**Example: Enable an ad group (update)**

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/adGroups:mutate
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "operations": [
    {
      "update": {
        "resourceName": "customers/3552856345/adGroups/111222333",
        "status": "ENABLED"
      },
      "updateMask": "status"
    }
  ],
  "partialFailure": false
}
```

**Example: Remove a keyword (negative)**

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/adGroupCriteria:mutate
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "operations": [
    {
      "remove": "customers/3552856345/adGroupCriteria/111222333~444555666"
    }
  ]
}
```

**Example: Create a campaign-level negative keyword**

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/campaignCriteria:mutate
Content-Type: application/json
...

{
  "operations": [
    {
      "create": {
        "campaign": "customers/3552856345/campaigns/123456789",
        "keyword": {
          "text": "repair",
          "matchType": "BROAD"
        },
        "negative": true
      }
    }
  ]
}
```

#### Response

```json
{
  "results": [
    {
      "resourceName": "customers/3552856345/adGroups/111222333"
    }
  ]
}
```

**Partial failure response** (when `partialFailure: true` and some ops fail):
```json
{
  "results": [
    { "resourceName": "customers/3552856345/adGroups/111222333" },
    {}
  ],
  "partialFailureError": {
    "code": 3,
    "message": "Multiple errors in response",
    "details": [
      {
        "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
        "errors": [
          {
            "errorCode": { "criterionError": "INVALID_KEYWORD_TEXT" },
            "message": "Keyword text is invalid.",
            "location": {
              "fieldPathElements": [
                { "fieldName": "operations", "index": 1 },
                { "fieldName": "create" }
              ]
            }
          }
        ]
      }
    ]
  }
}
```

---

### 5. `offlineUserDataJobs:create` — Create Customer Match Job

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/offlineUserDataJobs:create`

**When to use:** Step 1 of Customer Match upload. Creates the job, returns a `resourceName` used for subsequent `addOperations` and `run` calls.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `job.type` | string | Yes | `CUSTOMER_MATCH_USER_LIST` |
| `job.customerMatchUserListMetadata.userList` | string | Yes | Resource name of the target user list |
| `job.customerMatchUserListMetadata.consent.adUserData` | string | Yes (post-2024) | `GRANTED` or `DENIED` |
| `job.customerMatchUserListMetadata.consent.adPersonalization` | string | Yes (post-2024) | `GRANTED` or `DENIED` |

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/offlineUserDataJobs:create
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "job": {
    "type": "CUSTOMER_MATCH_USER_LIST",
    "customerMatchUserListMetadata": {
      "userList": "customers/3552856345/userLists/7654321",
      "consent": {
        "adUserData": "GRANTED",
        "adPersonalization": "GRANTED"
      }
    }
  }
}
```

#### Response

```json
{
  "resourceName": "customers/3552856345/offlineUserDataJobs/12345678"
}
```

Store this `resourceName` — it becomes the base path for steps 2 and 3.

---

### 6. `{job}:addOperations` — Upload Hashed PII

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/{job_resource_name}:addOperations`

Note: the full job resource name already contains `customers/{CID}/offlineUserDataJobs/{id}`, so the URL is:
```
https://googleads.googleapis.com/v24/customers/3552856345/offlineUserDataJobs/12345678:addOperations
```

**Batch in chunks of 100** (as used in `audience_upload_csv()`). Max documented limit is 100,000 per job total.

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `operations` | array | Yes | Array of `create` user data ops |
| `enableWarnings` | bool | No | Return warnings for skipped records |

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/offlineUserDataJobs/12345678:addOperations
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "operations": [
    {
      "create": {
        "userIdentifiers": [
          {
            "hashedEmail": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          },
          {
            "hashedPhoneNumber": "8f14e45fceea167a5a36dedd4bea2543380e7a6a602c6b3ba61b56f6718c5d07"
          },
          {
            "addressInfo": {
              "hashedFirstName": "2c624232cdd221771294dfbb310acbc8f27fac24b34beaccb8c77e4752dba689",
              "hashedLastName": "19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7",
              "countryCode": "AE"
            }
          }
        ]
      }
    }
  ],
  "enableWarnings": true
}
```

#### PII Hashing Rules (MANDATORY — violations cause silent drops or API errors)

| Identifier | Pre-processing | Hash |
|-----------|----------------|------|
| Email | `email.strip().lower()` | SHA-256 hex |
| Phone | Normalize to E.164 (`+971XXXXXXXXX`), then `.strip()` | SHA-256 hex |
| First name | `name.strip().lower()` | SHA-256 hex |
| Last name | `name.strip().lower()` | SHA-256 hex |
| Country code | ISO-3166 two-letter (e.g. `"AE"`) | **NOT hashed** |

**Phone E.164 normalization rules** (from `ads.py`):
- `00971...` → `+971...`
- `05XXXXXXXX` (10 digits) → `+9715XXXXXXXX`
- `5XXXXXXXX` (9 digits) → `+9715XXXXXXXX`
- `971...` (no plus) → `+971...`
- Must have at least 8 digits after stripping non-digits

**Name validation rules** (from `_is_valid_name()` in `ads.py`):
- Must be non-empty after strip
- Max 30 characters
- No special chars: `* ( ) , [ ] { } | / \`
- No digits
- Max 4 space-separated tokens (words)
- If either first or last name fails validation, `addressInfo` is omitted entirely

#### Response

```json
{}
```

Empty 200 response on success. Rate-limited responses return `429` — use exponential backoff.

---

### 7. `{job}:run` — Kick Off Processing

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/{job_resource_name}:run`

Triggers async processing of uploaded user data. Processing is fire-and-forget — poll the job status separately via GAQL on `offline_user_data_job` if needed.

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/offlineUserDataJobs/12345678:run
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{}
```

#### Response

```json
{
  "name": "customers/3552856345/operations/1234567890",
  "done": false
}
```

The returned `name` is a long-running operation resource name. To poll completion:
```gaql
SELECT offline_user_data_job.resource_name,
       offline_user_data_job.id,
       offline_user_data_job.status,
       offline_user_data_job.type,
       offline_user_data_job.failure_reason
FROM offline_user_data_job
WHERE offline_user_data_job.resource_name = 'customers/3552856345/offlineUserDataJobs/12345678'
```
Job `status` values: `PENDING`, `RUNNING`, `SUCCESS`, `FAILED`.

---

### 8. `userLists:mutate` — Manage Customer Match Lists

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/userLists:mutate`

**Create a CRM-based list:**

```http
POST https://googleads.googleapis.com/v24/customers/3552856345/userLists:mutate
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "operations": [
    {
      "create": {
        "name": "Talas CRM - All Customers 2026-Q2",
        "description": "All CRM contacts uploaded from Talas ERP",
        "membershipStatus": "OPEN",
        "membershipLifeSpan": 540,
        "crmBasedUserList": {
          "uploadKeyType": "CONTACT_INFO",
          "dataSourceType": "FIRST_PARTY"
        }
      }
    }
  ]
}
```

#### Response

```json
{
  "results": [
    {
      "resourceName": "customers/3552856345/userLists/7654321"
    }
  ]
}
```

**Find list by name** (GAQL via `run_gaql`):
```sql
SELECT user_list.resource_name, user_list.name, user_list.member_count
FROM user_list
WHERE user_list.name = 'Talas CRM - All Customers 2026-Q2'
```

---

### 9. `:generateKeywordIdeas` — Keyword Research

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}:generateKeywordIdeas`

**Access level required:** Standard (not available with Explorer or Basic tokens).

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keywordSeed.keywords` | string[] | One of the seeds required | Keywords describing your product/service |
| `urlSeed.url` | string | One of the seeds required | Landing page URL for content analysis |
| `keywordAndUrlSeed` | object | One of the seeds required | Combined keywords + URL |
| `siteSeed.site` | string | One of the seeds required | Domain, up to 250k keyword ideas |
| `languageId` | string | Yes | Language constant ID (e.g. `"1000"` = English) |
| `geoTargetConstants` | object[] | No | Array of `{"resourceName": "geoTargetConstants/{id}"}` |
| `keywordPlanNetwork` | string | No | `GOOGLE_SEARCH` or `GOOGLE_SEARCH_AND_PARTNERS` |
| `includeAdultKeywords` | bool | No | Default false |

**Common language IDs:** `1000` = English, `1019` = Arabic. **Common geo IDs:** `2784` = UAE, `2840` = USA, `2682` = Saudi Arabia.

**Keyword sanitization required** before sending (remove `! @ % , * '`).

```http
POST https://googleads.googleapis.com/v24/customers/3552856345:generateKeywordIdeas
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "keywordSeed": {
    "keywords": ["tesla parts", "tesla body parts", "model 3 bumper"]
  },
  "languageId": "1000",
  "geoTargetConstants": [
    {"resourceName": "geoTargetConstants/2784"}
  ],
  "keywordPlanNetwork": "GOOGLE_SEARCH"
}
```

#### Response

```json
{
  "results": [
    {
      "text": "tesla model 3 parts",
      "keywordIdeaMetrics": {
        "competition": "LOW",
        "avgMonthlySearches": "1000",
        "monthlySearchVolumes": [
          {"year": 2026, "month": "MAY", "monthlySearches": "880"},
          {"year": 2026, "month": "APRIL", "monthlySearches": "1100"}
        ],
        "competitionIndex": "12"
      }
    },
    {
      "text": "tesla parts uae",
      "keywordIdeaMetrics": {
        "competition": "MEDIUM",
        "avgMonthlySearches": "320",
        "competitionIndex": "45"
      }
    }
  ]
}
```

Source: https://developers.google.com/google-ads/api/docs/keyword-planning/generate-keyword-ideas (fetched 2026-06-23)

---

### 10. `:generateKeywordForecastMetrics` — Budget Forecasting

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}:generateKeywordForecastMetrics`

**Access level required:** Standard.

```http
POST https://googleads.googleapis.com/v24/customers/3552856345:generateKeywordForecastMetrics
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "campaignToForecast": {
    "keywordPlanKeywords": [
      {"keyword": "tesla parts"},
      {"keyword": "tesla body parts dubai"}
    ],
    "keywordPlanNetwork": "GOOGLE_SEARCH",
    "languageConstants": ["languageConstants/1000"],
    "geoTargetConstants": ["geoTargetConstants/2784"]
  }
}
```

#### Response

```json
{
  "campaignForecastMetrics": {
    "impressions": 4500.0,
    "clicks": 310.0,
    "averageCpc": {
      "amountMicros": "1850000",
      "currencyCode": "AED"
    },
    "costMicros": "573500000",
    "conversions": 8.4,
    "conversionRate": 0.027
  }
}
```

---

### 11. `:uploadClickConversions` — Offline Conversion Upload

**Method:** `POST`
**Full path:** `https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}:uploadClickConversions`

#### Request

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `conversions` | array | Yes | Array of `ClickConversion` objects |
| `conversions[].gclid` | string | Yes | Google Click ID from landing page URL |
| `conversions[].conversionAction` | string | Yes | Resource name: `customers/{CID}/conversionActions/{id}` |
| `conversions[].conversionDateTime` | string | Yes | `"YYYY-MM-DD HH:MM:SS+TZ"` format |
| `conversions[].conversionValue` | float | No | Conversion value in `currencyCode` currency |
| `conversions[].currencyCode` | string | No | ISO 4217, e.g. `"AED"` |
| `partialFailure` | bool | No | Allow partial success across conversions |

```http
POST https://googleads.googleapis.com/v24/customers/3552856345:uploadClickConversions
Authorization: Bearer ya29.A0AfH6SMBxxxxxxxx
developer-token: ABcDeFgHiJkLmNoPqRsTuV
login-customer-id: 6706955825
Content-Type: application/json

{
  "conversions": [
    {
      "gclid": "EAIaIQobChMI3pHX5r7N7AIVxxxxxx",
      "conversionAction": "customers/3552856345/conversionActions/987654321",
      "conversionDateTime": "2026-06-20 14:32:00+04:00",
      "conversionValue": 350.0,
      "currencyCode": "AED"
    }
  ],
  "partialFailure": true
}
```

#### Response (success)

```json
{
  "results": [
    {
      "gclid": "EAIaIQobChMI3pHX5r7N7AIVxxxxxx",
      "conversionAction": "customers/3552856345/conversionActions/987654321",
      "conversionDateTime": "2026-06-20 14:32:00+04:00"
    }
  ]
}
```

---

## GAQL Reference

### Syntax

```sql
SELECT field1, field2, ...
FROM resource_name
WHERE condition1 AND condition2
ORDER BY field ASC|DESC
LIMIT N
```

All clauses except `SELECT` and `FROM` are optional. No `JOIN` — implicit joins via attributed resources.

### Supported Resources (queryable FROM)

| Resource | Contains | Key fields |
|----------|---------|-----------|
| `campaign` | Campaign config + budget + bidding | `campaign.id`, `campaign.name`, `campaign.status`, `campaign.advertising_channel_type`, `campaign.target_cpa`, `campaign.target_roas` |
| `ad_group` | Ad group config | `ad_group.id`, `ad_group.name`, `ad_group.status`, `ad_group.campaign`, `ad_group.cpc_bid_micros` |
| `ad_group_ad` | Individual ads | `ad_group_ad.ad.id`, `ad_group_ad.ad.type`, `ad_group_ad.status`, `ad_group_ad.ad.responsive_search_ad` |
| `ad_group_criterion` | Keywords, audiences, criteria | `ad_group_criterion.keyword.text`, `ad_group_criterion.keyword.match_type`, `ad_group_criterion.status`, `ad_group_criterion.negative` |
| `keyword_view` | Keyword-level metrics | Use with `ad_group_criterion.*` fields for keyword text |
| `campaign_criterion` | Campaign-level criteria | `campaign_criterion.keyword.text`, `campaign_criterion.negative` |
| `user_list` | Audience lists | `user_list.name`, `user_list.resource_name`, `user_list.member_count`, `user_list.type` |
| `conversion_action` | Conversion action definitions | `conversion_action.name`, `conversion_action.type`, `conversion_action.status` |
| `offline_user_data_job` | Customer Match job status | `offline_user_data_job.status`, `offline_user_data_job.failure_reason` |
| `search_term_view` | Search terms that triggered ads | `search_term_view.search_term`, `search_term_view.status` |
| `geo_target_constant` | Geographic constants | `geo_target_constant.name`, `geo_target_constant.country_code` |

### Segment vs Resource Field Rules

Segments split metric rows by dimension. Key restrictions:

1. **Only one segmenting date field** — can use `segments.date`, `segments.week`, `segments.month`, or `segments.year` but not more than one time segment simultaneously.
2. **Segments and metrics must be compatible** — not all fields can appear together. Check `selectable_with` via `GoogleAdsFieldService` for unusual combos.
3. **Metrics require a reportable resource** — cannot select `metrics.*` from non-reportable resources like `geo_target_constant`.
4. **Attributed resources** — you can select fields from related resources (e.g. `campaign.name` in a query `FROM ad_group`) without explicit joins.

```sql
-- VALID: one date segment with metrics
SELECT campaign.name, segments.date, metrics.clicks, metrics.cost_micros
FROM campaign
WHERE segments.date DURING LAST_7_DAYS

-- INVALID: cannot mix segments.date and segments.week
-- SELECT campaign.name, segments.date, segments.week FROM campaign  ← ERROR

-- VALID: segment by device
SELECT campaign.name, segments.device, metrics.impressions
FROM campaign
WHERE segments.date DURING LAST_30_DAYS
```

### Date Filtering

**Using date macros (DURING keyword):**
```sql
WHERE segments.date DURING LAST_7_DAYS
WHERE segments.date DURING LAST_30_DAYS
WHERE segments.date DURING THIS_MONTH
WHERE segments.date DURING LAST_MONTH
WHERE segments.date DURING YESTERDAY
```

**Available date macros:** `TODAY`, `YESTERDAY`, `LAST_7_DAYS`, `LAST_14_DAYS`, `LAST_30_DAYS`, `THIS_WEEK_SUN_TODAY`, `THIS_WEEK_MON_TODAY`, `LAST_WEEK_SUN_SAT`, `LAST_WEEK_MON_SUN`, `THIS_MONTH`, `LAST_MONTH`, `LAST_BUSINESS_WEEK`

**Using explicit date range (BETWEEN):**
```sql
WHERE segments.date BETWEEN '2026-06-01' AND '2026-06-22'
```

**Using exact date:**
```sql
WHERE segments.date = '2026-06-22'
```

**Never use TODAY for performance analysis** — 24-48h attribution lag means today's data is incomplete. Always use `YESTERDAY` or earlier.

### WHERE Operators

| Operator | Types | Example |
|----------|-------|---------|
| `=`, `!=` | string, enum, int, bool | `campaign.status = 'ENABLED'` |
| `>`, `>=`, `<`, `<=` | int, float | `metrics.clicks > 100` |
| `IN`, `NOT IN` | list | `campaign.status IN ('ENABLED', 'PAUSED')` |
| `CONTAINS ANY` | repeated field | (for multi-value fields) |
| `LIKE`, `NOT LIKE` | string | `campaign.name LIKE '%Tesla%'` |
| `REGEXP_MATCH` | string | `campaign.name REGEXP_MATCH '.*Tesla.*'` (RE2 syntax) |
| `IS NULL`, `IS NOT NULL` | any | `campaign.target_cpa IS NOT NULL` |
| `DURING` | date | `segments.date DURING LAST_30_DAYS` |
| `BETWEEN` | date, int | `segments.date BETWEEN '2026-01-01' AND '2026-06-01'` |

**Enum values** use unquoted uppercase strings in some contexts but quoted strings in others. When in doubt, use quoted: `campaign.status = 'ENABLED'`.

Source: https://developers.google.com/google-ads/api/docs/query/grammar (fetched 2026-06-23)

### Common GAQL Patterns

```sql
-- Campaign performance with cost in AED
SELECT campaign.name, campaign.status,
       metrics.clicks, metrics.impressions, metrics.cost_micros,
       metrics.conversions, metrics.cost_per_conversion
FROM campaign
WHERE segments.date DURING LAST_7_DAYS
  AND campaign.status = 'ENABLED'
ORDER BY metrics.cost_micros DESC

-- Keywords with search volume
SELECT ad_group_criterion.keyword.text,
       ad_group_criterion.keyword.match_type,
       ad_group_criterion.status,
       metrics.impressions, metrics.clicks, metrics.ctr,
       metrics.average_cpc, metrics.cost_micros
FROM keyword_view
WHERE segments.date DURING LAST_30_DAYS
  AND ad_group_criterion.status != 'REMOVED'

-- Search terms (what users actually typed)
SELECT search_term_view.search_term,
       search_term_view.status,
       metrics.impressions, metrics.clicks, metrics.conversions
FROM search_term_view
WHERE segments.date DURING LAST_14_DAYS
ORDER BY metrics.impressions DESC
LIMIT 200

-- Ad performance
SELECT ad_group_ad.ad.id,
       ad_group_ad.ad.responsive_search_ad.headlines,
       ad_group_ad.status,
       metrics.clicks, metrics.impressions, metrics.ctr, metrics.conversions
FROM ad_group_ad
WHERE segments.date DURING LAST_30_DAYS
  AND ad_group_ad.status = 'ENABLED'

-- Audience (user list) inventory
SELECT user_list.resource_name, user_list.name,
       user_list.member_count, user_list.type,
       user_list.membership_status
FROM user_list

-- Conversion actions
SELECT conversion_action.name, conversion_action.status,
       conversion_action.type, conversion_action.id,
       conversion_action.counting_type
FROM conversion_action
WHERE conversion_action.status = 'ENABLED'
```


---

## Pagination & Quotas

### Pagination (`googleAds:search`)

- Page size: **fixed at 10,000 rows** since v19. `page_size` field removed — do not send.
- Use `nextPageToken` from response body → pass as `pageToken` in next request.
- Final page has no `nextPageToken` key (or it is an empty string).
- Query must be **byte-for-byte identical** across all page requests for server-side cache to hold.

### Rate Limits & Quotas

Concrete numbers **are** published — at `docs/best-practices/quotas`, not the `docs/concepts/quotas` path this file previously cited as a 404 (that path is still 404 today). Verified 2026-09-04:

| Limit | Value |
|-------|-------|
| Explorer access — daily operations (production account) | 2,880 / day |
| Explorer access — daily operations (test account) | 15,000 / day |
| Basic access — daily operations | 15,000 / day |
| Operations per mutate request | 10,000 max |
| Action operations per mutate request | 100 max |
| KeywordPlanIdeaService / Planning services | 1 QPS |
| Conversions per conversion-upload request | 2,000 max |
| Billing / AccountBudget operations per mutate request | 1 |
| gRPC response size cap | 64 MB |

Confirmed behavior (unchanged):

- Quotas are **per developer token**, not per customer account.
- Access level determines ceiling: Standard > Basic > Explorer > Test.
- Rate-limited responses: **HTTP 429**. gads-cli retries 429 unconditionally with exponential backoff (`GADS_HTTP_RETRIES`, default 4) — see the CLI's retry semantics in README.
- Batch efficiently: prefer ~500 operations per mutate request rather than individual calls.
- `addOperations` is most likely to hit 429 for large CSV uploads — retry with backoff.

Sources:
- https://developers.google.com/google-ads/api/docs/best-practices/quotas (fetched 2026-09-04, HTTP 200 — the authoritative numeric table)
- https://developers.google.com/google-ads/api/docs/best-practices/overview (fetched 2026-06-23)


---

## Error Reference

### HTTP Status Codes

| Status | Meaning | Common cause |
|--------|---------|-------------|
| 200 | Success | — |
| 400 | INVALID_ARGUMENT | Bad GAQL, wrong field name, invalid enum, missing required field |
| 401 | UNAUTHENTICATED | Expired or invalid OAuth token |
| 403 | PERMISSION_DENIED | Missing `login-customer-id` for MCC; wrong customer access; Basic token on Standard-only endpoint |
| 404 | NOT_FOUND | Wrong resource name, tilde vs slash in criterion path |
| 429 | RESOURCE_EXHAUSTED | Rate limit hit — backoff and retry |
| 500 | INTERNAL | Transient server error — retry with backoff |
| 503 | UNAVAILABLE | Service temporarily down — retry |

### Error Response Shape

All Google Ads API errors return the same envelope:

```json
{
  "error": {
    "code": 400,
    "message": "Human-readable summary",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
        "errors": [
          {
            "errorCode": {
              "{errorDomain}Error": "{ERROR_ENUM_VALUE}"
            },
            "message": "Detailed error message",
            "location": {
              "fieldPathElements": [
                { "fieldName": "operations", "index": 0 },
                { "fieldName": "create" }
              ]
            }
          }
        ],
        "requestId": "abc123xyz"
      }
    ]
  }
}
```

### Common Error Codes

| `errorCode` key | Value | Cause |
|----------------|-------|-------|
| `queryError` | `UNRECOGNIZED_FIELD` | Field name typo in GAQL |
| `queryError` | `PROHIBITED_FIELD_COMBINATION` | Incompatible fields selected together |
| `queryError` | `INVALID_VALUE` | Bad enum or filter value |
| `criterionError` | `INVALID_KEYWORD_TEXT` | Keyword contains invalid chars or too long |
| `criterionError` | `KEYWORD_HAS_TOO_MANY_WORDS` | Google Ads keyword word limit exceeded |
| `authorizationError` | `DEVELOPER_TOKEN_NOT_APPROVED` | Token not approved for production |
| `authorizationError` | `USER_PERMISSION_DENIED` | Account access issue |
| `resourceCountLimitExceededException` | — | Too many operations in one mutate |
| `internalError` | `TRANSIENT_ERROR` | Retry-able server-side error |

### Extracting Error Details in Python

```python
resp = requests.post(url, headers=headers, json=payload)
if resp.status_code != 200:
    try:
        err = resp.json()["error"]
        for detail in err.get("details", []):
            for gads_err in detail.get("errors", []):
                print(gads_err["message"])
                print(gads_err.get("errorCode"))
                print(gads_err.get("location"))
    except Exception:
        pass
    raise SystemExit(1)
```


---

## Gotchas

1. **`mutateOperations` vs `operations` key** — cross-resource batch mutate uses `mutateOperations`; single-resource mutate uses `operations`. Mixing causes 400. See gads-cli CLAUDE.md.

2. **Tilde `~` in ad group criterion resource names** — format is `customers/{CID}/adGroupCriteria/{adGroupId}~{criterionId}`. Slash instead of tilde → 404.

3. **Fixed page size of 10,000** — `page_size` was removed in v19. Sending it causes errors or is silently ignored. Source: paging docs (fetched 2026-06-23).

4. **No same-day data** — 24-48h attribution lag. Never use `TODAY` for performance analysis. Use `YESTERDAY` or earlier.

5. **Customer Match consent fields required** — `consent.adUserData` and `consent.adPersonalization` must be `"GRANTED"`. Missing these causes upload failure. Required post-2024.

6. **OfflineUserDataJobService Customer Match restriction — IN FORCE SINCE 2026-04-01, NOT a future note.** Developer tokens with no successful Customer Match request in the qualifying window (2025-10-01 to 2026-03-31) are restricted, and `OfflineUserDataJobService` uploads from them fail. Wording re-confirmed verbatim on the official page 2026-09-04 (page last updated 2026-08-19). **[UNVERIFIED for this account: no Customer Match call has been made from the Talas developer token in any audit, so whether that token retains access is unknown. Treat `gads audience upload` as at-risk until a live call proves otherwise.]** Fallback path: the Data Manager API (`gads data-manager audience-upload`).

7. **Keyword special characters** — `generateKeywordIdeas` and `generateKeywordForecastMetrics` reject `! @ % , * '`. Sanitize: `re.sub(r'[!@%,*\']', '', keyword)`.

8. **Asset creation is two-step** — create asset via `assets:mutate`, then link via `campaignAssets:mutate`. Cannot be combined in one call.

9. **sitelink finalUrls placement** — `finalUrls` at the top level of the create object, NOT nested inside `sitelinkAsset`. Nesting causes silent URL drops.

10. **Standard Access required for Keyword Planner / Forecast** — Explorer/Basic tokens → 403 PERMISSION_DENIED on these endpoints.

11. **`login-customer-id` header** — must be the MCC manager account ID. Without it when accessing a client account → PERMISSION_DENIED.

12. **`addressInfo` with empty names in Customer Match** — `{"addressInfo": {"countryCode": "AE"}}` with no hashed names is silently dropped. Validate both names are present and pass `_is_valid_name()` before including.

13. **GAQL segment compatibility** — not all field combinations are valid. Use `GoogleAdsFieldService` to check `selectable_with` constraints.

14. **`offlineUserDataJobs/{job}:addOperations` path** — uses the full resource name returned from `:create`, which already includes `customers/{CID}/`. Do not prepend the customer prefix again.

15. **Temporary resource names in batch mutate** — use `"-1"`, `"-2"`, etc. as resource names within the same `mutateOperations` array to reference just-created resources. Google resolves them in order.

16. **`updateMask` required for update ops** — when using `update` in any mutate operation, `updateMask` must list the fields being changed (comma-separated, camelCase). Omitting it may result in no change or 400.

17. **cost_micros arithmetic** — all cost values from the API are in micros (1/1,000,000 of the currency unit). `185340000 micros = 185.34 AED`. Always divide by `1_000_000`.

18. **camelCase in responses, snake_case in GAQL** — GAQL uses `metrics.cost_micros` but the JSON response uses `"costMicros"`. Field names transform on output.

Sources: gads-cli CLAUDE.md + `gads_lib/ads.py` + doc pages fetched 2026-06-23.


---

## Coverage vs Current gads-cli

### Endpoints Currently Used

| Endpoint | gads-cli function | CLI commands |
|---|---|---|
| `googleAds:searchStream` | `run_gaql()` | `query`, `campaign list/status/perf`, `adgroup`, `ad`, `keyword list/search-terms`, `report`, `audience list`, `conversion list/perf` |
| `googleAds:search` | `ads_search()` | Paginated queries |
| `googleAds:mutate` (batch) | `ads_batch_mutate()` | `batch-mutate`, two-step asset flows |
| `{resource}:mutate` | `ads_mutate()` | `campaign budget`, `keyword add/remove/negative`, `ad`, `asset`, `conversion create`, `audience create` |
| `offlineUserDataJobs:create` | `audience_upload_csv()` | `audience upload` |
| `{job}:addOperations` | `audience_upload_csv()` | `audience upload` |
| `{job}:run` | `audience_upload_csv()` | `audience upload` |
| `userLists:mutate` | `audience_create_list()` | `audience create` |
| `:generateKeywordIdeas` | `generate_keyword_ideas()` | `keyword ideas` |
| `:generateKeywordForecastMetrics` | `generate_keyword_forecast()` | `keyword forecast` |
| `:uploadClickConversions` | `ads_upload_click_conversions()` | `conversion upload` |

### Gaps / Not Yet Implemented

| Endpoint / Service | Purpose | Notes |
|---|---|---|
| `:uploadCallConversions` | Upload offline call conversions | Parallel to `:uploadClickConversions`; uses same pattern |
| `ConversionAdjustmentUploadService` | Restate/retract uploaded conversions | Correcting post-attribution conversion values |
| `offlineUserDataJobs` status poll | Check job completion | Currently fire-and-forget; poll via GAQL on `offline_user_data_job` |
| `BiddingStrategyService` | Portfolio bid strategies | Only inline campaign-level tCPA/tROAS handled |
| Shared budget management | `campaignBudgets:mutate` (shared) | Budget mutate works but no shared-budget workflow |
| `adSchedules:mutate` | Ad schedule criteria | Removal done via snapshot replay; no dedicated CLI command |
| `AssetGroupService` | PMax asset group management | No PMax asset group create/update commands |
| `AssetGroupListingGroupFilterService` | PMax product partitions | Not implemented |
| `AudienceService` | Audience definition (not user lists) | Different from `userLists`; segments management |
| `GoogleAdsFieldService` | Field metadata / `selectable_with` checks | Useful for GAQL field compatibility debugging |
| `LocalServicesLeadService` | Local Services Ads lead management | Not applicable to current account type |
| `SmartCampaignService` | Smart campaign management | Not implemented. Lower priority now: API creation of **new** Smart Campaigns is sunsetting 2026-08-03 (existing campaigns unaffected) — see DG-15 |


---

## Sources

URLs fetched on 2026-06-23 unless marked otherwise. Refresh pass on 2026-07-01 added items 16-24.

1. https://developers.google.com/google-ads/api/docs/get-started/introduction — API overview (as of 2026-06-23 fetch, v24.2 was still "announced"; it GA'd 2026-06-24 — see item 18)
2. https://developers.google.com/google-ads/api/docs/release-notes — Version timeline (v21–v24.1), release dates
3. https://developers.google.com/google-ads/api/rest/reference/rest — REST reference structure (v22, v23, v24 shown)
4. https://developers.google.com/google-ads/api/docs/query/grammar — GAQL grammar, operators, date macros
5. https://developers.google.com/google-ads/api/docs/reporting/paging — Pagination, 10,000-row fixed page size (v19+)
6. https://developers.google.com/google-ads/api/docs/keyword-planning/generate-keyword-ideas — KeywordPlanIdeaService, request shape, response fields
7. https://developers.google.com/google-ads/api/docs/best-practices/overview — Batch operations, error handling, development best practices
8. https://developers.google.com/google-ads/api/docs/get-started/dev-token — Developer token, access levels, `developer-token` header
9. https://developers.google.com/google-ads/api/docs/account-management/get-account-hierarchy — login-customer-id header, manager vs client account access
10. https://developers.google.com/google-ads/api/docs/sunset-dates — Sunset dates page exists; per-version table still not extracted as of 2026-07-01 (client-rendered), but the "1 year after release" policy sentence and the release-date table WERE extracted from raw HTML on 2026-07-01
11. https://developers.google.com/google-ads/api/docs/concepts/quotas — HTTP 404 at this URL (re-checked 2026-07-01, still true)
12. https://developers.google.com/google-ads/api/docs/query/overview — GAQL overview, resource types
13. `/home/talas9/talas-ads/gads-cli/gads_lib/ads.py` — Primary source for all endpoint paths, request shapes, response handling, PII hashing
14. `/home/talas9/talas-ads/gads-cli/gads_lib/config.py` — API_VERSION default (`v24`), env var names — re-confirmed via direct grep 2026-07-01
15. `/home/talas9/talas-ads/gads-cli/CLAUDE.md` — Command taxonomy, auth requirements per service, known gotchas
16. https://developers.google.com/google-ads/api/docs/concepts/versioning (fetched 2026-07-01) — vMAJOR_MINOR numbering scheme, major-vs-minor endpoint behavior
17. https://ads-developers.googleblog.com/2026/06/google-ads-api-v21-sunset-reminder.html (fetched 2026-07-01) — confirms v21 sunset = 2026-08-05
18. https://ads-developers.googleblog.com/2026/06/announcing-v242-of-google-ads-api.html (fetched 2026-07-01) — v24.2 GA, 2026-06-24
19. https://ppc.land/google-ads-api-v24-2-ai-transparency-and-pmax-segmentation-finally-arrive/ (fetched 2026-07-01) — v24.2 feature detail: SyntheticContentInfo, MPA, PMax network segmentation, new experiment types
20. https://ads-developers.googleblog.com/2026/ (fetched 2026-07-01) — 2026 blog archive listing, used to confirm no v25 post exists yet and to date-stamp the Smart Campaign / DSA / bidding-rename posts
21. https://searchengineland.com/google-ads-api-to-switch-to-a-monthly-release-cycle-461596 (fetched 2026-07-01, third-party — not independently confirmed on an official Google page this session) — monthly release cadence claim
22. https://searchengineland.com/google-ads-api-to-stop-supporting-new-smart-campaign-creation-480999 (fetched 2026-07-01) — Smart Campaign API creation sunset 2026-08-03, error enums by version
23. Search-result summary of https://ads-developers.googleblog.com/2026/06/dynamic-search-ads-dsa-automigration.html (fetched 2026-07-01; body not independently re-fetched) — DSA automigration delay to 2027-02
24. https://www.digitalapplied.com/blog/google-ads-bidding-budgeting-overhaul-june-2026-ppc-playbook (fetched 2026-07-01, third-party) — Smart Bidding strategy renaming described as cosmetic/UI-only


---

## Developer Guide

> Comprehensive implementation reference for LLM agents building Google Ads API integrations. Covers campaign workflows, resource schemas, GAQL deep-dives, mutation patterns, error handling, and operational rules — sufficient to implement without re-fetching docs.
>
> Sources: https://developers.google.com/google-ads/api/docs/ (canonical), cross-referenced against gads-cli live implementation.

---

### DG-1. Campaign Creation Workflow

Creating a campaign requires at minimum three resources in order: **CampaignBudget**, **Campaign**, and at least one **AdGroup**. Use `googleAds:mutate` (batch, cross-resource) with temporary resource names to wire them together atomically.

#### Step-by-step

| Step | Resource | Endpoint | Notes |
|------|----------|----------|-------|
| 1 | `CampaignBudget` | `campaignBudgets:mutate` or `googleAds:mutate` | Must exist before Campaign |
| 2 | `Campaign` | `campaigns:mutate` or `googleAds:mutate` | References budget resource name |
| 3 | `AdGroup` | `adGroups:mutate` or `googleAds:mutate` | References campaign resource name |
| 4 | `AdGroupCriterion` (keywords) | `adGroupCriteria:mutate` | References ad group |
| 5 | `AdGroupAd` (responsive search ad) | `adGroupAds:mutate` | References ad group |

#### Minimum required fields — Campaign

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | Yes | Unique within customer |
| `status` | enum | Yes | `ENABLED`, `PAUSED`, `REMOVED` |
| `advertisingChannelType` | enum | Yes | `SEARCH`, `DISPLAY`, `SHOPPING`, `PERFORMANCE_MAX`, `VIDEO`, `SMART`, `LOCAL`, `APP` |
| `campaignBudget` | string (resource name) | Yes | `customers/{CID}/campaignBudgets/{id}` |
| `biddingStrategyType` | enum | Conditional | Required unless using portfolio bidding strategy. See DG-7. |
| `startDate` | string | No | `YYYY-MM-DD`; defaults to today |
| `endDate` | string | No | `YYYY-MM-DD`; omit for no end date |
| `networkSettings.targetGoogleSearch` | bool | No | Search: usually `true` |
| `networkSettings.targetSearchNetwork` | bool | No | Search partners |
| `networkSettings.targetContentNetwork` | bool | No | Display network |
| `geoTargetTypeSetting.positiveGeoTargetType` | enum | No | `PRESENCE`, `PRESENCE_OR_INTEREST` |

#### Campaign status enum values

| Enum | Meaning |
|------|---------|
| `ENABLED` | Campaign is active and eligible to serve |
| `PAUSED` | Campaign is manually paused; can be re-enabled |
| `REMOVED` | Soft-deleted; cannot be re-enabled. Resource name preserved. |

#### CampaignBudget required fields

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | Yes | Unique name |
| `amountMicros` | string (int64) | Yes | Daily budget in micros. E.g. `"35000000"` = 35 AED |
| `deliveryMethod` | enum | No | `STANDARD` (default, spread evenly) or `ACCELERATED` (deprecated in Search/Shopping) |
| `explicitlyShared` | bool | No | `true` = shared budget usable by multiple campaigns. Default `false`. |

**Shared budget:** Set `explicitlyShared: true` and assign the same budget resource name to multiple campaigns. Without `explicitlyShared`, the budget is campaign-level only.

#### Atomic batch creation example

```json
POST customers/3552856345/googleAds:mutate
{
  "mutateOperations": [
    {
      "campaignBudgetOperation": {
        "create": {
          "resourceName": "customers/3552856345/campaignBudgets/-1",
          "name": "Tesla Search - QZ3 - Daily 35 AED",
          "amountMicros": "35000000",
          "deliveryMethod": "STANDARD",
          "explicitlyShared": false
        }
      }
    },
    {
      "campaignOperation": {
        "create": {
          "resourceName": "customers/3552856345/campaigns/-2",
          "name": "Search - Tesla Parts - QZ3",
          "status": "PAUSED",
          "advertisingChannelType": "SEARCH",
          "campaignBudget": "customers/3552856345/campaignBudgets/-1",
          "biddingStrategyType": "MAXIMIZE_CONVERSIONS",
          "networkSettings": {
            "targetGoogleSearch": true,
            "targetSearchNetwork": false,
            "targetContentNetwork": false
          },
          "startDate": "2026-06-25"
        }
      }
    },
    {
      "adGroupOperation": {
        "create": {
          "campaign": "customers/3552856345/campaigns/-2",
          "name": "Tesla Parts - Broad",
          "status": "ENABLED",
          "type": "SEARCH_STANDARD",
          "cpcBidMicros": "2000000"
        }
      }
    }
  ],
  "partialFailure": false
}
```

**Temporary resource name rule:** Use `"-1"`, `"-2"`, `"-3"` etc. within the same `mutateOperations` array. References in later operations resolve to the just-created resource. Cannot reference across different mutate calls.

Ref: https://developers.google.com/google-ads/api/docs/mutating/overview#temporary_resource_names

---

### DG-2. Bidding Strategy Types

#### Inline campaign-level strategies

Set `biddingStrategyType` directly on the campaign. The corresponding sub-message holds parameters.

| `biddingStrategyType` | Sub-message field | Key params | Notes |
|-----------------------|-------------------|-----------|-------|
| `MANUAL_CPC` | `manualCpc` | `enhancedCpcEnabled: bool` | Full manual control; set CPC at ad group or keyword level |
| `ENHANCED_CPC` | `manualCpc` | `enhancedCpcEnabled: true` | Manual CPC + Google auto-adjusts bids for conversions |
| `MAXIMIZE_CONVERSIONS` | `maximizeConversions` | `targetCpaMicros: int64` (optional) | Spends full budget; set tCPA to constrain |
| `MAXIMIZE_CONVERSION_VALUE` | `maximizeConversionValue` | `targetRoas: float` (optional) | Maximises value; set tROAS to constrain |
| `TARGET_CPA` | `targetCpa` | `targetCpaMicros: int64` | Average CPA target in micros |
| `TARGET_ROAS` | `targetRoas` | `targetRoas: float` | e.g. `3.5` = 350% ROAS |
| `TARGET_IMPRESSION_SHARE` | `targetImpressionShare` | `location`, `locationFractionMicros`, `cpcBidCeilingMicros` | Awareness campaigns |
| `TARGET_SPEND` | `targetSpend` | `cpcBidCeilingMicros` (optional) | Maximize clicks within budget |
| `PERCENT_CPC` | `percentCpc` | `cpcBidCeilingPercent` | Display/Hotels only |

#### Portfolio bidding strategy (shared)

Create a `BiddingStrategy` resource first, then reference it:

```json
{
  "campaignOperation": {
    "create": {
      "name": "Search - Tesla Parts",
      "biddingStrategy": "customers/3552856345/biddingStrategies/12345678"
      // do NOT set biddingStrategyType when using portfolio
    }
  }
}
```

Ref: https://developers.google.com/google-ads/api/docs/campaigns/bidding/portfolio-bid-strategies

#### Setting tCPA via update

```json
POST customers/3552856345/campaigns:mutate
{
  "operations": [{
    "update": {
      "resourceName": "customers/3552856345/campaigns/123456789",
      "maximizeConversions": {
        "targetCpaMicros": "15000000"
      }
    },
    "updateMask": "maximizeConversions.targetCpaMicros"
  }]
}
```

**updateMask is required for every update.** List only the fields being changed, dot-separated, camelCase.

Ref: https://developers.google.com/google-ads/api/docs/campaigns/bidding/bidding-strategies

---

### DG-3. Ad Group Types

Ad group type is set at creation and cannot be changed. The type constrains which ad types are valid inside it.

| `type` enum | Campaign type | Valid ad types |
|-------------|---------------|----------------|
| `SEARCH_STANDARD` | SEARCH | `EXPANDED_TEXT_AD` (deprecated), `RESPONSIVE_SEARCH_AD` |
| `SEARCH_DYNAMIC_ADS` | SEARCH (DSA only) | `EXPANDED_DYNAMIC_SEARCH_AD` |
| `DISPLAY_STANDARD` | DISPLAY | `RESPONSIVE_DISPLAY_AD`, `DISPLAY_UPLOAD_AD`, `IMAGE_AD` |
| `SHOPPING_PRODUCT` | SHOPPING | `SHOPPING_PRODUCT_AD` |
| `SHOPPING_SHOWCASE` | SHOPPING | `SHOPPING_COMPARISON_LISTING_AD` |
| `VIDEO_TRUE_VIEW_IN_STREAM` | VIDEO | `VIDEO_TRUEVIEW_IN_STREAM_AD` |
| `VIDEO_TRUE_VIEW_IN_DISPLAY` | VIDEO | `VIDEO_TRUEVIEW_DISCOVERY_AD` |
| `VIDEO_BUMPER` | VIDEO | `VIDEO_BUMPER_AD` |
| `VIDEO_NON_SKIPPABLE_IN_STREAM` | VIDEO | `VIDEO_NON_SKIPPABLE_IN_STREAM_AD` |
| `VIDEO_OUTSTREAM` | VIDEO | `VIDEO_OUTSTREAM_AD` |
| `VIDEO_RESPONSIVE` | VIDEO | `VIDEO_RESPONSIVE_AD` |
| `HOTEL_ADS` | HOTEL | `HOTEL_AD` |
| `SMART_CAMPAIGN_ADS` | SMART | `SMART_CAMPAIGN_AD` — **API creation of new Smart Campaigns (`SMART_CAMPAIGN_ADS`/`advertising_channel_sub_type: SMART_CAMPAIGN`) stops 2026-08-03**; existing ones stay readable/updatable. See DG-15. |

**PMax campaigns do NOT use ad groups** — they use Asset Groups instead (see DG-6).

**DSA note:** `SEARCH_DYNAMIC_ADS` / `EXPANDED_DYNAMIC_SEARCH_AD` creation remains fully supported via the API (not affected by the Smart Campaign cutoff above). Its separate auto-migration to AI Max was delayed from Sept 2026 to Feb 2027 — see DG-15.

#### AdGroup required fields

| Field | Required | Notes |
|-------|----------|-------|
| `campaign` | Yes | Parent campaign resource name |
| `name` | Yes | Unique within campaign |
| `status` | Yes | `ENABLED`, `PAUSED`, `REMOVED` |
| `type` | Yes | Enum above; must match campaign `advertisingChannelType` |
| `cpcBidMicros` | No | Default CPC for the group (overridden by keyword-level bids) |
| `targetCpaMicros` | No | Ad group-level tCPA override |
| `targetRoasMicros` | No | Ad group-level tROAS override |

Ref: https://developers.google.com/google-ads/api/docs/reference/rest/v24/customers.adGroups

---

### DG-4. GAQL Deep Dive

GAQL (Google Ads Query Language) is a SQL-like DSL. It is **SELECT-only** — no INSERT, UPDATE, DELETE. All mutations go through the REST mutate endpoints.

Ref: https://developers.google.com/google-ads/api/docs/query/overview

#### Full grammar

```
SELECT field1, field2, ...
FROM   resource_name
[WHERE condition [AND condition ...]]
[ORDER BY field [ASC|DESC] [, field [ASC|DESC] ...]]
[LIMIT n]
[PARAMETERS include_drafts=true]
```

#### Field naming convention

| Prefix | Category | Example |
|--------|----------|---------|
| `resource_name.*` | Resource fields (config, metadata) | `campaign.name`, `campaign.status`, `ad_group.cpc_bid_micros` |
| `segments.*` | Segmentation dimensions (split metric rows) | `segments.date`, `segments.device`, `segments.ad_network_type` |
| `metrics.*` | Aggregated performance metrics | `metrics.clicks`, `metrics.cost_micros`, `metrics.conversions` |

**Naming rules:**
- GAQL uses `snake_case` for all field names
- JSON response uses `camelCase` — `cost_micros` → `costMicros`
- Nested resource fields use dot notation: `ad_group_criterion.keyword.text`
- Attributed resource fields (cross-resource joins): `campaign.name` is valid in `FROM ad_group` — implicit join, no JOIN keyword needed

#### All queryable FROM resources

| Resource | What it represents |
|----------|--------------------|
| `account_budget` | Account-level budgets |
| `account_budget_proposal` | Budget proposals |
| `ad_group` | Ad group config |
| `ad_group_ad` | Individual ads |
| `ad_group_ad_asset_view` | Asset-level performance in RSAs |
| `ad_group_criterion` | Keywords, audiences, placements per ad group |
| `ad_group_criterion_simulation` | Bid simulation data |
| `ad_group_simulation` | Ad group bid simulation |
| `age_range_view` | Age targeting performance |
| `asset` | Asset inventory |
| `asset_group` | PMax asset groups |
| `asset_group_asset` | Assets linked to asset groups |
| `asset_group_listing_group_filter` | PMax listing group tree |
| `asset_group_signal` | PMax audience signals |
| `audience` | Audience definitions |
| `bidding_strategy` | Portfolio bid strategies |
| `campaign` | Campaign config + budget + bidding |
| `campaign_asset` | Assets linked to campaigns |
| `campaign_asset_set` | Asset sets per campaign |
| `campaign_budget` | Budget config |
| `campaign_criterion` | Campaign-level targeting criteria |
| `campaign_simulation` | Campaign bid simulation |
| `click_view` | Individual click records |
| `conversion_action` | Conversion action definitions |
| `customer` | Account-level info |
| `customer_user_access` | User access management |
| `display_keyword_view` | Display keyword performance |
| `dynamic_search_ads_search_term_view` | DSA search terms |
| `expanded_landing_page_view` | Landing page performance |
| `extension_feed_item` | Feed item extensions |
| `feed` | Feed definitions |
| `feed_item` | Feed items |
| `gender_view` | Gender targeting performance |
| `geo_target_constant` | Geographic target constants |
| `geographic_view` | Geographic performance |
| `group_placement_view` | Display placement groups |
| `hotel_performance_view` | Hotel ad performance |
| `keyword_plan_ad_group_keyword` | Keyword plan keywords |
| `keyword_view` | Keyword-level metrics (use with `ad_group_criterion.*`) |
| `label` | Label definitions |
| `language_constant` | Language targeting constants |
| `location_view` | Location-targeted performance |
| `managed_placement_view` | Managed placement performance |
| `mobile_app_category_constant` | Mobile app category constants |
| `mobile_device_constant` | Mobile device constants |
| `offline_user_data_job` | Customer Match job status |
| `operating_system_version_constant` | OS version constants |
| `paid_organic_search_term_view` | Paid + organic side-by-side |
| `product_group_view` | Shopping product group performance |
| `search_term_view` | Search terms that triggered ads |
| `shopping_performance_view` | Shopping campaign performance |
| `performance_max_placement_view` | PMax placement-level performance | As of v24.2, segmentable by `segments.ad_network_type` (SEARCH/CONTENT/YOUTUBE/etc.) — see DG-15 |
| `topic_view` | Contextual topic performance |
| `user_interest` | Interest audience categories |
| `user_list` | Audience lists (Customer Match, remarketing) |
| `video` | Video asset details |
| `webpage_view` | Website targeting performance |

#### Segments

Segments split aggregated metrics by a dimension. **Rules:**
1. Only one **time** segment per query (`segments.date` OR `segments.week` OR `segments.month` — not multiple)
2. Segments must be compatible with the FROM resource and each other (check via `GoogleAdsFieldService.getGoogleAdsField` → `selectableWith`)
3. Adding any segment causes one result row per unique dimension value per entity
4. Cannot segment by `segments.date` and also by `segments.week` in the same query

**Common segments:**

| Segment field | Values / format | Notes |
|---------------|-----------------|-------|
| `segments.date` | `YYYY-MM-DD` string | Most common; enables DURING/BETWEEN |
| `segments.week` | Week start date | Week Sun–Sat |
| `segments.month` | Month start date `YYYY-MM-01` | |
| `segments.quarter` | Quarter start date | |
| `segments.year` | 4-digit year | |
| `segments.device` | `DESKTOP`, `MOBILE`, `TABLET`, `CONNECTED_TV`, `OTHER` | |
| `segments.ad_network_type` | `SEARCH`, `SEARCH_PARTNERS`, `CONTENT`, `MIXED`, `YOUTUBE_SEARCH`, `YOUTUBE_WATCH` | |
| `segments.click_type` | `URL_CLICKS`, `CALLS`, `MOBILE_CALL_CLICKS`, etc. | |
| `segments.conversion_action` | Conversion action resource name | Splits by conversion type |
| `segments.conversion_action_category` | `PURCHASE`, `LEAD`, `SIGNUP`, etc. | |
| `segments.hour` | 0–23 | Use for dayparting analysis |
| `segments.day_of_week` | `MONDAY`–`SUNDAY` | |
| `segments.slot` | `SEARCH_TOP`, `SEARCH_OTHER`, `CONTENT` | Ad position |

#### Date filtering — DURING enum

`WHERE segments.date DURING {macro}` — macro values:

| Macro | Period |
|-------|--------|
| `TODAY` | Current calendar day (avoid — data incomplete) |
| `YESTERDAY` | Previous calendar day |
| `LAST_7_DAYS` | 7 complete days ending yesterday |
| `LAST_14_DAYS` | 14 complete days ending yesterday |
| `LAST_30_DAYS` | 30 complete days ending yesterday |
| `LAST_BUSINESS_WEEK` | Mon–Fri of previous week |
| `THIS_WEEK_SUN_TODAY` | Sunday through today |
| `THIS_WEEK_MON_TODAY` | Monday through today |
| `LAST_WEEK_SUN_SAT` | Previous Sun–Sat week |
| `LAST_WEEK_MON_SUN` | Previous Mon–Sun week |
| `THIS_MONTH` | First day of current month through today |
| `LAST_MONTH` | Full previous calendar month |
| `LAST_YEAR` | Full previous calendar year |
| `THIS_YEAR` | Jan 1 of current year through today |
| `ALL_TIME` | All available data (no date filter applied) |

**Explicit range:**
```sql
WHERE segments.date BETWEEN '2026-06-01' AND '2026-06-22'
-- Both bounds are inclusive. Format: 'YYYY-MM-DD'
```

**Single day:**
```sql
WHERE segments.date = '2026-06-22'
```

#### Aggregation rules

- Metrics are **automatically aggregated** (SUM or AVG depending on the metric) across the selected dimensions
- `metrics.clicks`, `metrics.impressions`, `metrics.cost_micros`, `metrics.conversions` → SUM
- `metrics.average_cpc`, `metrics.ctr`, `metrics.conversion_rate` → computed averages (do not double-aggregate)
- Without a date segment, metrics aggregate over the full WHERE date range
- With `segments.date`, one row per day per entity

#### SELECT-only restriction

GAQL is read-only. You CANNOT use:
- `INSERT`, `UPDATE`, `DELETE`, `CREATE`
- Subqueries
- `JOIN` keyword (implicit joins via attributed resources only)
- Aggregation functions like `SUM()`, `COUNT()` — the API aggregates automatically
- `HAVING` clause — filter with `WHERE metrics.clicks > 0` instead
- `UNION`

#### Attributed resource patterns (implicit joins)

```sql
-- Selecting from ad_group while referencing campaign fields — valid
SELECT ad_group.name, campaign.name, campaign.status, metrics.clicks
FROM ad_group
WHERE segments.date DURING LAST_7_DAYS

-- Selecting from keyword_view while getting ad group and campaign context
SELECT ad_group_criterion.keyword.text,
       ad_group_criterion.keyword.match_type,
       ad_group.name,
       campaign.name,
       metrics.impressions,
       metrics.clicks,
       metrics.cost_micros
FROM keyword_view
WHERE segments.date DURING LAST_30_DAYS
  AND ad_group_criterion.status != 'REMOVED'
  AND campaign.status = 'ENABLED'
```

Ref: https://developers.google.com/google-ads/api/docs/query/grammar

---

### DG-5. Keyword Match Types

Ref: https://developers.google.com/google-ads/api/docs/campaigns/keywords/match-types

#### Match type enum values

| Enum value | Description | Example keyword | Matches |
|-----------|-------------|-----------------|---------|
| `EXACT` | Exact match and close variants | `[tesla parts]` | "tesla parts", "parts tesla" (close variant) |
| `PHRASE` | Phrase match — meaning must be included | `"tesla parts"` | "buy tesla parts uae", "tesla parts near me" |
| `BROAD` | Broad match — related topics and synonyms | `tesla parts` | "ev body parts", "model 3 spare parts" |

In the API, match type is the `matchType` field on `AdGroupCriterion.keyword`:

```json
{
  "adGroupCriterion": {
    "adGroup": "customers/3552856345/adGroups/111222333",
    "keyword": {
      "text": "tesla parts uae",
      "matchType": "PHRASE"
    },
    "status": "ENABLED"
  }
}
```

#### Keyword text rules

- Max **80 characters**, max **10 words**
- Cannot contain: `! @ % ^ * () = {} [] \ | ; : ' " < > ?`
- Leading/trailing spaces are stripped by the API
- The combination of (`text`, `matchType`) must be unique within an ad group
- Match type cannot be changed after creation — remove and re-create

#### Negative keywords

A `negative: true` field on the criterion marks it as a negative. Can be set at the **ad group level** or **campaign level**.

```json
// Campaign-level negative — blocks all ad groups in campaign
POST customers/3552856345/campaignCriteria:mutate
{
  "operations": [{
    "create": {
      "campaign": "customers/3552856345/campaigns/123456789",
      "keyword": {
        "text": "repair",
        "matchType": "BROAD"
      },
      "negative": true
    }
  }]
}
```

```json
// Ad group-level negative
POST customers/3552856345/adGroupCriteria:mutate
{
  "operations": [{
    "create": {
      "adGroup": "customers/3552856345/adGroups/111222333",
      "keyword": {
        "text": "free",
        "matchType": "EXACT"
      },
      "negative": true
    }
  }]
}
```

**Negative keyword match type behavior:**
- Negative BROAD blocks queries that contain all words (any order)
- Negative PHRASE blocks queries that contain the phrase in order
- Negative EXACT blocks only that exact query

#### GAQL: query existing keywords

```sql
SELECT ad_group_criterion.criterion_id,
       ad_group_criterion.keyword.text,
       ad_group_criterion.keyword.match_type,
       ad_group_criterion.status,
       ad_group_criterion.negative,
       ad_group.name,
       campaign.name,
       metrics.impressions,
       metrics.clicks,
       metrics.cost_micros,
       metrics.conversions
FROM ad_group_criterion
WHERE ad_group_criterion.type = 'KEYWORD'
  AND ad_group_criterion.status != 'REMOVED'
  AND segments.date DURING LAST_30_DAYS
ORDER BY metrics.impressions DESC
```

---

### DG-6. Responsive Search Ads (RSA)

Ref: https://developers.google.com/google-ads/api/docs/ads/ads#responsive_search_ads

RSAs are the only active ad type for Search campaigns (Expanded Text Ads are deprecated and read-only as of June 2022).

#### Constraints

| Asset | Min | Max | Char limit | Notes |
|-------|-----|-----|-----------|-------|
| Headlines | 3 | 15 | 30 chars each | Google selects 3 per impression |
| Descriptions | 2 | 4 | 90 chars each | Google selects 2 per impression |
| Final URLs | 1 | — | 2048 chars | Must be HTTPS |
| Display path fields | 0 | 2 | 15 chars each | Appended to display URL |

#### Request shape

```json
POST customers/3552856345/adGroupAds:mutate
{
  "operations": [{
    "create": {
      "adGroup": "customers/3552856345/adGroups/111222333",
      "status": "ENABLED",
      "ad": {
        "finalUrls": ["https://shop.talas.ae/products/tesla?branch=QZ3"],
        "responsiveSearchAd": {
          "headlines": [
            {"text": "Tesla Parts UAE - QZ3"},
            {"text": "Genuine Tesla Spare Parts"},
            {"text": "Model 3 Y S X Parts"},
            {"text": "New & Used Tesla Parts"},
            {"text": "Fast UAE Delivery"},
            {"pinnedField": "HEADLINE_1", "text": "Tesla Auto Parts Dubai"}
          ],
          "descriptions": [
            {"text": "OEM & aftermarket Tesla parts. All models. QZ3 branch. Call now."},
            {"text": "New, used & aftermarket Tesla body parts. Fast UAE shipping."}
          ],
          "path1": "Tesla-Parts",
          "path2": "UAE"
        }
      }
    }
  }]
}
```

#### Pinning

Headlines and descriptions can be pinned to fixed positions using `pinnedField`:

| `pinnedField` value | Position |
|--------------------|----------|
| `HEADLINE_1` | Always shown in position 1 |
| `HEADLINE_2` | Always shown in position 2 |
| `HEADLINE_3` | Always shown in position 3 |
| `DESCRIPTION_1` | Always shown in position 1 |
| `DESCRIPTION_2` | Always shown in position 2 |

**Warning:** Pinning reduces Google's ability to optimize asset combinations and usually lowers Ad Strength. Avoid pinning unless legally required.

#### Asset Strength enum

`adGroupAd.adStrength` (read-only field, returned in GAQL, not set on create):

| Value | Meaning |
|-------|---------|
| `UNSPECIFIED` | Not set |
| `PENDING` | Asset strength not yet calculated |
| `NO_ADS` | Ad group has no enabled ads |
| `POOR` | Low asset diversity |
| `AVERAGE` | Typical diversity |
| `GOOD` | Good asset diversity |
| `EXCELLENT` | Maximum diversity; best performance potential |

Query asset strength:
```sql
SELECT ad_group_ad.ad.id,
       ad_group_ad.ad_strength,
       ad_group_ad.policy_summary.approval_status,
       ad_group_ad.ad.responsive_search_ad.headlines,
       ad_group_ad.ad.responsive_search_ad.descriptions
FROM ad_group_ad
WHERE ad_group_ad.status = 'ENABLED'
  AND ad_group_ad.ad.type = 'RESPONSIVE_SEARCH_AD'
```

#### Per-asset performance (asset view)

```sql
SELECT ad_group_ad_asset_view.field_type,
       ad_group_ad_asset_view.performance_label,
       ad_group_ad_asset_view.enabled,
       asset.text_asset.text,
       metrics.impressions
FROM ad_group_ad_asset_view
WHERE segments.date DURING LAST_30_DAYS
  AND ad_group_ad_asset_view.field_type IN ('HEADLINE', 'DESCRIPTION')
```

`performance_label` values: `UNSPECIFIED`, `PENDING`, `LEARNING`, `LOW`, `GOOD`, `BEST`.

---

### DG-7. PMax (Performance Max) Campaigns

PMax campaigns have a fundamentally different structure — no ad groups, no keywords. Instead they use **Asset Groups** and **Listing Group Filters**.

Ref: https://developers.google.com/google-ads/api/docs/performance-max/overview

#### Structure

```
Campaign (advertisingChannelType: PERFORMANCE_MAX)
  └── AssetGroup (one or more)
        ├── Assets (linked via AssetGroupAsset)
        │     ├── TEXT (headline, description, long headline, business name)
        │     ├── IMAGE (marketing image, square image, logo, portrait image)
        │     ├── VIDEO (youtube video URL)
        │     └── CALL_TO_ACTION
        ├── Audience Signals (AssetGroupSignal)
        │     ├── audience (remarketing list)
        │     └── searchTheme (keyword themes as signals, not targeting)
        └── ListingGroupFilter (product partitions for Shopping inventory)
```

#### PMax Campaign creation

```json
{
  "campaignOperation": {
    "create": {
      "name": "PMax - Tesla - All Branches",
      "status": "PAUSED",
      "advertisingChannelType": "PERFORMANCE_MAX",
      "campaignBudget": "customers/3552856345/campaignBudgets/-1",
      "biddingStrategyType": "MAXIMIZE_CONVERSION_VALUE",
      "maximizeConversionValue": {
        "targetRoas": 3.5
      }
    }
  }
}
```

**PMax bidding:** Only `MAXIMIZE_CONVERSIONS` (with optional `targetCpaMicros`) or `MAXIMIZE_CONVERSION_VALUE` (with optional `targetRoas`) are valid for PMax.

#### AssetGroup creation

```json
POST customers/3552856345/assetGroups:mutate
{
  "operations": [{
    "create": {
      "campaign": "customers/3552856345/campaigns/123456789",
      "name": "Tesla Parts - Main Asset Group",
      "status": "ENABLED",
      "finalUrls": ["https://shop.talas.ae/collections/tesla"],
      "finalMobileUrls": ["https://shop.talas.ae/collections/tesla"],
      "headlines": [
        {"text": "Tesla Parts UAE"},
        {"text": "Genuine Spare Parts"},
        {"text": "Shop Tesla Parts Online"},
        {"text": "New Used Aftermarket Parts"},
        {"text": "Fast UAE Delivery"}
      ],
      "longHeadlines": [
        {"text": "Shop Tesla Spare Parts in UAE - All Models Available"}
      ],
      "descriptions": [
        {"text": "Find Tesla Model 3, Y, S, X parts. New & used. Ships UAE-wide."},
        {"text": "Aftermarket & OEM Tesla parts. QZ3, IND4, SJA branches."}
      ],
      "businessName": "Talas Auto Parts"
    }
  }]
}
```

#### Asset types and fields

| Asset type (`type` enum) | Sub-message | Key fields |
|--------------------------|-------------|-----------|
| `TEXT` | `textAsset` | `text` (string) |
| `IMAGE` | `imageAsset` | `data` (base64), `mimeType` (`IMAGE_JPEG`, `IMAGE_PNG`) |
| `YOUTUBE_VIDEO` | `youtubeVideoAsset` | `youtubeVideoId` (11-char ID) |
| `MEDIA_BUNDLE` | `mediaBundleAsset` | `data` (base64 ZIP) |
| `CALL_TO_ACTION` | `callToActionAsset` | `callToAction` enum (`LEARN_MORE`, `GET_QUOTE`, `BUY_NOW`, `SHOP_NOW`, etc.) |
| `SITELINK` | `sitelinkAsset` | `linkText`, `description1`, `description2`, `finalUrls` |
| `CALLOUT` | `calloutAsset` | `calloutText` (max 25 chars) |
| `STRUCTURED_SNIPPET` | `structuredSnippetAsset` | `header`, `values[]` |
| `CALL` | `callAsset` | `countryCode`, `phoneNumber` |
| `LEAD_FORM` | `leadFormAsset` | Complex form definition |

**Asset creation is two-step:**
1. `POST customers/{CID}/assets:mutate` → get asset resource name
2. `POST customers/{CID}/assetGroupAssets:mutate` → link asset to asset group with `fieldType`

`fieldType` enum for AssetGroupAsset:
`HEADLINE`, `DESCRIPTION`, `LONG_HEADLINE`, `BUSINESS_NAME`, `MARKETING_IMAGE`, `SQUARE_MARKETING_IMAGE`, `PORTRAIT_MARKETING_IMAGE`, `LOGO`, `LANDSCAPE_LOGO`, `VIDEO`, `CALL_TO_ACTION_SELECTION`, `AD_IMAGE`

#### ListingGroupFilter (product partitions)

Used to partition Shopping inventory within a PMax asset group. Root node must be a `UNIT_INCLUDED` with no case value (`CATCH_ALL`).

```json
POST customers/3552856345/assetGroupListingGroupFilters:mutate
{
  "operations": [
    {
      "create": {
        "assetGroup": "customers/3552856345/assetGroups/987654",
        "type": "UNIT_INCLUDED",
        "listingSource": "SHOPPING",
        "caseValue": null
      }
    }
  ]
}
```

For segmented partitions (e.g., by brand):
```json
{
  "type": "SUBDIVISION",
  "caseValue": {
    "productBrand": {"value": "Tesla"}
  }
}
```

#### Audience signals

```json
POST customers/3552856345/assetGroupSignals:mutate
{
  "operations": [{
    "create": {
      "assetGroup": "customers/3552856345/assetGroups/987654",
      "audience": {
        "audience": "customers/3552856345/audiences/11111"
      }
    }
  }]
}
```

Ref: https://developers.google.com/google-ads/api/docs/performance-max/asset-groups

#### Reading PMax asset groups, signals, listing groups, search-term insights (GAQL)

`gads pmax asset-groups|signals|listing-groups|search-terms` (added 2026-09-04). All
four are read-only GAQL reports. Fields below were verified against the official
v24 field reference (fetched 2026-09-04) and/or live against the Talas account
(customer 3552856345) the same day.

**`asset_group`** — https://developers.google.com/google-ads/api/fields/v24/asset_group (fetched 2026-09-04)
Verified selectable: `asset_group.id`, `.name`, `.status`, `.primary_status`,
`.primary_status_reasons`, `.ad_strength`, `.campaign`, `.final_urls`,
`.final_mobile_urls`, `.path1`, `.path2`, `.resource_name` — plus the standard
`metrics.*` (impressions, clicks, conversions, cost_micros, conversions_value
confirmed present) and attributed `campaign.id`/`campaign.name` (campaign is
listed as a compatible "Selectable with" resource). No unusual constraints —
behaves like any other campaign-scoped resource; `WHERE campaign.id = N` is
optional (omit to list every asset group in the account).

**`asset_group_signal`** — https://developers.google.com/google-ads/api/fields/v24/asset_group_signal (fetched 2026-09-04)
Full field list is **only**: `asset_group_signal.resource_name`, `.asset_group`,
`.approval_status`, `.disapproval_reasons`, `.audience.audience`,
`.search_theme.text`, `.local_services_id.service_id`,
`.vertical_ads_item_group_rule_list.shared_set`. There is **no
`asset_group_signal.id`** and **no metrics** on this resource — each row is a
single signal (either an audience or a search theme, mutually exclusive) keyed
by its `resource_name`. Live-verified 2026-09-04 against campaign 23566187470
(returns audience-type signals only for that campaign).

**`asset_group_listing_group_filter`** — https://developers.google.com/google-ads/api/fields/v24/asset_group_listing_group_filter (fetched 2026-09-04)
Verified selectable: `.id`, `.type`, `.listing_source`,
`.parent_listing_group_filter`, `.path`, `.asset_group`, `.resource_name`, and
`.case_value` as a **oneof** with branches `product_category.category_id`/`.level`,
`product_brand.value`, `product_channel.channel`, `product_condition.condition`,
`product_custom_attribute.index`/`.value`, `product_item_id.value`,
`product_type.level`/`.value`, `product_custom_attribute.*`, `webpage.conditions`,
`retail_filter_bundle.shared_set`. Only the branch actually set on a given node
comes back populated; the rest are absent from the row, not null-valued errors.
Live-verified 2026-09-04: campaign 23159635175 ("Talas Shop Products") has one
root `UNIT_INCLUDED`/`SHOPPING` filter with no case_value (catch-all); campaign
23566187470 (feed-only PMax, no Shopping partitioning) returns 0 rows — a
correctly empty table, not an error.

**`campaign_search_term_insight`** — https://developers.google.com/google-ads/api/fields/v24/campaign_search_term_insight (fetched 2026-09-04)
Own fields are only `.campaign_id`, `.category_label`, `.id`, `.resource_name` —
rows are search-**category** buckets, not literal search terms. Real
constraints, **live-verified against the account** 2026-09-04 (not just docs):
- **Must filter to exactly one campaign.** Omitting
  `WHERE campaign_search_term_insight.campaign_id = N` raises
  `errorCode.searchTermInsightError = REQUIRES_FILTER_BY_SINGLE_RESOURCE`,
  message *"campaign_search_term_insight can only be selected when filtering
  by a single 'campaign_search_term_insight.campaign_id' in WHERE clause."*
- **No cost metric.** Selecting `metrics.cost_micros` raises
  `errorCode.queryError = PROHIBITED_METRIC_IN_SELECT_OR_WHERE_CLAUSE` — this
  resource's compatible metrics are only `impressions`, `clicks`,
  `conversions`, `conversions_from_interactions_rate`, `conversions_value`,
  `ctr`, `search_volume` (confirmed via the field reference's own
  "Selectable with" list — `cost_micros` is absent from it).
  `segments.date` works normally with just the campaign_id filter (a
  category-level query with `segments.date BETWEEN ... AND campaign_search_term_insight.campaign_id = N`
  succeeds without needing to also select or filter by `.id`).
- **`segments.search_term` (the literal term text, as opposed to the category
  label) requires an *additional* single-value filter** —
  `WHERE campaign_search_term_insight.id = <id>` — or it raises the same
  `REQUIRES_FILTER_BY_SINGLE_RESOURCE` error with message *"segments.search_term
  can only be selected when filtering by a single
  'campaign_search_term_insight.id' in WHERE clause."* `gads pmax search-terms`
  deliberately stays at the category level (no `.id` filter available) and does
  not select `segments.search_term`; per-category drill-down to literal terms
  is a documented gap, not implemented.
- Historical data available starting March 2023 (per
  https://developers.google.com/google-ads/api/docs/insights/overview,
  fetched 2026-09-04).

#### Shopping performance report (GAQL)

`gads report shopping` (added 2026-09-04). Read-only GAQL on
`shopping_performance_view`, per-SKU.

**`shopping_performance_view`** — https://developers.google.com/google-ads/api/fields/v24/shopping_performance_view
(fetched 2026-09-04 — canonical URL confirmed as the `v24` page, not a
redirect to `v25`). This resource has **no attributes of its own** beyond
`.resource_name` — it is a pure segments+metrics view. Confirmed selectable
product segments: `segments.product_item_id`, `.product_title`,
`.product_brand`, `.product_type_l1` through `.product_type_l5`,
`.product_category_level1` through `.product_category_level5`,
`.product_channel`, `.product_channel_exclusivity`, `.product_condition`,
`.product_country`, `.product_custom_attribute0`-`4`, `.product_feed_label`,
`.product_language`, `.product_merchant_id`, `.product_store_id`,
`.product_aggregator_id`. Confirmed metrics present:
`metrics.impressions`, `.clicks`, `.cost_micros`, `.conversions`,
`.conversions_value` (plus the full standard metrics set —
all_conversions, cost_per_conversion, etc.). `segments.date` is
filterable/selectable/sortable on this resource, so the standard
`WHERE segments.date BETWEEN ... AND ...` date-window pattern applies.
Talas's account has no Shopping campaigns serving as of 2026-09-04 — live
verification returned 0 rows with exit code 0, a valid (not erroneous) result.

#### Account-level negative criteria (GAQL + mutate)

`gads keyword account-negative list|add` (added 2026-09-04).

**`customer_negative_criterion`** — https://developers.google.com/google-ads/api/fields/v24/customer_negative_criterion
(fetched 2026-09-04). Resource description: "A negative criterion for
exclusions at the customer level." Confirmed selectable fields: `.id`,
`.type`, `.resource_name`, and, as a **oneof** keyed by `.type`:
`.content_label.type`, `.ip_block.ip_address`,
`.mobile_app_category.mobile_app_category_constant`,
`.mobile_application.app_id`/`.name`, `.negative_keyword_list.shared_set`,
`.placement.url`, `.placement_list.shared_set`, `.youtube_channel.channel_id`,
`.youtube_video.video_id`. `.type` is an `ATTRIBUTE`-category enum shared
across the whole API (AD_SCHEDULE, AGE_RANGE, ..., KEYWORD, ...,
NEGATIVE_KEYWORD_LIST, PLACEMENT, ...) — **only the subset with a matching
oneof field above is actually usable on this resource.**

**IMPORTANT — there is no `customer_negative_criterion.keyword` field.**
Despite `KEYWORD` appearing as a general enum value in `.type`, this resource
has no direct keyword sub-message. Account-level negative *keywords* are
represented differently: a `customer_negative_criterion` of type
`NEGATIVE_KEYWORD_LIST` points (`.negative_keyword_list.shared_set`) at a
`shared_set` resource, and the actual keyword text/match type live as
`shared_criterion` rows belonging to that shared set. Confirmed via
https://developers.google.com/google-ads/api/fields/v24/shared_set
(fetched 2026-09-04): `shared_set.type` enum includes both
`ACCOUNT_LEVEL_NEGATIVE_KEYWORDS` (the account-wide list — one per account)
and `NEGATIVE_KEYWORDS` (an ordinary shared negative-keyword list you attach
to individual campaigns via `campaign_shared_set` — a different feature).
`shared_criterion` fields confirmed via
https://developers.google.com/google-ads/api/fields/v24/shared_criterion
(fetched 2026-09-04): `.keyword.text`, `.keyword.match_type`, `.shared_set`,
`.negative`, `.type`, `.criterion_id`, `.resource_name`.

`gads keyword account-negative add` implements the full 3-step provisioning
flow the first time it runs (no existing `ACCOUNT_LEVEL_NEGATIVE_KEYWORDS`
shared set on the account): a `sharedSetOperation.create` (type
`ACCOUNT_LEVEL_NEGATIVE_KEYWORDS`), a `customerNegativeCriterionOperation.create`
(`negativeKeywordList.sharedSet` referencing the just-created set via the
`-1` temporary-resource-name convention), and a `sharedCriterionOperation.create`
(the keyword itself), all in one `ads_batch_mutate` call. Subsequent adds
reuse the existing shared set via a plain `sharedCriteria` single-resource
`ads_mutate`. Live-verified 2026-09-04 against the Talas account: `list`
returned one existing criterion (`CONTENT_LABEL` / `PARKED_DOMAIN`), no
`NEGATIVE_KEYWORD_LIST` yet provisioned — so `add` was verified with mocked
HTTP only per the task's constraint (no live mutations run).

**Correction (2026-09-04 code review):** the first shipped version of the
3-step batch above had a bug that the mocked-HTTP verification did NOT catch:
`sharedSetOperation.create` never DECLARED `"resourceName":
"customers/{CID}/sharedSets/-1"` on its own create body (see § Atomic batch
creation example below — the creating op MUST carry the temp resourceName
for a later op's reference to that same temp id to bind to anything). Ops
1/2 referenced `customers/{CID}/sharedSets/-1` in `negativeKeywordList.sharedSet`
/ `sharedCriterionOperation.create.sharedSet`, but with nothing declaring
that name, the batch would have been rejected by the live API on its first
real run. The original test asserted an exact-dict snapshot of `ops[0]`,
which passed even with the field missing — it never asserted the *binding*
between the declared and referenced resource names. Fixed in
`gads_lib/cli.py`'s `keyword_account_negative_add`; the regression test now
asserts the invariant (declared resourceName on ops[0] == the name ops[1]/
ops[2] reference), not a snapshot (`tests/test_shopping_negatives.py`).

Separately, this same batch was calling `ads_batch_mutate` with the default
`partialFailure=True`, which is wrong here: the batch provisions the shared
set AND attaches a criterion to it in one request, and needs ALL-OR-NOTHING
semantics — with `partialFailure=True`, op0 (create the shared set) could
succeed while op1/op2 (attach to it) fail, orphaning an unattached shared
set that the next `add` would provision *another* one of. `ads_batch_mutate`
now accepts an explicit `partial_failure` keyword (default `True`, unchanged
for `gads batch-mutate` and all other existing callers); this call site
passes `partial_failure=False` and runs the response through
`parse_partial_failure()` before reporting success.

---

### DG-8. Conversion Tracking

Ref: https://developers.google.com/google-ads/api/docs/conversions/overview

#### ConversionAction resource

Create a conversion action to define what counts as a conversion:

```json
POST customers/3552856345/conversionActions:mutate
{
  "operations": [{
    "create": {
      "name": "Purchase - Talas Shop",
      "category": "PURCHASE",
      "type": "WEBPAGE",
      "status": "ENABLED",
      "countingType": "MANY_PER_CLICK",
      "valueSettings": {
        "defaultValue": 350.0,
        "defaultCurrencyCode": "AED",
        "alwaysUseDefaultValue": false
      },
      "clickThroughLookbackWindowDays": 30,
      "viewThroughLookbackWindowDays": 1,
      "attributionModelSettings": {
        "attributionModel": "DATA_DRIVEN"
      }
    }
  }]
}
```

#### ConversionAction type enum

Verified 2026-08-29 against the live, authoritative source for this account's
API version -- `GoogleAdsFieldService.SearchGoogleAdsFields` (read-only field
metadata query, no account mutation):
`POST googleAdsFields:search` with `{"query": "SELECT name, enum_values WHERE name = 'conversion_action.type'"}`
(note: no `FROM` clause -- this service rejects one). This replaced a stale
table: `PHONE_CALL`, `APP_INSTALL`, `APP_IN_APP_PURCHASE`, `FIREBASE`, and
bare `GOOGLE_ANALYTICS` do NOT exist as values in the live enum -- they were
coarser-grained labels from an older API generation, since split into the
granular per-platform/per-event values below. The CLI's `conversion create
--type` bug (`UPLOAD` is not a valid value; `UPLOAD_CLICKS` is) was found and
fixed by cross-checking this same list.

| `type` value | Description |
|-------------|-------------|
| `WEBPAGE` | Tag on website (Google tag / gtag.js) |
| `WEBPAGE_CODELESS` | Auto-detected website conversion, no tag required |
| `UPLOAD_CLICKS` | Offline click conversions (gclid-based) |
| `UPLOAD_CALLS` | Offline call conversions |
| `AD_CALL` | Call from a call-only/call extension ad |
| `CLICK_TO_CALL` | Click on a call extension |
| `WEBSITE_CALL` | Phone call from website (Google forwarding number) |
| `SMART_CAMPAIGN_AD_CLICKS_TO_CALL` | Smart campaign: call from ad click |
| `SMART_CAMPAIGN_MAP_CLICKS_TO_CALL` | Smart campaign: call from Maps click |
| `SMART_CAMPAIGN_MAP_DIRECTIONS` | Smart campaign: directions request |
| `SMART_CAMPAIGN_TRACKED_CALLS` | Smart campaign: tracked call |
| `LOCAL_SERVICES_ADS` | Local Services Ads lead |
| `GOOGLE_HOSTED` | Google-hosted conversion (e.g. Google-hosted forms) |
| `GOOGLE_PLAY_DOWNLOAD` | Google Play app download |
| `GOOGLE_PLAY_IN_APP_PURCHASE` | Google Play in-app purchase |
| `FIREBASE_ANDROID_FIRST_OPEN` / `FIREBASE_IOS_FIRST_OPEN` | Firebase: first app open |
| `FIREBASE_ANDROID_IN_APP_PURCHASE` / `FIREBASE_IOS_IN_APP_PURCHASE` | Firebase: in-app purchase |
| `FIREBASE_ANDROID_GENERATE_LEAD` / `FIREBASE_IOS_GENERATE_LEAD` | Firebase: lead generated |
| `FIREBASE_ANDROID_QUALIFY_LEAD` / `FIREBASE_IOS_QUALIFY_LEAD` | Firebase: lead qualified |
| `FIREBASE_ANDROID_CLOSE_CONVERT_LEAD` / `FIREBASE_IOS_CLOSE_CONVERT_LEAD` | Firebase: lead closed/converted |
| `FIREBASE_ANDROID_CUSTOM` / `FIREBASE_IOS_CUSTOM` | Firebase: custom event |
| `THIRD_PARTY_APP_ANALYTICS_ANDROID_FIRST_OPEN` / `THIRD_PARTY_APP_ANALYTICS_IOS_FIRST_OPEN` | Third-party SDK: first app open |
| `THIRD_PARTY_APP_ANALYTICS_ANDROID_IN_APP_PURCHASE` / `THIRD_PARTY_APP_ANALYTICS_IOS_IN_APP_PURCHASE` | Third-party SDK: in-app purchase |
| `THIRD_PARTY_APP_ANALYTICS_ANDROID_CUSTOM` / `THIRD_PARTY_APP_ANALYTICS_IOS_CUSTOM` | Third-party SDK: custom event |
| `ANDROID_APP_PRE_REGISTRATION` | Android app pre-registration |
| `ANDROID_INSTALLS_ALL_OTHER_APPS` | Android install, all other apps |
| `GOOGLE_ANALYTICS_4_PURCHASE` | GA4: purchase |
| `GOOGLE_ANALYTICS_4_GENERATE_LEAD` | GA4: lead generated |
| `GOOGLE_ANALYTICS_4_QUALIFY_LEAD` | GA4: lead qualified |
| `GOOGLE_ANALYTICS_4_CLOSE_CONVERT_LEAD` | GA4: lead closed/converted |
| `GOOGLE_ANALYTICS_4_CUSTOM` | GA4: custom event |
| `GOOGLE_ANALYTICS_4` | GA4 connected property (legacy label; new setups use the granular `GOOGLE_ANALYTICS_4_*` values above) |
| `UNIVERSAL_ANALYTICS_GOAL` | Universal Analytics goal (legacy GA) |
| `UNIVERSAL_ANALYTICS_TRANSACTION` | Universal Analytics transaction (legacy GA) |
| `FLOODLIGHT_ACTION` | Floodlight (Campaign Manager 360) action |
| `FLOODLIGHT_TRANSACTION` | Floodlight (Campaign Manager 360) transaction |
| `SALESFORCE` | Salesforce CRM |
| `SEARCH_ADS_360` | Search Ads 360 conversion |
| `STORE_SALES` | Store sales (aggregated) |
| `STORE_SALES_DIRECT_UPLOAD` | Store sales, direct upload |
| `STORE_VISITS` | Store visit |
| `LEAD_FORM_SUBMIT` | Lead form submission |
| `UNKNOWN` / `UNSPECIFIED` | Not set / not returned by the API |

#### Counting type enum

| `countingType` value | Description |
|--------------------|-------------|
| `ONE_PER_CLICK` | Count only first conversion per click |
| `MANY_PER_CLICK` | Count every conversion per click (recommended for purchases) |

#### Attribution model enum

| `attributionModel` value | Description |
|--------------------------|-------------|
| `LAST_CLICK` | All credit to last ad click |
| `FIRST_CLICK` | All credit to first ad click |
| `LINEAR` | Equal credit across all clicks in path |
| `TIME_DECAY` | More credit to clicks closer to conversion |
| `POSITION_BASED` | 40% first, 40% last, 20% middle |
| `DATA_DRIVEN` | Machine learning model (recommended; requires 300+ conversions/30 days) |
| `LAST_CLICK_NON_DIRECT` | Last non-direct click |

#### Tag snippet

After creating a ConversionAction, retrieve the tag snippet:
```sql
SELECT conversion_action.id,
       conversion_action.name,
       conversion_action.type,
       conversion_action.tag_snippets,
       conversion_action.status
FROM conversion_action
WHERE conversion_action.status = 'ENABLED'
```

`tag_snippets` is an array of objects with fields:
- `type`: `WEBPAGE` (global site tag), `WEBPAGE_ONCLICK` (event snippet), `CLICK_TO_DOWNLOAD`, `WEBSITE_CALL`
- `globalSiteTagSnippet`: The `<script>` block for `<head>`
- `eventSnippet`: The event-specific `<script>` block for conversion page
- `trackingCodeType`: `TRACKING_CODE_HEAD` or `TRACKING_CODE_BODY`

Ref: https://developers.google.com/google-ads/api/docs/conversions/create-conversion

---

### DG-9. Customer Match — Full Reference

Ref: https://developers.google.com/google-ads/api/docs/remarketing/audience-types/customer-match

#### Job lifecycle

```
1. userLists:mutate (CREATE)          → get userList resource name
2. offlineUserDataJobs:create          → get job resource name
3. {job}:addOperations (batches ≤100) → upload hashed PII
4. {job}:run                           → trigger async processing
5. Poll job status via GAQL            → wait for SUCCESS/FAILED
6. Verify member_count via GAQL        → confirm upload
```

#### UserDataJobType enum

| Value | Use |
|-------|-----|
| `CUSTOMER_MATCH_USER_LIST` | Upload to a user list (most common) |
| `CUSTOMER_MATCH_WITH_ATTRIBUTES` | Upload with user attributes (product affinity) |
| `STORE_SALES_UPLOAD_FIRST_PARTY` | Upload store sales (first party) |
| `STORE_SALES_UPLOAD_THIRD_PARTY` | Upload store sales (third party) |
| `OFFLINE_USER_DATA_UPLOAD` | Generic offline data |

#### Data schema — UserIdentifier fields

```json
{
  "userIdentifiers": [
    {"hashedEmail": "{sha256_hex}"},
    {"hashedPhoneNumber": "{sha256_hex_e164}"},
    {
      "addressInfo": {
        "hashedFirstName": "{sha256_hex}",
        "hashedLastName": "{sha256_hex}",
        "countryCode": "AE",
        "city": "Dubai",
        "state": "Dubai",
        "postalCode": "00000",
        "streetAddress": "{sha256_hex}"
      }
    },
    {"thirdPartyUserId": "crm_id_12345"},
    {"mobileId": "device_advertising_id"}
  ]
}
```

#### SHA-256 hashing — implementation

```python
import hashlib, re

def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def normalize_email(email: str) -> str:
    return email.strip().lower()

def normalize_phone_e164(raw: str) -> str | None:
    """Normalize UAE phone to E.164 (+971XXXXXXXXX)."""
    digits = re.sub(r'\D', '', raw)
    if digits.startswith('00971'):
        digits = digits[2:]     # strip leading 00 → +971...
    elif len(digits) == 10 and digits.startswith('05'):
        digits = '971' + digits[1:]
    elif len(digits) == 9 and digits.startswith('5'):
        digits = '971' + digits
    if digits.startswith('971') and not digits.startswith('+'):
        digits = '+' + digits
    if not digits.startswith('+') or len(re.sub(r'\D', '', digits)) < 8:
        return None
    return digits

def hash_email(email: str) -> str:
    return sha256_hex(normalize_email(email))

def hash_phone(raw: str) -> str | None:
    normalized = normalize_phone_e164(raw)
    if not normalized:
        return None
    return sha256_hex(normalized)

def hash_name(name: str) -> str:
    return sha256_hex(name.strip().lower())
```

#### Membership lifespan

Set on the UserList at creation time:
- `membershipLifeSpan`: integer, days. `0` = no expiry (permanent). `540` = 18 months (maximum for Customer Match).

#### Upload quotas and batch size

- Batch size: max **100 operations** per `addOperations` call (gads-cli default)
- Total per job: up to **100,000 user records**
- Rate limit: 429 on `addOperations` — use exponential backoff (10s × attempt)

#### Job status polling

```sql
SELECT offline_user_data_job.resource_name,
       offline_user_data_job.id,
       offline_user_data_job.status,
       offline_user_data_job.type,
       offline_user_data_job.failure_reason,
       offline_user_data_job.customer_match_user_list_metadata.user_list
FROM offline_user_data_job
WHERE offline_user_data_job.status != 'FAILED'
```

Status values: `PENDING` → `RUNNING` → `SUCCESS` or `FAILED`.

#### Verify member count after upload

```sql
SELECT user_list.name,
       user_list.member_count,
       user_list.membership_status,
       user_list.size_range_for_search,
       user_list.size_range_for_display,
       user_list.eligible_for_search,
       user_list.eligible_for_display
FROM user_list
WHERE user_list.name = 'Talas CRM - All Customers 2026-Q2'
```

`member_count` may show `0` for 6-48h after a successful upload while Google matches. `size_range_for_search` / `size_range_for_display` become non-null once the list reaches the minimum threshold (typically 1000 matched users for Search, 100 for Display).

---

### DG-10. Error Handling — GoogleAdsException

Ref: https://developers.google.com/google-ads/api/docs/rest/error-types

#### Error envelope (full schema)

```json
{
  "error": {
    "code": 400,
    "message": "Request contains an invalid argument.",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
        "errors": [
          {
            "errorCode": {
              "{errorDomain}Error": "{ERROR_ENUM_VALUE}"
            },
            "message": "Human-readable error detail.",
            "location": {
              "fieldPathElements": [
                {"fieldName": "operations", "index": 0},
                {"fieldName": "create"},
                {"fieldName": "keyword"},
                {"fieldName": "text"}
              ]
            },
            "trigger": {
              "stringValue": "the bad input value"
            }
          }
        ],
        "requestId": "abc123xyz789"
      }
    ]
  }
}
```

#### Key fields

| Field | Description |
|-------|-------------|
| `error.code` | HTTP status code integer |
| `error.status` | gRPC status name (e.g., `INVALID_ARGUMENT`, `PERMISSION_DENIED`) |
| `error.details[0].errors` | Array of individual `GoogleAdsError` objects |
| `errors[].errorCode` | Object with ONE key: the error domain + "Error" suffix, value is the enum string |
| `errors[].message` | Human-readable description |
| `errors[].location.fieldPathElements` | Path to the offending field, including operation index |
| `errors[].trigger` | The actual value that triggered the error |
| `requestId` | Unique request ID — include in bug reports |

#### Error code domains (common)

| Domain key | Example enum values |
|-----------|---------------------|
| `queryError` | `UNRECOGNIZED_FIELD`, `PROHIBITED_FIELD_COMBINATION`, `INVALID_VALUE`, `MISSING_KEYWORD`, `UNEXPECTED_END_OF_QUERY` |
| `criterionError` | `INVALID_KEYWORD_TEXT`, `KEYWORD_HAS_TOO_MANY_WORDS`, `INVALID_MATCH_TYPE`, `CRITERION_TYPE_NOT_SUPPORTED` |
| `campaignError` | `DUPLICATE_CAMPAIGN_NAME`, `INVALID_START_DATE`, `CANNOT_MODIFY_REMOVED_CAMPAIGN` |
| `adGroupError` | `DUPLICATE_ADGROUP_NAME`, `INVALID_CONTENT_BID_CRITERION_TYPE_GROUP` |
| `adError` | `TOO_MANY_HEADLINES`, `TOO_MANY_DESCRIPTIONS`, `MAX_HEADLINE_LENGTH_EXCEEDED` |
| `authorizationError` | `DEVELOPER_TOKEN_NOT_APPROVED`, `USER_PERMISSION_DENIED`, `CUSTOMER_NOT_ENABLED` |
| `authenticationError` | `OAUTH_TOKEN_EXPIRED`, `OAUTH_TOKEN_INVALID`, `NOT_ADS_USER` |
| `biddingError` | `BIDDING_STRATEGY_NOT_COMPATIBLE_WITH_AD_GROUP_AD_TYPE` |
| `budgetError` | `BUDGET_AMOUNT_ZERO`, `BUDGET_CANNOT_BE_SHARED`, `TOTAL_BUDGET_AMOUNT_MUST_BE_UNSET` |
| `fieldError` | `REQUIRED`, `IMMUTABLE_FIELD`, `VALUE_OUT_OF_RANGE` |
| `urlFieldError` | `MISSING_URL`, `INVALID_URL`, `URL_MUST_CONTAIN_PROTOCOL` |
| `customerError` | `OPERATION_NOT_PERMITTED_FOR_SUBACCOUNT` |
| `internalError` | `TRANSIENT_ERROR`, `UNKNOWN` |
| `quotaError` | `RESOURCE_EXHAUSTED` |
| `requestError` | `UNKNOWN`, `INVALID_FIELD_NAME` |

#### Partial failure

When `partialFailure: true`, successful operations commit and failed ones return errors inline:

```json
{
  "results": [
    {"resourceName": "customers/.../adGroupCriteria/111~222"},
    {}
  ],
  "partialFailureError": {
    "code": 3,
    "details": [{
      "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
      "errors": [{
        "errorCode": {"criterionError": "INVALID_KEYWORD_TEXT"},
        "message": "Keyword text is invalid.",
        "location": {
          "fieldPathElements": [
            {"fieldName": "operations", "index": 1},
            {"fieldName": "create"},
            {"fieldName": "keyword"},
            {"fieldName": "text"}
          ]
        }
      }]
    }]
  }
}
```

Empty `{}` in `results` corresponds to a failed operation. Match by index to `partialFailureError.details[0].errors[].location.fieldPathElements[0].index`.

**`gads_lib.ads.parse_partial_failure()` gotchas (fixed 2026-09-04 code review):**
an error's `location.fieldPathElements` does not always carry an `index` —
request-level errors routinely omit one, since there's no single operation
to attribute them to. `parse_partial_failure()` returns a `(per_op,
unattributed_errors)` tuple (NOT just `per_op`, as an earlier version did):
every caller must check `unattributed_errors` and treat a non-empty list as
a failure, even when every attributed op in `per_op` reports `ok: True` —
otherwise a batch that failed at the request level silently reports success.
Two more edge cases it now handles: the REST API may serialise `index` as a
*string* (`"1"` not `1`) — coerced via `int()` in a `try`, since `1 in
{"1": ...}` is `False` and would make that index's lookup miss entirely; and
two errors can be attributed to the *same* index — both are kept (joined
with `"; "`), not last-write-wins.

#### Retry strategy

| HTTP status | Action |
|-------------|--------|
| 429 | Exponential backoff: `delay = 10 * (attempt + 1)` seconds, max 5 retries |
| 500 | Retry up to 3× with 5s delay |
| 503 | Retry up to 3× with 5s delay |
| 401 | Refresh OAuth token, then retry once |
| 400 | Fix request — do not retry same payload |
| 403 | Fix credentials/permissions — do not retry |
| 404 | Fix resource name — do not retry |

---

### DG-11. Pagination — Complete Reference

Ref: https://developers.google.com/google-ads/api/docs/reporting/paging

#### `googleAds:searchStream` (no pagination)

Use for complete data pulls. All rows returned in a single HTTP response as a JSON array of batch objects. No `pageToken`. No row limit. Preferred for bulk data.

```python
def run_gaql(creds, query: str) -> list[dict]:
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/googleAds:searchStream"
    resp = requests.post(url, headers=headers(creds), json={"query": query})
    resp.raise_for_status()
    rows = []
    for batch in resp.json():  # array of batch objects
        rows.extend(batch.get("results", []))
    return rows
```

#### `googleAds:search` (paginated)

- **Page size: fixed at 10,000 rows** (since API v19; `page_size` field removed)
- Pass `pageToken` from previous `nextPageToken` for next page
- **Query must be byte-for-byte identical** across pages (server-side cursor)
- Final page: `nextPageToken` is absent or empty string `""`

```python
def ads_search_all(creds, query: str) -> list[dict]:
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{CUSTOMER_ID}/googleAds:search"
    rows = []
    page_token = None
    while True:
        payload = {"query": query}
        if page_token:
            payload["pageToken"] = page_token
        resp = requests.post(url, headers=headers(creds), json=payload)
        resp.raise_for_status()
        data = resp.json()
        rows.extend(data.get("results", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break
    return rows
```

**Optional parameters for `googleAds:search`:**

| Field | Type | Notes |
|-------|------|-------|
| `returnTotalResultsCount` | bool | Adds `totalResultsCount` to response; counts rows without limit |
| `validateOnly` | bool | Validate query syntax without execution; returns empty results |
| `summaryRowSetting` | string | `NO_SUMMARY_ROW` (default), `SUMMARY_ROW_WITH_RESULTS`, `SUMMARY_ROW_ONLY` |

---

### DG-12. Rate Limits and Quotas

Ref: https://developers.google.com/google-ads/api/docs/best-practices/overview#request_limits

Specific numeric limits vary by developer token access level and are enforced server-side. Known confirmed behaviors:

#### Quotas by access level

| Access Level | Scope | Key restriction |
|-------------|-------|----------------|
| Test Account | Test accounts only | Production API blocked; Keyword Planner blocked |
| Explorer | Production | No Keyword Planner / Forecast |
| Basic | Production | No Keyword Planner / Forecast |
| Standard | Production | Full access including Keyword Planner, Forecast |

- Quotas are **per developer token**, not per customer account
- Exceeding quota → **HTTP 429** `RESOURCE_EXHAUSTED`
- Daily operation quotas reset at midnight Pacific time (Google's home timezone)

#### Rate limit behavior

| Trigger | Response |
|---------|----------|
| Too many requests per minute | HTTP 429 |
| Daily operation quota exceeded | HTTP 429 with `quotaError.RESOURCE_EXHAUSTED` |
| `addOperations` with large batches | HTTP 429 most common here |

#### Best practices to avoid limits

1. **Batch operations**: Prefer ~500 operations per `mutateOperations` call rather than one-by-one calls
2. **Use searchStream** instead of `search` for bulk queries (fewer round trips)
3. **Cache GAQL results** in SQLite rather than re-fetching same data
4. **Avoid repeated queries** within the same session — run once, store locally
5. **Off-peak scheduling**: Run heavy batch jobs outside UAE business hours (03:00–05:00 UTC+4)
6. **Exponential backoff on 429**: `delay = min(10 * (attempt + 1), 60)` seconds

---

### DG-13. API Versioning Policy

Ref: https://developers.google.com/google-ads/api/docs/sunset-dates, https://developers.google.com/google-ads/api/docs/concepts/versioning

#### Version lifecycle

| Phase | Duration | Notes |
|-------|----------|-------|
| Announced | ~3 months before GA | Docs published, no API access |
| GA (Generally Available) | Active production use | Supported, no breaking changes |
| Sunset announced | Reminder posted on the developer blog ahead of the date | e.g. v21's reminder post went up 2026-06-25 for its 2026-08-05 sunset |
| Sunset | Exactly **1 year after a version's release** [verified: sunset-dates page policy text, fetched 2026-07-01] | Returns error on all requests after this date |

#### Release cadence

- Confirmed released major versions to date: v21 (2025-08-06), v22 (2025-10-15), v23 (2026-01-28), v24 (2026-04-22) — each followed by 2-3 non-breaking minor releases (`.1`, `.2`, `.3`).
- Google's own versioning-concepts page states version numbers follow `vMAJOR_MINOR` format (major versions end in 0), major versions carry breaking changes and their own endpoint, minor versions are backward-compatible additions applied to the same endpoint. [verified: developers.google.com/google-ads/api/docs/concepts/versioning, fetched 2026-07-01]
- Third-party reporting (not independently confirmed on an official Google page in this session) describes a shift to a **monthly release cadence starting January 2026**: 4 major versions/year instead of 3 (v23, v24, v25, v26), each with a full 12-month support window, plus 2-3 minor point releases between majors. Under this schedule v25 would GA ~July 2026, v25.1 ~August 2026, v25.2 ~September 2026, with v25's sunset ~August 2027. (unverified — third-party sourced; treat as [inference] until confirmed via an official release-notes or blog entry)
- Major versions may have breaking changes — field renames, removed resources, changed enums. Minor versions (e.g., `v24.1`, `v24.2`) only add features/fields without breaking changes and do not require a URL or `GADS_API_VERSION` change to start using.

#### Migration path

1. Check https://developers.google.com/google-ads/api/docs/release-notes for new version features
2. Update `GADS_API_VERSION` env var (or `GOOGLE_ADS_API_VERSION`) in `.env`
3. Test all endpoints — breaking changes listed in release notes under "Removed features" or "Breaking changes"
4. Common migration issues:
   - Field renamed: `ad_group.base_ad_group` → check fieldPath changes in release notes
   - Enum value added/removed: new bidding strategies, new campaign types
   - Resource name format changed (rare)
   - `page_size` removed in v19 — do not send

#### Version in URL

The API version is embedded in every URL:
```
https://googleads.googleapis.com/v24/customers/...
                                 ^^^
```

Changing the env var changes all requests immediately — no code changes needed in gads-cli. Minor releases (`v24.1`, `v24.2`, ...) do **not** get their own URL segment — they layer new fields/resources onto the existing major-version endpoint (`/v24/`), confirmed by the release notes consistently describing v24.1/v24.2 as additive to the `/v24/` endpoint rather than a separate path. [verified: developers.google.com/google-ads/api/docs/release-notes cross-read, fetched 2026-07-01]

#### Current and recent versions (as of 2026-07-01)

| Version | Status | Released |
|---------|--------|----------|
| v25 | Not GA | Projected ~2026-07 (unverified — third-party reporting only, no official confirmation as of this fetch) |
| v24.2 | GA | 2026-06-24 |
| v24.1 | GA | 2026-05-13 |
| v24 | GA | 2026-04-22 |
| v23.3 | GA | 2026-06-24 |
| v23.2 | GA | 2026-03-25 |
| v23 | GA | 2026-01-28 |
| v22.2 | GA | 2026-06-24 |
| v22 | GA | 2025-10-15 |
| v21 | GA — **sunsets 2026-08-05** | 2025-08-06 |

---

### DG-14. Mutation Patterns — Complete Reference

Ref: https://developers.google.com/google-ads/api/docs/mutating/overview

#### Operation types

Every mutate request contains operations, each with ONE of three action keys:

| Action | When to use | Required fields |
|--------|-------------|----------------|
| `create` | Creating a new resource | All required fields for that resource type |
| `update` | Modifying an existing resource | `resourceName` (always) + changed fields + `updateMask` |
| `remove` | Soft-deleting a resource | The resource name as a string value |

#### Resource name formats

| Resource | Format |
|----------|--------|
| Campaign | `customers/{CID}/campaigns/{campaign_id}` |
| CampaignBudget | `customers/{CID}/campaignBudgets/{budget_id}` |
| AdGroup | `customers/{CID}/adGroups/{ad_group_id}` |
| AdGroupAd | `customers/{CID}/adGroupAds/{ad_group_id}~{ad_id}` |
| AdGroupCriterion (keyword) | `customers/{CID}/adGroupCriteria/{ad_group_id}~{criterion_id}` |
| CampaignCriterion | `customers/{CID}/campaignCriteria/{campaign_id}~{criterion_id}` |
| Asset | `customers/{CID}/assets/{asset_id}` |
| CampaignAsset | `customers/{CID}/campaignAssets/{campaign_id}~{asset_id}~{field_type}` |
| AssetGroup | `customers/{CID}/assetGroups/{asset_group_id}` |
| AssetGroupAsset | `customers/{CID}/assetGroupAssets/{asset_group_id}~{asset_id}~{field_type}` |
| ConversionAction | `customers/{CID}/conversionActions/{conversion_action_id}` |
| UserList | `customers/{CID}/userLists/{user_list_id}` |
| BiddingStrategy | `customers/{CID}/biddingStrategies/{bidding_strategy_id}` |

**Tilde `~` in compound resource names** — AdGroupCriteria, AdGroupAds, CampaignCriteria, CampaignAssets all use tilde as separator. Using slash instead → HTTP 404.

#### CREATE operation

```json
{
  "create": {
    "name": "New Campaign Name",
    "status": "PAUSED",
    "advertisingChannelType": "SEARCH"
    // ... all required fields
  }
}
```

- Do NOT include `resourceName` for new resources (server assigns it)
- Exception: temporary resource names (`"-1"`) for within-batch references

#### UPDATE operation

```json
{
  "update": {
    "resourceName": "customers/3552856345/campaigns/123456789",
    "status": "PAUSED",
    "name": "Updated Campaign Name"
  },
  "updateMask": "status,name"
}
```

**`updateMask` rules:**
- Required for every `update` operation
- Comma-separated list of field names to update
- Use **camelCase** field paths: `campaignBudget`, `targetCpaMicros`, `maximizeConversions.targetCpaMicros`
- Nested fields: `networkSettings.targetGoogleSearch`
- Fields NOT in updateMask are ignored — even if present in the update object
- Cannot update `resourceName` itself or immutable fields (e.g., `advertisingChannelType`)

**Immutable fields (cannot update after creation):**
- `campaign.advertisingChannelType`
- `campaign.advertisingChannelSubType`
- `ad_group.type`
- `ad_group_criterion.type`
- `conversion_action.type`
- `user_list.type`

#### REMOVE operation

```json
{
  "remove": "customers/3552856345/campaigns/123456789"
}
```

- The `remove` value is the resource name **string** (not an object)
- Removal is **soft delete** — resource gets status `REMOVED` and is preserved with its resource name
- Cannot un-remove (re-enable) a removed resource
- Removed resources still appear in GAQL if you query `status = 'REMOVED'`

#### Batch vs single-resource mutate

| Endpoint | Key | Wrapping | Use when |
|----------|-----|----------|---------|
| `customers/{CID}/googleAds:mutate` | `mutateOperations` (plural) | `{"{resource}Operation": {"create"/"update"/"remove": ...}}` | Multiple resource types in one call |
| `customers/{CID}/{resources}:mutate` | `operations` (singular) | `{"create"/"update"/"remove": ...}` | Single resource type only |

**Cross-resource batch example (campaigns + budgets together):**
```json
{
  "mutateOperations": [
    {"campaignBudgetOperation": {"create": {...}}},
    {"campaignOperation": {"create": {...}}}
  ]
}
```

**Single-resource example (keywords only):**
```json
POST customers/{CID}/adGroupCriteria:mutate
{
  "operations": [
    {"create": {"adGroup": "...", "keyword": {"text": "tesla parts", "matchType": "PHRASE"}}},
    {"create": {"adGroup": "...", "keyword": {"text": "tesla model 3 parts", "matchType": "EXACT"}}}
  ]
}
```

#### responseContentType

Optional field on mutate requests controlling what's returned:

| Value | What's returned |
|-------|----------------|
| `RESOURCE_NAME_ONLY` (default) | Only the new/updated resource name |
| `MUTABLE_RESOURCE` | Full resource object with all mutable fields |

```json
{
  "operations": [...],
  "responseContentType": "MUTABLE_RESOURCE"
}
```

Use `MUTABLE_RESOURCE` when you need the auto-assigned ID immediately after creation (e.g., to build follow-up resource names).

#### validateOnly — dry run

Add `"validateOnly": true` to any mutate request to validate fields and permissions without committing. Response shape is identical but no data changes:

```json
{
  "operations": [...],
  "validateOnly": true
}
```

Returns empty `results` on success, or errors on validation failure. Use before any production mutation.

Ref: https://developers.google.com/google-ads/api/docs/mutating/validate-mutate

---

### DG-15. What's New Since 2026-06-23 (v24.2 + 2026-Q2/Q3 policy changes)

> This section captures everything that changed between the file's original write date (2026-06-23) and this refresh (2026-07-01). Kept as a dated addendum rather than merged silently into the sections above, so future refreshes can see exactly what was added and when. Sources are cited inline; anything not independently confirmed on an official Google page is marked accordingly.

#### v24.2 (2026-06-24) — feature additions

All of the following are additive to the existing `/v24/` endpoint — no URL or config change needed to access them, only `updateMask`/field additions in existing request shapes.

| Area | What's new | Notes |
|------|-----------|-------|
| AI content transparency | `SyntheticContentInfo` / `SyntheticContentAttestation` structures on `Asset` and `Ad` resources | Lets advertiser + Google systems attest whether an asset/ad is AI-generated. `synthetic_content_info.advertiser_attestation.status` and `.source` are present but **immutable through v24.2**; per reporting they become mutable in v25 (unreleased as of 2026-07-01). Ties to the EU AI Act Article 50 transparency deadline of 2026-08-02. [verified via secondary summary: ppc.land, fetched 2026-07-01; primary announcement post body was not directly fetchable — treat feature *existence* as confirmed, exact field mutability timeline as (unverified)] |
| Account security | Multi-Party Approval (MPA) — a second-administrator approval requirement for sensitive account actions (user invitations, access escalation) | Backported simultaneously to v23.3, v22.2, v21.2. Ref: https://ads-developers.googleblog.com/2026/06/multi-party-approvals-in-google-ads-api.html (title/date confirmed via blog archive listing 2026-06-25; body not independently fetched — (unverified) detail level) |
| PMax reporting | `performance_max_placement_view` now segmentable by `segments.ad_network_type` (`SEARCH`, `SEARCH_PARTNERS`, `CONTENT`, `MIXED`, `YOUTUBE_SEARCH`, `YOUTUBE_WATCH`) | Add `performance_max_placement_view` to the queryable-resources list in DG-4 if building PMax placement/network reports. |
| Experiments | New `ExperimentType` values: `COMPARE_CAMPAIGNS` (multi-arm comparison, up to 5 experiment arms across mixed campaign types) and `PMAX_TEXT_CUSTOMIZATION_FINAL_URL_EXPANSION` (split-traffic test for PMax text customization + final URL expansion) | Extends the experiment-type enum used with `ExperimentService` (not otherwise documented in this file — see Gaps). |
| Asset automation | New `AssetAutomationType` value `LANDING_PAGE_TEXT_GENERATION` | Opt-in automatic text-asset generation sourced from landing page content. |
| v24.1 (2026-05-13) carry-forward | `ExperimentType` values `ADOPT_AI_MAX` and `ADOPT_BROAD_MATCH_KEYWORDS` | Formalized experiment types supporting the DSA→AI Max and broad-match migration workflows (see below). [reported via searchengineland.com summary, fetched 2026-07-01 — (unverified) against a primary Google source in this session] |

Source: https://ads-developers.googleblog.com/2026/06/announcing-v242-of-google-ads-api.html (title/date verified 2026-07-01; feature detail cross-checked against https://ppc.land/google-ads-api-v24-2-ai-transparency-and-pmax-segmentation-finally-arrive/, fetched 2026-07-01)

#### Smart Campaign creation sunset — 2026-08-03

Effective **2026-08-03**, the Google Ads API stops accepting **new** Smart Campaign creation (`campaign.advertising_channel_type = SMART` with `advertising_channel_sub_type = SMART_CAMPAIGN`). This is a creation-only cutoff:

- **Existing** Smart Campaigns keep running and remain fully readable/updatable via the API — no forced migration of live campaigns.
- Post-cutoff creation attempts return:
  - `SmartCampaignError.CREATION_FAILED` on **v24.x**
  - `OperationAccessDeniedError.CREATE_OPERATION_NOT_PERMITTED` on **v23.x and earlier**
- Google's recommended replacement path: Performance Max (primary), or Search / Demand Gen depending on goals.
- Affects: DG-3's `SMART_CAMPAIGN_ADS` ad-group type row (creation only; existing rows still valid for read/update), and the "Gaps / Not Yet Implemented" table's `SmartCampaignService` entry below.

Source: https://searchengineland.com/google-ads-api-to-stop-supporting-new-smart-campaign-creation-480999 (fetched 2026-07-01 — third-party reporting, cites the underlying Google Ads Developer Blog post directly; blog post body itself not independently re-fetched in this session, so treat exact error-enum names as (unverified) pending a direct primary-source read).

#### Dynamic Search Ads (DSA) → AI Max automigration — delayed to 2027-02

The forced automigration of DSA campaigns (ad_group type `SEARCH_DYNAMIC_ADS`, ad type `EXPANDED_DYNAMIC_SEARCH_AD` — see DG-3) to AI Max / broad-match Search was originally slated for September 2026 and has been **delayed to February 2027**:

- **2026-06 onward:** DSA campaign creation via the API is fully restored/unaffected (no creation freeze, unlike Smart Campaigns above).
- **2026-06 → 2027-01:** extended voluntary testing/migration window. New `ExperimentType` values `ADOPT_AI_MAX` / `ADOPT_BROAD_MATCH_KEYWORDS` (introduced v24.1) map to this testing path.
- **2027-01:** creation of new DSA campaigns is removed.
- **2027-02:** automatic migration begins for any DSA campaigns still active.
- **Not delayed:** auto-generated assets and the campaign-level broad-match setting still transition on the original September 2026 schedule.

Source: title/date confirmed via Google Ads Developer Blog archive listing (`ads-developers.googleblog.com/2026/`, post dated 2026-06-11, fetched 2026-07-01) and cross-referenced against searchengineland.com / ppc.land summaries (fetched 2026-07-01). Post body was not independently fetched in this session — treat the specific milestone dates above as (unverified) pending a direct primary-source read, though multiple independent secondary sources agree on them.

#### Smart Bidding strategy renaming — cosmetic only (2026-06-16)

Google renamed two Smart Bidding display labels in the Ads UI: "Maximize conversions with a Target CPA" → **Target CPA**, and "Maximize conversion value with a Target ROAS" → **Target ROAS**. Third-party reporting (digitalapplied.com, fetched 2026-07-01) explicitly describes this as a **UI-only, no-behavioral-change rename** requiring no account or integration changes. This session could not independently confirm from an official Google source whether the underlying `biddingStrategyType` REST enum values (`MAXIMIZE_CONVERSIONS`, `TARGET_CPA`, `TARGET_ROAS` in DG-2) were touched — treat "no API schema change" as (unverified, plausible-but-not-primary-sourced). If a caller sees an unexpected 400 on these bidding fields after 2026-06-16, re-verify against the live `GoogleAdsFieldService` output rather than assuming the rename is purely cosmetic.

---
