# Google Merchant API

## Status & Versions

| Version | Status | Notes |
|---------|--------|-------|
| v1 | **GA (stable)** | Current production version. Use this. No v2 exists — Merchant API versions each sub-API independently rather than bumping one global version number (confirmed via versioning guide, checked 2026-07-01). |
| v1beta | **Discontinued** | Shut down February 28, 2026. Do not use. |
| v1alpha | Experimental | Unstable surface; up to 30-day breaking-change notice per the versioning guide. Not for production. |

The Merchant API is a redesign of the legacy Content API for Shopping.

- **Merchant API v1 reached General Availability: August 18, 2025** (corrected — a prior version of this doc said "2024", which was wrong).
  (Sources: https://support.google.com/merchants/answer/16493611?hl=en — "Merchant API is now generally available", dated August 2025; corroborated by contemporaneous press coverage of the Aug 18, 2025 GA announcement, e.g. https://www.searchenginejournal.com/google-makes-merchant-api-generally-available-whats-new/554011/)
- **Content API for Shopping (v2.1) is ALREADY SUNSET — it happened on August 18, 2026, which is now in the past.**
  Re-verified 2026-09-04: the official quickstart page now reads "Content API for Shopping was sunset on August 18, 2026" (past tense) and adds that **"Starting September 1, 2026, requests will experience progressive errors."** Both dates are behind us, so any remaining v2.1 integration is already degrading, not merely deprecated. There is no migration deadline left to plan around — migration is overdue. gads-cli is unaffected: it calls Merchant API v1 only, never `shoppingcontent.googleapis.com`.
  (Source: https://developers.google.com/shopping-content/guides/quickstart — fetched 2026-09-04)
- **v1beta discontinued: February 28, 2026**
  (Source: https://developers.google.com/merchant/api/overview — "Merchant API v1beta was discontinued and shut down on February 28, 2026" — re-verified 2026-07-01, unchanged)
- **No v2 of any sub-API has shipped.** Per the versioning guide, a major bump (v1→v2) would only signal a backward-incompatible break; as of 2026-07-01 every stable sub-API is still at v1.
  (Source: https://developers.google.com/merchant/api/guides/versioning)

Sources:
- https://developers.google.com/merchant/api/overview
- https://developers.google.com/merchant/api/reference/rest
- https://developers.google.com/shopping-content/guides/quickstart
- https://developers.google.com/merchant/api/guides/versioning
- https://developers.google.com/merchant/api/latest-updates
- https://support.google.com/merchants/answer/16493611?hl=en


## Recent Interface Changes (checked 2026-07-01)

Nothing found changes the endpoints gads-cli already implements (accounts, products read, dataSources, shippingSettings, onlineReturnPolicies) — the items below are additive surface that has appeared since this doc's previous fetch (2026-06-23) and across the preceding months, per the "Latest updates" page. None are integrated into gads-cli yet; several are new entries for the Gaps table further down.

| Area | Change | Status |
|------|--------|--------|
| Accounts sub-API | New method `accounts.developerRegistration.getAccountForGcpRegistration` — looks up which Merchant Center account a given GCP project is registered to (the read-side companion to the `registerGcp` write already documented below under "Developer Registration API"). | Confirmed to exist (Source: https://developers.google.com/merchant/api/reference/rest/accounts_v1/accounts.developerRegistration/getAccountForGcpRegistration). Exact REST path unverified — the doc renders as nav-only via automated fetch; likely `GET accounts/v1/accounts:getAccountForGcpRegistration` (custom method on the collection, not a specific account, since the whole point is you don't know the account yet) but confirm against the live discovery doc before coding against it. (unverified path) |
| Accounts sub-API — Regions | New `batchCreate`, `batchUpdate`, `batchDelete` methods for `accounts.regions` (added ~September 2025). | (unverified detail — found via search summary of release notes, not a fetched schema page) |
| Products sub-API | New "conversational" `productAttributes` fields added ~May 2026 — Google's release notes describe additions covering Q&A, document links, related products, item-group title, variant option, and popularity rank. | (unverified exact field names — could not load the live `ProductAttributes` schema page to confirm camelCase spellings; treat names as directional until confirmed against `products_v1/ProductAttributes`) |
| Products sub-API | Vehicle-specific attribute set added to `productAttributes` (~May 2026), for vehicle-ads use cases. | Not applicable to Talas (parts catalog, not vehicle listings) — noted for completeness only. (unverified detail) |
| Products sub-API | `productInputs.patch` gaining lower-latency, more-frequent price/availability updates for allowlisted merchants (~May 2026). | (unverified — allowlist-gated, not general availability) |
| Notifications sub-API | New reporting-context enum value `FREE_LISTINGS_UCP_CHECKOUT` (Universal Commerce Protocol checkout). | (unverified — found via search summary only) |
| Reviews sub-API | In addition to the existing `reviews/v1beta`, a `v1alpha` surface now exists for enabling/disabling the Product Reviews program. | (unverified — could not independently confirm against a schema page) |
| New agentic surface | A Merchant API **MCP (Model Context Protocol) service, alpha**, offering read-only authorized access to Merchant Center data, was announced (~May 2026). Distinct from gads-cli's own architecture (REST, not MCP) — informational only. | (unverified detail) |

Given the "(unverified)" density above, treat this section as a pointer for what to re-check next time this file is refreshed, not as implementation-ready fact — re-fetch the specific schema/release-notes pages before writing code against any row here.


## Base URL(s)

The Merchant API uses **per-sub-API versioned hosts** — each sub-API has its own path prefix and version segment:

```
https://merchantapi.googleapis.com/{sub-api}/{version}/{resource-path}
```

| Sub-API | Base URL | Notes |
|---------|----------|-------|
| Accounts | `https://merchantapi.googleapis.com/accounts/v1` | Account mgmt, shipping, return policies, issues |
| Products | `https://merchantapi.googleapis.com/products/v1` | Product inputs + processed products |
| Data Sources | `https://merchantapi.googleapis.com/datasources/v1` | Feed / data source management |
| Inventories | `https://merchantapi.googleapis.com/inventories/v1` | Local + regional inventory |
| Reports | `https://merchantapi.googleapis.com/reports/v1` | SQL-like reporting |
| Promotions | `https://merchantapi.googleapis.com/promotions/v1` | Promotions management |
| Conversions | `https://merchantapi.googleapis.com/conversions/v1` | Conversion sources |
| Notifications | `https://merchantapi.googleapis.com/notifications/v1` | Event subscriptions |
| Order Tracking | `https://merchantapi.googleapis.com/ordertracking/v1` | Order fulfillment signals |
| Issue Resolution | `https://merchantapi.googleapis.com/issueresolution/v1` | Product issue resolution |
| LFP | `https://merchantapi.googleapis.com/lfp/v1` | Local Feeds Partnership |
| Quota | `https://merchantapi.googleapis.com/quota/v1` | API usage monitoring |

Source: https://merchantapi.googleapis.com/$discovery/rest?version=accounts_v1 (and equivalent per sub-API)


## Auth / OAuth Scopes

**Required scope:** `https://www.googleapis.com/auth/content`

Description: "Manage your product listings and accounts for Google Shopping"

This is the **same scope** used by the legacy Content API v2.1. No scope change is needed when migrating.

In the gads CLI the bearer token is obtained via `get_bearer_headers(creds)` in `gads_lib/http.py` — the same credential object used for all other Google services.

Source: discovery documents at `https://merchantapi.googleapis.com/$discovery/rest?version=accounts_v1`, `products_v1`, `datasources_v1`, `inventories_v1`, `reports_v1`


## Sub-APIs Overview

| Sub-API | Host Version | v1 GA? | v1alpha? | Purpose |
|---------|--------------|--------|----------|---------|
| Accounts | accounts/v1 | Yes | Yes | Account config, users, shipping, return policies, regions, issues |
| Products | products/v1 | Yes | No | Product inputs (write) + processed products (read) |
| Data Sources | datasources/v1 | Yes | No | Feed management (primary, supplemental, local, regional, promotion, review) |
| Inventories | inventories/v1 | Yes | No | Local + regional per-product inventory |
| Reports | reports/v1 | Yes | Yes | SQL-like performance + product reporting |
| Promotions | promotions/v1 | Yes | No | Promotions |
| Conversions | conversions/v1 | Yes | No | Conversion sources |
| Notifications | notifications/v1 | Yes | No | Event notifications |
| Order Tracking | ordertracking/v1 | Yes | No | Order signals |
| Issue Resolution | issueresolution/v1 | Yes | No | Account/product issue resolution |
| LFP | lfp/v1 | Yes | No | Local Feeds Partnership |
| Quota | quota/v1 | Yes | No | Quota monitoring |
| Reviews | reviews/v1beta + reviews/v1alpha | No (beta) | Yes | Merchant + product reviews; v1alpha adds enable/disable of the Product Reviews program (unverified detail, ~May 2026) |
| Loyalty Customers | — | No | Yes (alpha) | Loyalty program customers |
| Product Studio | — | No | Yes (alpha) | AI image/text generation |
| YouTube Shopping | — | No | beta/alpha | YouTube commerce |

Source: https://developers.google.com/merchant/api/reference/rest


## Resources & Endpoints

### Accounts Sub-API (`accounts/v1`)

| Resource | Method | HTTP | Path | Purpose |
|----------|--------|------|------|---------|
| accounts | get | GET | `accounts/v1/accounts/{account}` | Get single account details |
| accounts | list | GET | `accounts/v1/accounts` | List accessible accounts |
| accounts | create | POST | `accounts/v1/accounts` | Create new merchant account |
| accounts | patch | PATCH | `accounts/v1/accounts/{account}` | Update account settings |
| accounts | delete | DELETE | `accounts/v1/accounts/{account}` | Delete account |
| accounts.issues | list | GET | `accounts/v1/accounts/{account}/issues` | List account-level policy issues |
| accounts.shippingSettings | get | GET | `accounts/v1/accounts/{account}/shippingSettings` | Get shipping configuration |
| accounts.shippingSettings | insert | POST | `accounts/v1/accounts/{account}/shippingSettings` | Replace full shipping config |
| accounts.onlineReturnPolicies | get | GET | `accounts/v1/accounts/{account}/onlineReturnPolicies/{policy}` | Get specific return policy |
| accounts.onlineReturnPolicies | list | GET | `accounts/v1/accounts/{account}/onlineReturnPolicies` | List all return policies |
| accounts.onlineReturnPolicies | create | POST | `accounts/v1/accounts/{account}/onlineReturnPolicies` | Create return policy |
| accounts.onlineReturnPolicies | patch | PATCH | `accounts/v1/accounts/{account}/onlineReturnPolicies/{policy}` | Update return policy |
| accounts.onlineReturnPolicies | delete | DELETE | `accounts/v1/accounts/{account}/onlineReturnPolicies/{policy}` | Delete return policy |
| accounts.users | list | GET | `accounts/v1/accounts/{account}/users` | List account users |
| accounts.users | get | GET | `accounts/v1/accounts/{account}/users/{email}` | Get user |
| accounts.users | create | POST | `accounts/v1/accounts/{account}/users` | Add user |
| accounts.users | patch | PATCH | `accounts/v1/accounts/{account}/users/{email}` | Update user access |
| accounts.users | delete | DELETE | `accounts/v1/accounts/{account}/users/{email}` | Remove user |
| accounts.regions | list | GET | `accounts/v1/accounts/{account}/regions` | List shipping regions |
| accounts.regions | get | GET | `accounts/v1/accounts/{account}/regions/{region}` | Get region |
| accounts.regions | create | POST | `accounts/v1/accounts/{account}/regions` | Create region |
| accounts.regions | patch | PATCH | `accounts/v1/accounts/{account}/regions/{region}` | Update region |
| accounts.regions | delete | DELETE | `accounts/v1/accounts/{account}/regions/{region}` | Delete region |
| accounts.homepage | get | GET | `accounts/v1/accounts/{account}/homepage` | Get homepage (store URL) |
| accounts.homepage | claim | POST | `accounts/v1/accounts/{account}/homepage:claim` | Claim homepage ownership |
| accounts.homepage | unclaim | POST | `accounts/v1/accounts/{account}/homepage:unclaim` | Release homepage claim |

Source: discovery doc `https://merchantapi.googleapis.com/$discovery/rest?version=accounts_v1`

### Products Sub-API (`products/v1`)

| Resource | Method | HTTP | Path | Purpose |
|----------|--------|------|------|---------|
| accounts.products | list | GET | `products/v1/accounts/{account}/products` | List processed products (read-only) |
| accounts.products | get | GET | `products/v1/accounts/{account}/products/{product}` | Get single processed product |
| accounts.productInputs | insert | POST | `products/v1/accounts/{account}/productInputs:insert` | Upload/replace a product |
| accounts.productInputs | patch | PATCH | `products/v1/accounts/{account}/productInputs/{product}` | Partial update a product |
| accounts.productInputs | delete | DELETE | `products/v1/accounts/{account}/productInputs/{product}` | Delete a product input |

**Notes on Products vs ProductInputs:**
- `productInputs` = what you write (raw submitted data, per data source)
- `products` = what you read (processed/merged result; read-only)
- `insert` on `productInputs` requires `?dataSource=accounts/{account}/dataSources/{datasource}` query param
- `patch` requires `?dataSource=...` and `?updateMask=field1,field2` query params

Source: discovery doc `https://merchantapi.googleapis.com/$discovery/rest?version=products_v1`

### Data Sources Sub-API (`datasources/v1`)

| Resource | Method | HTTP | Path | Purpose |
|----------|--------|------|------|---------|
| accounts.dataSources | list | GET | `datasources/v1/accounts/{account}/dataSources` | List all data sources |
| accounts.dataSources | get | GET | `datasources/v1/accounts/{account}/dataSources/{dataSource}` | Get single data source |
| accounts.dataSources | create | POST | `datasources/v1/accounts/{account}/dataSources` | Create new data source |
| accounts.dataSources | patch | PATCH | `datasources/v1/accounts/{account}/dataSources/{dataSource}` | Update data source config |
| accounts.dataSources | delete | DELETE | `datasources/v1/accounts/{account}/dataSources/{dataSource}` | Delete data source |
| accounts.dataSources | fetch | POST | `datasources/v1/accounts/{account}/dataSources/{dataSource}:fetch` | Trigger immediate file fetch |
| accounts.dataSources.fileUploads | get | GET | `datasources/v1/accounts/{account}/dataSources/{dataSource}/fileUploads/latest` | Get latest file upload status |

Source: discovery doc `https://merchantapi.googleapis.com/$discovery/rest?version=datasources_v1`

### Inventories Sub-API (`inventories/v1`)

| Resource | Method | HTTP | Path | Purpose |
|----------|--------|------|------|---------|
| accounts.products.localInventories | list | GET | `inventories/v1/accounts/{account}/products/{product}/localInventories` | List local inventory for product |
| accounts.products.localInventories | insert | POST | `inventories/v1/accounts/{account}/products/{product}/localInventories:insert` | Set local inventory at a store |
| accounts.products.localInventories | delete | DELETE | `inventories/v1/accounts/{account}/products/{product}/localInventories/{storeCode}` | Remove local inventory |
| accounts.products.regionalInventories | list | GET | `inventories/v1/accounts/{account}/products/{product}/regionalInventories` | List regional inventory |
| accounts.products.regionalInventories | insert | POST | `inventories/v1/accounts/{account}/products/{product}/regionalInventories:insert` | Set regional inventory |
| accounts.products.regionalInventories | delete | DELETE | `inventories/v1/accounts/{account}/products/{product}/regionalInventories/{region}` | Remove regional inventory |

Source: discovery doc `https://merchantapi.googleapis.com/$discovery/rest?version=inventories_v1`

### Reports Sub-API (`reports/v1`)

| Resource | Method | HTTP | Path | Purpose |
|----------|--------|------|------|---------|
| accounts.reports | search | POST | `reports/v1/accounts/{account}/reports:search` | Run SQL-like report query |

**Available report tables:**

| Table | Description |
|-------|-------------|
| `product_view` | Current inventory products with status and issues |
| `product_performance_view` | Clicks, impressions, conversions |
| `price_competitiveness_product_view` | Price benchmarking vs. competitors |
| `price_insights_product_view` | AI-driven price suggestions |
| `competitive_visibility_top_merchant_view` | Top-ranking competitor domains |
| `competitive_visibility_benchmark_view` | Category-level benchmarks |
| `competitive_visibility_competitor_view` | Similar businesses analysis |
| `best_sellers_brand_view` | Popular brands by category/country |
| `best_sellers_product_cluster_view` | Popular product groupings |
| `non_product_performance_view` | Image and link performance metrics |

Source: discovery doc `https://merchantapi.googleapis.com/$discovery/rest?version=reports_v1`


---

## Concrete Request/Response Examples

This section documents every endpoint used by gads-cli (plus priority gap endpoints) with exact HTTP details, typed parameters, and realistic example payloads. Use these as the implementation reference when building new subcommands.

### Conventions

- `{merchantId}` — numeric string, e.g. `"355285634"`. In path it appears as the bare number, not as a resource name prefix.
- `{account}` — the full resource name form used in some discovery docs: `accounts/{merchantId}`.
- The gads CLI uses the numeric form directly: `MA_ACCOUNTS + "/accounts/" + MERCHANT_CENTER_ID`.
- All request headers must include `Authorization: Bearer {token}`. Write operations also need `Content-Type: application/json`.
- `pageSize` defaults vary by endpoint; always supply it explicitly to avoid surprises.

---

### GET /accounts/v1/accounts/{merchantId}

**Purpose:** Fetch basic account info — name, timezone, language, test flag.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | e.g. `"355285634"` |

**Example request:**

```http
GET https://merchantapi.googleapis.com/accounts/v1/accounts/355285634
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK):**

```json
{
  "name": "accounts/355285634",
  "accountId": "355285634",
  "accountName": "Talas Auto Parts",
  "testAccount": false,
  "timeZone": {
    "id": "Asia/Dubai",
    "version": "2024b"
  },
  "languageCode": "en",
  "adultContent": false
}
```

**Error cases:**

```json
// 403 — wrong scope or token expired
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
          "service": "merchantapi.googleapis.com",
          "method": "google.shopping.merchant.accounts.v1.AccountsService.GetAccount"
        }
      }
    ]
  }
}

// 404 — account not found or no access
{
  "error": {
    "code": 404,
    "message": "Account '999999999' not found or caller does not have access.",
    "status": "NOT_FOUND"
  }
}
```

---

### GET /accounts/v1/accounts/{merchantId}/issues

**Purpose:** List account-level policy issues (disapprovals, warnings, suggestions). Used by `mc_get_account_status()` in gads-cli.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `pageSize` | query | int | no | Recommended: 50. Max unspecified; use 50 for safety. |
| `pageToken` | query | string | no | Pagination cursor from previous response |
| `languageCode` | query | string | no | BCP-47; localises `title` and `detail` fields |

**Example request:**

```http
GET https://merchantapi.googleapis.com/accounts/v1/accounts/355285634/issues?pageSize=50
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK — one CRITICAL issue):**

```json
{
  "accountIssues": [
    {
      "name": "accounts/355285634/issues/missing_return_policy",
      "title": "Missing return policy",
      "severity": "CRITICAL",
      "impactedDestinations": [
        {
          "impacts": [
            {
              "regionCode": "AE",
              "severity": "CRITICAL",
              "impactedRanking": [
                {
                  "type": "SHOPPING_ADS",
                  "region": "AE",
                  "rank": "SEVERELY_IMPACTED"
                }
              ]
            }
          ],
          "destination": "Shopping ads"
        }
      ],
      "detail": "Your account is missing a return policy for the United Arab Emirates. Ads for products in AE may be disapproved.",
      "documentationUri": "https://support.google.com/merchants/answer/7538732"
    },
    {
      "name": "accounts/355285634/issues/phone_verification_required",
      "title": "Phone number verification required",
      "severity": "ERROR",
      "impactedDestinations": [],
      "detail": "Verify your business phone number to improve trust signals.",
      "documentationUri": "https://support.google.com/merchants/answer/176793"
    }
  ],
  "nextPageToken": "CjQKMgoubWlzc2luZ19yZXR1cm5fcG9saWN5EiJhY2NvdW50cy8zNTUyODU2MzQ..."
}
```

**Severity enum values:** `CRITICAL`, `ERROR`, `SUGGESTION`

**Notes:**
- `nextPageToken` absent means last page.
- `impactedDestinations[].impacts[].rank` values: `SEVERELY_IMPACTED`, `DEMOTED`, `UNKNOWN`.
- When `accountIssues` is an empty array, the account is issue-free.

---

### GET /products/v1/accounts/{merchantId}/products

**Purpose:** List processed (read-only) products with their attributes and status. Used by both `mc_list_products()` and `mc_list_product_statuses()` in gads-cli.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `pageSize` | query | int | no | Default 25, max 1000 |
| `pageToken` | query | string | no | Pagination cursor |

**Example request:**

```http
GET https://merchantapi.googleapis.com/products/v1/accounts/355285634/products?pageSize=50
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK — one product fully expanded):**

```json
{
  "products": [
    {
      "name": "accounts/355285634/products/ZW4tQUUtVGVzbGFNb2RlbDNSZWFyQnVtcGVy",
      "offerId": "TeslaModel3RearBumper",
      "contentLanguage": "en",
      "feedLabel": "AE",
      "dataSource": "accounts/355285634/dataSources/7823401256",
      "versionNumber": "1714567890123",
      "archived": false,
      "productAttributes": {
        "title": "Tesla Model 3 Rear Bumper Cover — Used OEM",
        "description": "Original Tesla Model 3 rear bumper cover in good condition, minor scuffs. Fits 2017-2022 Model 3. No installation included — parts only.",
        "link": "https://shop.talas.ae/products/tesla-model3-rear-bumper?branch=QZ3",
        "imageLink": "https://cdn.talas.ae/images/tesla-m3-rear-bumper-001.jpg",
        "additionalImageLinks": [
          "https://cdn.talas.ae/images/tesla-m3-rear-bumper-002.jpg",
          "https://cdn.talas.ae/images/tesla-m3-rear-bumper-003.jpg"
        ],
        "brand": "Tesla",
        "condition": "used",
        "availability": "in_stock",
        "price": {
          "amountMicros": "450000000",
          "currencyCode": "AED"
        },
        "googleProductCategory": "5613",
        "productTypes": [
          "Auto Parts > Body Parts > Bumpers",
          "Tesla Parts > Model 3"
        ],
        "gtins": [],
        "mpn": "1084665-00-E",
        "itemGroupId": "tesla-model3-bumpers",
        "shipping": [
          {
            "country": "AE",
            "service": "Standard",
            "price": {
              "amountMicros": "0",
              "currencyCode": "AED"
            }
          }
        ]
      },
      "productStatus": {
        "destinationStatuses": [
          {
            "destination": "Shopping ads",
            "approvedCountries": ["AE"],
            "pendingCountries": [],
            "disapprovedCountries": []
          },
          {
            "destination": "Buy on Google listings",
            "approvedCountries": [],
            "pendingCountries": [],
            "disapprovedCountries": ["AE"]
          }
        ],
        "itemLevelIssues": [
          {
            "code": "missing_gtin",
            "severity": "SUGGESTION",
            "resolution": "merchant_action",
            "attribute": "gtin",
            "destination": "Shopping ads",
            "description": "Missing value [gtin]",
            "detail": "Add a GTIN to improve your product's performance in shopping ads.",
            "documentation": "https://support.google.com/merchants/answer/160161"
          }
        ]
      }
    }
  ],
  "nextPageToken": "CiQKIgogYWNjb3VudHMvMzU1Mjg1NjM0L3Byb2R1Y3RzL2VuLUFFL..."
}
```

**Product ID encoding note:**
The `{product}` path segment in `products/{product}` is the unpadded base64url of `contentLanguage~feedLabel~offerId`.
- `en~AE~TeslaModel3RearBumper` → `ZW4tQUUtVGVzbGFNb2RlbDNSZWFyQnVtcGVy`
- Python: `base64.urlsafe_b64encode(b"en~AE~TeslaModel3RearBumper").rstrip(b"=").decode()`

**`productStatus.itemLevelIssues[].severity` values:** `ERROR`, `SUGGESTION`
**`productStatus.itemLevelIssues[].resolution` values:** `merchant_action`, `pending_processing`

---

### GET /datasources/v1/accounts/{merchantId}/dataSources

**Purpose:** List all data sources (feeds) in the account. Used by `mc_list_datafeeds()` in gads-cli.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `pageSize` | query | int | no | Max 1000 |
| `pageToken` | query | string | no | Pagination cursor |

**Example request:**

```http
GET https://merchantapi.googleapis.com/datasources/v1/accounts/355285634/dataSources?pageSize=50
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK):**

```json
{
  "dataSources": [
    {
      "name": "accounts/355285634/dataSources/7823401256",
      "dataSourceId": "7823401256",
      "displayName": "Talas Shop — Primary Feed (AE)",
      "input": "FILE",
      "primaryProductDataSource": {
        "feedLabel": "AE",
        "contentLanguage": "en",
        "countries": ["AE"],
        "destinations": [
          {
            "destination": "Shopping ads",
            "state": "ENABLED"
          }
        ]
      },
      "fileInput": {
        "fileInputType": "FETCH",
        "fetchSettings": {
          "frequency": "DAILY",
          "fetchUri": "https://shop.talas.ae/feeds/google-shopping.xml",
          "enabled": true,
          "timeOfDay": {
            "hours": 2,
            "minutes": 0,
            "seconds": 0,
            "nanos": 0
          },
          "timeZone": "Asia/Dubai"
        }
      }
    },
    {
      "name": "accounts/355285634/dataSources/7823401999",
      "dataSourceId": "7823401999",
      "displayName": "API Direct Upload",
      "input": "API",
      "primaryProductDataSource": {
        "feedLabel": "AE",
        "contentLanguage": "en",
        "countries": ["AE"]
      }
    }
  ]
}
```

**`input` enum values:** `API`, `FILE`, `UI`, `AUTOFEED` (read-only — reflects how the data source receives data)

---

### GET /accounts/v1/accounts/{merchantId}/shippingSettings

**Purpose:** Fetch full shipping configuration. Used by `mc_get_shipping()` in gads-cli.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |

**Example request:**

```http
GET https://merchantapi.googleapis.com/accounts/v1/accounts/355285634/shippingSettings
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK):**

```json
{
  "name": "accounts/355285634/shippingSettings",
  "services": [
    {
      "serviceName": "UAE Standard Delivery",
      "active": true,
      "deliveryCountries": ["AE"],
      "currencyCode": "AED",
      "deliveryTime": {
        "minHandlingDays": 0,
        "maxHandlingDays": 1,
        "minTransitDays": 2,
        "maxTransitDays": 5,
        "transitTimeTable": null
      },
      "rateGroups": [
        {
          "singleValue": {
            "flatRate": {
              "amountMicros": "0",
              "currencyCode": "AED"
            }
          },
          "name": "Free Shipping AE"
        }
      ],
      "shipmentType": "DELIVERY"
    }
  ],
  "warehouses": [
    {
      "name": "QZ3 Warehouse",
      "shippingAddress": {
        "streetAddress": "Al Quoz Industrial Area 3",
        "city": "Dubai",
        "administrativeArea": "DU",
        "postalCode": "00000",
        "regionCode": "AE"
      },
      "cutoffTime": {
        "hours": 14,
        "minutes": 0
      },
      "handlingDays": 1,
      "businessDaysConfig": {
        "businessDays": ["MONDAY","TUESDAY","WEDNESDAY","THURSDAY","FRIDAY"]
      }
    }
  ],
  "etag": "\"AbCdEfGhIjKlMnOp12345\""
}
```

**Critical:** Store the `etag` when you GET. You must include it when calling `shippingSettings:insert` (POST) to prevent concurrent-write conflicts. If your etag is stale the API returns 409 Conflict.

---

### GET /accounts/v1/accounts/{merchantId}/onlineReturnPolicies

**Purpose:** List all online return policies. Used by `mc_get_return_policy()` in gads-cli.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `pageSize` | query | int | no | gads-cli uses 10 |

**Example request:**

```http
GET https://merchantapi.googleapis.com/accounts/v1/accounts/355285634/onlineReturnPolicies?pageSize=10
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK):**

```json
{
  "onlineReturnPolicies": [
    {
      "name": "accounts/355285634/onlineReturnPolicies/return_policy_AE_default",
      "returnPolicyId": "return_policy_AE_default",
      "label": "default",
      "countries": ["AE"],
      "policy": {
        "type": "NUMBER_OF_DAYS_AFTER_DELIVERY",
        "days": 14
      },
      "restockingFee": {
        "fixedFee": {
          "amountMicros": "0",
          "currencyCode": "AED"
        }
      },
      "returnMethods": ["BY_MAIL"],
      "itemConditions": ["NEW", "USED"],
      "returnShippingFee": {
        "type": "FREE",
        "fixedFee": null
      }
    }
  ]
}
```

**`policy.type` enum values:** `NUMBER_OF_DAYS_AFTER_DELIVERY`, `NO_RETURNS`, `LIFETIME_RETURNS`

---

## ProductInputs Write Path

These endpoints are **not yet implemented in gads-cli** but are documented here implementation-ready for future subcommands (e.g. `gads merchant product-insert`, `gads merchant product-patch`, `gads merchant product-delete`).

### POST /products/v1/accounts/{merchantId}/productInputs:insert

**Purpose:** Upload a new product or fully replace an existing one in a specific data source. Idempotent on `(contentLanguage, feedLabel, offerId, dataSource)` tuple.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `dataSource` | query | string | yes | Full resource name: `accounts/{merchantId}/dataSources/{dataSourceId}`. The data source must have `input=API`. |

**Request headers:**
```
Authorization: Bearer {token}
Content-Type: application/json
```

**Request body — ProductInput object:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | no | Ignored on insert; auto-assigned |
| `product` | string | no | Read-only; do not supply |
| `offerId` | string | yes | Your SKU; must be stable across updates |
| `contentLanguage` | string | yes | ISO 639-1, e.g. `"en"` |
| `feedLabel` | string | yes | Country/feed label ≤20 chars, e.g. `"AE"` |
| `productAttributes` | object | yes | See fields below |
| `customAttributes` | array | no | Key-value pairs for custom data |
| `versionNumber` | int64 | no | If set, insert is rejected if existing versionNumber is higher (freshness guard) |

**`productAttributes` key fields:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `title` | string | yes | Max 150 chars |
| `description` | string | yes | Max 5000 chars |
| `link` | string | yes | Must include `?branch=` for Talas |
| `imageLink` | string | yes | HTTPS, min 100×100px |
| `brand` | string | recommended | |
| `condition` | string | yes | `"new"`, `"used"`, `"refurbished"` |
| `availability` | string | yes | `"in_stock"`, `"out_of_stock"`, `"preorder"` |
| `price` | object | yes | `{"amountMicros": int64, "currencyCode": "AED"}` |
| `googleProductCategory` | string | recommended | Numeric or string category |
| `gtins` | string[] | recommended | Improves matching; can be empty array |
| `mpn` | string | recommended | Manufacturer part number |

**Example request:**

```http
POST https://merchantapi.googleapis.com/products/v1/accounts/355285634/productInputs:insert?dataSource=accounts%2F355285634%2FdataSources%2F7823401999
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "offerId": "TeslaModel3FrontBumper-Used-001",
  "contentLanguage": "en",
  "feedLabel": "AE",
  "productAttributes": {
    "title": "Tesla Model 3 Front Bumper Cover — Used OEM",
    "description": "Original Tesla Model 3 front bumper in good condition. Fits 2017-2022 models. Parts only — no installation.",
    "link": "https://shop.talas.ae/products/tesla-model3-front-bumper-001?branch=QZ3",
    "imageLink": "https://cdn.talas.ae/images/tesla-m3-front-bumper-001.jpg",
    "brand": "Tesla",
    "condition": "used",
    "availability": "in_stock",
    "price": {
      "amountMicros": "380000000",
      "currencyCode": "AED"
    },
    "googleProductCategory": "5613",
    "mpn": "1059186-00-E",
    "gtins": []
  }
}
```

**Example response (200 OK — returns the ProductInput as stored):**

```json
{
  "name": "accounts/355285634/productInputs/ZW4tQUUtVGVzbGFNb2RlbDNGcm9udEJ1bXBlci1Vc2VkLTAwMQ",
  "product": "accounts/355285634/products/ZW4tQUUtVGVzbGFNb2RlbDNGcm9udEJ1bXBlci1Vc2VkLTAwMQ",
  "offerId": "TeslaModel3FrontBumper-Used-001",
  "contentLanguage": "en",
  "feedLabel": "AE",
  "versionNumber": "1714599000000",
  "productAttributes": {
    "title": "Tesla Model 3 Front Bumper Cover — Used OEM",
    "description": "Original Tesla Model 3 front bumper in good condition. Fits 2017-2022 models. Parts only — no installation.",
    "link": "https://shop.talas.ae/products/tesla-model3-front-bumper-001?branch=QZ3",
    "imageLink": "https://cdn.talas.ae/images/tesla-m3-front-bumper-001.jpg",
    "brand": "Tesla",
    "condition": "used",
    "availability": "in_stock",
    "price": {
      "amountMicros": "380000000",
      "currencyCode": "AED"
    },
    "googleProductCategory": "5613",
    "mpn": "1059186-00-E",
    "gtins": []
  }
}
```

**Note:** The processed `products` resource will not reflect this insert for several minutes. Check via `GET /products/v1/.../products/{encodedId}`.

---

### PATCH /products/v1/accounts/{merchantId}/productInputs/{productInputId}

**Purpose:** Partial update — change only specific fields of an existing product input.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `productInputId` | path | string | yes | Encoded product input name (base64url of `contentLanguage~feedLabel~offerId`) |
| `dataSource` | query | string | yes | `accounts/{merchantId}/dataSources/{dataSourceId}` |
| `updateMask` | query | string | yes | Comma-separated field paths to update, e.g. `productAttributes.price,productAttributes.availability` |

**Example request — price update only:**

```http
PATCH https://merchantapi.googleapis.com/products/v1/accounts/355285634/productInputs/ZW4tQUUtVGVzbGFNb2RlbDNGcm9udEJ1bXBlci1Vc2VkLTAwMQ?dataSource=accounts%2F355285634%2FdataSources%2F7823401999&updateMask=productAttributes.price
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "productAttributes": {
    "price": {
      "amountMicros": "350000000",
      "currencyCode": "AED"
    }
  }
}
```

**Example response (200 OK):** Returns the full updated ProductInput (same shape as insert response).

**Important:** `updateMask` must exactly match the fields in the body — unmasked fields in the body are silently ignored, and masked fields not in the body are set to null.

---

### DELETE /products/v1/accounts/{merchantId}/productInputs/{productInputId}

**Purpose:** Remove a product from the catalog.

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |
| `productInputId` | path | string | yes | Encoded product ID |
| `dataSource` | query | string | yes | `accounts/{merchantId}/dataSources/{dataSourceId}` |

**Example request:**

```http
DELETE https://merchantapi.googleapis.com/products/v1/accounts/355285634/productInputs/ZW4tQUUtVGVzbGFNb2RlbDNGcm9udEJ1bXBlci1Vc2VkLTAwMQ?dataSource=accounts%2F355285634%2FdataSources%2F7823401999
Authorization: Bearer ya29.a0AfB_byC...
```

**Example response (200 OK):**

```json
{}
```

(Empty object — standard Google API "Empty" response.)

**Note:** Deletion is not immediate. The product may remain visible in `GET /products` for several minutes.

---

## Reports Sub-API — Implementation Reference

### POST /reports/v1/accounts/{merchantId}/reports:search

**Purpose:** Execute a query against Merchant Center data. This is the Merchant API equivalent of a GAQL query — one endpoint, many report types — but it is **a different language**: officially the **Merchant Center Query Language (MCQL)**, described by Google as "similar to SQL". Do **not** assume GAQL syntax, functions, or field names carry over. (Source: https://developers.google.com/merchant/api/guides/reports/query-language — verified 2026-09-04.)

**Parameters:**

| Name | In | Type | Required | Notes |
|------|----|------|----------|-------|
| `merchantId` | path | string (numeric) | yes | |

**Request headers:**
```
Authorization: Bearer {token}
Content-Type: application/json
```

**Request body:**

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `query` | string | yes | SQL-like query — see syntax below |
| `pageSize` | int | no | Default 1000, max 100000 |
| `pageToken` | string | no | Pagination cursor |

**Query syntax:**

```sql
SELECT field1, field2, ...
FROM table_name
WHERE condition
ORDER BY field ASC|DESC
LIMIT n
```

Supported `WHERE` operators: `=`, `!=`, `<`, `>`, `<=`, `>=`, `IN`, `NOT IN`, `LIKE`, `IS NULL`, `IS NOT NULL`, `AND`, `OR`.

---

#### Example 1 — product_view: disapproved products

```http
POST https://merchantapi.googleapis.com/reports/v1/accounts/355285634/reports:search
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "query": "SELECT id, title, brand, availability, price_micros, currency_code, feed_label, item_issues FROM product_view WHERE channel = 'ONLINE' AND item_issues IS NOT NULL LIMIT 100",
  "pageSize": 100
}
```

**Example response (200 OK):**

```json
{
  "results": [
    {
      "productView": {
        "id": "online:en:AE:TeslaModel3FrontBumper-Used-001",
        "title": "Tesla Model 3 Front Bumper Cover — Used OEM",
        "brand": "Tesla",
        "availability": "IN_STOCK",
        "priceMicros": "380000000",
        "currencyCode": "AED",
        "feedLabel": "AE",
        "itemIssues": [
          {
            "type": {
              "code": "missing_gtin",
              "canonicalAttribute": "gtin",
              "resolution": "MERCHANT_ACTION"
            },
            "severity": {
              "severityPerDestination": [
                {
                  "destination": "SHOPPING_ADS",
                  "demotionImpact": "DEMOTED",
                  "approvalStatus": "APPROVED_LIMITED"
                }
              ],
              "aggregatedSeverity": "DISAPPROVED"
            }
          }
        ]
      }
    }
  ],
  "nextPageToken": null
}
```

---

#### Example 2 — product_performance_view: clicks and impressions last 30 days

```http
POST https://merchantapi.googleapis.com/reports/v1/accounts/355285634/reports:search
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "query": "SELECT offer_id, title, clicks, impressions, click_through_rate FROM product_performance_view WHERE date BETWEEN '2026-05-24' AND '2026-06-22' ORDER BY clicks DESC LIMIT 50",
  "pageSize": 50
}
```

**Example response (200 OK):**

```json
{
  "results": [
    {
      "productPerformanceView": {
        "offerId": "TeslaModel3RearBumper",
        "title": "Tesla Model 3 Rear Bumper Cover — Used OEM",
        "clicks": "42",
        "impressions": "1834",
        "clickThroughRate": 0.022900
      }
    },
    {
      "productPerformanceView": {
        "offerId": "TeslaModel3FrontBumper-Used-001",
        "title": "Tesla Model 3 Front Bumper Cover — Used OEM",
        "clicks": "18",
        "impressions": "921",
        "clickThroughRate": 0.019500
      }
    }
  ]
}
```

---

#### Example 3 — product_view: all products with aggregated approval status

```http
POST https://merchantapi.googleapis.com/reports/v1/accounts/355285634/reports:search
Authorization: Bearer ya29.a0AfB_byC...
Content-Type: application/json

{
  "query": "SELECT id, title, aggregated_destination_status, item_issues FROM product_view WHERE channel = 'ONLINE' ORDER BY aggregated_destination_status LIMIT 200",
  "pageSize": 200
}
```

**`aggregatedDestinationStatus` enum values:**
- `NOT_ELIGIBLE_OR_DISAPPROVED` — blocked from all surfaces
- `NOT_ELIGIBLE` — not eligible but no active disapproval
- `ELIGIBLE_LIMITED` — approved with restrictions (e.g. missing GTIN)
- `ELIGIBLE` — fully approved

---

## Key Request/Response Fields

### Account Object (`accounts/v1`)

```json
{
  "name": "accounts/{accountId}",
  "accountId": "string (numeric)",
  "accountName": "string (display name)",
  "testAccount": false,
  "timeZone": { "id": "string", "version": "string" },
  "languageCode": "string (BCP-47)",
  "adultContent": false
}
```

### AccountIssue Object (`accounts/{id}/issues`)

```json
{
  "name": "string (resource name)",
  "title": "string (human-readable)",
  "severity": "CRITICAL | ERROR | SUGGESTION",
  "impactedDestinations": ["array of destination strings"],
  "detail": "string",
  "documentationUri": "string (URL to help docs)"
}
```

### Product Object (read-only, from `products/v1/.../products`)

```json
{
  "name": "accounts/{account}/products/{product}",
  "offerId": "string (merchant-assigned SKU)",
  "contentLanguage": "string (ISO 639-1)",
  "feedLabel": "string (country/feed label, max 20 chars)",
  "dataSource": "string (resource name of primary data source)",
  "versionNumber": "int64 (freshness identifier, read-only)",
  "archived": "boolean",
  "productAttributes": {
    "title": "string",
    "description": "string",
    "link": "string (canonical URL)",
    "brand": "string",
    "condition": "string enum",
    "availability": "string enum",
    "gtins": ["string array"],
    "price": {
      "amountMicros": "int64 (price × 1,000,000)",
      "currencyCode": "string (ISO 4217)"
    },
    "imageLink": "string",
    "additionalImageLinks": ["string array"],
    "googleProductCategory": "string",
    "productTypes": ["string array"],
    "shipping": ["shipping overrides"],
    "mpn": "string",
    "itemGroupId": "string"
  },
  "productStatus": {
    "destinationStatuses": [
      {
        "destination": "string",
        "approvedCountries": ["string array"],
        "pendingCountries": ["string array"],
        "disapprovedCountries": ["string array"]
      }
    ],
    "itemLevelIssues": [
      {
        "code": "string",
        "severity": "string",
        "resolution": "string",
        "attribute": "string",
        "destination": "string",
        "description": "string",
        "detail": "string",
        "documentation": "string (URL)"
      }
    ]
  }
}
```

**Product ID encoding:** Product IDs use tilde-separated `contentLanguage~feedLabel~offerId`.
For offerId values with special characters (slashes, etc.), use unpadded base64url encoding.
Example: `en~US~sku/123` encodes to `ZW5-VVN-c2t1LzEyMw`.

### DataSource Object

```json
{
  "name": "accounts/{account}/dataSources/{dataSourceId}",
  "dataSourceId": "int64 (read-only)",
  "displayName": "string (required)",
  "input": "API | FILE | UI | AUTOFEED (read-only)",
  "primaryProductDataSource": {
    "feedLabel": "string (immutable, ≤20 chars)",
    "contentLanguage": "string (immutable, ISO 639-1)",
    "countries": ["CLDR territory codes"],
    "destinations": ["marketing method selections"],
    "defaultRule": {}
  },
  "supplementalProductDataSource": {},
  "localInventoryDataSource": {},
  "regionalInventoryDataSource": {},
  "promotionDataSource": {},
  "productReviewDataSource": {},
  "merchantReviewDataSource": {},
  "fileInput": {
    "fileInputType": "UPLOAD | FETCH | GOOGLE_SHEETS (read-only)",
    "fileName": "string (required for UPLOAD)",
    "fetchSettings": {
      "frequency": "DAILY | WEEKLY | MONTHLY",
      "fetchUri": "string",
      "enabled": "boolean",
      "timeOfDay": {},
      "dayOfWeek": "MONDAY..SUNDAY",
      "dayOfMonth": "int32 1-31",
      "timeZone": "string (CLDR, default UTC)",
      "username": "string",
      "password": "string"
    }
  }
}
```

### ShippingSettings Object

```json
{
  "name": "accounts/{account}/shippingSettings",
  "services": [
    {
      "serviceName": "string",
      "active": "boolean",
      "deliveryCountries": ["string array"],
      "currencyCode": "string (ISO 4217)",
      "deliveryTime": { "minTransitDays": "int", "maxTransitDays": "int" },
      "rateGroups": ["RateGroup objects"],
      "shipmentType": "string enum",
      "storeConfig": {}
    }
  ],
  "warehouses": [
    {
      "name": "string",
      "shippingAddress": {},
      "cutoffTime": {},
      "handlingDays": "int32",
      "businessDaysConfig": {}
    }
  ],
  "etag": "string (concurrency token)"
}
```

**Important:** `shippingSettings:insert` (POST) is a full-replace — NULL or missing fields will null out existing values. Always GET first and include the `etag`.

### OnlineReturnPolicy Object

```json
{
  "name": "accounts/{account}/onlineReturnPolicies/{returnPolicyId}",
  "returnPolicyId": "string",
  "label": "string",
  "countries": ["string array (country codes)"],
  "policy": {
    "type": "string enum",
    "days": "int32"
  }
}
```


## Pagination & Quotas

### Pagination

All list methods use cursor-based pagination with `pageToken`:

```
GET ...?pageSize=100&pageToken={nextPageToken}

Response:
{
  "items": [...],
  "nextPageToken": "string | absent when last page"
}
```

| Sub-API | Collection field | Default pageSize | Max pageSize |
|---------|-----------------|-----------------|-------------|
| Products (list) | `products` | 25 | 1000 |
| DataSources (list) | `dataSources` | unspecified | 1000 |
| Issues (list) | `accountIssues` | unspecified | 50 (recommended) |
| LocalInventories | `localInventories` | 25000 | 25000 |
| RegionalInventories | `regionalInventories` | 25000 | 100000 |
| Reports (search) | `results` | 1000 | 100000 |

When `nextPageToken` is absent from a response, you have reached the last page.

**Python pagination helper pattern:**

```python
def paginate(fetch_fn, collection_key, **kwargs):
    """Generic paginator. fetch_fn(page_token=None, **kwargs) -> dict."""
    items = []
    page_token = None
    while True:
        resp = fetch_fn(page_token=page_token, **kwargs)
        items.extend(resp.get(collection_key, []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return items
```

### Quotas

The Merchant API has a **Quota sub-API** (`quota/v1`) for monitoring usage. Specific QPS/QPD limits are account-dependent. Use `GET quota/v1/accounts/{account}/quotas` to inspect current limits.

**429 quota exceeded response:**

```json
{
  "error": {
    "code": 429,
    "message": "Quota exceeded for quota metric 'merchantapi.googleapis.com/default' and limit 'DEFAULT-LIMIT' of service 'merchantapi.googleapis.com'.",
    "status": "RESOURCE_EXHAUSTED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.QuotaFailure",
        "violations": [
          {
            "subject": "merchantapiuser:355285634",
            "description": "Quota exceeded for quota metric 'merchantapi.googleapis.com/default'"
          }
        ]
      }
    ]
  }
}
```

**Retry strategy:** Exponential backoff starting at 1s. Merchant API is not high-QPS — typical scripts hit quota only if looping without pagination delay.

Source: https://developers.google.com/merchant/api/reference/rest


## Error Reference

### Common Error Shapes

All errors use the standard Google API error envelope:

```json
{
  "error": {
    "code": 403,
    "message": "string",
    "status": "PERMISSION_DENIED | NOT_FOUND | INVALID_ARGUMENT | RESOURCE_EXHAUSTED | ALREADY_EXISTS | FAILED_PRECONDITION | INTERNAL",
    "details": [...]
  }
}
```

| HTTP code | `status` string | Typical cause |
|-----------|----------------|---------------|
| 400 | `INVALID_ARGUMENT` | Bad field value, missing required field, wrong enum string |
| 401 | `UNAUTHENTICATED` | Token expired or missing |
| 403 | `PERMISSION_DENIED` | Wrong scope, wrong account, or no access |
| 404 | `NOT_FOUND` | Account ID wrong, resource doesn't exist |
| 409 | `ABORTED` | ETag conflict on shippingSettings insert |
| 429 | `RESOURCE_EXHAUSTED` | Quota exceeded |
| 500 | `INTERNAL` | Google-side error; retry with backoff |

### 400 INVALID_ARGUMENT — missing required query param

```json
{
  "error": {
    "code": 400,
    "message": "Request is missing required query parameter 'dataSource'.",
    "status": "INVALID_ARGUMENT"
  }
}
```

Trigger: calling `productInputs:insert` without `?dataSource=` query param.

### 403 PERMISSION_DENIED — insufficient scope

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
        "domain": "googleapis.com"
      }
    ]
  }
}
```

**Fix:** Ensure the OAuth token includes `https://www.googleapis.com/auth/content`. Re-run `python generate_token.py` if the stored token predates scope additions.

### 404 NOT_FOUND — account doesn't exist or no access

```json
{
  "error": {
    "code": 404,
    "message": "Account '999999999' not found or caller does not have access.",
    "status": "NOT_FOUND"
  }
}
```


## Migration Notes: Content API v2.1 → Merchant API

### Timeline

| Event | Date |
|-------|------|
| Merchant API v1beta discontinued | February 28, 2026 |
| Content API v2.1 sunset | **August 18, 2026 — already past** |
| Content API v2.1 progressive errors begin | **September 1, 2026 — already past** |

Source: https://developers.google.com/shopping-content/guides/quickstart, https://developers.google.com/merchant/api/overview

### Key Structural Changes

| Area | Content API v2.1 | Merchant API v1 |
|------|-----------------|-----------------|
| Base URL | `https://shoppingcontent.googleapis.com/content/v2.1/` | `https://merchantapi.googleapis.com/{sub-api}/v1/` |
| Merchant ID param | Path: `/{merchantId}/products` | Path: `accounts/{account}/products` |
| Account ID format | Numeric string in path | `accounts/{id}` resource name |
| OAuth scope | `https://www.googleapis.com/auth/content` | **Same scope — no change** |
| Product status | Separate `productstatuses` resource | Folded into `products` resource under `productStatus.*` |
| Data sources | `datafeeds` resource | `dataSources` sub-API at `datasources/v1/` |
| Write vs read products | Same resource | Split: `productInputs` (write) vs `products` (read) |
| Shipping settings | `shippingsettings` resource | `accounts/{id}/shippingSettings` under accounts sub-API |
| Return policies | `returnpolicy` resource | `accounts/{id}/onlineReturnPolicies` under accounts sub-API |

### Field Renames

| Content API field | Merchant API field |
|------------------|--------------------|
| `merchant_id` | `name` (resource name string) |
| `product.id` | `product.offerId` |
| `productStatus.productId` | (embedded in product `name`) |
| `datafeed.id` | `dataSource.dataSourceId` |
| `price.value` (string) | `price.amountMicros` (int64, ×1,000,000) |
| `price.currency` | `price.currencyCode` |

### Removed / No-Longer-Separate Endpoints

- `productstatuses.list` / `productstatuses.get` — status is now embedded in the `products` resource under `productStatus.*`
- `accounts.authinfo` — replaced by the accounts sub-API methods
- Batch-insert for products — must now insert one at a time via `productInputs:insert`, or use file data sources

### Authentication

No OAuth scope change. Still uses `https://www.googleapis.com/auth/content`.
Service account approach is the same.


## Gotchas

1. **v1beta is dead.** The gads CLI correctly uses `v1` paths (`/accounts/v1`, `/products/v1`, `/datasources/v1`). Any code referencing `v1beta` paths will 404 as of February 28, 2026.

2. **productInputs vs products confusion.** You cannot write to `products` (it's read-only processed output). All writes go to `productInputs:insert` or `productInputs:patch`. The CLI's `mc_list_product_statuses` correctly delegates to the `products` list endpoint since status is embedded there.

3. **shippingSettings:insert is destructive.** The `INSERT` (POST) method replaces the entire shipping config. Missing fields are nulled. Always GET → modify → INSERT with the etag. (Source: https://developers.google.com/merchant/api/guides/shipping-settings/overview)

4. **dataSource required for productInput writes.** Both `insert` and `patch` on `productInputs` require a `?dataSource=accounts/{account}/dataSources/{id}` query parameter. The data source must have `input=API` type.

5. **Price is in micros.** `price.amountMicros` is the price multiplied by 1,000,000. AED 99.00 = `99000000`.

6. **Product ID encoding.** For offer IDs containing `/`, `~`, or other special characters, the product resource name uses unpadded base64url of `contentLanguage~feedLabel~offerId`. The CLI must handle this when constructing GET paths for individual products.

7. **Processing lag.** Product inserts/patches/deletes take "several minutes" to reflect in the `products` read endpoint.

8. **API data source prerequisite.** Before using `productInputs:insert`, at least one data source with `input=API` must exist in the account.

9. **Issues list, not a single status object.** `accounts/{id}/issues` returns a paginated list of `AccountIssue` objects — not a single status field. The CLI fetches with `pageSize=50`.

10. **fileUploads only accepts `latest` alias.** To get the most recent upload status: `GET datasources/v1/.../fileUploads/latest`. There is no `list` method for file uploads.

11. **Reports date format.** In `reports:search` queries, dates must be quoted strings in `'YYYY-MM-DD'` format. The `BETWEEN` operator is inclusive on both ends. Do not use `TODAY` or relative keywords — use explicit dates computed in Python.

12. **updateMask is required for PATCH.** A `productInputs:patch` without `?updateMask=` will return 400. The mask must exactly list the dotted field paths to update.

13. **ETag on shippingSettings.** The `etag` field is a quoted string (includes the surrounding double-quotes in the value). Pass it verbatim in the `If-Match` header or in the body when calling insert: `"etag": "\"AbCdEfGhIjKlMnOp12345\""`.


## Coverage vs Current gads CLI

### Currently Used (gads_lib/merchant.py)

| Function | Endpoint | Status |
|----------|----------|--------|
| `mc_get_account` | `GET accounts/v1/accounts/{id}` | Correct v1 path |
| `mc_get_account_status` | `GET accounts/v1/accounts/{id}/issues` | Correct — issues list |
| `mc_list_products` | `GET products/v1/accounts/{id}/products` | Correct |
| `mc_list_product_statuses` | `GET products/v1/accounts/{id}/products` | Correct — delegates to products (status embedded) |
| `mc_list_datafeeds` | `GET datasources/v1/accounts/{id}/dataSources` | Correct v1 path |
| `mc_get_shipping` | `GET accounts/v1/accounts/{id}/shippingSettings` | Correct |
| `mc_get_return_policy` | `GET accounts/v1/accounts/{id}/onlineReturnPolicies` | Correct |
| `mc_reports_search` | `POST reports/v1/accounts/{id}/reports:search` | Correct — verified live 2026-09-04 (`gads merchant report`, `gads merchant report-product-performance`) |

### Gaps — Available But Not Implemented

| Capability | Sub-API | Endpoint |
|------------|---------|----------|
| Write products | products/v1 | `productInputs:insert`, `productInputs:patch`, `productInputs:delete` |
| Get single product | products/v1 | `GET .../products/{product}` |
| Create/update data source | datasources/v1 | `POST .../dataSources`, `PATCH .../dataSources/{id}` |
| Trigger file fetch | datasources/v1 | `POST .../dataSources/{id}:fetch` |
| Check file upload status | datasources/v1 | `GET .../dataSources/{id}/fileUploads/latest` |
| Local inventory | inventories/v1 | `localInventories` insert/list/delete |
| Regional inventory | inventories/v1 | `regionalInventories` insert/list/delete |
| Promotions | promotions/v1 | Full promotions sub-API |
| Users management | accounts/v1 | `accounts/{id}/users` |
| Regions management | accounts/v1 | `accounts/{id}/regions` |
| Homepage claim | accounts/v1 | `homepage:claim`, `homepage:unclaim` |
| Business identity | accounts/v1 | Business identity attributes |
| Quota monitoring | quota/v1 | `quotas` list |
| GCP registration lookup | accounts/v1 | `accounts.developerRegistration.getAccountForGcpRegistration` — new as of 2026 (unverified path, see "Recent Interface Changes"); complements the already-implemented `register-gcp` write |
| Regions batch ops | accounts/v1 | `regions:batchCreate`, `regions:batchUpdate`, `regions:batchDelete` — new alongside existing single-region CRUD (unverified detail, see "Recent Interface Changes") |

### Priority Gaps for Talas Use Case

1. ~~**Reports** (`reports/v1`)~~ — **implemented 2026-09-04**: `gads merchant report --query "..."` (escape hatch, any table) and `gads merchant report-product-performance` (canned `product_performance_view` query). `product_view` (disapproved products) is reachable via the escape hatch but has no dedicated canned command yet.
2. **Product writes** (`productInputs`) — needed to fix disapproved products programmatically.
3. **File upload status** — to monitor feed health after data source fetch.


## Sources

All claims in this document are sourced from the following URLs. Original fetch 2026-06-23; version/interface claims re-verified and extended 2026-07-01 (see "Recent Interface Changes" section near the top for what changed in this pass); Reports Sub-API implementation (path, request/response schema, and `product_performance_view` column list) verified live 2026-09-04 by fetching `https://merchantapi.googleapis.com/$discovery/rest?version=reports_v1` directly (raw JSON — bypasses the JS-rendered docs site) and cross-checked against a live `reports:search` call against the Talas account (see `gads merchant report -q "SELECT id, title, brand FROM product_view LIMIT 5"`, which returned real rows).

| Source | URL |
|--------|-----|
| Merchant API overview (version, v1beta shutdown) | https://developers.google.com/merchant/api/overview |
| Merchant API reference index (sub-APIs, versions) | https://developers.google.com/merchant/api/reference/rest |
| Content API sunset date (Aug 18, 2026) | https://developers.google.com/shopping-content/guides/quickstart |
| Accounts sub-API: shipping settings guide | https://developers.google.com/merchant/api/guides/shipping-settings/overview |
| Accounts sub-API: accounts overview | https://developers.google.com/merchant/api/guides/accounts/overview |
| Products sub-API: overview | https://developers.google.com/merchant/api/guides/products/overview |
| Data sources sub-API: overview | https://developers.google.com/merchant/api/guides/data-sources/overview |
| Discovery doc: accounts_v1 (auth, schemas, methods) | https://merchantapi.googleapis.com/$discovery/rest?version=accounts_v1 |
| Discovery doc: products_v1 (methods, product schema) | https://merchantapi.googleapis.com/$discovery/rest?version=products_v1 |
| Discovery doc: datasources_v1 (methods, DataSource schema) | https://merchantapi.googleapis.com/$discovery/rest?version=datasources_v1 |
| Discovery doc: inventories_v1 (methods, schemas) | https://merchantapi.googleapis.com/$discovery/rest?version=inventories_v1 |
| Discovery doc: reports_v1 (search method, report tables) — full schema (SearchRequest/SearchResponse/ReportRow/ProductPerformanceView field lists) re-fetched and parsed 2026-09-04 | https://merchantapi.googleapis.com/$discovery/rest?version=reports_v1 |
| Versioning guide (confirms no v2 exists; v1alpha 30-day notice policy) | https://developers.google.com/merchant/api/guides/versioning |
| Latest updates changelog (source of the 2026-07-01 "Recent Interface Changes" additions) | https://developers.google.com/merchant/api/latest-updates |
| Merchant API v1 GA date correction (Aug 18, 2025, not 2024) | https://support.google.com/merchants/answer/16493611?hl=en |
| `getAccountForGcpRegistration` method existence | https://developers.google.com/merchant/api/reference/rest/accounts_v1/accounts.developerRegistration/getAccountForGcpRegistration |

### Unverified Claims (doc fetch failed)

- Specific Content API v2.1 migration field-rename details (migration guide URL 404d) — field renames table above is based on discovery doc comparison and overview doc, not a dedicated migration guide.
- Exact `onlineReturnPolicies` object shape — full schema not fetched (404); shape above derived from accounts_v1 discovery doc summary.
- Exact `issues` response field names (specifically `impactedDestinations` nesting depth) — primary source is CLI source code docstring + accounts overview; dedicated issues reference page 404d.
- ~~Reports query field names in `product_view` and `product_performance_view`~~ — **RESOLVED 2026-09-04**: the full `reports_v1` discovery doc schema was fetched directly as raw JSON and parsed. `ProductPerformanceView` fields (camelCase, as returned in the JSON response body): `offerId`, `title`, `brand`, `clicks`, `impressions`, `clickThroughRate`, `conversions`, `conversionRate`, `conversionValue` (a nested `Price` object), `date`/`week` (nested `Date` objects), `customLabel0`-`4`, `productTypeL1`-`L5`, `categoryL1`-`L5`, `customerCountryCode`, `storeType` (enum `ONLINE_STORE`/`LOCAL_STORES`), `marketingMethod` (enum `ORGANIC`/`ADS`). The *query* itself uses snake_case (`offer_id`, `click_through_rate`, etc. — confirmed via the KB's own worked examples below, both of which were written from real request/response pairs). **No cost/spend field exists on this table** — Merchant Center reports carry no ad-spend data (spend lives only in Google Ads' `shopping_performance_view`, see `kb/google-ads.md`). `conversions`/`conversionValue`/`conversionRate` on this table are documented as "Available only for the `FREE` traffic source" — i.e. organic Shopping listings, never paid Shopping ads. `date` is a **required** WHERE-clause condition ("Condition on `date` is required in the `WHERE` clause" per the discovery doc description).
- Everything in the 2026-07-01 "Recent Interface Changes" table (near top of doc): the live `products_v1/ProductAttributes` schema page and the exact REST path for `getAccountForGcpRegistration` both failed to load as full schemas during this pass (returned nav-only content or 404) — those rows are sourced from Google's own release-notes/search summaries, not a fetched schema, and are flagged `(unverified)` individually.


---

## Developer Guide

> Sources: https://developers.google.com/merchant/api, https://developers.google.com/shopping-content, https://developers.google.com/merchant/api/reference/rest, https://developers.google.com/merchant/api/guides

---

### 1. Merchant API vs Legacy Content API — Key Differences and Migration

#### Why the new API exists

The Content API for Shopping (v2.1) was a monolithic API with a single base URL and tightly coupled resources. The Merchant API redesigns the surface into purpose-built sub-APIs, each independently versioned and deployable. This allows Google to iterate on (say) the Reports surface without impacting the Products surface.

#### Timeline

| Milestone | Date |
|-----------|------|
| Merchant API v1 GA | **August 18, 2025** (corrected — previously misstated as "2024" in this doc) |
| Merchant API v1beta discontinued | February 28, 2026 |
| Content API for Shopping v2.1 sunset | **August 18, 2026** |

Source: https://developers.google.com/merchant/api/overview, https://developers.google.com/shopping-content/guides/quickstart, https://support.google.com/merchants/answer/16493611?hl=en

#### Migration table — endpoint-by-endpoint

| Operation | Content API v2.1 | Merchant API v1 |
|-----------|-----------------|-----------------|
| Base URL | `https://shoppingcontent.googleapis.com/content/v2.1/{merchantId}/` | `https://merchantapi.googleapis.com/{sub-api}/v1/accounts/{merchantId}/` |
| List products | `GET /{merchantId}/products` | `GET products/v1/accounts/{merchantId}/products` |
| Insert product | `POST /{merchantId}/products` | `POST products/v1/accounts/{merchantId}/productInputs:insert?dataSource=...` |
| Patch product | `PATCH /{merchantId}/products/{id}` | `PATCH products/v1/accounts/{merchantId}/productInputs/{id}?dataSource=...&updateMask=...` |
| Delete product | `DELETE /{merchantId}/products/{id}` | `DELETE products/v1/accounts/{merchantId}/productInputs/{id}?dataSource=...` |
| Product status | `GET /{merchantId}/productstatuses/{id}` | Embedded in `products` resource under `productStatus.*` — no separate resource |
| List feeds | `GET /{merchantId}/datafeeds` | `GET datasources/v1/accounts/{merchantId}/dataSources` |
| Create feed | `POST /{merchantId}/datafeeds` | `POST datasources/v1/accounts/{merchantId}/dataSources` |
| Shipping settings | `GET /{merchantId}/shippingsettings/{merchantId}` | `GET accounts/v1/accounts/{merchantId}/shippingSettings` |
| Return policies | `GET /{merchantId}/returnpolicy` | `GET accounts/v1/accounts/{merchantId}/onlineReturnPolicies` |
| Account info | `GET /{merchantId}/accounts/{merchantId}` | `GET accounts/v1/accounts/{merchantId}` |
| Account issues | `GET /{merchantId}/accountstatuses/{merchantId}` | `GET accounts/v1/accounts/{merchantId}/issues` |
| Batch insert products | `POST /{merchantId}/products/batch` | No batch endpoint — use file data sources, or insert serially |
| Reports / performance | `GET /{merchantId}/reports/search` (Reports API) | `POST reports/v1/accounts/{merchantId}/reports:search` |

#### Field renames

| Content API v2.1 field | Merchant API v1 field | Notes |
|------------------------|----------------------|-------|
| `product.id` | `offerId` | The merchant-assigned SKU string |
| `product.offerId` | `offerId` | Unchanged name, now the primary identifier |
| `price.value` (string) | `price.amountMicros` (int64) | Multiply AED price by 1,000,000 |
| `price.currency` | `price.currencyCode` | ISO 4217 three-letter code |
| `datafeed.id` | `dataSource.dataSourceId` | int64 string |
| `datafeed.name` | `dataSource.displayName` | |
| `productStatus.productId` | (encoded in `name` path segment) | `products/{encodedId}` |
| `shippingSettings.services[].name` | `services[].serviceName` | |

#### What was removed or consolidated

- **`productstatuses` resource removed.** Product status is now folded into the `products` read resource under `productStatus.destinationStatuses` and `productStatus.itemLevelIssues`. There is no separate endpoint.
- **Batch product insert removed.** The Content API supported `POST /products/batch`. The Merchant API has no equivalent single-call batch. Use file data sources (PRIMARY feed type) for bulk uploads, or insert products individually via `productInputs:insert`.
- **`accounts.authinfo` removed.** Use `GET accounts/v1/accounts` or the account-level methods instead.
- **Sub-accounts via `accounts.list` still available** — see section 10 below.

#### Authentication — no change

The OAuth scope is identical between Content API v2.1 and Merchant API v1:

```
https://www.googleapis.com/auth/content
```

No token regeneration is required for the migration. The existing token from `generate_token.py` works on all Merchant API v1 endpoints.

Source: https://developers.google.com/merchant/api/overview#auth

---

### 2. Product Schema — Required and Optional Fields

The product schema lives on the `productAttributes` object within a `ProductInput`. The full schema reference is in the products_v1 discovery doc.

#### Required fields (without these, products will be disapproved)

| Field | Type | Constraint | Example |
|-------|------|-----------|---------|
| `offerId` | string | Stable SKU; unique per data source; max 50 chars | `"TeslaModel3RearBumper-Used-001"` |
| `contentLanguage` | string | ISO 639-1 two-letter code; immutable after first insert | `"en"` |
| `feedLabel` | string | Country/feed label; max 20 chars; immutable | `"AE"` |
| `productAttributes.title` | string | Max 150 chars; no ALL-CAPS; no promotional phrases | `"Tesla Model 3 Rear Bumper — Used OEM"` |
| `productAttributes.description` | string | Max 5000 chars | `"Original Tesla Model 3..."` |
| `productAttributes.link` | string | HTTPS; canonical product URL | `"https://shop.talas.ae/products/..."` |
| `productAttributes.imageLink` | string | HTTPS; JPEG/PNG/GIF/WEBP; min 100×100px recommended 800×800 | `"https://cdn.talas.ae/images/..."` |
| `productAttributes.availability` | string enum | See section 3 | `"in_stock"` |
| `productAttributes.condition` | string enum | See section 4 | `"used"` |
| `productAttributes.price` | object | `{amountMicros, currencyCode}` | `{"amountMicros":"450000000","currencyCode":"AED"}` |

#### Strongly recommended (disapproval risk or ranking loss without them)

| Field | Type | Notes |
|-------|------|-------|
| `productAttributes.brand` | string | Required for most clothing + electronics categories; strongly recommended everywhere |
| `productAttributes.gtin` or `productAttributes.gtins` | string / string[] | Required for products with assigned GTINs; omit only if none assigned |
| `productAttributes.mpn` | string | Manufacturer part number; critical for auto parts matching |
| `productAttributes.googleProductCategory` | string | Google taxonomy numeric ID or full string path |
| `productAttributes.itemGroupId` | string | Groups color/size variants; required for variant listings |
| `productAttributes.additionalImageLinks` | string[] | Up to 10 additional image URLs |

#### Optional fields (improve ranking, coverage, or targeting)

| Field | Type | Purpose |
|-------|------|---------|
| `productAttributes.productTypes` | string[] | Merchant's own taxonomy; up to 5 levels with ` > ` separator |
| `productAttributes.shipping` | ShippingObject[] | Per-product shipping overrides; if absent, account-level shipping rules apply |
| `productAttributes.shippingWeight` | object | Used for carrier-calculated rates |
| `productAttributes.shippingLength/Width/Height` | object | Dimensions for shipping rate calculation |
| `productAttributes.salePrice` | object | Sale price (must be lower than `price`) |
| `productAttributes.salePriceEffectiveDate` | string | ISO 8601 interval for sale price |
| `productAttributes.ageGroup` | string | `newborn`, `infant`, `toddler`, `kids`, `adult` |
| `productAttributes.gender` | string | `male`, `female`, `unisex` |
| `productAttributes.color` | string | Color description |
| `productAttributes.size` | string | Product size |
| `productAttributes.material` | string | Material description |
| `productAttributes.pattern` | string | Pattern description |
| `productAttributes.loyaltyPoints` | object | Loyalty program points |
| `productAttributes.productHighlights` | string[] | Up to 10 bullet-point highlights |
| `productAttributes.includedDestinations` | string[] | Restrict which surfaces this product appears on |
| `productAttributes.excludedDestinations` | string[] | Exclude specific surfaces |
| `customAttributes` | array | `[{"name":"key","value":"val"}]` — pass-through custom data |
| `versionNumber` | int64 | Freshness guard; reject insert if existing version is higher |

#### productType taxonomy

`productTypes` uses the merchant's own category hierarchy, not Google's taxonomy. Each string in the array represents one category path using ` > ` as the level separator:

```json
{
  "productTypes": [
    "Auto Parts > Body Parts > Bumpers",
    "Tesla Parts > Model 3 > Exterior"
  ]
}
```

Rules:
- Up to 5 strings per product
- Each path can have multiple levels separated by ` > `
- These appear as filters in Google Merchant Center reports
- Distinct from `googleProductCategory` which must use Google's taxonomy

`googleProductCategory` example values for auto parts:

| Category | Numeric ID |
|----------|------------|
| Vehicles & Parts > Vehicle Parts & Accessories | 5613 |
| Vehicles & Parts > Vehicle Parts & Accessories > Motor Vehicle Parts | 899 |
| Vehicles & Parts > Vehicle Parts & Accessories > Motor Vehicle Body Parts | 2768 |

Full taxonomy: https://www.google.com/basepages/producttype/taxonomy-with-ids.en-US.txt

---

### 3. Availability Values

The `productAttributes.availability` field accepts a controlled vocabulary. Values are lowercase strings.

| Value | Meaning | Shopping Ads impact |
|-------|---------|-------------------|
| `"in_stock"` | Product is available now | Eligible for all surfaces |
| `"out_of_stock"` | Product is not currently available | Can still appear but labeled; may reduce impression share |
| `"preorder"` | Not yet released; can be ordered in advance | Requires `availabilityDate` field |
| `"backorder"` | Temporarily out of stock; will ship when available | Should include expected availability date |

Additional notes:
- `availabilityDate` (optional ISO 8601 string) should accompany `preorder` and `backorder` values
- Mismatching availability (API says `in_stock`, landing page says sold out) is a policy violation and causes disapproval
- The read-only `productStatus` in the `products` resource returns these values in uppercase: `IN_STOCK`, `OUT_OF_STOCK`, etc.

Source: https://support.google.com/merchants/answer/6324448

---

### 4. Condition Values

The `productAttributes.condition` field accepts exactly three values:

| Value | Meaning | Notes for Talas |
|-------|---------|----------------|
| `"new"` | Brand new, never used, in original packaging | New aftermarket parts |
| `"refurbished"` | Professionally restored, may come with a warranty | Remanufactured parts |
| `"used"` | Previously used; may show wear | OEM used / pulled parts |

Rules:
- `condition` is **required** for all products
- For used auto parts, always use `"used"` — Google audits product condition vs. landing page content
- Do not use `"used"` for aftermarket new parts even if they are lower quality than OEM — that would be inaccurate
- The Talas PARTS ONLY rule: condition should reflect the actual physical state of the part, not the seller

Source: https://support.google.com/merchants/answer/6324350

---

### 5. Feed Management — Data Source Types, Fetch Schedules, File Formats

#### Data source types

A data source (`DataSource` object) tells Merchant Center where to get product data and how. The `type` of a data source is implied by which sub-object is present in the `DataSource` payload:

| Sub-object present | Type | Description |
|-------------------|------|-------------|
| `primaryProductDataSource` | PRIMARY | Main product feed; one per language/country combo |
| `supplementalProductDataSource` | SUPPLEMENTAL | Overrides/supplements the primary feed; linked by `offerId` match |
| `localInventoryDataSource` | LOCAL_INVENTORY | In-store availability for local listings |
| `regionalInventoryDataSource` | REGIONAL_INVENTORY | Region-level price/availability overrides |
| `promotionDataSource` | PROMOTION | Promotions feed |
| `productReviewDataSource` | PRODUCT_REVIEW | User-submitted product reviews |
| `merchantReviewDataSource` | MERCHANT_REVIEW | User-submitted merchant reviews |

The `input` field (read-only) reflects how the data source receives updates:

| `input` value | Meaning |
|---------------|---------|
| `API` | Products submitted via `productInputs:insert` / `productInputs:patch` |
| `FILE` | Products in a file (TSV, XML, or Google Sheets) fetched or uploaded |
| `UI` | Products added manually in Merchant Center UI |
| `AUTOFEED` | Google auto-detects products from the website |

#### Fetch schedule

For `FILE` data sources with `fileInputType = FETCH`, configure `fetchSettings`:

```json
{
  "fetchSettings": {
    "frequency": "DAILY",
    "fetchUri": "https://shop.talas.ae/feeds/google-shopping.xml",
    "enabled": true,
    "timeOfDay": {
      "hours": 2,
      "minutes": 0,
      "seconds": 0,
      "nanos": 0
    },
    "timeZone": "Asia/Dubai",
    "username": "",
    "password": ""
  }
}
```

`frequency` options:

| Value | Description |
|-------|-------------|
| `DAILY` | Fetches once per day at `timeOfDay` |
| `WEEKLY` | Fetches once per week; requires `dayOfWeek` field |
| `MONTHLY` | Fetches once per month; requires `dayOfMonth` field (1-31) |

To trigger an immediate fetch outside the schedule:
```http
POST datasources/v1/accounts/{merchantId}/dataSources/{dataSourceId}:fetch
```
(No request body required.)

#### File format requirements

**TSV (Tab-Separated Values):**
- First row must be column headers matching Google's attribute names (e.g. `id`, `title`, `description`, `link`, `image link`, `condition`, `availability`, `price`, `brand`, `gtin`, `mpn`)
- UTF-8 encoding
- One product per row
- Price format: `450.00 AED` (value + space + ISO currency)
- No quoted strings required unless field contains tab characters

**XML:**
- Uses RSS 2.0 format with Google namespace
- Root element: `<rss version="2.0" xmlns:g="http://base.google.com/ns/1.0">`
- Each product in a `<item>` element
- Price element: `<g:price>450.00 AED</g:price>`

**Google Sheets:**
- Create a sheet with headers in row 1 matching TSV column names
- Share the sheet with `content-api@system.gserviceaccount.com` (view access)
- `fileInputType` will be `GOOGLE_SHEETS`; set `fetchUri` to the sheet's published CSV URL

Source: https://support.google.com/merchants/answer/160567 (feed specification)

---

### 6. Shipping Setup

Shipping is configured via `accounts/{merchantId}/shippingSettings`. The full config is a single object with `services[]` and `warehouses[]`.

#### Service configuration components

**DeliveryTime:**
```json
{
  "deliveryTime": {
    "minHandlingDays": 0,
    "maxHandlingDays": 1,
    "minTransitDays": 2,
    "maxTransitDays": 5,
    "cutoffTime": {
      "hour": 14,
      "minute": 0,
      "timezone": "Asia/Dubai"
    }
  }
}
```

- `handlingDays` = time to pack and hand to carrier
- `transitDays` = carrier transit time
- `cutoffTime` = orders placed after this time start handling the next business day

**Transit time labels** — assign named transit time windows to carrier services:
```json
{
  "transitTimeTable": {
    "postalCodeGroupNames": ["UAE_NORTH", "UAE_SOUTH"],
    "transitTimeLabels": ["STANDARD", "EXPRESS"],
    "rows": [
      {"values": [{"minTransitDays": 2, "maxTransitDays": 3}, {"minTransitDays": 1, "maxTransitDays": 1}]},
      {"values": [{"minTransitDays": 3, "maxTransitDays": 5}, {"minTransitDays": 2, "maxTransitDays": 2}]}
    ]
  }
}
```

#### Rate structures

**Flat rate (simplest):**
```json
{
  "rateGroups": [
    {
      "singleValue": {
        "flatRate": {
          "amountMicros": "0",
          "currencyCode": "AED"
        }
      },
      "name": "Free Shipping AE"
    }
  ]
}
```

**CarrierRate (carrier-calculated):**
```json
{
  "carrierRates": [
    {
      "name": "Aramex Standard",
      "carrierName": "Aramex",
      "carrierService": "Standard",
      "originPostalCode": "00000",
      "percentageAdjustment": "0",
      "flatAdjustment": {"amountMicros": "0", "currencyCode": "AED"}
    }
  ]
}
```

**RateGroup with Table (matrix of conditions):**
```json
{
  "rateGroups": [
    {
      "mainTable": {
        "rowHeaders": {
          "prices": [
            {"amountMicros": "100000000", "currencyCode": "AED"},
            {"amountMicros": "500000000", "currencyCode": "AED"}
          ]
        },
        "columnHeaders": {"locations": [{"locationIds": ["21022"]}]},
        "rows": [
          {"cells": [{"flatRate": {"amountMicros": "25000000", "currencyCode": "AED"}}]},
          {"cells": [{"flatRate": {"amountMicros": "0", "currencyCode": "AED"}}]}
        ]
      },
      "name": "Tiered by order value"
    }
  ]
}
```

Tables support rows keyed by: `prices` (order value breakpoints), `weights`, `number_of_items`, `location` (country/region/postal), or `time_zone`.

**Important:** `shippingSettings:insert` is a full replace. Always GET the current config, modify in memory, then POST the full object including the `etag`.

Source: https://developers.google.com/merchant/api/guides/shipping-settings/overview

---

### 7. Product Status

Product status is embedded in the `products` read resource under `productStatus`. It is computed asynchronously — inserts/patches take minutes to reflect.

#### destinationStatuses

```json
{
  "destinationStatuses": [
    {
      "destination": "Shopping ads",
      "approvedCountries": ["AE"],
      "pendingCountries": [],
      "disapprovedCountries": []
    },
    {
      "destination": "Free listings",
      "approvedCountries": [],
      "pendingCountries": ["AE"],
      "disapprovedCountries": []
    }
  ]
}
```

**Destinations:**

| Destination string | Surface |
|-------------------|---------|
| `"Shopping ads"` | Paid Shopping ads |
| `"Free listings"` | Organic Shopping / Google Search free listings |
| `"Buy on Google listings"` | Buy on Google (US only) |
| `"Display ads"` | Google Display Network |

#### itemLevelIssues — severity

| Severity | Meaning | Impact |
|----------|---------|--------|
| `"ERROR"` | Hard disapproval — product cannot serve on this destination | Blocked |
| `"SUGGESTION"` | Soft warning — product is approved but ranked lower | Eligible Limited |

`resolution` values:

| Value | Meaning |
|-------|---------|
| `"merchant_action"` | You must fix this (missing attribute, policy violation) |
| `"pending_processing"` | Google is still processing; check back later |

#### aggregatedDestinationStatus (in reports `product_view`)

| Value | Meaning |
|-------|---------|
| `NOT_ELIGIBLE_OR_DISAPPROVED` | Blocked from all surfaces |
| `NOT_ELIGIBLE` | Not eligible; no active disapproval |
| `ELIGIBLE_LIMITED` | Approved with restrictions (e.g. missing GTIN) |
| `ELIGIBLE` | Fully approved |

---

### 8. productInputs Write Path

All product writes go through the `productInputs` sub-resource, not the `products` resource (which is read-only).

#### Resource name format

```
accounts/{merchantId}/productInputs/{encodedId}
```

Where `{encodedId}` is the unpadded base64url of `contentLanguage~feedLabel~offerId`:

```python
import base64

def encode_product_id(content_language: str, feed_label: str, offer_id: str) -> str:
    raw = f"{content_language}~{feed_label}~{offer_id}"
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()

# Example:
# encode_product_id("en", "AE", "TeslaModel3RearBumper") -> "ZW4tQUUtVGVzbGFNb2RlbDNSZWFyQnVtcGVy"
```

Note: The tilde `~` character is used as the separator, not a hyphen.

#### insert (POST)

```
POST products/v1/accounts/{merchantId}/productInputs:insert?dataSource=accounts/{merchantId}/dataSources/{dataSourceId}
```

- Idempotent on `(contentLanguage, feedLabel, offerId, dataSource)` tuple
- Full replace of the product — unset fields are cleared
- Requires an API-type data source (`input=API`)
- `dataSource` query param must be the full resource name

#### patch (PATCH)

```
PATCH products/v1/accounts/{merchantId}/productInputs/{encodedId}?dataSource=accounts/{merchantId}/dataSources/{dataSourceId}&updateMask=field1,field2
```

- Partial update — only fields listed in `updateMask` are modified
- `updateMask` uses dotted field paths: `productAttributes.price`, `productAttributes.availability`
- Fields not in the mask are untouched even if present in the body
- Fields in the mask but absent from body are set to null

Example update mask values:

| Intent | updateMask value |
|--------|-----------------|
| Update price only | `productAttributes.price` |
| Update availability + price | `productAttributes.price,productAttributes.availability` |
| Update title and description | `productAttributes.title,productAttributes.description` |
| Update all attributes | `productAttributes` (replaces entire attributes object) |

#### delete (DELETE)

```
DELETE products/v1/accounts/{merchantId}/productInputs/{encodedId}?dataSource=accounts/{merchantId}/dataSources/{dataSourceId}
```

Returns `{}` (empty object). Deletion takes several minutes to propagate.

#### Processing lag

After any write operation, the processed `products` resource is **not immediately updated**. Allow 5-15 minutes for the change to reflect in `GET products/...`. The `versionNumber` field can be used to confirm which version of the product is currently processed.

---

### 9. Reports Sub-API

The Reports sub-API uses a SQL-like query language called Merchant Query Language (MQL), analogous to GAQL in the Google Ads API.

#### Endpoint

```
POST reports/v1/accounts/{merchantId}/reports:search
Body: {"query": "SELECT ... FROM ... WHERE ... ORDER BY ... LIMIT ...", "pageSize": 1000}
```

#### Available report tables

| Table | Primary use | Key dimensions | Key metrics |
|-------|------------|----------------|-------------|
| `product_view` | Inventory health, approvals, issues | `id`, `title`, `brand`, `feed_label`, `channel` | `aggregated_destination_status`, `item_issues` |
| `product_performance_view` | Click/impression performance | `offer_id`, `title`, `brand`, `feed_label`, `date` | `clicks`, `impressions`, `click_through_rate`, `conversions`, `conversion_value` |
| `price_competitiveness_product_view` | Price benchmarking | `offer_id`, `title`, `brand`, `country_of_sale` | `benchmark_price`, `price_difference_micros`, `price_difference_percent` |
| `price_insights_product_view` | AI-driven price recommendations | `offer_id`, `title`, `brand` | `suggested_price`, `predicted_impressions_change_fraction`, `predicted_clicks_change_fraction` |
| `best_sellers_brand_view` | Popular brands by category | `category_id`, `category_path`, `country_code`, `rank_type` | `rank`, `previous_rank` |
| `best_sellers_product_cluster_view` | Popular product clusters | `title`, `category_id`, `country_code` | `rank`, `inventory_status`, `brand_inventory_status` |
| `competitive_visibility_top_merchant_view` | Top competitor domains | `domain`, `category_id`, `country_code`, `date` | `ads_organic_ratio`, `page_overlap_rate`, `higher_listing_rate` |
| `competitive_visibility_benchmark_view` | Category-level benchmarks | `category_id`, `country_code`, `date` | `traffic_source`, `your_domain_visibility_trend`, `category_benchmark_visibility_trend` |
| `non_product_performance_view` | Image and link performance | `date`, `week`, `month` | `image_clicks`, `link_clicks` |

#### Query syntax details

```sql
-- Date filtering (use explicit dates, not TODAY keyword)
SELECT offer_id, clicks, impressions
FROM product_performance_view
WHERE date BETWEEN '2026-05-01' AND '2026-06-22'
  AND feed_label = 'AE'
ORDER BY clicks DESC
LIMIT 50

-- Filter by issue severity
SELECT id, title, item_issues
FROM product_view
WHERE channel = 'ONLINE'
  AND aggregated_destination_status != 'ELIGIBLE'
LIMIT 200

-- Price competitiveness
SELECT offer_id, title, benchmark_price, price_difference_percent
FROM price_competitiveness_product_view
WHERE country_of_sale = 'AE'
ORDER BY price_difference_percent DESC
LIMIT 100
```

Supported operators: `=`, `!=`, `<`, `>`, `<=`, `>=`, `IN (...)`, `NOT IN (...)`, `LIKE`, `IS NULL`, `IS NOT NULL`, `AND`, `OR`, `BETWEEN`

**Date notes:**
- Dates must be quoted `'YYYY-MM-DD'` strings
- Do NOT use `TODAY`, `YESTERDAY`, or relative date keywords — they are not supported in MQL
- Always compute dates explicitly in Python using `datetime.date.today() - timedelta(days=N)`
- `BETWEEN` is inclusive on both ends
- Maximum date range varies by table; `product_performance_view` supports up to 90 days

#### Pagination

Reports use the same cursor pattern as other sub-APIs:

```python
def query_all(merchant_id, query, headers):
    url = f"https://merchantapi.googleapis.com/reports/v1/accounts/{merchant_id}/reports:search"
    results = []
    page_token = None
    while True:
        body = {"query": query, "pageSize": 1000}
        if page_token:
            body["pageToken"] = page_token
        resp = requests.post(url, json=body, headers=headers).json()
        results.extend(resp.get("results", []))
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return results
```

Source: https://developers.google.com/merchant/api/reference/rest/v1/accounts.reports/search

---

### 10. Account Management — Sub-accounts and MCA Structure

#### Multi-Client Account (MCA)

An MCA (also called a "manager account" or "aggregator account") is a top-level Merchant Center account that can manage multiple sub-accounts. This mirrors the Google Ads Manager Account (MCC) structure.

**Account hierarchy:**

```
MCA (manager account)
├── Sub-account A (independent merchant)
├── Sub-account B (independent merchant)
└── Sub-account C (independent merchant)
```

Each sub-account is a full Merchant Center account with its own products, feeds, and shipping settings. The MCA provides a single login and API access point.

#### Listing sub-accounts

```http
GET https://merchantapi.googleapis.com/accounts/v1/accounts?parent=accounts/{mcaAccountId}
Authorization: Bearer {token}
```

Response:
```json
{
  "accounts": [
    {
      "name": "accounts/355285634",
      "accountId": "355285634",
      "accountName": "Talas Auto Parts",
      "timeZone": {"id": "Asia/Dubai"},
      "languageCode": "en"
    }
  ],
  "nextPageToken": null
}
```

#### Creating a sub-account

```http
POST https://merchantapi.googleapis.com/accounts/v1/accounts
Authorization: Bearer {token}
Content-Type: application/json

{
  "accountName": "New Sub-Account",
  "timeZone": {"id": "Asia/Dubai"},
  "languageCode": "en"
}
```

The new account is automatically linked to the MCA that owns the calling credentials.

#### Account labels

Account labels allow grouping of sub-accounts (e.g. by business unit or region). Labels are managed via the `accounts.labels` resource (alpha as of mid-2026):

```http
GET https://merchantapi.googleapis.com/accounts/v1/accounts/{mcaAccountId}/labels
```

Labels can then be assigned to sub-accounts for filtering in reports and the UI.

#### User management within an account

```http
# List users
GET accounts/v1/accounts/{merchantId}/users

# Add user (sends invitation email)
POST accounts/v1/accounts/{merchantId}/users
Body: {
  "name": "accounts/{merchantId}/users/user@example.com",
  "accessRights": ["ADMIN"]
}

# Remove user
DELETE accounts/v1/accounts/{merchantId}/users/{email}
```

`accessRights` enum values: `ADMIN`, `PERFORMANCE_REPORTING`, `STANDARD`

Source: https://developers.google.com/merchant/api/guides/accounts/overview

---

### 11. Error Patterns

All Merchant API errors use the standard Google API error envelope:

```json
{
  "error": {
    "code": 400,
    "message": "Human-readable description",
    "status": "STATUS_STRING",
    "details": [...]
  }
}
```

#### Common errors and fixes

| Error code | `status` | Typical cause | Fix |
|-----------|---------|--------------|-----|
| 400 | `INVALID_ARGUMENT` | Missing required field, wrong enum value, malformed resource name | Check field names and enum values against schema |
| 400 | `INVALID_ARGUMENT` | Missing `?dataSource=` query param on `productInputs` calls | Add `dataSource=accounts/{id}/dataSources/{id}` to query string |
| 400 | `INVALID_ARGUMENT` | Missing `?updateMask=` on PATCH | Add `updateMask=field1,field2` to query string |
| 401 | `UNAUTHENTICATED` | Token expired | Refresh token via `gads refresh` or re-run `generate_token.py` |
| 403 | `PERMISSION_DENIED` | Wrong OAuth scope | Ensure token includes `https://www.googleapis.com/auth/content` |
| 403 | `PERMISSION_DENIED` | `ACCESS_TOKEN_SCOPE_INSUFFICIENT` | Re-generate token to pick up new scopes |
| 403 | `SERVICE_DISABLED` | `merchantapi.googleapis.com` not enabled on GCP project | Enable API in Cloud Console → APIs & Services |
| 404 | `NOT_FOUND` | Wrong account ID, resource doesn't exist, or no access | Verify numeric account ID; check access in MC UI |
| 409 | `ABORTED` | ETag conflict on `shippingSettings:insert` | Re-GET shipping settings for fresh etag, then retry |
| 429 | `RESOURCE_EXHAUSTED` | Quota exceeded | Exponential backoff; check `quota/v1` endpoint |
| 500 | `INTERNAL` | Google-side transient error | Retry with exponential backoff (start at 1s) |

#### `MISSING_REQUIRED_FIELD` pattern

```json
{
  "error": {
    "code": 400,
    "message": "Missing required field: productAttributes.title",
    "status": "INVALID_ARGUMENT",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.BadRequest",
        "fieldViolations": [
          {
            "field": "productAttributes.title",
            "description": "Missing required field"
          }
        ]
      }
    ]
  }
}
```

The `details[].fieldViolations[].field` path tells you exactly which field is missing.

#### `INVALID_VALUE` pattern

```json
{
  "error": {
    "code": 400,
    "message": "Invalid value for field 'productAttributes.availability': 'instock'. Must be one of: in_stock, out_of_stock, preorder, backorder",
    "status": "INVALID_ARGUMENT"
  }
}
```

Common `INVALID_VALUE` triggers:
- `availability` = `"instock"` instead of `"in_stock"`
- `condition` = `"Used"` (capitalized) instead of `"used"`
- `price.amountMicros` sent as integer instead of int64 string

#### Retry strategy

```python
import time
import requests

def api_call_with_retry(url, method="GET", headers=None, json=None, max_retries=4):
    delay = 1.0
    for attempt in range(max_retries):
        if method == "GET":
            resp = requests.get(url, headers=headers)
        elif method == "POST":
            resp = requests.post(url, headers=headers, json=json)
        else:
            raise ValueError(f"Unsupported method: {method}")

        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt < max_retries - 1:
                time.sleep(delay)
                delay *= 2  # exponential backoff
                continue
        return resp
    return resp  # return last response after exhausting retries
```

---

### 12. Rate Limits and Quotas

The Merchant API uses the **Quota sub-API** (`quota/v1`) for programmatic quota monitoring.

#### Inspect current quotas

```http
GET https://merchantapi.googleapis.com/quota/v1/accounts/{merchantId}/quotas
Authorization: Bearer {token}
```

Response lists each method group with its limit and current usage:

```json
{
  "quotaGroups": [
    {
      "name": "products.list",
      "quotaUsage": 45,
      "quotaLimit": 500,
      "quotaMinuteLimit": 60,
      "methodDetails": [
        {
          "method": "GET",
          "subApi": "products",
          "path": "accounts/{account}/products"
        }
      ]
    }
  ]
}
```

#### General quota guidance

| Operation type | Typical limit (account-dependent) | Notes |
|---------------|----------------------------------|-------|
| Read operations (list, get) | 500–1000 QPD per method | Higher for MCA accounts |
| Write operations (insert, patch, delete) | 100–500 QPD per method | Lower limits; batch via file feeds for bulk |
| Reports search | 200 QPD | Paginate large result sets |
| Shipping settings insert | 100 QPD | Full-replace; use sparingly |
| Trigger file fetch | 10 QPD | Manual trigger only; rely on scheduled fetch |

**QPD** = Queries Per Day. The Merchant API does not publish a fixed QPS limit — it enforces daily quotas rather than per-second burst limits for most operations.

#### Quota exceeded response (429)

```json
{
  "error": {
    "code": 429,
    "message": "Quota exceeded for quota metric 'merchantapi.googleapis.com/default'",
    "status": "RESOURCE_EXHAUSTED"
  }
}
```

Recovery: wait until the next quota window (resets at midnight Pacific time), or use exponential backoff for transient spikes.

Source: https://developers.google.com/merchant/api/reference/rest (quota section)

---

### 13. Inventories API

The Inventories sub-API (`inventories/v1`) manages per-store and per-region overrides for products that already exist in the primary feed.

#### Local inventory

Local inventory assigns in-store availability and pricing to a specific store code for a specific product. Used for Local Inventory Ads.

**Insert local inventory:**

```http
POST https://merchantapi.googleapis.com/inventories/v1/accounts/{merchantId}/products/{encodedProductId}/localInventories:insert
Authorization: Bearer {token}
Content-Type: application/json

{
  "storeCode": "QZ3",
  "price": {
    "amountMicros": "450000000",
    "currencyCode": "AED"
  },
  "availability": "in_stock",
  "quantity": 2,
  "pickupMethod": "ship to store",
  "pickupSla": "same day"
}
```

`storeCode` must match a verified store in Google Business Profile linked to your Merchant Center account.

**List local inventories for a product:**

```http
GET inventories/v1/accounts/{merchantId}/products/{encodedProductId}/localInventories?pageSize=25000
```

**Delete local inventory for one store:**

```http
DELETE inventories/v1/accounts/{merchantId}/products/{encodedProductId}/localInventories/{storeCode}
```

#### Regional inventory

Regional inventory overrides price and availability for a geographic region (defined in `accounts/{id}/regions`).

**Insert regional inventory:**

```http
POST https://merchantapi.googleapis.com/inventories/v1/accounts/{merchantId}/products/{encodedProductId}/regionalInventories:insert
Authorization: Bearer {token}
Content-Type: application/json

{
  "region": "accounts/{merchantId}/regions/{regionId}",
  "price": {
    "amountMicros": "420000000",
    "currencyCode": "AED"
  },
  "availability": "in_stock"
}
```

**Delete regional inventory:**

```http
DELETE inventories/v1/accounts/{merchantId}/products/{encodedProductId}/regionalInventories/{regionId}
```

#### Update patterns

- **No patch for inventories** — use insert (it is upsert behavior: inserts or fully replaces)
- **pageSize max:** 25,000 for local inventories; 100,000 for regional inventories
- **Product must exist** in the primary data source before inventory can be set — the `encodedProductId` must resolve to an active product
- **Processing lag:** ~15 minutes for inventory changes to reflect in Shopping ads

Source: https://developers.google.com/merchant/api/reference/rest/inventories_v1/accounts.products.localInventories

---

### 14. Best Practices

#### Batch updates via file data sources (not API inserts)

For catalogs with more than ~100 products, prefer file-based feeds over individual `productInputs:insert` calls:

- File feeds (TSV/XML) process all products in a single scheduled fetch
- API inserts count against write quotas (100-500 QPD)
- File feeds support up to 1,000,000 products per feed
- API data sources (`input=API`) are best for real-time single-product updates (e.g. price change on one SKU)

Decision matrix:

| Scenario | Preferred approach |
|----------|-------------------|
| Initial catalog upload (1,000+ products) | FILE data source (TSV/XML) |
| Daily full catalog sync | FILE data source with DAILY fetch |
| Real-time price/availability update (1-50 products) | `productInputs:patch` via API data source |
| Removing a discontinued product | `productInputs:delete` via API data source |
| Override price in one region | Regional inventory via `regionalInventories:insert` |
| In-store availability | Local inventory via `localInventories:insert` |

#### Incremental updates

When patching products, always use `updateMask` to specify only changed fields. This:
1. Reduces the chance of accidentally nulling required fields
2. Makes the write idempotent and auditable
3. Uses less quota than a full insert

```python
# Good: targeted patch
payload = {"productAttributes": {"price": {"amountMicros": "420000000", "currencyCode": "AED"}}}
params = {"dataSource": datasource_name, "updateMask": "productAttributes.price"}

# Avoid: full insert when only price changed (overwrites all other fields)
```

#### Content language and target country combinations

Each data source is tied to a specific `(contentLanguage, feedLabel)` pair. These are **immutable** after creation — you cannot change them on an existing data source.

For Talas, the UAE market uses:

| contentLanguage | feedLabel | Target country | Notes |
|----------------|-----------|---------------|-------|
| `en` | `AE` | UAE | Primary feed in English |

If you need to serve in Arabic, create a **separate data source** with `contentLanguage=ar`:

| contentLanguage | feedLabel | Notes |
|----------------|-----------|-------|
| `ar` | `AE` | Arabic-language product titles and descriptions |

The two data sources with the same `feedLabel` and same `offerId` values will be merged by Google into a single product, with the correct language served based on user locale.

**Common mistake:** Mixing languages within a single data source (e.g. Arabic titles in an `en` feed). Google will flag this as a language mismatch.

#### Pre-mutation checklist

Before any write operation on products or shipping settings:

1. **Snapshot** current state: `./gads snapshot pre-{change-name} --save-file`
2. **Verify** the data source ID is an API-type source (`input=API`)
3. **Build** the product ID correctly using base64url encoding
4. **Test** with a single product before bulk updates
5. **Log** the change via `./gads log` after confirming success
6. **Monitor** disapproval rate for 24 hours after a bulk update

#### Handling missing identifier fields (identifier_exists)

For products without GTINs, MPNs, or brands (uncommon for auto parts), set:

```json
{
  "productAttributes": {
    "identifierExists": false
  }
}
```

This tells Google the product genuinely has no standard identifier, avoiding a `missing_gtin` disapproval. However, for auto parts (which almost always have MPNs), you should provide the MPN even if you don't have the GTIN:

```json
{
  "productAttributes": {
    "mpn": "1084665-00-E",
    "brand": "Tesla",
    "gtins": []
  }
}
```

This combination (brand + mpn, no gtin) is sufficient for auto parts categories and avoids the identifier-related demotion.

Source: https://support.google.com/merchants/answer/160161

---

## Developer Registration API

### Overview

Some Merchant Center API errors (`auth/gcp_unknown`, `GCP_NOT_REGISTERED`, HTTP 401) indicate the GCP OAuth project has not been registered as an authorised developer for the MC account. The **Developer Registration API** fixes this without any console steps.

### Endpoint

```
POST https://merchantapi.googleapis.com/accounts/v1/accounts/{account}/developerRegistration:registerGcp
```

**OAuth scope:** `https://www.googleapis.com/auth/content` (same scope as all other Merchant API calls — no extra scope needed)

**Request body:**
```json
{"developerEmail": "developer@example.com"}
```

**Success response:** Empty object `{}` (HTTP 200).

**Effect:** Associates the GCP project that generated the OAuth token with the MC account. The association propagates in ~5 minutes.

### CLI command

```bash
gads merchant register-gcp --developer-email admin@talas.ae
gads merchant register-gcp -e admin@talas.ae --account 12345678 --json
```

Defaults: `--account` defaults to `GOOGLE_MERCHANT_CENTER_ID` from config.

### When to use

- `gads merchant account` returns HTTP 401 with `GCP_NOT_REGISTERED` in the message
- `gads merchant status` returns `auth/gcp_unknown` error
- The GCP project is newly registered or the OAuth client was recently created

### Notes

- One-time setup per GCP project + MC account pair
- After registration, wait ~5 minutes before retrying merchant commands
- The `--developer-email` should be the GCP project owner or developer email (the email associated with the GCP project, not necessarily the MC account owner)

### Related (not yet implemented): checking existing registration

A newer read-side method, `accounts.developerRegistration.getAccountForGcpRegistration`, can answer "which Merchant Center account is this GCP project already registered to?" — useful before blindly calling `register-gcp` again. It exists (confirmed via the reference doc URL below) but this KB could not load its full schema to confirm the exact REST path/params, so it is not yet wired into `gads merchant register-gcp`. Treat as a gap for a future `gads merchant gcp-registration-status`-style subcommand.

Source: https://developers.google.com/merchant/api/reference/rest/accounts_v1/accounts.developerRegistration/getAccountForGcpRegistration (unverified path detail — see "Recent Interface Changes" near the top of this doc)
