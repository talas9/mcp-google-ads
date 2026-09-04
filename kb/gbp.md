# Google Business Profile APIs

## Status & Versions

The Google Business Profile (GBP) API suite was restructured in late 2021/early 2022 from a monolithic
"Google My Business API v4.9" into multiple purpose-specific APIs, each with its own hostname and versioning.

| API | Current Version | Status | Notes |
|---|---|---|---|
| My Business Account Management API | **v1.1** (bumped from v1; REST path is still `/v1/`) | Active | Replaced v4 account management. v1.1 added `locations.admins` (location-level admin management), `placeId` on pending invitations, and renamed `toAccount`→`destinationAccount` on `locations.transfer`. Source: https://developers.google.com/my-business/content/accountmanagement/change-log |
| My Business Business Information API | v1 | Active | Replaced v4 location data. No `v1.1`+ change-log entries as of July 2026 — unchanged since original migration. |
| Business Profile Performance API | v1 | Active | Replaced deprecated v4 Insights endpoints. No new change-log entries as of July 2026. |
| Google My Business API (legacy) | v4 | Partially active | Reviews + Posts still here; most other resources sunset |
| Business Calls API (`mybusinessbusinesscalls.googleapis.com`) | v1 | **Deprecated** (whole resource tree, incl. `businesscallsinsights`) | Confirmed still deprecated as of July 2026 — do not implement |
| My Business Verifications API (`mybusinessverifications.googleapis.com`) | v1 | Active (out of current scope for Talas) | Holds `getVoiceOfMerchantState`/suspension fields that used to live in Business Information's `LocationState` (now folded into `metadata` + this API). Not implemented in gads-cli; noted for completeness. |

**Legacy v4 sunset history** (source: https://developers.google.com/my-business/content/sunset-dates):
- `accounts.locations.reportInsights` — discontinued March 30, 2023
- `accounts.locations.localPosts.reportInsights` — discontinued February 20, 2023
- `accounts.locations.getHealthProviderAttributes` / `updateHealthProviderAttributes` / `insuranceNetworks` — discontinued July 1, 2024
- `mybusinessbusinesscalls.googleapis.com` (My Business Business Calls API) — discontinued May 30, 2023; re-verified still fully deprecated (every method in the nav tree, including `businesscallsinsights.list`) as of July 2026
- `accounts.locations.admins` (legacy v4 location-admin management) — now marked **Deprecated** in the official nav; superseded by `locations.admins` on the v1.1 Account Management API (see below)
- **Reviews endpoints** (`list`, `get`, `updateReply`, `deleteReply`) — **NOT sunset, still active as of July 2026**

The reviews and local posts endpoints remain on `mybusiness.googleapis.com/v4` with no announced sunset date
as of July 2026. Google has indicated these will migrate to v1 "eventually" but has not committed to a timeline.
The `batchGetReviews` v4 method (see Coverage gaps below) is marked **"new"** in Google's own nav, not deprecated —
still a safe implementation target.

---

## Base URLs

| API | Base URL |
|---|---|
| Account Management | `https://mybusinessaccountmanagement.googleapis.com` |
| Business Information | `https://mybusinessbusinessinformation.googleapis.com` |
| Business Profile Performance | `https://businessprofileperformance.googleapis.com` |
| Legacy (Reviews, Posts) | `https://mybusiness.googleapis.com` |

---

## Auth / OAuth Scopes

All GBP APIs use OAuth 2.0. The primary scope covers all APIs:

| Scope | Coverage |
|---|---|
| `https://www.googleapis.com/auth/business.manage` | All current GBP APIs (Account Mgmt, Business Info, Performance) |
| `https://www.googleapis.com/auth/plus.business.manage` | Legacy v4 only (reviews endpoints also accept this scope) |

**Recommendation:** Use `business.manage` — it is accepted by all endpoints including v4 reviews.
The `plus.business.manage` scope is legacy and maps to v4 only.

Sources:
- https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/updateReply

---

## APIs Overview

| API | Host | Version | Status | Purpose |
|---|---|---|---|---|
| My Business Account Management API | `mybusinessaccountmanagement.googleapis.com` | v1.1 (docs revision; path still `/v1/`) | Active | Manage accounts, account-level + location-level admins, invitations, location transfer |
| My Business Business Information API | `mybusinessbusinessinformation.googleapis.com` | v1 | Active | CRUD on locations, attributes, categories |
| Business Profile Performance API | `businessprofileperformance.googleapis.com` | v1 | Active | Daily metric time series, search keyword impressions |
| Google My Business API (legacy) | `mybusiness.googleapis.com` | v4 | Partially active | Reviews, local posts (no v1 replacements yet) |

---

## Resources & Endpoints

| API | Resource | Method | HTTP | Path | Purpose | Source URL |
|---|---|---|---|---|---|---|
| Account Mgmt | accounts | list | GET | `/v1/accounts` | List all accounts accessible to authenticated user | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts/list |
| Account Mgmt | accounts | get | GET | `/v1/{name=accounts/*}` | Get a single account | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts | create | POST | `/v1/accounts` | Create a new account | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts | patch | PATCH | `/v1/{account.name=accounts/*}` | Update account | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts.admins | list | GET | `/v1/{parent=accounts/*}/admins` | List admins for an account | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts.admins | create | POST | `/v1/{parent=accounts/*}/admins` | Add admin to account | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts.admins | delete | DELETE | `/v1/{name=accounts/*/admins/*}` | Remove admin | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts.invitations | list | GET | `/v1/{parent=accounts/*}/invitations` | List pending invitations (response `Invitation.targetLocation.placeId` added in v1.1) | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts.invitations/list |
| Account Mgmt | accounts.invitations | accept | POST | `/v1/{name=accounts/*/invitations/*}:accept` | Accept invitation | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | accounts.invitations | decline | POST | `/v1/{name=accounts/*/invitations/*}:decline` | Decline invitation | https://developers.google.com/my-business/reference/accountmanagement/rest |
| Account Mgmt | locations | transfer | POST | `/v1/{name=locations/*}:transfer` | Transfer location to another account; body field is `destinationAccount` (v1.1 rename of `toAccount`) | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/locations/transfer |
| Account Mgmt | locations.admins | list | GET | `/v1/{parent=locations/*}/admins` | List admins for a **location** — **new in v1.1** | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/locations.admins/list |
| Account Mgmt | locations.admins | create | POST | `/v1/{parent=locations/*}/admins` | Invite an admin for a location — **new in v1.1** | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/locations.admins/create |
| Account Mgmt | locations.admins | patch | PATCH | `/v1/{locationAdmin.name=locations/*/admins/*}` | Update a location admin — **new in v1.1** | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/locations.admins/patch |
| Account Mgmt | locations.admins | delete | DELETE | `/v1/{name=locations/*/admins/*}` | Remove a location admin — **new in v1.1** | https://developers.google.com/my-business/reference/accountmanagement/rest/v1/locations.admins/delete |
| Business Info | accounts.locations | list | GET | `/v1/{parent=accounts/*}/locations` | List locations for account (readMask required) | https://developers.google.com/my-business/reference/businessinformation/rest/v1/accounts.locations/list |
| Business Info | accounts.locations | create | POST | `/v1/{parent=accounts/*}/locations` | Create a new location | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | locations | get | GET | `/v1/{name=locations/*}` | Get single location (readMask required) | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | locations | patch | PATCH | `/v1/{location.name=locations/*}` | Update location | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | locations | delete | DELETE | `/v1/{name=locations/*}` | Delete location | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | locations | getAttributes | GET | `/v1/{name=locations/*/attributes}` | Get location attributes | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | locations | updateAttributes | PATCH | `/v1/{attributes.name=locations/*/attributes}` | Update location attributes | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | locations | getGoogleUpdated | GET | `/v1/{name=locations/*}:getGoogleUpdated` | Get Google-suggested location updates | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | attributes | list | GET | `/v1/attributes` | List all available attributes | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | categories | list | GET | `/v1/categories` | List available business categories | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | categories | batchGet | GET | `/v1/categories:batchGet` | Get multiple categories | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | chains | get | GET | `/v1/{name=chains/*}` | Get a chain | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | chains | search | GET | `/v1/chains:search` | Search for chains | https://developers.google.com/my-business/reference/businessinformation/rest |
| Business Info | googleLocations | search | POST | `/v1/googleLocations:search` | Search Google Maps for locations | https://developers.google.com/my-business/reference/businessinformation/rest |
| Performance | locations | fetchMultiDailyMetricsTimeSeries | GET | `/v1/{location=locations/*}:fetchMultiDailyMetricsTimeSeries` | Fetch multiple daily metrics in one call | https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries |
| Performance | locations | getDailyMetricsTimeSeries | GET | `/v1/{name=locations/*}:getDailyMetricsTimeSeries` | Fetch a single daily metric | https://developers.google.com/my-business/reference/performance/rest/v1/locations/getDailyMetricsTimeSeries |
| Performance | locations.searchkeywords.impressions.monthly | list | GET | `/v1/{parent=locations/*}/searchkeywords/impressions/monthly` | Monthly search keyword impressions | https://developers.google.com/my-business/reference/performance/rest |
| Legacy v4 | accounts.locations.reviews | list | GET | `/v4/{parent=accounts/*/locations/*}/reviews` | List reviews for a location | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list |
| Legacy v4 | accounts.locations.reviews | get | GET | `/v4/{name=accounts/*/locations/*/reviews/*}` | Get a specific review | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews |
| Legacy v4 | accounts.locations.reviews | updateReply | PUT | `/v4/{name=accounts/*/locations/*/reviews/*}/reply` | Create or update reply to a review | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/updateReply |
| Legacy v4 | accounts.locations.reviews | deleteReply | DELETE | `/v4/{name=accounts/*/locations/*/reviews/*}/reply` | Delete a review reply | https://developers.google.com/my-business/reference/rest |
| Legacy v4 | accounts.locations.localPosts | list | GET | `/v4/{parent=accounts/*/locations/*}/localPosts` | List local posts | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts |
| Legacy v4 | accounts.locations.localPosts | create | POST | `/v4/{parent=accounts/*/locations/*}/localPosts` | Create a local post | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts |
| Legacy v4 | accounts.locations.localPosts | patch | PATCH | `/v4/{localPost.name=accounts/*/locations/*/localPosts/*}` | Update a local post | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts |
| Legacy v4 | accounts.locations.localPosts | delete | DELETE | `/v4/{name=accounts/*/locations/*/localPosts/*}` | Delete a local post | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts |
| Legacy v4 | accounts.locations.localPosts | get | GET | `/v4/{name=accounts/*/locations/*/localPosts/*}` | Get a local post | https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts |

---

## Concrete Endpoint Reference

Each section below gives the exact HTTP call, all parameters typed and annotated required/optional,
a realistic example request, and a realistic example response. Use these to implement new CLI subcommands.

---

### GET /v1/accounts — List Accounts

**Base URL:** `https://mybusinessaccountmanagement.googleapis.com`

**Full URL:**
```
GET https://mybusinessaccountmanagement.googleapis.com/v1/accounts
```

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `pageSize` | integer | optional | Max 20, default 20 |
| `pageToken` | string | optional | Cursor from previous response `nextPageToken` |
| `parentAccount` | string | optional | Filter to sub-accounts: `accounts/{id}` |
| `filter` | string | optional | e.g. `type=USER_GROUP` |

**Headers:**
```
Authorization: Bearer {access_token}
```
No `Content-Type` header needed (GET with no body).

**Example request:**
```
GET https://mybusinessaccountmanagement.googleapis.com/v1/accounts?pageSize=20
Authorization: Bearer ya29.a0AfH6...
```

**Example response:**
```json
{
  "accounts": [
    {
      "name": "accounts/111222333444",
      "accountName": "Talas Auto Parts",
      "type": "LOCATION_GROUP",
      "role": "OWNER",
      "verificationState": "VERIFIED",
      "vettedState": "IS_VETTED"
    },
    {
      "name": "accounts/555666777888",
      "accountName": "Mohammed Al Rashid",
      "type": "PERSONAL",
      "role": "OWNER",
      "verificationState": "VERIFICATION_REQUESTED",
      "vettedState": "NOT_VETTED"
    }
  ],
  "nextPageToken": "CAUQAA"
}
```

**Account object fields:**

> **CORRECTION (verified July 2026 against the live `AccountRole` enum reference):** the current
> `role` enum has **no `CO_OWNER` value**. The real values are `ACCOUNT_ROLE_UNSPECIFIED`,
> `PRIMARY_OWNER`, `OWNER`, `MANAGER`, `SITE_MANAGER`. `CO_OWNER` and `COMMUNITY_MANAGER` were the
> **legacy v4 names**, renamed to `OWNER`/`PRIMARY_OWNER` and `SITE_MANAGER` respectively when the
> account moved to v1 (`OWNER`→`PRIMARY_OWNER`, `CO_OWNER`→`OWNER`, `COMMUNITY_MANAGER`→`SITE_MANAGER`).
> An earlier version of this doc still listed the legacy v4 names for the v1 API — that was wrong.
> Source: https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts#AccountRole
> (rename history: https://developers.google.com/my-business/content/accountmanagement/change-log)

| Field | Type | Notes |
|---|---|---|
| `name` | string | Resource name: `accounts/{accountId}` |
| `accountName` | string | Display name of the account |
| `type` | enum | `PERSONAL`, `LOCATION_GROUP`, `USER_GROUP`, `ORGANIZATION` |
| `role` | enum | Authenticated user's role: `ACCOUNT_ROLE_UNSPECIFIED`, `PRIMARY_OWNER`, `OWNER`, `MANAGER`, `SITE_MANAGER` (no `CO_OWNER` — see correction above) |
| `verificationState` | enum | `VERIFIED`, `UNVERIFIED`, `VERIFICATION_REQUESTED` |
| `vettedState` | enum | `IS_VETTED`, `NOT_VETTED`, `IS_VETTED_UNCONFIRMED` |

**Error cases:**
- `401 UNAUTHENTICATED` — token missing or expired; refresh with `./gads auth refresh`
- `403 PERMISSION_DENIED` — token lacks `business.manage` scope
- `429 RESOURCE_EXHAUSTED` — quota is 0 (allowlist not approved — see Access Requirements)

Source: https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts/list

---

### GET /v1/{accountName}/locations — List Locations

**Base URL:** `https://mybusinessbusinessinformation.googleapis.com`

**Full URL:**
```
GET https://mybusinessbusinessinformation.googleapis.com/v1/{accountName}/locations
```

**Path variables:**

| Variable | Type | Req? | Example |
|---|---|---|---|
| `accountName` | string | required | `accounts/111222333444` |

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `readMask` | string | **required** | Comma-separated field names; omitting causes 400 error |
| `pageSize` | integer | optional | Range 1–100, default 10 |
| `pageToken` | string | optional | Cursor from previous response |
| `filter` | string | optional | SQL-style filter e.g. `storeCode="QZ3"` |
| `orderBy` | string | optional | `title`, `title desc`, `storeCode`, `storeCode desc` |

**Headers:**
```
Authorization: Bearer {access_token}
```

**Example request (all useful fields):**
```
GET https://mybusinessbusinessinformation.googleapis.com/v1/accounts/111222333444/locations
    ?readMask=name,title,phoneNumbers,categories,storefrontAddress,websiteUri,regularHours,metadata,latlng,storeCode
    &pageSize=100
Authorization: Bearer ya29.a0AfH6...
```

**Example response:**
```json
{
  "locations": [
    {
      "name": "locations/17303088970776446827",
      "title": "Talas Auto Parts - Qatar Zone 3",
      "storeCode": "QZ3",
      "phoneNumbers": {
        "primaryPhone": "+974 4444 1234",
        "additionalPhones": ["+974 5555 9876"]
      },
      "categories": {
        "primaryCategory": {
          "name": "categories/gcid:auto_parts_store",
          "displayName": "Auto Parts Store"
        },
        "additionalCategories": [
          {
            "name": "categories/gcid:used_auto_parts_store",
            "displayName": "Used Auto Parts Store"
          }
        ]
      },
      "storefrontAddress": {
        "regionCode": "AE",
        "languageCode": "en",
        "postalCode": "00000",
        "administrativeArea": "Dubai",
        "locality": "Al Quoz",
        "addressLines": ["Zone 3, Industrial Area", "Warehouse 12, Street 8"]
      },
      "websiteUri": "https://shop.talas.ae/?branch=QZ3",
      "regularHours": {
        "periods": [
          {
            "openDay": "MONDAY",
            "openTime": { "hours": 8, "minutes": 0 },
            "closeDay": "MONDAY",
            "closeTime": { "hours": 18, "minutes": 0 }
          },
          {
            "openDay": "SATURDAY",
            "openTime": { "hours": 9, "minutes": 0 },
            "closeDay": "SATURDAY",
            "closeTime": { "hours": 14, "minutes": 0 }
          }
        ]
      },
      "latlng": {
        "latitude": 25.1234,
        "longitude": 55.5678
      },
      "metadata": {
        "mapsUri": "https://maps.google.com/?cid=17303088970776446827",
        "newReviewUri": "https://search.google.com/local/writereview?placeid=ChIJXXXXXXX",
        "placeId": "ChIJXXXXXXXXXXXXXXXXXXXX",
        "hasPendingEdits": false,
        "canDelete": false,
        "canOperateLocalPost": true,
        "canModifyServiceList": true,
        "canHaveFoodMenus": false,
        "canOperateHealthData": false,
        "canOperateLodgingData": false
      }
    }
  ],
  "totalSize": 3,
  "nextPageToken": "CAUQBA"
}
```

**Key Location object fields** (all available in `readMask`):

| Field | Type | Notes |
|---|---|---|
| `name` | string | Resource name: `locations/{locationId}` — the numeric ID is the GBP listing ID |
| `title` | string | Business name as customers see it; no taglines, codes, or URLs |
| `storeCode` | string | Owner-assigned identifier (e.g. `QZ3`, `IND4`, `SJA`) |
| `phoneNumbers` | object | `primaryPhone` (string) + `additionalPhones` (string[]) |
| `categories` | object | `primaryCategory` + `additionalCategories[]`; each has `name` and `displayName` |
| `storefrontAddress` | object | `regionCode`, `administrativeArea`, `locality`, `addressLines[]` |
| `websiteUri` | string | Business website URL |
| `regularHours` | object | `periods[]` each with `openDay`, `openTime`, `closeDay`, `closeTime` |
| `specialHours` | object | Holiday/exception hours |
| `latlng` | object | `latitude` (float), `longitude` (float) |
| `metadata` | object | Output-only: `placeId`, `mapsUri`, `newReviewUri`, `hasPendingEdits`, capability flags |
| `serviceArea` | object | For service-area businesses (no storefront) |

**Error cases:**
- `400 INVALID_ARGUMENT` — `readMask` is missing or contains an invalid field name
- `403 PERMISSION_DENIED` — account not accessible to this token
- `429 RESOURCE_EXHAUSTED` — zero quota (allowlist not approved)

Source: https://developers.google.com/my-business/reference/businessinformation/rest/v1/accounts.locations/list

---

### GET /v4/{locationName}/reviews — List Reviews

**Base URL:** `https://mybusiness.googleapis.com`

> **v4 LEGACY — still the only way to access reviews as of July 2026. No v1 replacement exists.**

**Full URL:**
```
GET https://mybusiness.googleapis.com/v4/{locationName}/reviews
```

**Path variables:**

| Variable | Type | Req? | Example |
|---|---|---|---|
| `locationName` | string | required | `accounts/111222333444/locations/17303088970776446827` |

Note: unlike Business Info API, reviews use the full `accounts/{id}/locations/{id}` path, not just `locations/{id}`.

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `pageSize` | integer | optional | Max 50, no documented default |
| `pageToken` | string | optional | Cursor from previous response |
| `orderBy` | string | optional | `rating`, `rating desc`, `updateTime desc` |

**Headers:**
```
Authorization: Bearer {access_token}
```

**Example request:**
```
GET https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/reviews
    ?pageSize=50&orderBy=updateTime+desc
Authorization: Bearer ya29.a0AfH6...
```

**Example response:**
```json
{
  "reviews": [
    {
      "name": "accounts/111222333444/locations/17303088970776446827/reviews/AbCdEfGhIjKlMnOp",
      "reviewId": "AbCdEfGhIjKlMnOp",
      "reviewer": {
        "displayName": "Ahmed Al Mansoori",
        "profilePhotoUrl": "https://lh3.googleusercontent.com/a-/XXXXXXXX",
        "isAnonymous": false
      },
      "starRating": "FIVE",
      "comment": "Excellent service! Found the Tesla Model 3 rear bumper I needed. Fast shipping.",
      "createTime": "2026-05-15T10:23:45.000Z",
      "updateTime": "2026-05-15T10:23:45.000Z",
      "reviewReply": {
        "comment": "Thank you Ahmed! We're glad we could help with your Tesla parts. Visit us again!",
        "updateTime": "2026-05-16T08:00:00.000Z",
        "reviewReplyState": "APPROVED"
      }
    },
    {
      "name": "accounts/111222333444/locations/17303088970776446827/reviews/QrStUvWxYzAbCd",
      "reviewId": "QrStUvWxYzAbCd",
      "reviewer": {
        "isAnonymous": true
      },
      "starRating": "THREE",
      "comment": "Good selection but had to wait a while.",
      "createTime": "2026-04-20T14:11:00.000Z",
      "updateTime": "2026-04-20T14:11:00.000Z"
    }
  ],
  "averageRating": 4.3,
  "totalReviewCount": 47,
  "nextPageToken": "CAUQBA"
}
```

**Review object fields:**

| Field | Type | Notes |
|---|---|---|
| `name` | string | Full resource path: `accounts/{id}/locations/{id}/reviews/{id}` |
| `reviewId` | string | Unique identifier for this review |
| `reviewer.displayName` | string | Only present when `isAnonymous=false` |
| `reviewer.profilePhotoUrl` | string | Only present when `isAnonymous=false` |
| `reviewer.isAnonymous` | boolean | Always present |
| `starRating` | enum | `ONE`, `TWO`, `THREE`, `FOUR`, `FIVE` |
| `comment` | string | Review text; may include markup |
| `createTime` | string | RFC3339 timestamp |
| `updateTime` | string | RFC3339 timestamp (changes when reviewer edits) |
| `reviewReply` | object | Present if owner has replied; absent otherwise |
| `reviewMediaItems` | array | Associated photos/videos (if any) |

**reviewReply sub-fields:**

| Field | Type | Notes |
|---|---|---|
| `comment` | string | Owner reply text, max 4,096 bytes |
| `updateTime` | string | RFC3339 timestamp (output only) |
| `reviewReplyState` | enum | `PENDING`, `REJECTED`, `APPROVED` |

**ListReviewsResponse fields:**

| Field | Notes |
|---|---|
| `reviews[]` | Array of Review objects |
| `averageRating` | Float 1.0–5.0 across all reviews for this location |
| `totalReviewCount` | Total reviews (all pages) |
| `nextPageToken` | Present if more pages; absent on last page |

**Error cases:**
- `403 PERMISSION_DENIED` — location not accessible or not verified
- `404 NOT_FOUND` — location name is wrong (check full `accounts/.../locations/...` path)
- `429 RESOURCE_EXHAUSTED` — zero quota (allowlist not approved)

Source: https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list

---

### PUT /v4/{reviewName}/reply — Reply to Review

**Base URL:** `https://mybusiness.googleapis.com`

> **v4 LEGACY — still the only way to reply to reviews as of July 2026.**

**Full URL:**
```
PUT https://mybusiness.googleapis.com/v4/{reviewName}/reply
```

**Path variables:**

| Variable | Type | Req? | Example |
|---|---|---|---|
| `reviewName` | string | required | `accounts/111222333444/locations/17303088970776446827/reviews/AbCdEfGhIjKlMnOp` |

**Request body:**

```json
{
  "comment": "string (required, max 4096 bytes)"
}
```

**Headers:**
```
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Example request:**
```
PUT https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/reviews/AbCdEfGhIjKlMnOp/reply
Authorization: Bearer ya29.a0AfH6...
Content-Type: application/json

{
  "comment": "Thank you for your kind words! We're happy to help with your Tesla parts needs. Come back anytime!"
}
```

**Example response** (ReviewReply object):
```json
{
  "comment": "Thank you for your kind words! We're happy to help with your Tesla parts needs. Come back anytime!",
  "updateTime": "2026-06-23T09:15:00.000Z",
  "reviewReplyState": "PENDING"
}
```

Note: `reviewReplyState` starts as `PENDING` — Google moderates replies before showing them publicly.
Typically transitions to `APPROVED` within minutes to hours.

**Constraints:**
- Location must be verified
- If a reply already exists, this replaces it (idempotent upsert — creates if missing, updates if present)

**Error cases:**
- `400 INVALID_ARGUMENT` — `comment` field missing or over 4,096 bytes
- `403 PERMISSION_DENIED` — location not verified, or token lacks write access
- `404 NOT_FOUND` — review name path is wrong
- `429 RESOURCE_EXHAUSTED` — zero quota

Source: https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/updateReply

---

### DELETE /v4/{reviewName}/reply — Delete Review Reply

**Full URL:**
```
DELETE https://mybusiness.googleapis.com/v4/{reviewName}/reply
```

**Example request:**
```
DELETE https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/reviews/AbCdEfGhIjKlMnOp/reply
Authorization: Bearer ya29.a0AfH6...
```

**Response:** Empty body, HTTP 200 on success.

**Error cases:**
- `404 NOT_FOUND` — no reply exists to delete, or review name is wrong
- `403 PERMISSION_DENIED` — location not verified or no write access

---

### GET /v1/{location}:fetchMultiDailyMetricsTimeSeries — Performance Metrics (Multi)

**Base URL:** `https://businessprofileperformance.googleapis.com`

> **IMPORTANT — CORRECT ENDPOINT NAME:**
> The documented endpoint is `fetchMultiDailyMetricsTimeSeries` (GET with repeated query params).
> The gads CLI `gbp_multi_daily_metrics()` function uses this correctly via GET.
> There is NO `fetchMultiDailyMetrics` POST endpoint. An earlier comment in the Coverage section
> flagged this as a potential bug — that was incorrect. The CLI implementation is correct.
> Source: https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries

**Full URL:**
```
GET https://businessprofileperformance.googleapis.com/v1/{location}:fetchMultiDailyMetricsTimeSeries
```

**Path variables:**

| Variable | Type | Req? | Example |
|---|---|---|---|
| `location` | string | required | `locations/17303088970776446827` (no `accounts/` prefix) |

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `dailyMetrics` | string (repeated) | required | One param per metric; repeat the key for each metric |
| `dailyRange.startDate.year` | integer | required | e.g. `2026` |
| `dailyRange.startDate.month` | integer | required | e.g. `6` |
| `dailyRange.startDate.day` | integer | required | e.g. `1` |
| `dailyRange.endDate.year` | integer | required | e.g. `2026` |
| `dailyRange.endDate.month` | integer | required | e.g. `22` |
| `dailyRange.endDate.day` | integer | required | e.g. `22` |

**Headers:**
```
Authorization: Bearer {access_token}
```

**Example request (three metrics, 30-day window):**
```
GET https://businessprofileperformance.googleapis.com/v1/locations/17303088970776446827:fetchMultiDailyMetricsTimeSeries
    ?dailyMetrics=WEBSITE_CLICKS
    &dailyMetrics=CALL_CLICKS
    &dailyMetrics=BUSINESS_DIRECTION_REQUESTS
    &dailyRange.startDate.year=2026
    &dailyRange.startDate.month=5
    &dailyRange.startDate.day=1
    &dailyRange.endDate.year=2026
    &dailyRange.endDate.month=5
    &dailyRange.endDate.day=31
Authorization: Bearer ya29.a0AfH6...
```

**Example response:**
```json
{
  "multiDailyMetricTimeSeries": [
    {
      "dailyMetricTimeSeries": [
        {
          "dailyMetric": "WEBSITE_CLICKS",
          "timeSeries": {
            "datedValues": [
              { "date": { "year": 2026, "month": 5, "day": 1 }, "value": "14" },
              { "date": { "year": 2026, "month": 5, "day": 2 }, "value": "9" },
              { "date": { "year": 2026, "month": 5, "day": 3 }, "value": "0" }
            ]
          }
        },
        {
          "dailyMetric": "CALL_CLICKS",
          "timeSeries": {
            "datedValues": [
              { "date": { "year": 2026, "month": 5, "day": 1 }, "value": "3" },
              { "date": { "year": 2026, "month": 5, "day": 2 }, "value": "5" },
              { "date": { "year": 2026, "month": 5, "day": 3 }, "value": "0" }
            ]
          }
        },
        {
          "dailyMetric": "BUSINESS_DIRECTION_REQUESTS",
          "timeSeries": {
            "datedValues": [
              { "date": { "year": 2026, "month": 5, "day": 1 }, "value": "7" },
              { "date": { "year": 2026, "month": 5, "day": 2 }, "value": "2" },
              { "date": { "year": 2026, "month": 5, "day": 3 }, "value": "0" }
            ]
          }
        }
      ]
    }
  ]
}
```

**Response structure notes:**
- Top-level key: `multiDailyMetricTimeSeries` (array)
- Each element has a `dailyMetricTimeSeries` array (the inner grouping)
- Each series has `dailyMetric` (string) and `timeSeries.datedValues[]`
- Each dated value: `{ date: { year, month, day }, value: "N" }` — value is a **string**, not integer; parse with `int()`
- Days with no data return `value: "0"`, not `null`
- Recent days (last 2–3 days) may return `0` due to processing lag

**Error cases:**
- `400 INVALID_ARGUMENT` — invalid metric name or date range
- `403 PERMISSION_DENIED` — location not accessible or token lacks `business.manage` scope
- `429 RESOURCE_EXHAUSTED` — zero quota (allowlist not approved)

Source: https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries

---

### GET /v1/{location}:getDailyMetricsTimeSeries — Performance Metrics (Single)

**Full URL:**
```
GET https://businessprofileperformance.googleapis.com/v1/{location}:getDailyMetricsTimeSeries
```

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `dailyMetric` | string | required | Single `DailyMetric` enum value (singular, not repeated) |
| `dailyRange.startDate.year/month/day` | integer | required | Start of date range |
| `dailyRange.endDate.year/month/day` | integer | required | End of date range |
| `dailySubEntityType` | object | optional | Sub-entity breakdown for supported metrics |

**Example response:**
```json
{
  "timeSeries": {
    "datedValues": [
      { "date": { "year": 2026, "month": 5, "day": 1 }, "value": "14" },
      { "date": { "year": 2026, "month": 5, "day": 2 }, "value": "9" }
    ]
  }
}
```

Use `fetchMultiDailyMetricsTimeSeries` instead when fetching more than one metric — it saves API calls.

Source: https://developers.google.com/my-business/reference/performance/rest/v1/locations/getDailyMetricsTimeSeries

---

## Performance Metrics — Complete DailyMetric Enum

Source: https://developers.google.com/my-business/reference/performance/rest/v1/DailyMetric

| Enum Value | Description |
|---|---|
| `DAILY_METRIC_UNKNOWN` | Default/unknown — do not request this value |
| `BUSINESS_IMPRESSIONS_DESKTOP_MAPS` | Views on Google Maps desktop; deduplicated: 1 per unique user per day |
| `BUSINESS_IMPRESSIONS_DESKTOP_SEARCH` | Views on Google Search desktop; deduplicated: 1 per unique user per day |
| `BUSINESS_IMPRESSIONS_MOBILE_MAPS` | Views on Google Maps mobile; deduplicated: 1 per unique user per day |
| `BUSINESS_IMPRESSIONS_MOBILE_SEARCH` | Views on Google Search mobile; deduplicated: 1 per unique user per day |
| `BUSINESS_CONVERSATIONS` | Message conversations received on the business profile |
| `BUSINESS_DIRECTION_REQUESTS` | Direction requests to the business location |
| `CALL_CLICKS` | Clicks on the call button on the profile |
| `WEBSITE_CLICKS` | Clicks on the website link on the profile |
| `BUSINESS_BOOKINGS` | Bookings made via Reserve with Google |
| `BUSINESS_FOOD_ORDERS` | Food orders received from the business profile |
| `BUSINESS_FOOD_MENU_CLICKS` | Menu interactions; deduplicated: 1 per unique user per day |

---

## Local Posts (Implementation-Ready Reference)

Local posts appear on the Google Business Profile in Google Search and Maps results.
All localPosts endpoints are on the legacy v4 API — `mybusiness.googleapis.com/v4`.

> **Note:** `localPosts.reportInsights` was discontinued February 20, 2023. Do not implement it.
> All other localPosts methods (create, list, get, patch, delete) remain active as of July 2026.

### POST /v4/{locationName}/localPosts — Create Post

**Full URL:**
```
POST https://mybusiness.googleapis.com/v4/{locationName}/localPosts
```

**Path variables:**

| Variable | Type | Req? | Example |
|---|---|---|---|
| `locationName` | string | required | `accounts/111222333444/locations/17303088970776446827` |

**Headers:**
```
Authorization: Bearer {access_token}
Content-Type: application/json
```

**Request body — LocalPost object:**

| Field | Type | Req? | Notes |
|---|---|---|---|
| `topicType` | enum | required | `STANDARD`, `EVENT`, `OFFER`, `ALERT` |
| `summary` | string | required for STANDARD | Main post text |
| `callToAction` | object | optional | See below |
| `media` | array | optional | See below |
| `event` | object | required for EVENT/OFFER | See below |
| `languageCode` | string | optional | e.g. `en`, `ar` |
| `alertType` | enum | optional (ALERT posts) | `COVID_19` |
| `offer` | object | optional (OFFER posts) | `couponCode`, `redeemOnlineUrl`, `termsConditions` |

**callToAction object:**

| Field | Type | Notes |
|---|---|---|
| `actionType` | enum | `BOOK`, `ORDER`, `SHOP`, `LEARN_MORE`, `SIGN_UP`, `CALL` |
| `url` | string | Landing URL (omit for `CALL` type) |

**media array item:**

| Field | Type | Notes |
|---|---|---|
| `mediaFormat` | enum | `PHOTO`, `VIDEO` |
| `sourceUrl` | string | Publicly accessible URL to the media file |

**event object:**

| Field | Type | Notes |
|---|---|---|
| `title` | string | Event name |
| `schedule` | object | `{ startDate, startTime, endDate, endTime }` — uses Date and TimeOfDay objects |
| `schedule.startDate` | object | `{ year, month, day }` |
| `schedule.startTime` | object | `{ hours, minutes }` |
| `schedule.endDate` | object | `{ year, month, day }` |
| `schedule.endTime` | object | `{ hours, minutes }` |

**Example request — STANDARD post with CTA:**
```
POST https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/localPosts
Authorization: Bearer ya29.a0AfH6...
Content-Type: application/json

{
  "topicType": "STANDARD",
  "summary": "Original Tesla Model 3 used body parts now available at Talas — Qatar Zone 3. Front doors, bumpers, hoods. Call or visit us.",
  "callToAction": {
    "actionType": "CALL"
  },
  "languageCode": "en"
}
```

**Example request — OFFER post:**
```
POST https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/localPosts
Authorization: Bearer ya29.a0AfH6...
Content-Type: application/json

{
  "topicType": "OFFER",
  "summary": "10% off all Tesla Model 3 rear bumpers this week only.",
  "event": {
    "title": "Tesla Parts Sale",
    "schedule": {
      "startDate": { "year": 2026, "month": 6, "day": 23 },
      "startTime": { "hours": 8, "minutes": 0 },
      "endDate": { "year": 2026, "month": 6, "day": 30 },
      "endTime": { "hours": 18, "minutes": 0 }
    }
  },
  "offer": {
    "couponCode": "TESLA10",
    "redeemOnlineUrl": "https://shop.talas.ae/?branch=QZ3",
    "termsConditions": "Valid in-store and online. One use per customer."
  },
  "callToAction": {
    "actionType": "SHOP",
    "url": "https://shop.talas.ae/?branch=QZ3"
  }
}
```

**Example request — EVENT post with photo:**
```
POST https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/localPosts
Authorization: Bearer ya29.a0AfH6...
Content-Type: application/json

{
  "topicType": "EVENT",
  "summary": "New Tesla Model Y parts just arrived. Limited stock.",
  "event": {
    "title": "Model Y Parts Arrival",
    "schedule": {
      "startDate": { "year": 2026, "month": 7, "day": 1 },
      "startTime": { "hours": 8, "minutes": 0 },
      "endDate": { "year": 2026, "month": 7, "day": 7 },
      "endTime": { "hours": 18, "minutes": 0 }
    }
  },
  "media": [
    {
      "mediaFormat": "PHOTO",
      "sourceUrl": "https://cdn.talas.ae/photos/model-y-parts-2026.jpg"
    }
  ],
  "callToAction": {
    "actionType": "LEARN_MORE",
    "url": "https://shop.talas.ae/tesla/model-y?branch=QZ3"
  }
}
```

**Example response:**
```json
{
  "name": "accounts/111222333444/locations/17303088970776446827/localPosts/102345678901234567",
  "languageCode": "en",
  "summary": "Original Tesla Model 3 used body parts now available at Talas — Qatar Zone 3. Front doors, bumpers, hoods. Call or visit us.",
  "topicType": "STANDARD",
  "state": "LIVE",
  "callToAction": {
    "actionType": "CALL"
  },
  "createTime": "2026-06-23T09:30:00.000Z",
  "updateTime": "2026-06-23T09:30:00.000Z",
  "searchUrl": "https://search.google.com/local/posts?q=Talas+Auto+Parts&ludocid=17303088970776446827"
}
```

**LocalPost state enum:**

| Value | Meaning |
|---|---|
| `LIVE` | Visible on Google |
| `PROCESSING` | Under review |
| `SCHEDULED` | Set to go live in the future |
| `REJECTED` | Violates policy; post not shown |
| `RECURRING` | A recurring post |

**Error cases:**
- `400 INVALID_ARGUMENT` — `topicType` missing, `event` missing for EVENT/OFFER type, or `media.sourceUrl` not publicly accessible
- `403 PERMISSION_DENIED` — location not accessible or not verified
- `404 NOT_FOUND` — location path is wrong
- `429 RESOURCE_EXHAUSTED` — zero quota

Source: https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/create

---

### GET /v4/{locationName}/localPosts — List Posts

**Full URL:**
```
GET https://mybusiness.googleapis.com/v4/{locationName}/localPosts
```

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `pageSize` | integer | optional | Range 1–100, default 20 |
| `pageToken` | string | optional | Cursor from previous response |

**Example request:**
```
GET https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/localPosts
    ?pageSize=50
Authorization: Bearer ya29.a0AfH6...
```

**Example response:**
```json
{
  "localPosts": [
    {
      "name": "accounts/111222333444/locations/17303088970776446827/localPosts/102345678901234567",
      "summary": "Original Tesla Model 3 used body parts now available...",
      "topicType": "STANDARD",
      "state": "LIVE",
      "callToAction": { "actionType": "CALL" },
      "createTime": "2026-06-23T09:30:00.000Z",
      "updateTime": "2026-06-23T09:30:00.000Z",
      "searchUrl": "https://search.google.com/local/posts?..."
    }
  ],
  "nextPageToken": "CAUQBA"
}
```

Source: https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/list

---

### PATCH /v4/{localPostName} — Update Post

**Full URL:**
```
PATCH https://mybusiness.googleapis.com/v4/{localPostName}
```

**Path variables:**

| Variable | Type | Req? | Example |
|---|---|---|---|
| `localPostName` | string | required | `accounts/111222333444/locations/17303088970776446827/localPosts/102345678901234567` |

**Query parameters:**

| Parameter | Type | Req? | Notes |
|---|---|---|---|
| `updateMask` | string | required | Comma-separated field paths to update; omitting updates all fields |

**Example request (update summary only):**
```
PATCH https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/localPosts/102345678901234567
      ?updateMask=summary
Authorization: Bearer ya29.a0AfH6...
Content-Type: application/json

{
  "summary": "Updated: Tesla Model 3 parts — front and rear bumpers in stock now."
}
```

**Response:** Returns the updated LocalPost object.

### DELETE /v4/{localPostName} — Delete Post

**Full URL:**
```
DELETE https://mybusiness.googleapis.com/v4/{localPostName}
```

**Example request:**
```
DELETE https://mybusiness.googleapis.com/v4/accounts/111222333444/locations/17303088970776446827/localPosts/102345678901234567
Authorization: Bearer ya29.a0AfH6...
```

**Response:** Empty body, HTTP 200 on success.

---

## Key Request/Response Fields

### Accounts

Resource: `Account`

| Field | Type | Notes |
|---|---|---|
| `name` | string | Resource name: `accounts/{accountId}` |
| `accountName` | string | Display name of the account |
| `type` | enum | `PERSONAL`, `LOCATION_GROUP`, `USER_GROUP`, `ORGANIZATION` |
| `role` | enum | Authenticated user's role: `ACCOUNT_ROLE_UNSPECIFIED`, `PRIMARY_OWNER`, `OWNER`, `MANAGER`, `SITE_MANAGER` — no `CO_OWNER` (see correction under the `accounts.list` section above) |
| `verificationState` | enum | Verification status |
| `vettedState` | enum | Vetting status |

**accounts.list request parameters:**
- `pageSize` — max 20, default 20
- `pageToken` — pagination token
- `parentAccount` — filter by parent account resource name
- `filter` — supports `type=USER_GROUP`

Source: https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts/list

### Locations

Resource: `Location` (Business Information API v1)

**accounts.locations.list request parameters:**
- `parent` (required) — `accounts/{accountId}`
- `readMask` (required) — comma-separated field list; request will fail with 400 without it
- `pageSize` — range 1–100, default 10
- `pageToken` — pagination token
- `filter` — SQL-style filter on location fields
- `orderBy` — sort by `title` or `storeCode` (append ` desc` for descending)

**Response:** `{ locations: [...], nextPageToken: "...", totalSize: N }`

**readMask field reference:**

```
name,title,storeCode,phoneNumbers,categories,storefrontAddress,websiteUri,
regularHours,specialHours,latlng,metadata,serviceArea,openInfo,labels
```

**Recommended readMask for most CLI uses:**
```
name,title,storeCode,phoneNumbers,categories,storefrontAddress,websiteUri,regularHours,latlng,metadata
```

Source: https://developers.google.com/my-business/reference/businessinformation/rest/v1/accounts.locations/list

### Reviews (v4 legacy — still active)

The reviews endpoints live at `mybusiness.googleapis.com/v4`. There is no v1 replacement as of July 2026.
See the Concrete Endpoint Reference sections above for full request/response examples.

### Performance Metrics

See the Concrete Endpoint Reference sections above for full examples.

---

## Pagination & Quotas

### Pagination

All list methods use cursor-based pagination via `pageToken`:

| API / Method | Default pageSize | Max pageSize |
|---|---|---|
| accounts.list | 20 | 20 |
| accounts.locations.list (Business Info) | 10 | 100 |
| reviews.list (v4) | — | 50 |
| localPosts.list (v4) | 20 | 100 |
| searchkeywords.impressions.monthly.list | — | unspecified |

Pattern: Include `pageToken` from the previous response's `nextPageToken` to fetch the next page.
When `nextPageToken` is absent from the response, you've reached the last page.

### Quotas & Rate Limits

**Corrected 2026-09-04 — QPM values ARE published.** A previous revision of this file said they were
not; that was wrong. Official figures from https://developers.google.com/my-business/content/limits
(fetched 2026-09-04):

| Limit | Value |
|-------|-------|
| Default QPM — Account Management, Business Information, Performance (also Verifications, Lodging, Place Actions, Notifications) | **300 QPM** |
| Business Information — `CreateLocation` | 300 QPD |
| Business Information — `SearchGoogleLocation` | 300 QPD |
| Business Information — `UpdateLocation` | 10,000 QPD |
| Edits per profile | 10 per minute — **not increasable** |

- After enabling any GBP API in Google Cloud Console, **default quota is 0** — API calls will
  return HTTP 429 (RESOURCE_EXHAUSTED) until access is approved (see Access Requirements below).
  Official wording, re-confirmed 2026-09-04: *"If you have a quota of 0 after enabling the API,
  please request for GBP API access."*
- Sources: https://developers.google.com/my-business/content/limits (fetched 2026-09-04);
  https://developers.google.com/my-business/reference/businessinformation/rest (quota note)

---

## Access Requirements

**There is a mandatory allowlist/approval gate** for the GBP APIs that is separate from simply
enabling the API in Google Cloud Console.

**Steps:**
1. Enable the desired APIs in Google Cloud Console (Account Management, Business Information, Performance, Google My Business)
2. Create OAuth 2.0 credentials
3. **Request API access** via: `https://support.google.com/business/contact/api_default`
   - Select "Application for Basic API Access"
   - Sign in as the GBP account owner (not a manager)
   - Describe your use case and specific endpoints needed
4. Wait for approval (typically 7–10 business days, but can range from 4 days to 6 weeks)

**Prerequisites before applying** (four, not three — the website requirement was missing from a
previous revision; re-verified 2026-09-04 against https://developers.google.com/my-business/content/prereqs):
- Business profile must be at least 60 days old
- Profile must be verified
- You must be the account owner
- The business must **have a website listed on the Google Business Profile**

**What happens without approval:**
- API calls return HTTP 429 (`RESOURCE_EXHAUSTED`) — looks like a rate limit but is actually zero quota
- This is NOT a rate limit that resolves with slower requests; only approval resolves it

Sources:
- https://xovionlabs.com/blog/google-business-profile-api-hidden-gate/
- https://developers.google.com/my-business/reference/businessinformation/rest ("If you have a quota of 0 after enabling the API, please request for GBP API access")

---

## Gotchas

1. **`readMask` is required** on `accounts.locations.list` and `locations.get` in the Business
   Information API. Omitting it causes a `400 INVALID_ARGUMENT` error. Supply a comma-separated
   list of field names you need.

2. **Reviews are stuck on v4** — `mybusiness.googleapis.com/v4` for reviews is still the only way
   to list/reply to reviews. There is no v1 reviews API as of July 2026. The gads-cli correctly uses
   v4 for reviews. Do not try to migrate to v1 — no such endpoint exists yet.

3. **Local posts are also stuck on v4** — same situation as reviews. The `localPosts` resource
   lives at `mybusiness.googleapis.com/v4`.

4. **Location ID format differs between APIs:**
   - Business Information API: `locations/{locationId}` (no account prefix)
   - Performance API: `locations/{locationId}` (same, no account prefix)
   - v4 reviews: `accounts/{accountId}/locations/{locationId}/reviews/{reviewId}` (full path)
   - v4 localPosts: `accounts/{accountId}/locations/{locationId}/localPosts/{postId}` (full path)
   Mixing up these formats causes `404 NOT_FOUND`.

5. **Allowlist is mandatory** — enabling the API in Cloud Console is not enough. Zero quota = 429
   errors that look like rate limiting. See Access Requirements.

6. **`plus.business.manage` scope is legacy** — both scopes work for v4 reviews/posts, but
   `business.manage` is the current standard and works across all APIs. Prefer it.

7. **Daily metrics are deduplicated per surface per user per day** — impression metrics count
   unique users. `BUSINESS_IMPRESSIONS_DESKTOP_MAPS` and `BUSINESS_IMPRESSIONS_MOBILE_MAPS` can
   each fire for the same user (one per surface), but each surface deduplicates within itself.

8. **Performance API uses `locations/` path without account prefix** — unlike v4 which requires
   `accounts/*/locations/*`, the Performance API only needs `locations/{locationId}`.

9. **`fetchMultiDailyMetricsTimeSeries` is GET, not POST** — it uses repeated `dailyMetrics=`
   query params (one per metric), not a JSON body. The gads CLI (`gbp_multi_daily_metrics`)
   implements this correctly. There is no `fetchMultiDailyMetrics` POST endpoint.

10. **Performance data lags 2–3 days** — recent days typically return `value: "0"` even when
    there was real activity. Never alert on zeros within the last 3 days.

11. **`value` in datedValues is a string, not integer** — the API returns `"value": "42"` (quoted).
    Always parse with `int(dv.get("value", 0))`.

12. **`reviewReplyState` starts as `PENDING`** — after `PUT .../reply`, the reply is not
    immediately visible. Google moderates it; transitions to `APPROVED` or `REJECTED`.

13. **`media.sourceUrl` for local posts must be publicly accessible** — private URLs (signed S3,
    Cloudinary auth-required) fail with `400 INVALID_ARGUMENT`. Use public CDN URLs.

---

## Coverage vs Current gads CLI

The current `gads_lib/gbp.py` uses these endpoints:

| Feature | gads CLI function | Endpoint | Status |
|---|---|---|---|
| List accounts | `gbp_list_accounts` | `GET /v1/accounts` | Correct |
| List locations | `gbp_list_locations` | `GET /v1/{account}/locations` | Correct; readMask passed as param |
| Get location | `gbp_get_location` | `GET /v1/{location}` | Correct; readMask passed as param |
| List reviews | `gbp_list_reviews` | `GET /v4/{location}/reviews` | Correct; v4 is the only option |
| Reply to review | `gbp_reply_review` | `PUT /v4/{review}/reply` | Correct |
| Delete reply | `gbp_delete_reply` | `DELETE /v4/{review}/reply` | Correct |
| Single daily metric | `gbp_daily_metrics` | `GET /v1/{location}:getDailyMetricsTimeSeries` | Correct |
| Multi daily metrics | `gbp_multi_daily_metrics` | `GET /v1/{location}:fetchMultiDailyMetricsTimeSeries` | Correct — GET with repeated query params |
| Search keywords | `gbp_search_keywords_monthly` | `GET /v1/{location}/searchkeywords/impressions/monthly` | Correct; handles pagination |

**Endpoints/features NOT yet in gads CLI (implementation gaps):**

| Feature | API | HTTP | Path | Notes |
|---|---|---|---|---|
| Local posts — create | v4 | POST | `/v4/{location}/localPosts` | topicType, summary, callToAction, media, event |
| Local posts — list | v4 | GET | `/v4/{location}/localPosts` | pageSize max 100 |
| Local posts — update | v4 | PATCH | `/v4/{localPost}?updateMask=...` | updateMask required |
| Local posts — delete | v4 | DELETE | `/v4/{localPost}` | No body |
| Batch get reviews | v4 | POST | `/v4/{account}/locations:batchGetReviews` | Multi-location review fetch, max 50 locations/call; marked "new" (not deprecated) in Google's nav |
| Business attributes | Business Info v1 | GET | `/v1/{location}/attributes` | Hours, accessibility, amenities |
| Account admins | Account Mgmt v1 | GET | `/v1/{account}/admins` | Who has access to each account |
| **Location admins** (new in v1.1) | Account Mgmt v1 | GET/POST/PATCH/DELETE | `/v1/{location}/admins` | Who has access to each *location* directly (as opposed to account-level admins); supersedes deprecated v4 `accounts.locations.admins` |
| Location categories | Business Info v1 | GET | `/v1/categories` | Enumerate valid categories |
| Google-suggested updates | Business Info v1 | GET | `/v1/{location}:getGoogleUpdated` | See what Google has auto-changed |
| Voice-of-merchant / suspension state | Verifications v1 (`mybusinessverifications.googleapis.com`) | GET | `/v1/{location}:getVoiceOfMerchantState` | Replaces old v4 `LocationState` fields; not currently used by gads-cli |

---

## Sources

All claims in this document are sourced from the following URLs, fetched July 2026:

- https://developers.google.com/my-business/reference/accountmanagement/rest — Account Management API reference (confirms v1.1, `locations.admins` resource)
- https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts/list — accounts.list details
- https://developers.google.com/my-business/reference/accountmanagement/rest/v1/accounts#AccountRole — live `AccountRole` enum: `ACCOUNT_ROLE_UNSPECIFIED`, `PRIMARY_OWNER`, `OWNER`, `MANAGER`, `SITE_MANAGER` (no `CO_OWNER`)
- https://developers.google.com/my-business/content/accountmanagement/change-log — v1.1 change log (`destinationAccount`, invitation `placeId`, legacy role-name rename table); last updated 2026-05-13
- https://developers.google.com/my-business/reference/businessinformation/rest — Business Information API reference
- https://developers.google.com/my-business/reference/businessinformation/rest/v1/accounts.locations/list — accounts.locations.list details
- https://developers.google.com/my-business/content/businessinformation/change-log — confirms no `v1.1`+ entries as of July 2026; documents `locations.getVoiceOfMerchantState` migration to Verifications API
- https://developers.google.com/my-business/reference/performance/rest — Performance API reference
- https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries — fetchMultiDailyMetricsTimeSeries details
- https://developers.google.com/my-business/reference/performance/rest/v1/locations/getDailyMetricsTimeSeries — getDailyMetricsTimeSeries details
- https://developers.google.com/my-business/reference/performance/rest/v1/DailyMetric — Complete DailyMetric enum values; unchanged, last updated 2024-10-16
- https://developers.google.com/my-business/content/performance/change-log — confirms no new entries as of July 2026
- https://developers.google.com/my-business/reference/rest — Legacy v4 API reference (reviews, posts)
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list — reviews.list details
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/updateReply — updateReply details
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations/batchGetReviews — confirms `batchGetReviews` is marked "new", not deprecated
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts — localPosts resource overview
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/create — localPosts.create details
- https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/list — localPosts.list details
- https://developers.google.com/my-business/content/review-data — Reviews API working guide
- https://developers.google.com/my-business/content/sunset-dates — Deprecation and sunset schedule; last updated 2025-08-28, no new entries since
- https://developers.google.com/my-business/reference/businesscalls/rest — Business Calls API; re-verified fully deprecated (nav-wide "Deprecated" markers) as of July 2026
- https://developers.google.com/my-business/reference/verifications/rest — My Business Verifications API (`mybusinessverifications.googleapis.com`, v1) — `getVoiceOfMerchantState`, `fetchVerificationOptions`, `verify`
- https://xovionlabs.com/blog/google-business-profile-api-hidden-gate/ — API access approval gate details

---

## Developer Guide

This section is a self-contained implementation reference for building new GBP CLI commands
or integrations. It covers access, resource hierarchies, attribute/category systems, all major
workflows, error patterns, and integration with Google Ads — everything needed to go from zero
to a working implementation without reading the scattered upstream docs.

---

### 1. API Access Requirements

#### Allowlist Approval Process

GBP APIs are **not open access**. Enabling them in Google Cloud Console gives you zero quota —
every call returns HTTP 429 (`RESOURCE_EXHAUSTED`) until Google manually approves your application.

**Steps to get access:**

1. Enable the APIs in Google Cloud Console:
   - My Business Account Management API
   - My Business Business Information API
   - Business Profile Performance API
   - Google My Business API (legacy — for reviews and posts)

2. Create OAuth 2.0 credentials (Web or Desktop application type).

3. Submit the access request form:
   ```
   https://support.google.com/business/contact/api_default
   ```
   - Select **"Application for Basic API Access"**
   - Sign in as the GBP **account owner** (not a manager account)
   - Describe your intended use case and list the specific API methods you need
   - Provide your Google Cloud project number

4. Wait for approval: typically 7-10 business days; can range from 4 days to 6 weeks.

**Prerequisites before applying** (re-verified 2026-09-04 — https://developers.google.com/my-business/content/prereqs):
- Business profile must exist and be at least 60 days old
- Profile must be **verified** (physical postcard or video verification)
- Applicant must be the **owner** of the GBP account, not just a manager
- The business must **have a website listed on the profile**

**What happens without approval:**

```
HTTP 429 RESOURCE_EXHAUSTED
{
  "error": {
    "code": 429,
    "message": "Quota exceeded for quota metric 'mybusiness.googleapis.com/default' ...",
    "status": "RESOURCE_EXHAUSTED"
  }
}
```

This looks identical to a rate-limit error but is actually zero quota. Slowing down or backing
off will not help — only approval resolves it.

**Supported use cases Google accepts:**
- Business owners managing their own profiles
- Agency-level management tools for client GBP accounts
- Analytics and review monitoring tools
- Automated posting or update tools
- Reputation management platforms

**Not supported:**
- Bulk scraping of competitor data
- Accessing GBP data for locations you do not manage
- Reselling raw GBP data

Sources:
- https://developers.google.com/my-business/reference/businessinformation/rest
- https://xovionlabs.com/blog/google-business-profile-api-hidden-gate/

---

### 2. Account vs Location Hierarchy

GBP organizes data in a two-level hierarchy: Accounts to Locations.

#### Account Resource Names

Format: `accounts/{accountId}`

Example: `accounts/111222333444`

The `accountId` is a numeric string. It is **not** the same as a Google Ads customer ID,
even if the same business uses both services.

Account types:
- `PERSONAL` — individual Google account that owns locations directly
- `LOCATION_GROUP` — most common for businesses; a group that holds multiple locations
- `USER_GROUP` — team-level access container
- `ORGANIZATION` — large enterprise multi-location container

**`accountName` pattern:** The display name string (e.g. `"Talas Auto Parts"`). This is different
from the resource `name` field (`accounts/111222333444`). When the API returns an `Account` object:
```json
{
  "name": "accounts/111222333444",
  "accountName": "Talas Auto Parts"
}
```

The `name` field is what you pass in API calls. `accountName` is the human-readable label.

#### Location Resource Names

Format: `locations/{locationId}`

Example: `locations/17303088970776446827`

The `locationId` is a large numeric string (often 19-20 digits). It is the GBP listing ID,
equivalent to the Maps CID.

**Short form vs full form:**

The Business Information API and Performance API use **short form** (no account prefix):
```
locations/17303088970776446827
```

The legacy v4 API (reviews, posts) uses **full form** (with account):
```
accounts/111222333444/locations/17303088970776446827
```

Mixing these up causes `404 NOT_FOUND`.

**`locationName` pattern (v4):**
```
accounts/{accountId}/locations/{locationId}
```
This is used as the `{parent}` path parameter when calling v4 reviews or posts endpoints.

#### How to Get Location IDs

From `GET /v1/{accountName}/locations` (Business Information API), each location object includes:
- `name` — the `locations/{locationId}` resource name
- `storeCode` — your own business code (e.g. `QZ3`, `IND4`, `SJA`)
- `metadata.placeId` — Google Maps Place ID (used in Maps URLs and directions)
- `metadata.mapsUri` — direct Google Maps link

Store the `name` field locally. It is stable and does not change unless the listing is deleted.

---

### 3. Location Attributes

Attributes are structured metadata fields for a location: parking, wheelchair access, payment
methods, service options, URL links, etc. Available attributes depend on the location's primary
category.

#### Attribute Value Types

| Type | Example Attributes | Storage |
|---|---|---|
| `URL` | `url_website_url`, `url_appointment_url`, `url_menu_url` | Single string URL |
| `BOOL` | `has_wheelchair_accessible_entrance`, `has_takeout`, `serves_dine_in` | `true` or `false` |
| `REPEATED_ENUM` | `pay_credit_card_types_accepted`, `parking_options` | Array of enum values |
| `INTEGER` | `url_wifi_quality` (rare) | Integer value |

#### Fetching Attribute Metadata

Before setting attributes, fetch the list of valid attributes for your location's category:

```
GET https://mybusinessbusinessinformation.googleapis.com/v1/attributes
    ?categoryName=categories/gcid:auto_parts_store
    &regionCode=AE
    &languageCode=en
```

Query parameters:
- `categoryName` — `categories/gcid:{categoryId}` format (required)
- `regionCode` — ISO 3166-1 alpha-2 country code
- `languageCode` — BCP-47 language code
- `pageSize` — max 100
- `pageToken` — pagination cursor

Response shape:
```json
{
  "attributeMetadata": [
    {
      "parent": "categories/gcid:auto_parts_store",
      "attributeId": "has_wheelchair_accessible_entrance",
      "displayName": "Wheelchair accessible entrance",
      "groupDisplayName": "Accessibility",
      "valueType": "BOOL"
    },
    {
      "parent": "categories/gcid:auto_parts_store",
      "attributeId": "url_website_url",
      "displayName": "Website",
      "groupDisplayName": "Links",
      "valueType": "URL"
    }
  ],
  "nextPageToken": "..."
}
```

Source: https://developers.google.com/my-business/reference/businessinformation/rest/v1/attributes/list

#### Getting a Location's Current Attributes

```
GET https://mybusinessbusinessinformation.googleapis.com/v1/{name}/attributes
```

Where `{name}` = `locations/17303088970776446827/attributes`

Response:
```json
{
  "name": "locations/17303088970776446827/attributes",
  "attributes": [
    {
      "name": "attributes/has_wheelchair_accessible_entrance",
      "valueType": "BOOL",
      "values": [true]
    },
    {
      "name": "attributes/url_website_url",
      "valueType": "URL",
      "uriValues": [
        { "uri": "https://shop.talas.ae/?branch=QZ3" }
      ]
    }
  ]
}
```

Note: URL attributes use `uriValues` (array of `{uri}` objects), not `values`.

#### Setting / Updating Attributes

```
PATCH https://mybusinessbusinessinformation.googleapis.com/v1/{name}/attributes
      ?updateMask=attributes
```

Where `{name}` = `locations/17303088970776446827/attributes`

Request body mirrors the GET response shape. Only include the attributes you want to change.
`updateMask=attributes` means replace the full attributes list — there is no patch-one-attribute mode.

```json
{
  "name": "locations/17303088970776446827/attributes",
  "attributes": [
    {
      "name": "attributes/has_wheelchair_accessible_entrance",
      "valueType": "BOOL",
      "values": [true]
    },
    {
      "name": "attributes/url_appointment_url",
      "valueType": "URL",
      "uriValues": [{ "uri": "https://shop.talas.ae/contact?branch=QZ3" }]
    }
  ]
}
```

Source: https://developers.google.com/my-business/reference/businessinformation/rest/v1/locations/updateAttributes

---

### 4. Business Categories

Categories determine which attributes are available and how Google classifies the location in
search results. Every location has exactly one primary category and optionally up to 9 additional
categories.

#### Category Resource Name Format

Format: `categories/gcid:{categoryId}`

Example: `categories/gcid:auto_parts_store`

The `gcid:` prefix distinguishes GBP category IDs from other identifier schemes. The full
resource name is used when setting `primaryCategory` or `additionalCategories` on a location.

#### Primary vs Additional Categories

```json
"categories": {
  "primaryCategory": {
    "name": "categories/gcid:auto_parts_store",
    "displayName": "Auto Parts Store"
  },
  "additionalCategories": [
    {
      "name": "categories/gcid:used_auto_parts_store",
      "displayName": "Used Auto Parts Store"
    },
    {
      "name": "categories/gcid:auto_body_parts_supplier",
      "displayName": "Auto Body Parts Supplier"
    }
  ]
}
```

**Rules:**
- Primary category is the most important signal for search placement and attribute eligibility
- Additional categories extend attribute availability and search coverage
- Maximum 9 additional categories
- Categories must be valid for the location's region — not all categories are available in all countries

#### Listing Available Categories

```
GET https://mybusinessbusinessinformation.googleapis.com/v1/categories
    ?languageCode=en
    &regionCode=AE
    &filter=displayName=auto
    &pageSize=100
```

Query parameters:
- `languageCode` — required; BCP-47
- `regionCode` — optional; filter to region-available categories
- `filter` — optional; full-text search on `displayName`
- `view` — `BASIC` (default) or `FULL` (includes applicable attribute metadata)

Response:
```json
{
  "categories": [
    {
      "name": "categories/gcid:auto_parts_store",
      "displayName": "Auto Parts Store",
      "moreHoursTypes": []
    }
  ],
  "nextPageToken": "..."
}
```

#### How Categories Affect Available Attributes

The attribute metadata endpoint (`/v1/attributes?categoryName=...`) is category-scoped.
If you change a location's primary category, the set of valid attributes may change.
Always re-fetch attribute metadata after a category change before attempting to set attributes.

Source: https://developers.google.com/my-business/reference/businessinformation/rest/v1/categories/list

---

### 5. Reviews Workflow

All reviews endpoints are on the **legacy v4 API** at `mybusiness.googleapis.com`. There is no
v1 replacement as of July 2026.

#### List Reviews (with Pagination)

```
GET https://mybusiness.googleapis.com/v4/{parent}/reviews
    ?pageSize=50&orderBy=updateTime+desc
```

Where `{parent}` = `accounts/111222333444/locations/17303088970776446827`

**Pagination pattern:**
```python
def list_all_reviews(account_id, location_id, access_token):
    base = "https://mybusiness.googleapis.com/v4"
    parent = f"accounts/{account_id}/locations/{location_id}"
    url = f"{base}/{parent}/reviews"
    headers = {"Authorization": f"Bearer {access_token}"}
    page_token = None
    reviews = []

    while True:
        params = {"pageSize": 50, "orderBy": "updateTime desc"}
        if page_token:
            params["pageToken"] = page_token
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        reviews.extend(data.get("reviews", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return reviews
```

**`orderBy` options:**
- `rating` — ascending star rating (1 first)
- `rating desc` — descending star rating (5 first)
- `updateTime desc` — most recently updated first (recommended for sync workflows)

#### Star Rating Enum

| Enum Value | Numeric | Display |
|---|---|---|
| `STAR_RATING_UNSPECIFIED` | -- | Unknown or not set |
| `ONE` | 1 | 1 star |
| `TWO` | 2 | 2 stars |
| `THREE` | 3 | 3 stars |
| `FOUR` | 4 | 4 stars |
| `FIVE` | 5 | 5 stars |

When storing to SQLite, map enum to integer: `{"ONE": 1, "TWO": 2, "THREE": 3, "FOUR": 4, "FIVE": 5}`.

#### Reviewer Info Fields

| Field | Type | Present when |
|---|---|---|
| `reviewer.displayName` | string | `isAnonymous = false` |
| `reviewer.profilePhotoUrl` | string | `isAnonymous = false` |
| `reviewer.isAnonymous` | boolean | Always |

Always check `isAnonymous` before accessing `displayName`.

#### updateTime Field

`updateTime` on the review itself reflects the **last time the reviewer edited the review**.
`reviewReply.updateTime` reflects the **last time the owner reply was updated**.

For sync workflows, track `updateTime` on the review to detect edits by the reviewer.

#### Reply to Review

```
PUT https://mybusiness.googleapis.com/v4/{reviewName}/reply
```

Where `{reviewName}` = `accounts/111222333444/locations/17303088970776446827/reviews/AbCdEfGhIjKlMnOp`

Body: `{ "comment": "Reply text (max 4096 bytes)" }`

Response returns the `ReviewReply` object with `reviewReplyState: "PENDING"`. This is an upsert —
calling it again replaces the existing reply.

#### Delete Reply

```
DELETE https://mybusiness.googleapis.com/v4/{reviewName}/reply
```

Returns empty body with HTTP 200. Returns 404 if no reply exists.

Source: https://developers.google.com/my-business/reference/rest/v4/accounts.locations.reviews/list

---

### 6. Performance Metrics

All performance data comes from `businessprofileperformance.googleapis.com/v1`.

#### Complete DailyMetric Enum and Availability

| Metric | Description | Notes |
|---|---|---|
| `BUSINESS_IMPRESSIONS_DESKTOP_MAPS` | Views on Google Maps (desktop) | Deduplicated per user per day |
| `BUSINESS_IMPRESSIONS_MOBILE_MAPS` | Views on Google Maps (mobile) | Deduplicated per user per day |
| `BUSINESS_IMPRESSIONS_DESKTOP_SEARCH` | Views on Google Search (desktop) | Deduplicated per user per day |
| `BUSINESS_IMPRESSIONS_MOBILE_SEARCH` | Views on Google Search (mobile) | Deduplicated per user per day |
| `BUSINESS_DIRECTION_REQUESTS` | Direction requests tapped on Maps | Counts each request event |
| `CALL_CLICKS` | Taps on the phone number / call button | Counts each tap |
| `WEBSITE_CLICKS` | Taps on the website link | Counts each click |
| `BUSINESS_BOOKINGS` | Bookings via Reserve with Google | Only non-zero if Reserve with Google is enabled |
| `BUSINESS_FOOD_ORDERS` | Food orders via the profile | Only relevant for food businesses |
| `BUSINESS_FOOD_MENU_CLICKS` | Taps on the food menu | Deduplicated per user per day |
| `BUSINESS_CONVERSATIONS` | Message threads started via profile | Only non-zero if messaging is enabled |

**Availability notes for Talas locations (auto parts, non-food):**
- `BUSINESS_BOOKINGS` and `BUSINESS_FOOD_ORDERS` return `0` — no booking/food integration
- `BUSINESS_CONVERSATIONS` returns `0` unless GBP messaging is turned on for the location
- `BUSINESS_FOOD_MENU_CLICKS` returns `0` for non-food categories

The actionable metrics for Talas are:
`WEBSITE_CLICKS`, `CALL_CLICKS`, `BUSINESS_DIRECTION_REQUESTS`,
`BUSINESS_IMPRESSIONS_DESKTOP_MAPS`, `BUSINESS_IMPRESSIONS_MOBILE_MAPS`,
`BUSINESS_IMPRESSIONS_DESKTOP_SEARCH`, `BUSINESS_IMPRESSIONS_MOBILE_SEARCH`

#### How to Query

Use `fetchMultiDailyMetricsTimeSeries` to fetch multiple metrics in a single call (see section 7).
Use `getDailyMetricsTimeSeries` only when you need a single metric.

#### Date Range Limits

- Maximum date range per request: **18 months** (documented limit)
- Recommended maximum for performance: 90 days per call
- Data begins accumulating from the date the GBP listing was verified
- Data lags: most recent 2-3 days typically return `"0"` due to processing delay

Source: https://developers.google.com/my-business/reference/performance/rest/v1/locations/getDailyMetricsTimeSeries

---

### 7. fetchMultiDailyMetricsTimeSeries

#### Correct Method Name

The method is `fetchMultiDailyMetricsTimeSeries` — a GET request with repeated query parameters.

**There is no `fetchMultiDailyMetrics` POST endpoint.** If you see that name in older notes
or code comments, it is incorrect. The only documented endpoint is:

```
GET https://businessprofileperformance.googleapis.com/v1/{location}:fetchMultiDailyMetricsTimeSeries
```

Source: https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries

#### Request Shape

Path parameter: `{location}` = `locations/17303088970776446827` (no account prefix)

Query parameters with repeated `dailyMetrics=` for each metric:
```
?dailyMetrics=WEBSITE_CLICKS
&dailyMetrics=CALL_CLICKS
&dailyMetrics=BUSINESS_DIRECTION_REQUESTS
&dailyMetrics=BUSINESS_IMPRESSIONS_DESKTOP_MAPS
&dailyMetrics=BUSINESS_IMPRESSIONS_MOBILE_MAPS
&dailyMetrics=BUSINESS_IMPRESSIONS_DESKTOP_SEARCH
&dailyMetrics=BUSINESS_IMPRESSIONS_MOBILE_SEARCH
&dailyRange.startDate.year=2026
&dailyRange.startDate.month=5
&dailyRange.startDate.day=1
&dailyRange.endDate.year=2026
&dailyRange.endDate.month=5
&dailyRange.endDate.day=31
```

In Python with `requests`, use a list of tuples (not a dict) to repeat the key:
```python
params = [
    ("dailyMetrics", "WEBSITE_CLICKS"),
    ("dailyMetrics", "CALL_CLICKS"),
    ("dailyMetrics", "BUSINESS_DIRECTION_REQUESTS"),
    ("dailyRange.startDate.year", 2026),
    ("dailyRange.startDate.month", 5),
    ("dailyRange.startDate.day", 1),
    ("dailyRange.endDate.year", 2026),
    ("dailyRange.endDate.month", 5),
    ("dailyRange.endDate.day", 31),
]
resp = requests.get(url, headers=headers, params=params)
```

Using a dict for `params` will only keep one `dailyMetrics` value. Always use a list of tuples.

#### Response Shape with timeSeries

```json
{
  "multiDailyMetricTimeSeries": [
    {
      "dailyMetricTimeSeries": [
        {
          "dailyMetric": "WEBSITE_CLICKS",
          "timeSeries": {
            "datedValues": [
              { "date": { "year": 2026, "month": 5, "day": 1 }, "value": "14" },
              { "date": { "year": 2026, "month": 5, "day": 2 }, "value": "9" }
            ]
          }
        },
        {
          "dailyMetric": "CALL_CLICKS",
          "timeSeries": {
            "datedValues": [
              { "date": { "year": 2026, "month": 5, "day": 1 }, "value": "3" },
              { "date": { "year": 2026, "month": 5, "day": 2 }, "value": "5" }
            ]
          }
        }
      ]
    }
  ]
}
```

**Parsing pattern:**
```python
def parse_multi_daily(response_json):
    results = {}
    outer = response_json.get("multiDailyMetricTimeSeries", [])
    for group in outer:
        for series in group.get("dailyMetricTimeSeries", []):
            metric = series["dailyMetric"]
            for dv in series.get("timeSeries", {}).get("datedValues", []):
                d = dv["date"]
                date_str = f"{d['year']}-{d['month']:02d}-{d['day']:02d}"
                value = int(dv.get("value", 0))  # value is a string; parse to int
                results.setdefault(date_str, {})[metric] = value
    return results
```

Key parsing notes:
- `value` is a **string** (`"14"`) not an integer — always use `int(dv.get("value", 0))`
- Days with no activity return `"value": "0"`, not `null` or absent
- The outer list (`multiDailyMetricTimeSeries`) has exactly one element in practice

---

### 8. Monthly Search Keywords

The search keywords endpoint reports which search terms drove impressions to a location in a
given calendar month.

#### Endpoint

```
GET https://businessprofileperformance.googleapis.com/v1/{parent}/searchkeywords/impressions/monthly
```

Where `{parent}` = `locations/17303088970776446827`

#### Date Range Format

Unlike daily metrics which use `dailyRange`, this endpoint uses `monthlyRange`:

```
?monthlyRange.startMonth.year=2026
&monthlyRange.startMonth.month=3
&monthlyRange.endMonth.year=2026
&monthlyRange.endMonth.month=5
```

Only `year` and `month` fields are used (no `day`). The range is **inclusive** of both endpoints.

#### Response Shape

```json
{
  "searchKeywordsCounts": [
    {
      "searchKeyword": "tesla parts dubai",
      "insightsValue": {
        "value": "42",
        "threshold": "15"
      }
    },
    {
      "searchKeyword": "used tesla bumper",
      "insightsValue": {
        "value": "28",
        "threshold": "15"
      }
    }
  ],
  "nextPageToken": "..."
}
```

**Response field notes:**
- `searchKeyword` — the search term string (lowercased)
- `insightsValue.value` — impression count as a **string** (parse with `int()`)
- `insightsValue.threshold` — minimum count threshold; keywords with counts below this value
  have their count replaced with the threshold string instead of the real value. If `value`
  equals `threshold`, the real count may be lower than reported.
- Results are ordered by impression count descending
- Pagination: use `pageToken` / `nextPageToken` to fetch all pages

**Limitations:**
- Data is **monthly** — no daily breakdown available for keywords
- Maximum lookback: 6 months from current date
- Keywords with fewer than approximately 15 impressions in the period are suppressed entirely

Source: https://developers.google.com/my-business/reference/performance/rest/v1/locations.searchkeywords.impressions.monthly/list

---

### 9. Local Posts

Local posts appear in Google Search and Maps results as cards below the business listing.
They are on the **legacy v4 API** at `mybusiness.googleapis.com`.

#### Post Types (`topicType`)

| Type | Use Case | Required Extra Fields |
|---|---|---|
| `STANDARD` | General updates, news, announcements | `summary` |
| `EVENT` | Dated events with schedule | `summary`, `event` (title + schedule) |
| `OFFER` | Promotions and discount codes | `summary`, `event` (title + schedule), optionally `offer` |
| `ALERT` | Emergency / COVID notices | `summary`, `alertType` |

#### Required Fields Per Type

**STANDARD:**
```json
{
  "topicType": "STANDARD",
  "summary": "Post text (max approx. 1500 chars)"
}
```

**EVENT:**
```json
{
  "topicType": "EVENT",
  "summary": "Post text",
  "event": {
    "title": "Event name",
    "schedule": {
      "startDate": { "year": 2026, "month": 7, "day": 1 },
      "startTime": { "hours": 8, "minutes": 0 },
      "endDate": { "year": 2026, "month": 7, "day": 7 },
      "endTime": { "hours": 18, "minutes": 0 }
    }
  }
}
```

**OFFER:**
```json
{
  "topicType": "OFFER",
  "summary": "Promotion description",
  "event": {
    "title": "Offer name",
    "schedule": { "startDate": {...}, "endDate": {...}, "startTime": {...}, "endTime": {...} }
  },
  "offer": {
    "couponCode": "SAVE10",
    "redeemOnlineUrl": "https://shop.talas.ae/?branch=QZ3",
    "termsConditions": "One per customer."
  }
}
```

**ALERT:**
```json
{
  "topicType": "ALERT",
  "summary": "We are open during the public holiday.",
  "alertType": "COVID_19"
}
```

Note: `ALERT` posts with `alertType: "COVID_19"` may be the only valid alert type available.
Google has not documented other `alertType` values.

#### `topicType` Enum

Values: `LOCAL_POST_TOPIC_TYPE_UNSPECIFIED`, `STANDARD`, `EVENT`, `OFFER`, `ALERT`

#### `state` Enum

| Value | Meaning |
|---|---|
| `LOCAL_POST_STATE_UNSPECIFIED` | Default/unknown |
| `REJECTED` | Violates policy; not shown publicly |
| `PROCESSING` | Submitted; under moderation review |
| `LIVE` | Visible on Google Search and Maps |
| `SCHEDULED` | Set to go live at a future time |
| `RECURRING` | Repeating post |

#### Media Attachment

Add `media` array to any post type:
```json
"media": [
  {
    "mediaFormat": "PHOTO",
    "sourceUrl": "https://cdn.talas.ae/photos/stock-photo.jpg"
  }
]
```

Constraints:
- `sourceUrl` must be **publicly accessible** without authentication
- Supports `PHOTO` (JPEG, PNG) and `VIDEO` (MP4)
- One media item per post (only the first item is used by most surfaces)

Source: https://developers.google.com/my-business/reference/rest/v4/accounts.locations.localPosts/create

---

### 10. Media Management

GBP media (photos and videos) are managed via the v4 API.

#### MediaItem Schema

```json
{
  "name": "accounts/111222333444/locations/17303088970776446827/media/AF1QipXXXXXXXXXXX",
  "mediaFormat": "PHOTO",
  "locationAssociation": {
    "category": "EXTERIOR"
  },
  "googleUrl": "https://lh3.googleusercontent.com/p/AF1QipXXXX",
  "thumbnailUrl": "https://lh3.googleusercontent.com/p/AF1QipXXXX=s1080",
  "createTime": "2026-04-01T12:00:00.000Z",
  "dimensions": {
    "widthPixels": 4032,
    "heightPixels": 3024
  },
  "insights": {
    "viewCount": "127"
  },
  "attributionData": {
    "profileName": "Mohammed Al Rashid",
    "profilePhotoUrl": "https://lh3.googleusercontent.com/a-/XXXXX"
  }
}
```

#### `sourceUrl` vs `googleUrl`

| Field | Type | Purpose |
|---|---|---|
| `sourceUrl` | string | **Input only** — URL you provide when uploading media |
| `googleUrl` | string | **Output only** — Google-hosted URL after processing |

When creating a media item, supply `sourceUrl` (must be public). After creation, use
`googleUrl` for display. Do not attempt to upload to `googleUrl`.

#### `mediaFormat`

| Value | Description |
|---|---|
| `MEDIA_FORMAT_UNSPECIFIED` | Default; do not use |
| `PHOTO` | JPEG or PNG image |
| `VIDEO` | MP4 video |

#### Media Categories (`locationAssociation.category`)

| Value | Use |
|---|---|
| `EXTERIOR` | Outside storefront, signage, parking |
| `INTERIOR` | Inside the store |
| `PRODUCT` | Products being sold |
| `AT_WORK` | Staff, work environment |
| `COMMON_AREA` | Waiting areas, showroom |
| `TEAMS` | Team photos |
| `ADDITIONAL` | Miscellaneous |
| `COVER` | Profile cover photo (one per location) |
| `PROFILE` | Profile logo/identity photo |

For Talas, use `EXTERIOR`, `INTERIOR`, `PRODUCT`, and `ADDITIONAL` primarily.

#### Create Media Item

```
POST https://mybusiness.googleapis.com/v4/{locationName}/media
```

Body:
```json
{
  "mediaFormat": "PHOTO",
  "locationAssociation": { "category": "PRODUCT" },
  "sourceUrl": "https://cdn.talas.ae/photos/tesla-bumper-sku-1234.jpg"
}
```

#### List Media Items

```
GET https://mybusiness.googleapis.com/v4/{locationName}/media
    ?pageSize=100
```

---

### 11. Error Patterns

#### Common Errors and Causes

| HTTP Code | gRPC Status | Typical Cause | Fix |
|---|---|---|---|
| 400 | `INVALID_ARGUMENT` | Missing required field (e.g. `readMask`), invalid field name, bad enum value | Check field names against API reference; add `readMask` |
| 401 | `UNAUTHENTICATED` | OAuth token expired or missing | Refresh token with `./gads auth refresh` |
| 403 | `PERMISSION_DENIED` | Token lacks `business.manage` scope, OR API allowlist not approved | Check scope; if scope OK, apply for API access |
| 404 | `NOT_FOUND` | Resource name wrong format, resource doesn't exist, or location not under this account | Verify resource name format (v4 vs v1 differ) |
| 429 | `RESOURCE_EXHAUSTED` | Zero quota (allowlist not approved) OR rate limit | If consistent 429, it's zero quota; apply for access |
| 500 | `INTERNAL` | Google-side error | Retry with backoff; if persistent, check Google Cloud Status |

#### PERMISSION_DENIED Without Allowlist

When the allowlist is not approved, API calls may return `PERMISSION_DENIED` or `RESOURCE_EXHAUSTED`
depending on which API and method you call. Do not assume `PERMISSION_DENIED` means only a scope
problem — check the allowlist approval status first.

```json
{
  "error": {
    "code": 403,
    "message": "The caller does not have permission",
    "status": "PERMISSION_DENIED",
    "details": [
      {
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "GBP_RESTRICTED_API",
        "domain": "mybusiness.googleapis.com"
      }
    ]
  }
}
```

If you see `GBP_RESTRICTED_API` in the error details, this is specifically the allowlist gate.

#### INVALID_ARGUMENT for Bad Fields

The most common `INVALID_ARGUMENT` errors in the Business Information API:

1. **Missing `readMask`** on `locations.list` or `locations.get`:
   ```
   "error": { "message": "Request contains an invalid argument.", "status": "INVALID_ARGUMENT" }
   ```
   Fix: add `?readMask=name,title,storeCode,...`

2. **Invalid field in `readMask`** — field name typo or field not available for the resource type

3. **Invalid metric name** in `dailyMetrics` parameter — typo in enum value

4. **`media.sourceUrl` not publicly accessible** for local posts or media uploads

#### Retry Pattern

For transient errors (5xx, intermittent 429):

```python
import time
import random

def api_call_with_retry(fn, max_retries=3):
    for attempt in range(max_retries):
        try:
            return fn()
        except requests.HTTPError as e:
            if e.response.status_code in (500, 502, 503, 504):
                if attempt < max_retries - 1:
                    backoff = (2 ** attempt) + random.uniform(0, 1)
                    time.sleep(backoff)
                    continue
            raise  # 4xx or final attempt: re-raise
```

Do NOT retry `400 INVALID_ARGUMENT` or `403 PERMISSION_DENIED` — these require code or config fixes.
Do NOT retry `429` from zero quota — retrying wastes time; only approval resolves it.

---

### 12. Ads Integration

GBP locations can be linked to Google Ads campaigns to enable **location extensions** (now called
"location assets"), which append the business address, phone, and a directions link to ads.

#### How GBP Location Extensions Link to Google Ads

The link is established in Google Ads, not in GBP directly. In the Google Ads API:

1. The GBP location is represented as a `LocationAsset` under the `Asset` resource.
2. Assets are linked to campaigns via `CampaignAsset` or to the account via `CustomerAsset`.

#### Asset Resource — location_asset

A `LocationAsset` in Google Ads stores the GBP place ID and links to the location:

```json
{
  "resourceName": "customers/3552856345/assets/123456789",
  "type": "LOCATION",
  "locationAsset": {
    "placeId": "ChIJXXXXXXXXXXXXXXXXXXXX",
    "locationOwnershipType": "BUSINESS_OWNER"
  }
}
```

The `placeId` corresponds to the GBP location's `metadata.placeId` field.

#### Linking the GBP Account to Google Ads

Before location assets can be used in ads, the GBP account must be linked to the Google Ads
account. This is done in the Google Ads UI (Tools and Settings > Linked accounts > Google Business
Profile) or via the Google Ads API `CustomerLink` resource. Once linked, location assets become
available automatically.

#### callout_asset

Separate from location assets, callout assets are short text snippets that appear below the ad:

```json
{
  "resourceName": "customers/3552856345/assets/987654321",
  "type": "CALLOUT",
  "calloutAsset": {
    "calloutText": "Genuine Tesla Parts"
  }
}
```

Callout assets can be created via the gads CLI:
```bash
./gads asset callout "Genuine Tesla Parts"
./gads asset callout "Same Day UAE Delivery"
```

#### GAQL Query for Location Asset Performance

```sql
SELECT
  asset.resource_name,
  asset.type,
  asset.location_asset.place_id,
  metrics.clicks,
  metrics.impressions,
  metrics.all_conversions
FROM
  campaign_asset
WHERE
  asset.type = 'LOCATION'
  AND segments.date DURING LAST_30_DAYS
```

Use `./gads gbp ads-perf` or `./gads gbp ads-daily` for pre-built versions of this query.

---

### 13. Best Practices

#### Batch Operations

**GBP does not support batch mutation** in the same way as Google Ads. There is no
`batchMutate` for GBP resources. Each mutation (patch location, update reply, create post) is
a separate HTTP call.

For reading, prefer fetching multiple locations with a single `locations.list` call (up to
`pageSize=100`) rather than individual `locations.get` calls per location.

For performance metrics, use `fetchMultiDailyMetricsTimeSeries` to fetch all needed metrics
in one call instead of one `getDailyMetricsTimeSeries` call per metric.

#### Quota Limits

**Published limit: 300 QPM** by default for Account Management, Business Information and
Performance, plus per-method QPD caps and a non-increasable 10 edits/min per profile — see the
"Quotas & Rate Limits" table earlier in this file (verified 2026-09-04 against
https://developers.google.com/my-business/content/limits). The earlier "not published" claim in
this file was incorrect. Additional observed practical limits from the field:
- Bulk listing operations: pause approximately 1 second between pages when fetching many pages
- Mutation operations (PATCH, PUT, POST): do not send more than 1 per second per location
- Reviews pagination: 50 reviews per page is the max; paginate sequentially

#### Field Masks for Partial Updates

When using PATCH on a location, always supply `updateMask` to avoid accidentally overwriting
fields you did not intend to change:

```
PATCH https://mybusinessbusinessinformation.googleapis.com/v1/{location.name=locations/*}
      ?updateMask=websiteUri,regularHours
```

Without `updateMask`, the entire resource is replaced with the request body, wiping fields
you omit. With `updateMask`, only the listed fields are updated.

Comma-separate field paths for nested fields: `phoneNumbers.primaryPhone,websiteUri`

For attributes, always use `updateMask=attributes` and supply the complete attributes list
(see section 3 — there is no patch-one-attribute shortcut).

#### Verification States

A location's verification state affects what you can do via the API:

| State | What works | What does not work |
|---|---|---|
| `VERIFIED` | All operations | N/A |
| `UNVERIFIED` | Read operations, some metadata updates | Reviews (list/reply), posts, attribute updates |
| `VERIFICATION_REQUESTED` | Read operations | Same as UNVERIFIED |

Check `metadata.canOperateLocalPost` and related flags in the Location object before
attempting post or review operations. If these flags are `false`, the operation will fail
with `403 PERMISSION_DENIED`.

Field flags in `metadata` that gate operations:
- `canDelete` — whether this location can be deleted
- `canOperateLocalPost` — whether local posts can be created/managed
- `canModifyServiceList` — whether service list can be updated
- `canHaveFoodMenus` — false for auto parts stores
- `canOperateHealthData` — false for non-health categories
- `canOperateLodgingData` — false for non-lodging categories
- `hasPendingEdits` — whether Google has suggested edits awaiting owner review

If `hasPendingEdits` is `true`, call `getGoogleUpdated` to see what Google has changed:
```
GET https://mybusinessbusinessinformation.googleapis.com/v1/{name=locations/*}:getGoogleUpdated
    ?readMask=name,title,phoneNumbers,categories,storefrontAddress
```

**Suspension / "voice of merchant" state lives in a separate API (not `metadata`):** the legacy v4
`LocationState` object (which used to carry suspension and detailed verification fields) was removed
during the original v1 migration. Most of its fields moved into Business Information's `metadata`
(the flags above), but the detailed suspension/voice-of-merchant fields moved to a dedicated
**My Business Verifications API** (`mybusinessverifications.googleapis.com`, v1 — not currently used
by gads-cli):
```
GET https://mybusinessverifications.googleapis.com/v1/{name=locations/*}/VoiceOfMerchantState
```
Also on that API: `locations.fetchVerificationOptions` and `locations.verify` (start a verification).
Not implemented in the CLI as of July 2026 — Talas locations are already verified, so this is low
priority, but reach for this API (not Business Information) if a "why can't I mutate this location"
question turns out to be a suspension/voice-of-merchant problem rather than a plain `VERIFIED`/
`UNVERIFIED` one.

Sources:
- https://developers.google.com/my-business/reference/businessinformation/rest/v1/locations/patch
- https://developers.google.com/my-business/reference/businessinformation/rest/v1/locations/getGoogleUpdated
- https://developers.google.com/my-business/reference/performance/rest/v1/locations/fetchMultiDailyMetricsTimeSeries
- https://developers.google.com/my-business/reference/verifications/rest — Verifications API (voice-of-merchant/suspension state)
- https://developers.google.com/my-business/content/businessinformation/change-log — documents the `LocationState` → `metadata` + Verifications API split
