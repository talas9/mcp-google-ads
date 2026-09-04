# Data Manager API

> Implementation-grade reference for `gads data-manager conversion-ingest` / `gads data-manager
> audience-upload` (`gads_lib/datamanager.py`). Schemas verified against official Google reference
> pages fetched 2026-07-02; version/quota figures per the confirmed facts supplied at build time
> (not independently re-fetched — flagged below).

---

## Status & Versions

| Version | Status |
|---------|--------|
| v1.8    | **Current (2026-07-30)** |
| v1.7    | 2026-05-28 |
| v1.3    | First GA release (2025-10-06) |

`gads-cli` calls the unversioned-minor `v1` path segment (`https://datamanager.googleapis.com/v1/...`)
— minor releases (v1.3 → v1.7) are additive/non-breaking on the same `/v1/` URL, matching the same
pattern documented for Google Ads REST minor versions in `google-ads.md`.

**Note on sourcing:** the version table above was re-verified on **2026-09-04** against
`https://developers.google.com/data-manager/api/reference` (release-notes page) — v1.8 dated
2026-07-30 is current, superseding the v1.7 figure this file previously carried. The quota figures
below were supplied as pre-verified facts at build time and were **not** re-fetched on 2026-09-04. The request/response **schemas** in this document (Destination, Event,
AudienceMember, UserData, UserIdentifier, Consent, Encoding) were fetched directly from
`developers.google.com/data-manager/api/reference/rest/v1/*` on 2026-07-02 and are current as of
that fetch.

---

## Base URL

```
https://datamanager.googleapis.com/v1
```

No customer/account ID in the URL path — unlike the Google Ads REST API
(`googleads.googleapis.com/{version}/customers/{CID}/...`), the target Google Ads account is
identified **inside the JSON request body** via the `Destination.operatingAccount` /
`loginAccount` objects (see below), not the URL.

Two top-level methods used by this CLI:

| Method | HTTP | gads-cli function |
|--------|------|--------------------|
| `events:ingest` | `POST /v1/events:ingest` | `datamanager_ingest_events()` |
| `audienceMembers:ingest` | `POST /v1/audienceMembers:ingest` | `datamanager_ingest_audience_members()` |

**Casing note:** the audience endpoint is `audienceMembers:ingest` (camelCase `M`), not
`audiencemembers:ingest` — verified directly against the REST method-index page
(`developers.google.com/data-manager/api/reference/rest`) on 2026-07-02.

Two adjacent methods exist but are **not implemented** by this CLI: `adEvents:ingest` (a separate,
narrower ad-event path) and `audienceMembers:remove` / `requestStatus:retrieve` (no current use
case in this account).

---

## Auth / OAuth Scopes

| Scope | Services | How to pass |
|-------|---------|-------------|
| `https://www.googleapis.com/auth/datamanager` | All Data Manager API endpoints | `Authorization: Bearer {token}` header |

**No `developer-token` or `login-customer-id` HTTP header** — Data Manager calls use only a bearer
token (`get_bearer_headers()` in `gads_lib/http.py`, the same pattern already used for
GBP/Merchant/GA4/GSC — NOT `get_ads_headers()`, which is Ads-REST-specific). The MCC "acting as"
relationship that `login-customer-id` expresses for the Ads REST API is instead expressed **inside
the JSON body** via `Destination.loginAccount` (see Destination schema below).

`gads-cli` adds this scope to the shared, unified OAuth client (`generate_token.py`'s `SCOPES`
list) rather than standing up a second credential set / GCP project — confirmed viable via
`gcloud services enable datamanager.googleapis.com --project <existing project>` succeeding with no
dedicated-project error. **Existing tokens must be regenerated** (`python generate_token.py`) to
pick up the new scope before Data Manager calls will succeed; a 403
`INSUFFICIENT_AUTHENTICATION_SCOPES` on a `datamanager.googleapis.com` URL is what a stale token
looks like (see `gads_lib/output.py::classify_api_error`'s `datamanager` branch).

Source: https://developers.google.com/data-manager/api/reference/rest/v1/events/ingest (Authorization
section, fetched 2026-07-02); https://developers.google.com/data-manager/api/reference/rest/v1/audienceMembers/ingest
(fetched 2026-07-02).

---

## Quotas

| Limit | Value |
|-------|-------|
| Requests / day | 100,000 |
| Requests / minute (IngestionService) | 300 |
| Max `Event` objects per `events:ingest` request | 2,000 |
| Max `AudienceMember` objects per `audienceMembers:ingest` request | 10,000 |
| Max `UserIdentifier` entries per `UserData` (per Event or AudienceMember) | 10 |
| Max destinations per event/member reference | 10 |

`gads_lib/datamanager.py` enforces the 2,000/10,000 per-request caps client-side
(`MAX_EVENTS_PER_REQUEST`, `MAX_AUDIENCE_MEMBERS_PER_REQUEST`) and raises `ValueError` before any
HTTP call if a caller hands it more than that in one call. The `gads data-manager conversion-ingest`
CLI command chunks a larger JSON-lines file into multiple `--batch-size`-sized calls automatically;
`gads data-manager audience-upload` currently sends the whole parsed CSV as one call and hard-fails
(no chunking) if it exceeds 10,000 rows.

---

## Developer Guide

### `events:ingest` request schema

```json
{
  "destinations": [ { "Destination object" } ],
  "events": [ { "Event object" } ],
  "consent": { "Consent object" },
  "validateOnly": false,
  "encoding": "HEX",
  "encryptionInfo": { "EncryptionInfo object" }
}
```

- **destinations[]** (required) — where the events go.
- **events[]** (required) — max 2,000 per request.
- **consent** (optional) — request-level consent applied to every event that doesn't set its own.
- **validateOnly** (optional) — when `true`, validates the request without executing it and returns
  errors only (not currently exposed via a CLI flag; the CLI's own `--dry-run` validates
  structurally client-side instead — see Known Limitation below for why these are different things).
- **encoding** — required whenever `UserData` (hashed PII) is present; `HEX` or `BASE64`
  (`ENCODING_UNSPECIFIED` is the invalid default). `gads_lib/datamanager.py` always hashes with
  `hashlib.sha256(...).hexdigest()` (hex), matching `HEX`.

#### `Destination` object

```json
{
  "reference": "string",
  "operatingAccount": { "accountId": "string", "accountType": "GOOGLE_ADS" },
  "loginAccount": { "accountId": "string", "accountType": "GOOGLE_ADS" },
  "linkedAccount": { "accountId": "string", "accountType": "GOOGLE_ADS" },
  "productDestinationId": "string"
}
```

- `operatingAccount` (**required**) — the account the data lands in. `gads_lib/datamanager.py` sets
  this to `GOOGLE_ADS_CUSTOMER_ID`.
- `loginAccount` (optional, defaults to `operatingAccount`) — the credential's "acting as" account.
  When `GOOGLE_ADS_LOGIN_CUSTOMER_ID` (MCC manager ID) is set, `gads_lib/datamanager.py` sends it
  here — the manager-access scenario from Google's own examples:

  ```json
  {
    "operatingAccount": { "accountId": "C2_CUSTOMER_ID", "accountType": "GOOGLE_ADS" },
    "loginAccount":     { "accountId": "M2_CUSTOMER_ID", "accountType": "GOOGLE_ADS" },
    "productDestinationId": "USER_LIST_ID"
  }
  ```
- `linkedAccount` — data-partner scenarios only (not used by this CLI).
- `productDestinationId` (**required**) — the object *within* the account to ingest into: a Google
  Ads **conversion action ID** for `events:ingest`, or a Customer Match **user-list ID** for
  `audienceMembers:ingest`. **Both are the bare numeric ID, not a
  `customers/{CID}/conversionActions/{ID}`-style resource name** — confirmed from Google's own
  examples (`"productDestinationId": "123456789"` for a conversion action). This is the opposite
  convention from the legacy Ads REST API (`ads_upload_click_conversions()` in `gads_lib/ads.py`
  takes a full resource name) — do not conflate the two when passing `--action-id` /
  `--list-resource-name`.

Source: https://developers.google.com/data-manager/api/devguides/concepts/destinations (fetched
2026-07-02); https://developers.google.com/data-manager/api/reference/rest/v1/Destination (fetched
2026-07-02).

#### `Event` object (key fields used by this CLI)

```json
{
  "destinationReferences": ["string"],
  "transactionId": "string",
  "eventTimestamp": "2026-01-01T10:00:00+04:00",
  "lastUpdatedTimestamp": "string",
  "userData": { "userIdentifiers": [ { "UserIdentifier object" } ] },
  "consent": { "Consent object" },
  "adIdentifiers": { "gclid": "string" },
  "currency": "AED",
  "eventSource": "WEB",
  "conversionValue": 30.03,
  "conversionCount": 1,
  "eventName": "string"
}
```

At most 2,000 `Event` objects per request (hard API limit, not just this CLI's default
`--batch-size`). Each event needs at least one identifier — a click ID (`gclid`/`gbraid`/`wbraid`
under `adIdentifiers`), session attributes, `userData`, or IP-based signal. `gads-cli`'s
`_load_and_validate_events()` additionally requires `eventTimestamp` on every line before
submitting (client-side structural check, not a documented API-level requirement, but omitting it
makes the conversion unattributable in practice).

### `audienceMembers:ingest` request schema

```json
{
  "destinations": [ { "Destination object" } ],
  "audienceMembers": [ { "AudienceMember object" } ],
  "consent": { "Consent object" },
  "validateOnly": false,
  "encoding": "HEX",
  "encryptionInfo": { "EncryptionInfo object" },
  "termsOfService": { "TermsOfService object" }
}
```

Max 10,000 `AudienceMember` objects per request.

#### `AudienceMember` object

```json
{
  "destinationReferences": ["string"],
  "consent": { "Consent object" },
  "userData": { "userIdentifiers": [ { "UserIdentifier object" } ] }
}
```

`AudienceMember` is a union type — besides `userData` it also supports `pairData` (data-partner PAIR
IDs), `mobileData` (advertising IDs), `userIdData` (advertiser-defined unique ID), `ppidData`
(publisher-provided ID), and `compositeData`. `gads-cli`'s `data-manager audience-upload` only ever
builds `userData` (from CSV Phone/Email columns) — the other four are not used.

### `UserData` / `UserIdentifier` (shared by `Event` and `AudienceMember`)

```json
{
  "userIdentifiers": [
    { "UserIdentifier object" }
  ]
}
```

Max 10 `UserIdentifier` entries per `UserData`. Each `UserIdentifier` is a **union** — exactly one
of:

```json
{ "emailAddress": "sha256-hex-or-base64-string" }
{ "phoneNumber": "sha256-hex-or-base64-string" }
{ "address": { "givenName": "sha256-hex", "familyName": "sha256-hex", "regionCode": "AE", "postalCode": "00000" } }
```

**Field names differ from the legacy Ads REST / `OfflineUserDataJobService` schema** —
`gads_lib/ads.py`'s `_build_user_op()` (used by the legacy `audience upload` command) emits
`hashedEmail` / `hashedPhoneNumber` / `addressInfo.{hashedFirstName,hashedLastName,countryCode}`.
Data Manager instead uses `emailAddress` / `phoneNumber` / `address.{givenName,familyName,
regionCode,postalCode}` — do not copy identifier objects between the two paths verbatim.

**Known limitation (this CLI, not the API):** `AddressInfo.givenName` / `familyName` / `regionCode`
/ `postalCode` are **all required** per the API reference. The CSV shape `gads data-manager
audience-upload` accepts (`Phone,Email,First Name,Last Name,Country` — the same shape as the legacy
`audience upload` command) carries no postal code, so `gads_lib/datamanager.py::build_user_identifiers()`
intentionally **never builds address-based identifiers** — only phone and email. Rows with neither a
usable phone nor email are skipped (counted and reported as `skipped_rows` in the command's output).

Source: https://developers.google.com/data-manager/api/reference/rest/v1/UserData (fetched
2026-07-02); https://developers.google.com/data-manager/api/reference/rest/v1/AudienceMember
(fetched 2026-07-02).

### `Consent`

```json
{
  "adUserData": "CONSENT_GRANTED",
  "adPersonalization": "CONSENT_GRANTED"
}
```

Enum `ConsentStatus`: `CONSENT_STATUS_UNSPECIFIED` | `CONSENT_GRANTED` | `CONSENT_DENIED`. Not
currently set by `gads_lib/datamanager.py` (no `--consent` flag on either CLI command yet) — a gap
to close before this path is relied on for EU/consent-mode-sensitive traffic; the legacy
`audience_upload_csv()` path in `gads_lib/ads.py` does set consent (`adUserData`/`adPersonalization`
= `"GRANTED"`, the *older* enum spelling) on every upload, so parity is worth adding here.

Source: https://developers.google.com/data-manager/api/reference/rest/v1/Consent (fetched
2026-07-02).

### `Encoding`

Enum: `ENCODING_UNSPECIFIED` | `HEX` | `BASE64`. `gads_lib/datamanager.py` hashes with
`hashlib.sha256(...).hexdigest()`, i.e. `HEX` — the request currently does not set the `encoding`
field explicitly (relying on it being optional / inferred); if Google's API starts requiring it
explicitly, add `"encoding": "HEX"` to both request payloads.

Source: https://developers.google.com/data-manager/api/reference/rest/v1/Encoding (fetched
2026-07-02).

### Response schema (both methods)

```json
{
  "requestId": "string",
  "fieldWarnings": [ { /* FieldWarning */ } ]
}
```

**Changed in v1.8 (2026-07-30):** the response is no longer `requestId`-only. `IngestEventsResponse`
and `IngestAudienceMembersResponse` both gained a `fieldWarnings` array of `FieldWarning` objects.
Verified 2026-09-04 against the live discovery document
`https://datamanager.googleapis.com/$discovery/rest?version=v1` (revision `20260828`), which shows
both properties on both schemas. `fieldWarnings` reports **non-blocking validation issues on
optional fields only** — it is not per-event success/failure. See Known Limitation below.

---

## ⚠️ Known Limitation — ingestion is asynchronous; the response carries no per-item outcome

**Both `events:ingest` and `audienceMembers:ingest` return `requestId` plus (since v1.8)
`fieldWarnings` on a 200 — and nothing else.** `fieldWarnings` flags optional-field validation
problems; it does **not** tell you which events were matched or ingested. There is still no
synchronous per-event or per-member success/failure detail in the response — unlike the
legacy Ads REST `uploadClickConversions` (`ads_upload_click_conversions()` in `gads_lib/ads.py`),
which returns a `partialFailureError` with per-conversion error detail in the same response, and
unlike `OfflineUserDataJobService` (`audience_upload_csv()`), whose job resource can be polled for a
terminal status (`gads audience job-status`).

**Practical consequence:** `gads data-manager conversion-ingest` and `gads data-manager
audience-upload` can only ever report *"N events/members submitted, ingestion is asynchronous, no
per-item status available in this response"* — never a false "✓ N conversions uploaded
successfully" claim. Both CLI commands are deliberately worded this way (see
`tests/test_gads.py::TestDataManagerConversionIngestCli::test_json_output_never_claims_per_event_success`).
The API *does* expose `POST /v1/requestStatus:retrieve` for looking up a `requestId`'s outcome
later — confirmed present in the live discovery document on 2026-09-04, and available since v1.3 —
but **gads-cli does not implement it** (open coverage gap; wiring it up would let the CLI report a
terminal ingestion status instead of only "submitted") — verify match/ingestion success indirectly, e.g. via `gads conversion perf` a day or
two later, the same attribution-lag caveat that already applies to every other conversion path in
this account.

---

## Sources

- Method reference (events): https://developers.google.com/data-manager/api/reference/rest/v1/events/ingest (fetched 2026-07-02)
- Method reference (audience members): https://developers.google.com/data-manager/api/reference/rest/v1/audienceMembers/ingest (fetched 2026-07-02)
- Method index (confirms exact `audienceMembers:ingest` casing + adjacent methods): https://developers.google.com/data-manager/api/reference/rest (fetched 2026-07-02)
- Destination concepts + worked examples (direct/manager/data-partner access): https://developers.google.com/data-manager/api/devguides/concepts/destinations (fetched 2026-07-02)
- Send-events guide (worked `events:ingest` request example): https://developers.google.com/data-manager/api/devguides/events/send-events (fetched 2026-07-02)
- `UserData` / `UserIdentifier` schema: https://developers.google.com/data-manager/api/reference/rest/v1/UserData (fetched 2026-07-02)
- `AudienceMember` schema: https://developers.google.com/data-manager/api/reference/rest/v1/AudienceMember (fetched 2026-07-02)
- `Consent` / `ConsentStatus` schema: https://developers.google.com/data-manager/api/reference/rest/v1/Consent (fetched 2026-07-02)
- `Encoding` enum: https://developers.google.com/data-manager/api/reference/rest/v1/Encoding (fetched 2026-07-02)
- Version/quota figures (v1.3 GA 2025-10-06, current v1.7 2026-05-28, 100k req/day, 300/min
  IngestionService, max 2000 events / 10000 audience members per request, max 10
  destinations/identifiers per event): supplied as pre-verified facts at build time, not
  independently re-fetched in this session — re-verify against
  https://developers.google.com/data-manager/api/reference and
  https://developers.google.com/data-manager/api/reference/limits before relying on exact figures
  in a compliance-sensitive context.
