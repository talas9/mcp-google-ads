# gads CLI — External API Knowledge Base

Documentation-sourced reference for every external Google API the `gads` CLI talks to.
Each KB file is built from **official Google docs** (not training memory); every endpoint/version/
claim cites a source URL, and anything that couldn't be doc-verified is marked `(unverified)`.
Original build 2026-06-23; **all six files re-verified against official docs fetched 2026-09-04**
(see "What changed in the 2026-09-04 pass" below).

Machine-readable summary: [`manifest.json`](./manifest.json).

## APIs

| # | API | KB file | Current version | Status / key sunset |
|---|-----|---------|-----------------|----------------------|
| 1 | **Google Ads REST API** | [google-ads.md](./google-ads.md) | **v25.1 GA (2026-08-19) is upstream latest**; CLI pins `v25` (the URL segment for that line) | Active. Per-version sunset dates **are** published: v23 → Feb 2027, v24 → May 2027, **v25 → Aug 2027** (v21 already sunset 2026-08-05). CLI is current with upstream as of 2026-09-04. **Customer Match offline-upload restriction has been IN FORCE since 2026-04-01** — token needs a prior successful Customer Match request; whether the Talas token qualifies is **unverified** (open risk). |
| 2 | **Merchant API** (new) | [merchant-api.md](./merchant-api.md) | v1 GA | Active. v1beta **discontinued 2026-02-28**. Legacy Content API for Shopping v2.1 **is already sunset (2026-08-18)** and has been returning progressive errors **since 2026-09-01** — gads-cli never called it, so no action. Reports sub-API uses **MCQL** (Merchant Center Query Language), *not* GAQL. |
| 3 | **GA4 Data + Admin APIs** | [ga4.md](./ga4.md) | Data API v1beta (stable, no v1 GA exists); Admin API v1beta (`preferred`). CLI uses Data v1beta + Admin **v1beta** for key events (migrated from v1alpha in v3.8.0). | Active. No sunset announced. **2026-09-04 re-check: zero drift** — versions, base URLs, scopes and the full quota table all matched. |
| 4 | **Google Business Profile** (suite) | [gbp.md](./gbp.md) | Account Mgmt v1, Business Information v1, Performance v1 (all active); legacy My Business v4 for Reviews/Posts | Mixed. v1 APIs active. Legacy **v4 Reviews/Posts still active, no sunset announced** (re-confirmed 2026-09-04); most other v4 resources already sunset. API access requires **allowlist approval** (un-allowlisted projects get HTTP 429 at 0 quota). **Quotas are published after all: 300 QPM default**, plus per-method QPD caps — a prior "not published" claim in the KB was wrong and is corrected. |
| 5 | **Search Console API** | [search-console.md](./search-console.md) | `searchconsole` v1; paths still `webmasters/v3/...`. **Canonical host is now `searchconsole.googleapis.com`** for *all* resources (discovery revision `20260902`), not just URL Inspection | Active. CLI still sends the legacy `www.googleapis.com/webmasters/v3` host — **still live** (both hosts answer 401, not 404, probed 2026-09-04), just no longer canonical. No deprecation notice for the legacy host found → whether it is ever retired is **unverified**. Row limit 25,000, `startRow` zero-based — unchanged. |
| 6 | **Data Manager API** | [data-manager-api.md](./data-manager-api.md) | **v1.8 (2026-07-30)**; CLI calls the unversioned-minor `/v1/` path | Active. GA since v1.3 (2025-10-06). Modern path for offline conversion/audience uploads. **v1.8 added `fieldWarnings` to both ingest responses**, so they are no longer `requestId`-only — but ingestion is still async with no per-event outcome. `requestStatus:retrieve` exists and is **not yet wired into the CLI** (coverage gap). |

## OAuth scopes at a glance

| API | Scope(s) |
|-----|----------|
| Google Ads | `https://www.googleapis.com/auth/adwords` |
| Merchant API | `https://www.googleapis.com/auth/content` |
| GA4 | `analytics.readonly` (reads); `analytics.edit` (Admin key-event writes) |
| GBP | `https://www.googleapis.com/auth/business.manage` |
| Search Console | `webmasters.readonly` (reads); `webmasters` (writes) |
| Data Manager API | `https://www.googleapis.com/auth/datamanager` |

## What changed in the 2026-09-04 pass

Every claim class (version, base URL, endpoint, field name, quota/limit, deprecation date, gotcha)
was re-checked against official Google pages and live discovery documents fetched that day.
Drift found and corrected:

| KB file | Drift corrected | Official source fetched 2026-09-04 |
|---------|-----------------|-------------------------------------|
| google-ads.md | Said v24.2 was latest and v25 unreleased. **v25 GA'd 2026-07-22, v25.1 GA'd 2026-08-19.** | developers.google.com/google-ads/api/docs/release-notes |
| google-ads.md | Said the per-version sunset table was client-rendered/unextractable and gave *inferred* dates. **The table is in static HTML**; real dates are v23 Feb 2027, v24 May 2027, v25 Aug 2027 — the inferences were ~1 month early. | developers.google.com/google-ads/api/docs/sunset-dates |
| google-ads.md | Said quota numbers were unavailable (cited a 404 path). **They are published** at `best-practices/quotas`: 2,880/day Explorer, 15,000/day Basic, 10,000 ops/mutate request, 100 action ops/request, 2,000 conversions/request, 1 QPS planning, 64 MB gRPC cap. | developers.google.com/google-ads/api/docs/best-practices/quotas |
| google-ads.md | Framed the Customer Match restriction as a future note. **It has been in force since 2026-04-01**; account exposure remains **unverified**. | developers.google.com/google-ads/api/docs/remarketing/audience-types/customer-match |
| merchant-api.md | Said Content API v2.1 "will be sunset". **It already was (2026-08-18), with progressive errors since 2026-09-01.** | developers.google.com/shopping-content/guides/quickstart |
| merchant-api.md | Called the reports query "SQL-like" without naming it. It is **MCQL**, a distinct language — not GAQL. | developers.google.com/merchant/api/guides/reports/query-language |
| data-manager-api.md | Said current version v1.7 and ingest responses are `requestId`-only. **v1.8 (2026-07-30) added `fieldWarnings`** to both ingest response schemas. | developers.google.com/data-manager/api/reference + live `$discovery/rest?version=v1` (rev `20260828`) |
| search-console.md | Said `www.googleapis.com/webmasters/v3` was the current base. **Discovery rev `20260902` makes `searchconsole.googleapis.com` canonical for all resources.** Legacy host still live. | live `discovery/v1/apis/searchconsole/v1/rest` |
| gbp.md | Said QPM values "are not published". **They are: 300 QPM default**, plus CreateLocation/SearchGoogleLocation 300 QPD, UpdateLocation 10,000 QPD, 10 edits/min per profile (non-increasable). | developers.google.com/my-business/content/limits |
| gbp.md | Access prerequisites listed 3 items. **There are 4** — the business must also have a website listed on the profile. | developers.google.com/my-business/content/prereqs |
| ga4.md | **No drift.** Versions, base URLs, scopes, keyEvents methods and the entire quota table matched. | live discovery directory + GA4 quotas page |

Verified but unchanged: Google Ads REST base-URL form; the GAQL resources behind the new `pmax`,
`report shopping`, `merchant report` and `keyword account-negative` commands (`asset_group`,
`asset_group_signal`, `asset_group_listing_group_filter`, `campaign_search_term_insight`,
`shopping_performance_view`, `shared_set`, `customer_negative_criterion`) — no v25/v25.1 breaking
changes to any of them; Merchant API v1 GA status and `reports:search` path; `product_performance_view`
having no cost field and FREE-traffic-only conversions; `products.list` pageSize default 25 / max 1000;
Data Manager base URL and scope; GBP v1/v4 base URLs, `fetchMultiDailyMetricsTimeSeries`, the 12
`DailyMetric` enum values, and v4 Reviews/localPosts paths; GSC 25,000-row cap and `startRow`.

## Open risks and unverified items

1. **Customer Match access (live risk, unresolved).** The 2026-04-01 restriction is in force. No
   Customer Match call has ever been made from the Talas developer token in any audit, so whether it
   is allowlisted is **unknown**. `gads audience upload` should be treated as at-risk until a live
   call proves otherwise; `gads data-manager audience-upload` is the fallback path.
2. ~~**gads-cli pins Google Ads v24 while upstream is v25.1.**~~ **RESOLVED 2026-09-04** — bumped to
   `v25` after a live A/B run (39 read-only commands + 22 fetch-script GAQL field lists, all
   byte-identical between `/v24/` and `/v25/`). Note `v25.1` is not a valid URL segment: only the
   major is. `gads doctor` now carries an `api_version_currency` check that warns when the pinned
   major falls behind the manifest's `latest_upstream_version`.
3. **GSC legacy host retirement date is unverified.** No deprecation notice exists today.
4. **GBP allowlist approval timing** ("7–10 business days, 4 days to 6 weeks") could not be
   re-verified from an official page.

## KB expansion status (v3.8.0)

Each KB file now contains both an **endpoint reference** section and a comprehensive **Developer Guide** section covering schemas, enums, workflows, limits, and best practices — sufficient for an LLM agent to implement against the API without re-fetching docs.

| KB file | Lines (v3.7.0 → v3.8.0) | New sections |
|---------|--------------------------|--------------|
| google-ads.md | 1,304 → 2,710 | Developer Guide: campaign creation, bidding, GAQL deep dive, RSA, PMax, Customer Match, error handling, pagination, rate limits |
| merchant-api.md | 1,471 → 2,508 | Developer Guide: product schema, feed types, shipping, Reports sub-API, inventories, MCA, error patterns |
| ga4.md | 1,088 → 1,961 | Developer Guide: report schema, filter expressions, key events, realtime, batch/pivot/compatibility, quota, Admin v1beta migration |
| gbp.md | 1,202 → 2,301 | Developer Guide: allowlist approval, attributes, reviews workflow, fetchMultiDailyMetricsTimeSeries, local posts, media, Ads integration |
| search-console.md | 692 → 1,243 | Developer Guide: Search Analytics schema, all dimensions/searchTypes, pagination, dimensionFilterGroups, URL Inspection, Sites/Sitemaps APIs |

## Top coverage gaps (feed the next "add support" task)

- **Data Manager:** `requestStatus:retrieve` (would let the CLI report a terminal ingestion status instead of only "submitted") — added to this list 2026-09-04.
- **Google Ads:** conversion adjustment upload, `GoogleAdsFieldService` (GAQL field compatibility), audience definition service, PMax asset group *mutation* (create/update/remove asset groups, signals, listing group filters — still write-gap). **Resolved:** `uploadClickConversions` / `uploadCallConversions` (legacy ConversionUploadService, still supported) now sit alongside the modern **Data Manager API** path (`gads data-manager conversion-ingest` / `audience-upload` — see [data-manager-api.md](./data-manager-api.md)); the two are parallel, not a replacement — legacy `conversion upload` / `audience upload` are unchanged and still the only paths with synchronous-ish feedback (partialFailureError / job-status polling). **Resolved (2026-09-04):** PMax read-only reporting — `gads pmax asset-groups|signals|listing-groups|search-terms` (see google-ads.md DG-7 "Reading PMax asset groups, signals, listing groups, search-term insights").
- **Merchant API:** dataSource fileUploads status.
- **GA4:** `runFunnelReport`, Admin `keyEvents.patch`.
- **GBP:** Google-suggested location updates. **Resolved:** `fetchMultiDailyMetricsTimeSeries` correct method name now documented in gbp.md Developer Guide.
- **Search Console:** Remaining gaps (`startRow` pagination, `dataState`, `dimensionFilterGroups`) documented in search-console.md Developer Guide. URL Inspection (`gsc_url_inspect`) and sitemaps (`gsc_list_sitemaps`) are now implemented in `gads_lib/gsc.py`.

## Notes on verification

- **Google Ads sunset-dates table:** resolved 2026-09-04 — the table is readable in static HTML and the real dates are now recorded in google-ads.md.
- All version/status claims were confirmed against the cited doc URLs on 2026-09-04 unless explicitly
  marked `(unverified)`; the items still unverified are enumerated under "Open risks" above.

## Sister tool

This `gads-cli/kb/` is the Google-side counterpart of **[`mads-cli/kb/`](../../mads-cli/kb/INDEX.md)**
— the same documentation-sourced, source-cited knowledge-base convention applied to Meta
(Facebook/Instagram) Ads: Marketing API, Graph API (Business Manager/Pages/Webhooks), Conversions
API (CAPI), and Commerce Manager Catalog, instead of Google Ads/GA4/GBP/Merchant Center/Search
Console. Consult `mads-cli/kb/` for Meta-side APIs; this directory is Google-only. Sister CLI:
https://github.com/talas9/mads-cli
