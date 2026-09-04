# gads CLI — External API Knowledge Base

Documentation-sourced reference for every external Google API the `gads` CLI talks to.
Each KB file is built from **official Google docs fetched on 2026-06-23** (not training memory);
every endpoint/version/claim cites a source URL, and anything that couldn't be doc-verified is
marked `(unverified)`.

Machine-readable summary: [`manifest.json`](./manifest.json).

## APIs

| # | API | KB file | Current version | Status / key sunset |
|---|-----|---------|-----------------|----------------------|
| 1 | **Google Ads REST API** | [google-ads.md](./google-ads.md) | v24.1 GA (v24.2 announced); CLI default `v24` | Active. No per-version sunset dates published; versions typically supported ~12 months. **Customer Match offline uploads change April 1 2026** (token must have a prior successful Customer Match request). |
| 2 | **Merchant API** (new) | [merchant-api.md](./merchant-api.md) | v1 GA | Active. v1beta **discontinued 2026-02-28**. Legacy Content API for Shopping **v2.1 sunsets 2026-08-18** — migrate before then. |
| 3 | **GA4 Data + Admin APIs** | [ga4.md](./ga4.md) | Data API v1beta (stable); Admin API v1beta (stable). CLI uses Data v1beta + Admin **v1beta** for key events (migrated from v1alpha in v3.8.0). | Active. No sunset announced. |
| 4 | **Google Business Profile** (suite) | [gbp.md](./gbp.md) | Account Mgmt v1, Business Information v1, Performance v1 (all active); legacy My Business v4 for Reviews/Posts | Mixed. v1 APIs active. Legacy **v4 Reviews/Posts still active, no sunset announced**; most other v4 resources already sunset. API access requires **allowlist approval** (un-allowlisted projects get HTTP 429 at 0 quota). |
| 5 | **Search Console API** | [search-console.md](./search-console.md) | `webmasters/v3` REST endpoints (active); discovery name now `searchconsole` v1; URL Inspection on `searchconsole.googleapis.com/v1` | Active. The `webmasters` → `searchconsole` rename was discovery-level only; REST URLs unchanged. CLI's `webmasters/v3` base is correct. |
| 6 | **Data Manager API** | [data-manager-api.md](./data-manager-api.md) | v1.7 (2026-05-28); CLI calls the unversioned-minor `/v1/` path | Active. GA since v1.3 (2025-10-06). Modern replacement path for offline conversion/audience uploads — see Known Limitation in the KB file: response is async, `{requestId}`-only, no per-event/-member status. |

## OAuth scopes at a glance

| API | Scope(s) |
|-----|----------|
| Google Ads | `https://www.googleapis.com/auth/adwords` |
| Merchant API | `https://www.googleapis.com/auth/content` |
| GA4 | `analytics.readonly` (reads); `analytics.edit` (Admin key-event writes) |
| GBP | `https://www.googleapis.com/auth/business.manage` |
| Search Console | `webmasters.readonly` (reads); `webmasters` (writes) |
| Data Manager API | `https://www.googleapis.com/auth/datamanager` |

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

- **Google Ads:** conversion adjustment upload, `GoogleAdsFieldService` (GAQL field compatibility), audience definition service, PMax asset group *mutation* (create/update/remove asset groups, signals, listing group filters — still write-gap). **Resolved:** `uploadClickConversions` / `uploadCallConversions` (legacy ConversionUploadService, still supported) now sit alongside the modern **Data Manager API** path (`gads data-manager conversion-ingest` / `audience-upload` — see [data-manager-api.md](./data-manager-api.md)); the two are parallel, not a replacement — legacy `conversion upload` / `audience upload` are unchanged and still the only paths with synchronous-ish feedback (partialFailureError / job-status polling). **Resolved (2026-09-04):** PMax read-only reporting — `gads pmax asset-groups|signals|listing-groups|search-terms` (see google-ads.md DG-7 "Reading PMax asset groups, signals, listing groups, search-term insights").
- **Merchant API:** dataSource fileUploads status.
- **GA4:** `runFunnelReport`, Admin `keyEvents.patch`.
- **GBP:** Google-suggested location updates. **Resolved:** `fetchMultiDailyMetricsTimeSeries` correct method name now documented in gbp.md Developer Guide.
- **Search Console:** Remaining gaps (`startRow` pagination, `dataState`, `dimensionFilterGroups`) documented in search-console.md Developer Guide. URL Inspection (`gsc_url_inspect`) and sitemaps (`gsc_list_sitemaps`) are now implemented in `gads_lib/gsc.py`.

## Notes on verification

- **Google Ads sunset-dates table:** the page exists but the dates table content was not extractable from the fetch — marked `(unverified)` in google-ads.md.
- All other version/status claims were confirmed against the cited doc URLs on 2026-06-23.

## Sister tool

This `gads-cli/kb/` is the Google-side counterpart of **[`mads-cli/kb/`](../../mads-cli/kb/INDEX.md)**
— the same documentation-sourced, source-cited knowledge-base convention applied to Meta
(Facebook/Instagram) Ads: Marketing API, Graph API (Business Manager/Pages/Webhooks), Conversions
API (CAPI), and Commerce Manager Catalog, instead of Google Ads/GA4/GBP/Merchant Center/Search
Console. Consult `mads-cli/kb/` for Meta-side APIs; this directory is Google-only. Sister CLI:
https://github.com/talas9/mads-cli
