# Changelog

All notable changes to this project will be documented in this file.

## [3.12.0] - 2026-09-04

### Added

- **`gads campaign goals [--json]`** — reads the v25 unified goals schema: the account-level `goal` resource and per-campaign `campaign_goal_config` attachments, which replace the v24 `campaign_lifecycle_goal` / `customer_lifecycle_goal` resources removed in v25. gads-cli never referenced the removed resources (confirmed by grep before the `[3.11.0]` v24→v25 default bump), so the removal broke nothing here — this command is new coverage, not a migration fix. Verified live against the Talas account: one account goal (`goal_id 6547439698`, `NEW_CUSTOMER_ACQUISITION`, `additional_value = 7`), attached to campaign `23556258912` (`9-Search-HighIntent-Feb2026`) with `target_option = TARGET_ALL`.
- **`gads campaign migration [--json]`** — reads the two v25.1 AI Max auto-migration date fields, `campaign.aca_migration_date_time` and `campaign.broad_match_migration_date_time`. Both are absent from the API response entirely (not null/empty) when no migration is scheduled; the command prints `—` for those cases. Verified live: no Talas campaign currently has either field set.
- **`gads conversion perf` gained an `orig_value` column** — `metrics.original_conversion_value` (v25.1), the conversion value before conversion-value-rule adjustments. A gap versus the existing `value`/`metrics.conversions_value` column would indicate active value rules; verified live the two are currently equal for every conversion action on this account (no value rules in effect).
- **`kb/google-ads.md` DG-16** (new KB section) — full field reference for the v25/v25.1 additions above, produced from an authoritative live `GoogleAdsFieldService` diff (149 fields added, 11 removed vs v24). Also documents, as verified-not-applicable-here (so future refreshes don't re-investigate): Brand Lift / Conversion Lift (7 resources + ~60 metrics, no lift study configured), the lift-only `segments.country`/`country_localized_name`/`age_range`/`gender`/`experiment_arm` trap (selectable only with `lift_measurement_*`, despite the names, NOT general-purpose geo/demographic segments), YouTube/video-only fields (Talas runs no video campaigns), `ad_group_criterion.entity_bid.item_code` (empty `selectable_with`, not reportable at all), and `recommendation.campaign_specific_app_goal_recommendation` (app campaigns only). "Coverage vs Current gads-cli" updated to move `goal`/`campaign_goal_config`/the two migration fields/`metrics.original_conversion_value` from gaps to covered.

### Changed

- Test suite expanded from 415 → **428 tests**, all passing.
- Command count: 129 → **131 command paths** (125 distinct, up from 123) — `gads catalog --json` remains authoritative; README.md/CLAUDE.md/AGENTS.md/llms.txt updated accordingly.

### Notes

- `gads_lib/__init__.py::__version__` bumped `3.11.0` → `3.12.0`, with the pinned `tests/test_gads.py::TestVersion` assertion updated to match. `pyproject.toml` takes its version dynamically (`attr = "gads_lib.__version__"`) and needed no separate edit.
- The `campaign goals` table resolves whichever settings block a goal actually carries (`NEW_CUSTOMER_ACQUISITION`, `RETENTION`, or `LOYALTY_RETENTION`), rather than reading only the new-customer-acquisition block, so non-acquisition goal types render their real values instead of em-dashes.
- **`kb/google-ads.md` DG-16 updated: `goal`/`campaign_goal_config` confirmed READ-ONLY over REST (v24 and v25)** — a live probe found `goals:mutate` and `campaignGoalConfigs:mutate` both return an HTML 404 (not a JSON `GoogleAdsFailure`), with a `campaigns:mutate validateOnly=true` positive control proving the probe was live-authenticated, not misconfigured. `gads campaign goals` is confirmed to be, and remain, read-only; changing a goal requires the Ads UI. A gRPC-only write path was not tested (this client is REST-only). Also fills in the previously-incomplete `target_option` and `goal_type` enum lists, and records `additional_high_lifetime_value = 10` on the live account goal alongside the already-documented `additional_value = 7`. Docs-only — no code changed, so no version bump.

## [3.11.0] - 2026-09-04

### Changed

- **Google Ads API default bumped `v24` → `v25`** (`gads_lib/config.py`). v25 went GA 2026-07-22 and v25.1 on 2026-08-19; the CLI had been one major behind by choice. v25 sunsets **August 2027** (v24 would have sunset May 2027).
  - **Only the MAJOR is a URL path segment.** `GOOGLE_ADS_API_VERSION=v25.1` builds `https://googleads.googleapis.com/v25.1/...`, which Google answers with a **404 HTML error page**, not a JSON API error — verified live against the Talas account 2026-09-04. Minor releases ride the same `/v25/` path, so the CLI already serves v25.1 fields with no further change. The manifest records this explicitly in a new `url_path_segment` key.
  - **Validated by a live A/B run before the bump**, not by reading release notes alone: all 39 documented read-only commands, plus the 22 distinct GAQL field lists issued by the talas-ads fetch scripts (`tools/fetch_daily.py`, `tools/fetch_detail.py`, `tools/check_tracking_health.py`, `tools/full_performance_fetch.py`) were run under `/v24/` and `/v25/` and compared. Every result set was byte-identical once row order was normalised. The only textual deltas were the per-request `requestId` and the error-type URL (`...v24.errors.GoogleAdsFailure` → `...v25.errors...`).
  - Two apparent mismatches were chased to ground and were **not** version differences: `audit`'s Quality Score section drifted because live QS changed between the two sequential runs (a same-version re-run reproduced the change), and several `LIMIT`-without-`ORDER BY` queries returned different arbitrary samples (removing the `LIMIT` gave identical full sets).
  - None of the v25 breaking changes listed in the official release notes touch this CLI's surface. The removals target lifecycle goals, Local Services leads, reach/creator-insights planning, Demand Gen / video ad required fields, and deprecated keyword-plan forecast fields — none of which gads-cli reads or writes.

### Added

- **`gads doctor` now carries an `api_version_currency` check** (`gads_lib/kb.py::api_version_currency`), warning when the pinned Google Ads major is older than the manifest's `latest_upstream_version`. This closes a real blind spot: `gads kb check` compares the KB against the *code*, so it reports zero drift even when both are a major version behind Google — which is exactly the state this release fixes. The check degrades to `unknown` (never raises) on an unreadable manifest or an unparseable version, so `doctor` keeps working.

### Fixed

- **`gads gbp ads-perf --json` and `gads gbp ads-daily --json` crashed with `NameError: name 'json' is not defined`** (`gads_lib/cli.py`). Both `--json` branches called a bare `json.dumps`, but `cli.py` has no module-level `json` import — it uses a local `import json as _json` convention everywhere else. Every `--json` invocation of these two commands died with an unhandled traceback. Found while sweeping read-only commands for the v25 comparison. Both now use the local `_json` alias.

### Notes

- Test suite: 395 → **404 tests**, all passing. The one test that hardcoded `"v24"` in a mutate URL now asserts against `config.API_VERSION`, so it no longer needs editing on each version bump.
- **Downstream action required in the talas-ads repo:** `/home/talas9/talas-ads/.env` line 13 still sets `GOOGLE_ADS_API_VERSION=v24`, which overrides this new default. Until it is changed to `v25`, the CLI keeps calling `/v24/` and `gads kb check` exits non-zero. No other talas-ads change is needed — all its GAQL was validated clean against v25.

## [3.10.0] - 2026-07-02

### Added

- **Data Manager API support** (`gads_lib/datamanager.py`, new): `datamanager_ingest_events()` (POST `/v1/events:ingest`) and `datamanager_ingest_audience_members()` (POST `/v1/audienceMembers:ingest`), plus `build_user_identifiers()` reusing the existing SHA-256 phone/email hashing from `gads_lib/ads.py`. Uses `get_bearer_headers()` — no developer-token / login-customer-id headers; the MCC "acting as" relationship is instead expressed via `Destination.loginAccount` in the JSON body.
- **New `data-manager` command group** in `gads_lib/cli.py`:
  - `gads data-manager conversion-ingest EVENTS_PATH --action-id ID [--batch-size 2000] [--dry-run] [--yes] [--json]` — JSON-lines input (one Event object per line), auto-chunks into ≤2000-event batches, prints each batch's `requestId`. `--dry-run` validates structurally (event count, batch-size, required `eventTimestamp` field) with zero network calls.
  - `gads data-manager audience-upload CSV_PATH --list-resource-name NAME [--dry-run] [--yes] [--json]` — same CSV shape as `audience upload` (`Phone,Email,First Name,Last Name,Country`); a **new, parallel path** alongside the existing `audience upload` (OfflineUserDataJobService) command, not a replacement.
  - Both commands are **additive only** — the legacy `conversion upload` and `audience upload` commands are unchanged. Both are worded to never claim false per-event/-member success: the Data Manager API's response is asynchronous (`{"requestId": "..."}` only), so both commands report *"N submitted — ingestion is asynchronous, no per-item status available in this response"* instead.
- **`https://www.googleapis.com/auth/datamanager` OAuth scope** added to `generate_token.py`'s unified `SCOPES` list (same credential set as every other Google service this CLI talks to — verified via `gcloud services enable datamanager.googleapis.com` succeeding with no dedicated-project requirement). **Existing tokens must be regenerated** (`python generate_token.py`) to pick up the new scope.
- **`kb/data-manager-api.md`** (new) — full Developer Guide: `Destination`/`Event`/`AudienceMember`/`UserData`/`UserIdentifier`/`Consent`/`Encoding` schemas (verified against official reference pages), quotas, and a Known Limitation callout on the async `{requestId}`-only response. `kb/manifest.json` and `kb/INDEX.md` updated accordingly (OAuth-scopes table, coverage-gaps reword — Data Manager now covers the modern conversion/audience-upload path alongside the still-supported legacy endpoints).
- **20 new offline pytest tests** across `TestDatamanagerIngestEvents`, `TestDatamanagerIngestAudienceMembers`, `TestBuildUserIdentifiers`, `TestDataManagerConversionIngestCli`, `TestDataManagerAudienceUploadCli` — including a dedicated assertion that CLI output never claims per-event/-member success, and `--dry-run` tests confirming zero `requests.request` calls.

### Fixed

- **`gads_lib/output.py::classify_api_error()`** — added a `datamanager` URL branch so an `INSUFFICIENT_AUTHENTICATION_SCOPES` error on a `datamanager.googleapis.com` call correctly reports `https://www.googleapis.com/auth/datamanager` as the missing scope (previously fell through to `"unknown (check kb/manifest.json)"`).
- **`.gitignore`'s blanket `*.json` rule was silently excluding `kb/manifest.json` from version control** (discovered while adding the Data Manager entry — `git ls-files` confirmed the file had never been committed, meaning a fresh clone/CI checkout has no `kb/manifest.json` at all, which every `TestKBManifest*` test depends on). Added a `!kb/manifest.json` exception, matching the existing `!pyproject.toml` / `!.env.example` pattern.

### Changed

- Test suite expanded from 235 → 255 tests (all passing).
- `tests/test_gads.py::TestVersion` updated to assert v3.10.0.

## [3.9.1] - 2026-06-25

### Fixed

- **P0: `ads_mutate()` URL construction — snake_case resource names produced HTTP 404 (HTML) from Google.** The `mutate` CLI escape hatch accepted arbitrary `resource_type` strings (e.g. `campaign_criterion`) and passed them directly into the URL, building paths like `https://googleads.googleapis.com/v24/customers/CID/campaign_criterion:mutate`. Google's REST API requires camelCase plural form (`campaignCriteria`), so any snake_case name hit Google's generic 404 HTML page instead of a JSON API error — completely blocking all account mutations via the escape hatch. Fix: added `_canonicalize_resource()` in `ads.py` with a `_RESOURCE_ALIASES` dict (21 entries, all known mutation resources) that maps snake_case singular → camelCase plural. Unknown snake_case names now raise `ValueError` before any HTTP call (previously they silently 404'd). Canonical camelCase names pass through unchanged — no breakage to typed commands or internal `ads_mutate()` callers.

### Added

- **`_canonicalize_resource()` and `_RESOURCE_ALIASES` in `ads.py`** — public normalization helper (21 alias entries) for use by `ads_mutate()` and any future callers.
- **6 new pytest tests in `TestAdsMutateUrlConstruction`** covering: `campaign_criterion` → `campaignCriteria` URL, `ad_group_criterion` → `adGroupCriteria` URL, camelCase passthrough, version+customer in URL, unknown-alias `ValueError`, all aliases map to underscore-free camelCase.

### Changed

- Test suite expanded from 217 → 231 tests (all passing).
- `tests/test_gads.py::TestVersion` updated to assert v3.9.1.

## [3.9.0] - 2026-06-24

### Added

- **7 new `gads analyze` check commands** (`gads_lib/analyze/checks.py`):
  - `gads analyze rsa-lengths` — flags RSA headlines < 20 chars or descriptions < 60 chars (too-short copy that hurts Ad Strength). Impact: HIGH/MEDIUM/INFO.
  - `gads analyze rsa-duplicates` — detects intra-RSA duplicate headlines (same text twice in one ad, case-insensitive). Impact: HIGH/INFO.
  - `gads analyze dki` — reports Dynamic Keyword Insertion (`{keyword:}`) usage or absence across RSA ads. Impact: MEDIUM when absent.
  - `gads analyze ad-schedule` — checks which active SEARCH campaigns have dayparting rules (campaign_criterion AD_SCHEDULE); flags campaigns serving 24/7. Impact: HIGH/MEDIUM/INFO.
  - `gads analyze attribution` — checks conversion action attribution models; flags Last-Click usage (recommend DATA_DRIVEN). Impact: HIGH/INFO.
  - `gads analyze budget-is` — reports `search_budget_lost_impression_share` per SEARCH campaign; flags campaigns > 10%. Impact: HIGH/MEDIUM/INFO. Gracefully handles API sentinel values.
  - `gads analyze qs-distribution` — Quality Score sub-signal distribution (post-click quality, creative quality / expected CTR, predicted CTR) in ABOVE_AVERAGE/AVERAGE/BELOW_AVERAGE bands, plus overall avg QS and 1-3/4-6/7-10 band breakdown. Impact: HIGH/MEDIUM/INFO.

- **`gads audit` top-level command** — runs the full 12-section structural-compliance audit via `--format md` (default, human-readable) or `--format json` (machine-readable for agents). Wraps `gads analyze audit` as a first-class top-level command. Example: `gads audit --format json --days 14`.

- **43 new offline pytest tests** (`tests/test_checks.py`) covering all 7 check functions:
  - Empty-response / graceful degradation (no crashes)
  - Positive cases with correct impact classification
  - Edge cases (sentinel values, case-insensitive matching, deduplication, partial coverage)
  - CLI `--help` exit-code-0 for all 9 new commands (7 analyze + audit top-level + format option)
  - `--json` shape assertions via CliRunner

- **All checks read-only** — only `run_gaql` (SELECT GAQL); no account mutations. Date windows end yesterday (24-48h attribution lag respected).

- **`gads merchant register-gcp`** — registers the caller's GCP OAuth project with a Merchant Center account by calling `POST /accounts/v1/accounts/{account}/developerRegistration:registerGcp`. Fixes the `auth/gcp_unknown` / `GCP_NOT_REGISTERED` error that blocks Merchant API reads when the GCP project has not been associated with the MC account. Uses the existing `content` OAuth scope (no re-auth required). Defaults `--account` to `GOOGLE_MERCHANT_CENTER_ID`. Human-readable and `--json` modes; errors routed through the v3.8.2 error-envelope standard. After success, wait ~5 minutes before retrying merchant commands. KB (`kb/merchant-api.md`) updated with Developer Registration API reference.

### Changed

- Test suite expanded from 174 → 217 tests (all passing).
- `tests/test_gads.py::TestVersion` updated to assert v3.9.0.

## [3.8.2] - 2026-06-23

### Fixed

- **Uniform error routing (ads.py):** All Google Ads API call sites (`run_gaql`, `ads_search`, `ads_mutate`, `ads_batch_mutate`, `ads_upload_click_conversions`, `generate_keyword_ideas`, `generate_keyword_forecast`, and the job-create/job-run calls in `audience_upload_csv`) now route through `request_json()` from `gads_lib.http`. Under `--json`, 4xx errors emit a classified JSON envelope `{"error": {"code": ..., "message": ..., "action": ..., ...}}` to stdout and exit with code 5 instead of printing raw text to stderr and exiting 1.
- **Uniform error routing (ga4.py):** `list_key_events`, `create_key_event`, and `delete_key_event` now accept `as_json=False` parameter. A new `_handle_admin_error()` helper routes errors through `classify_api_error` + JSON envelope under `--json` (exit 5), while preserving the GA4-specific human-readable messages (analytics.edit scope hint, property ID hint) for human mode. `_raise_for_admin_status` now exits with code 5 (EXIT_CODES["API"]) instead of 1.
- **Uniform error routing (gbp.py):** `gbp_multi_daily_metrics` replaced raw `requests.get` + manual error check with `request_json()`. Errors now classify through the standard 4-class system instead of printing raw text and exiting 1.
- **partialFailure surface (cli.py):** `conversion_upload_cmd` now checks `result.get("partialFailureError")` after a successful HTTP 200 response. If partial failures exist, the command warns in human mode (per-conversion field path and error code) or returns a structured `{"status":"partial_failure",...}` JSON in `--json` mode, and exits 1. Previously it silently printed "✓ Conversion uploaded" even when some conversions failed.

### Added

- **`generate_keyword_ideas` and `generate_keyword_forecast` now accept `as_json=False`** so callers can propagate `--json` into the error envelope path.
- **Test coverage expanded from 64 → 127 tests.** New tests cover every endpoint in `ads.py`, `ga4.py`, `gbp.py`, `gsc.py`, and `merchant.py` — request-construction correctness (URL, body, params) AND error-envelope behaviour under `as_json=True`. All tests are offline (mocked HTTP).

### Changed

- **KB drift corrected (kb/search-console.md, kb/INDEX.md):** `gsc_url_inspect()` and `gsc_list_sitemaps()` are now correctly documented as implemented. The "CLI gap — not yet implemented" label on the URL Inspection API section and the "Not implemented" row for `sitemaps.*` in the coverage table have been updated. The coverage-gaps list no longer includes items 4 (URL Inspection) and 5 (sitemaps) as gaps.
- **Env dep floors met:** `requests` upgraded from 2.32.3 → 2.34.2 (floor >=2.33.0); `python-dotenv` upgraded from 1.0.1 → 1.2.2 (floor >=1.2.2). All 127 tests pass on the new versions.

## [3.8.1] - 2026-06-23
### Fixed
- `--json` mode: classified access errors (API_NOT_ENABLED, MERCHANT_NOT_REGISTERED, INSUFFICIENT_SCOPE, PERMISSION_DENIED) now emit a parseable JSON envelope on STDOUT instead of printing human-readable advisory text to STDERR with empty STDOUT. Exit code 5 preserved. The interactive gcloud-enable offer is suppressed in JSON mode.

## [3.8.0] - 2026-06-23

### Added

- **KB comprehensive expansion (task #14):** All five KB files (google-ads.md, merchant-api.md,
  ga4.md, gbp.md, search-console.md) now contain a full **Developer Guide** section alongside
  the existing endpoint reference. Total KB grew from 5,793 → 10,764 lines. Each guide covers
  schemas, enums, request/response shapes, workflows, limits, error patterns, and best practices —
  LLM-agent-complete: implementable against the KB alone without re-fetching docs.
  - `google-ads.md`: +1,406 lines — campaign creation, all bidding strategies, GAQL deep dive,
    RSA constraints, PMax asset groups, Customer Match lifecycle, error handling, pagination,
    rate limits, API versioning policy, mutation patterns.
  - `merchant-api.md`: +1,037 lines — product schema (required/optional fields), feed types,
    shipping setup, product status issues, productInputs write path, Reports sub-API, MCA
    structure, error patterns, Inventories API.
  - `ga4.md`: +873 lines — full report request schema, dimension/metric naming (no `ga:` prefix
    in GA4), filter expressions, key events Admin API, realtime, batchRunReports, pivot, quota
    buckets, Admin v1alpha vs v1beta resource table.
  - `gbp.md`: +1,099 lines — allowlist approval process, location attributes, reviews workflow,
    `fetchMultiDailyMetricsTimeSeries` (correct method name), monthly search keywords, local
    posts, media management, Ads integration, retry patterns.
  - `search-console.md`: +551 lines — Search Analytics full schema, all dimension/searchType
    combos, pagination (rowLimit=25000 + startRow loop), dimensionFilterGroups, Sites/Sitemaps
    APIs, URL Inspection API, OAuth scope mapping.
  - `kb/INDEX.md`: updated with KB expansion table + resolved coverage gaps.

- **GSC OAuth scope fix (task #18):** Added `https://www.googleapis.com/auth/webmasters.readonly`
  to `SCOPES` in `generate_token.py`. This was the root cause of GSC 403 errors. **User must
  re-run `python generate_token.py` to re-consent and receive the new scope in their token.**

- **GA4 Admin API v1alpha → v1beta migration (task C):** Migrated `GA4_ADMIN_BASE` in
  `gads_lib/ga4.py` from `analyticsadmin.googleapis.com/v1alpha` to
  `analyticsadmin.googleapis.com/v1beta`. Key events (`list`, `create`, `delete`) exist
  identically in both versions; v1beta carries the "no breaking changes" stability guarantee.
  `gads kb check` now exits 0 with all APIs aligned.

- **Code ↔ KB cross-references (task #15):** Added module-level docstrings citing KB file +
  official doc URL, plus per-function `# KB: kb/<slug>.md § <section>` comments, to all five
  service modules: `ads.py` (11 refs), `ga4.py` (9 refs), `gbp.py` (13 refs), `gsc.py`
  (4 refs), `merchant.py` (7 refs). Total: 44 cross-reference annotations.

- **Test suite (task #16):** Added `tests/test_gads.py` (58 tests, 100% pass, offline/CI-safe).
  Covers: request construction correctness (GA4 body shape, v1beta URL, GSC startRow, Merchant
  products URL, GBP perf URL), `--json` output structure, SELECT-only guard, error envelope +
  exit codes, `gads kb check` alignment, manifest validity, version sentinel.

- **Graceful access-error handling:** `gads_lib/output.py` gains `classify_api_error()` and
  `offer_gcloud_enable()`; `gads_lib/http.py` now dispatches classified errors instead of
  printing raw API responses. Four error classes handled:
  1. **API_NOT_ENABLED** (403 SERVICE_DISABLED) — names the service, offers to run
     `gcloud services enable <service>.googleapis.com --project <id>` interactively
     (requires confirmation; falls back to console link if gcloud is absent/declined).
  2. **MERCHANT_NOT_REGISTERED** (401 GCP_NOT_REGISTERED) — shows registration link;
     gcloud cannot fix this.
  3. **INSUFFICIENT_SCOPE** (403 INSUFFICIENT_AUTHENTICATION_SCOPES) — names the
     exact missing scope per API and instructs `python generate_token.py`.
  4. **PERMISSION_DENIED / allowlist** (403 PERMISSION_DENIED or 429 zero-quota) —
     advises requesting allowlist access with the relevant GBP or IAM console link.
  All paths exit with code 5 (`EXIT_CODES["API"]`) and never print a traceback. All 4
  mappings covered by 7 new tests in `TestGracefulErrorHandling`.

### Fixed

- **GA4 `kb check` drift:** `gads kb check` previously flagged `[DRIFT] ga4 manifest=v1beta
  code=v1alpha`. Resolved by migrating the code to v1beta. `kb check` now exits 0 cleanly.

## [3.7.0] - 2026-06-23

### Added
- **GA4 Data API — `batchRunReports`** (`gads ga4 batch-report`): Run up to 5 GA4 reports in a
  single API call, reducing quota overhead. Accepts a `--requests-file` JSON path or uses a
  sensible default (sessions by source + key events by date). Live-verified against property
  271773771.
- **GA4 Data API — `runPivotReport`** (`gads ga4 pivot-report`): Cross-tabulation reports with
  a configurable pivot dimension. Useful for campaign × device or source × medium breakdowns.
- **GA4 Data API — `checkCompatibility`** (`gads ga4 check-compatibility`): Pre-validate which
  dimension+metric combinations are compatible before running a report. Returns 378 dimension
  and 107 metric compatibility entries for the Talas property. Live-verified.
- **GSC — pagination via `startRow`** (`gads gsc queries/pages/performance`): All
  `gsc_search_analytics` calls now support `start_row` offset pagination so queries returning
  exactly `rowLimit` rows are no longer silently truncated.
- **GSC — `dataState` exposure**: All Search Console analytics commands now support `--data-state`
  (`final` / `all` / `hourly_all`) to opt into fresher unconfirmed data.
- **GSC — server-side `dimensionFilterGroups`**: `gsc_search_analytics` now accepts
  `dimension_filter_groups` parameter for server-side filtering before aggregation, avoiding
  rowLimit truncation of large datasets.
- **GSC — URL Inspection API** (`gads gsc inspect URL -s SITE`): Inspect any URL's Google index
  status, indexing state, page fetch state, mobile usability, and last crawl time via the URL
  Inspection API (`searchconsole.googleapis.com/v1`). Read-only. Verified via `--help`; live
  verification pending token regeneration with `webmasters.readonly` scope (see note below).
- **GSC — sitemaps list** (`gads gsc sitemaps -s SITE`): List all submitted sitemaps for a
  Search Console property. Verified via `--help`; live verification pending token regen.
- **GBP — batch-get reviews** (`gads gbp batch-reviews LOCATION_NAME...`): Fetch reviews from
  multiple GBP locations in one command, returning a dict keyed by location name.
- **GBP — local posts list** (`gads gbp local-posts --account A --location L`): List all local
  posts for a GBP location using the legacy v4 API.
- **GBP — local posts create/delete** (`gads gbp create-post` / `gads gbp delete-post`): CRUD
  for GBP local posts. Both commands are WRITE operations — added and verified via `--help` /
  `--dry-run`; NOT live-mutation-verified to avoid mutating the live account.
- **KB drift check** (`gads kb check`): Compares API versions hard-coded in each service module
  against `kb/manifest.json`. Exits non-zero on drift — CI-able. Detected real drift on first
  run: GA4 Admin API uses `v1alpha` in code but `v1beta` is the stable KB-documented version
  (flagged for future migration). `gads kb list` surfaces all KB files with sizes. `gads kb show
  <slug>` prints the full KB doc for any API.
- **KB directory committed**: `gads-cli/kb/` (5 files: google-ads.md, ga4.md, gbp.md,
  search-console.md, merchant-api.md, INDEX.md, manifest.json) is now git-tracked as a shipping
  deliverable.

### Fixed
- **GSC `gsc_search_analytics`**: Added `startRow` and `dataState` fields to the request body
  (previously omitted, causing silent truncation at `rowLimit` and no way to request fresh data).

### Notes
- **GSC live verification pending**: All GSC commands require the `webmasters.readonly` OAuth
  scope. The current token was generated before this scope was added. Re-run `gads auth login
  --force` to regenerate the token and enable live GSC verification.
- **Merchant skipped**: Merchant Center gaps deferred — the `merchantapi.googleapis.com` API is
  not enabled on the GCP project yet. No Merchant changes in this release.
- **GA4 Admin `v1alpha` known drift**: The KB drift check flags GA4 Admin API as DRIFT
  (`v1alpha` in code vs `v1beta` in manifest). Key events still work on `v1alpha`; migrating to
  `v1beta` is a separate task.

## [3.6.0] - 2026-06-23

### Changed
- **Google Ads API default bumped `v19` → `v24`** (`gads_lib/config.py`). v19 was
  sunset 2026-02-11; v24 is the current GA version. GAQL `searchStream`/`search`,
  `mutate`, `uploadClickConversions`, and `generateKeywordIdeas` endpoints are
  unchanged across v23→v24 — version-string-only. Docs (`CLAUDE.md`, `README.md`,
  `.env.example`) updated to state v24.
- **Keyword forecast rebuilt for v24** (`gads_lib/ads.py` `generate_keyword_forecast`).
  v24 reshaped `generateKeywordForecastMetrics`: top-level key is now `campaign`
  (was `campaignToForecast`), keywords moved into `campaign.adGroups[].keywords[]`
  as `{text, matchType}`, `keywordPlanNetwork` removed, `biddingStrategy`
  (manual CPC) is now required, and a forward-looking `forecastPeriod`
  (`startDate`/`endDate`, `YYYY-MM-DD`) is required. The old body returned HTTP 400.

### Fixed
- **`keyword ideas` request payload** (`gads_lib/ads.py` `generate_keyword_ideas`) —
  corrected to the documented `generateKeywordIdeas` REST schema: `language` is a
  single `languageConstants/{id}` string (was the invalid `languageId`),
  `geoTargetConstants` is an array of plain resource-name strings (was objects),
  `keywordPlanNetwork` is now sent, and both-seed requests use `keywordAndUrlSeed`.
  The command previously returned HTTP 400 for all inputs; now returns ideas.
- **`keyword ideas` / `keyword forecast` accept ISO codes** for `--language`
  (`en`, `ar`) and `--geo` (`AE`) in addition to numeric constant IDs, resolved
  to verified `languageConstants`/`geoTargetConstants` IDs (`gads_lib/cli.py`).

### Changed (breaking — Merchant `--json` shape)
- **Merchant Center migrated from Content API for Shopping v2.1 to Merchant API v1**
  (`gads_lib/merchant.py`, host `merchantapi.googleapis.com`). Content API v2.1
  sunsets 2026-08-18. OAuth scope is unchanged (`.../auth/content`). The
  `gads merchant ...` command names and human-readable table columns are preserved,
  but `--json` now returns Merchant API v1 objects, so machine consumers must adapt:
  - `products`: array `resources` → `products`; price `{value,currency}` →
    `productAttributes.price.{amountMicros,currencyCode}` (micros); product id →
    `offerId`; title/availability now under `productAttributes`; `channel` removed.
  - `product-status`: no standalone endpoint in v1 — folded into the products
    resource; statuses read from each product's `productStatus`.
  - `status`: array `accountLevelIssues` → `accountIssues`.
  - `feeds` (data sources): array `resources` → `dataSources`; `name` →
    `displayName`; `fileName` → `fileInput.fileName`; `contentType` → type union.
  - `shipping`: service `name` → `serviceName`; `deliveryCountry` →
    `deliveryCountries[]`; `currency` → `currencyCode`.
  - `returns`: array → `onlineReturnPolicies`.
  All merchant commands remain read-only (GET).

### Security
- **Dependency floors raised** (`pyproject.toml`): `requests>=2.33.0` (closes
  CVE-2024-47081 netrc leak and CVE-2026-25645 temp-file reuse),
  `python-dotenv>=1.2.2` (closes CVE-2026-28684 symlink overwrite),
  `click>=8.1`, `google-auth>=2.35`, `google-auth-oauthlib>=1.2`; dev `pytest>=9.0`,
  `pytest-cov>=6.0` (held below 7.0 which dropped built-in subprocess coverage).

### Notes
- GA4 (Data API v1beta), GBP (Account/Business Info/Performance v1), and GSC
  (webmasters/v3) confirmed current — unchanged. Monitor items: GA4 Admin and
  GBP Reviews still require legacy surfaces (My Business v4 for reviews).

## [3.5.0] - 2026-06-23

### Added
- **`catalog` command** — emits a complete machine-readable manifest of every
  command, subcommand, param, type, default, and help string by walking the live
  Click command tree (`gads catalog --json`). Lets an agent discover the CLI's
  full capabilities without parsing `--help`. Human-readable fallback without
  `--json`. New module `gads_lib/catalog.py`.
- **Structured error envelope + stable exit codes** — `main()` now wraps the CLI
  so failures emit `{"error":{"code":...,"message":...,"exit_code":N}}` to stderr
  when `--json` is in effect (colored text otherwise). Stable codes: 0 OK,
  1 GENERAL, 2 USAGE, 3 AUTH, 4 NOT_FOUND, 5 API, 6 VALIDATION, 7 DB. New
  `print_error()` helper and `EXIT_CODES` in `gads_lib/output.py`.
- **Read-only history-DB access**:
  - `gads db "<SQL>" [--json] [--limit N]` — SELECT-only passthrough to the local
    SQLite history DB. Rejects any mutating/multi-statement SQL (exit code 6) and
    enforces `PRAGMA query_only` as defense in depth.
  - `gads changelog` / `gads decisions` / `gads milestones` `[--json] [-n LIMIT]` —
    native readers for the project's own memory tables.
  - New module `gads_lib/dbread.py` with `assert_select_only`, `run_select`, and
    the convenience readers.
- **`--json` added to `log`, `snapshot`, `refresh`** — these three top-level
  commands now emit structured JSON like every other command.
- **Global `--plain` and `--quiet`/`-q` flags** — `--plain` produces
  deterministic, no-color/no-emoji output for parsing; `--quiet` suppresses
  non-essential progress output.
- **`AGENTS.md` and `llms.txt`** at the CLI root — capability index documenting
  how an agent should drive the CLI (catalog-first discovery, output contract,
  exit codes, reading project memory, mutation discipline).

### Changed
- `cli` root group now carries global `--plain`/`--quiet` options and a context
  object; `main()` runs Click with `standalone_mode=False` to own error handling.

## [3.4.0] - 2026-06-23

### Added
- **`analyze` command group** (5 new read-only analysis commands; no account mutations):
  - `analyze landing-page` — fetches a branch landing page over HTTP and scores it
    (0-100) on message-match, trust signals, mobile/viewport, load weight,
    WhatsApp/branch CTA, and `?branch=` survival; lists concrete issues. Branch
    choices: qz3 / sja / ind4.
  - `analyze wasted-spend` — AED-ranked wasted spend on zero-conversion and
    below-average-CPA search terms and campaigns (window ends yesterday).
  - `analyze ngrams` — 1/2/3-gram clustering of search terms (Arabic + English),
    aggregating cost & conversions per n-gram and surfacing high-cost zero/low-conv
    negative-keyword candidates.
  - `analyze ad-copy` — performance-ranked RSA ads validated against PARTS-ONLY
    business rules (no install/repair/workshop/battery-service; "Tesla" not "EV";
    not OEM/Genuine-only; branch phone). Rules sourced from the `business_rules`
    DB table plus encoded detectors; flags violations by severity.
  - `analyze competition` — competitive pressure from impression-share metrics
    (impression share, top/abs-top IS, rank-lost IS) per keyword, plus a
    best-effort auction-insights attempt that degrades gracefully when the REST
    API does not expose auction-insight fields.
- New `gads_lib/analyze/` sub-package: `lp_score.py`, `wasted_spend.py`,
  `ngrams.py`, `adcopy.py`, `competitive.py`.

### Changed
- Total command groups: 15 → 16 (added `analyze`).

## [3.3.0] - 2026-03-31

### Added
- **GBP Performance API** (4 new commands):
  - `gbp perf` — daily performance metrics for a single location
  - `gbp perf-all` — daily metrics for ALL locations with auto-discovery
  - `gbp search-keywords` — monthly search keyword impressions
  - `gbp metrics-list` — list all available daily metrics
- **GBP Location Asset Performance** (2 new commands, via Google Ads GAQL):
  - `gbp ads-perf` — per-branch aggregate (clicks, impr, CTR, CPC, cost, conv)
  - `gbp ads-daily` — per-branch daily breakdown with totals
  - Uses `asset_set_asset` resource with `LOCATION_SYNC` asset set
  - Matches Ads UI Asset Report > Associations > Location view exactly
- **Google Search Console** (4 new commands, new `gsc` command group):
  - `gsc sites` — list verified Search Console sites
  - `gsc queries` — top search queries with clicks, impressions, CTR, position
  - `gsc pages` — top pages performance
  - `gsc performance` — daily performance time series
- New OAuth scope: `webmasters.readonly` (Search Console access)
- New GCP API: Business Profile Performance API added to `auth setup`
- New GCP API: Search Console API added to `auth setup`
- `auth test` now tests Search Console access
- Scope display in `auth login` now shows Search Console grant status

### Changed
- Total commands: 65 → 75 across 15 groups (was 14)
- GBP commands: 6 → 12
- OAuth SCOPES list: 4 → 5 scopes

## [3.2.0] - 2026-03-28

### Changed
- README: accurate access level documentation (Test/Explorer/Basic/Standard)
- README: Features table now shows all 65 commands across 14 groups
- README: Command Requirements table shows auth needs per command
- CLAUDE.md: AI-agent-friendly reference with full command taxonomy
- CLAUDE.md: GAQL patterns, known gotchas, architecture overview

### Added
- CI pipeline (`.github/workflows/ci.yml`): Python 3.10-3.13 × Ubuntu + macOS
- CI: syntax check, import verification, secret scanning, version validation
- April 2026 Customer Match deprecation warning in docs

## [3.1.0] - 2026-03-27

### Added
- `audience create` — create CRM-based Customer Match user lists
- `audience upload` — full CSV upload pipeline (phone normalization, name validation, SHA-256 hashing, consent, batch retry with 429 backoff)
- `audience job-status` — check Customer Match upload job status and match rate
- `ads.py`: `audience_find_list()`, `audience_create_list()`, `audience_upload_csv()`
- Phone normalization for UAE formats (05X, 5X, 971X, 00971X, +971X)
- Name validation (`is_valid_name`) — rejects companies, garbage, special chars

## [3.0.0] - 2026-03-27

### Added
- **50+ new commands** across 10 new groups
- `campaign list`, `status`, `budget`, `perf` — campaign management
- `adgroup list`, `status`, `create` — ad group management
- `ad list`, `status`, `perf` — ad management with creatives
- `keyword list`, `add`, `remove`, `negative`, `search-terms`, `ideas`, `forecast` — keyword management and research
- `asset list`, `sitelink`, `callout`, `call` — asset management with two-step extension creation
- `conversion list`, `create`, `tag`, `perf`, `upload` — conversion tracking and offline upload
- `audience list` — user list / audience listing
- `report geo`, `hourly`, `devices`, `search-terms` — specialized reports
- `mutate`, `batch-mutate` — generic escape hatches for any API mutation
- `accounts` — list accessible Google Ads accounts
- `ads.py`: `ads_mutate()`, `ads_batch_mutate()`, `ads_search()`, `ads_upload_click_conversions()`, `generate_keyword_ideas()`, `generate_keyword_forecast()`, `sanitize_keyword()`
- Mutation safety: `--dry-run`, `--yes`, auto-changelog logging, caller enforcement

### Changed
- Repo renamed: `google-business-cli` → `gads-cli`
- All internal references updated to `gads-cli`

## [2.2.0] - 2026-03-27

### Added
- Scope-aware configuration: auto-detects project vs global (`~/.config/gads/`)
- `auth setup` wizard detects scope and writes `.env` to correct location
- Currency step in setup wizard
- Developer token access level guide in setup wizard (Test/Basic/Standard + MCC requirement)

### Fixed
- Global pip install now uses `~/.config/gads/` for credentials/data/snapshots
- `auth setup` no longer writes to site-packages directory

## [2.1.0] - 2026-03-27

### Added
- `GADS_CURRENCY` env var (ISO 4217, default: USD)
- Dynamic versioning from `gads_lib.__version__`

### Changed
- CLI logic moved into `gads_lib/cli.py` — proper pip install
- DB columns: `cost_aed` → `cost`, `budget_aed` → `budget`

### Fixed
- `pip install` broken by invalid build backend and missing CLI module

## [2.0.0] - 2026-03-26

### Added
- Google Business Profile: `gbp accounts`, `locations`, `location`, `reviews`, `reply-review`, `delete-reply`
- Google Merchant Center: `merchant account`, `status`, `products`, `product-status`, `feeds`, `shipping`, `returns`
- Google Analytics 4: `ga4 metadata`, `report`, `realtime`
- Modular library (`gads_lib/`), `doctor`, `auth status`, agent enforcement
- `fetch_daily.py`, `generate_token.py`, `pyproject.toml`, `--json` on all commands

### Changed
- All config via environment variables — zero hardcoded values

## [1.0.0] - 2026-02-11

### Added
- Initial CLI: `query`, `log`, `snapshot`, `perf`, `config`, `refresh`
- Google Ads GAQL queries, SQLite database, OAuth credentials
