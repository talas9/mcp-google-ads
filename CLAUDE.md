# gads-cli

Unified Google platform CLI for Google Ads, Google Business Profile, Google Merchant Center, and GA4. Built for AI agents — all commands support `--json` and `--help`.

## Related skill

When this CLI is used inside the **talas-ads** workspace, a companion Claude Code skill lives at [`../skills/google-ads-management/SKILL.md`](../skills/google-ads-management/SKILL.md) (symlinked into `~/.claude/skills/`). That skill layers Talas-specific operational knowledge on top of the raw CLI: campaign management workflows, mutation safety (snapshot → mutate → log), cross-channel analysis across Ads + GBP + Merchant Center + GA4, and the business rules for Talas ad copy (PARTS ONLY, Tesla-specific language, branch-specific phone numbers QZ3 / IND4 / SJA, landing-page `?branch=` parameter, etc.). This file (`CLAUDE.md`) stays focused on the generic CLI contract; reach for the skill when the caller is operating the Talas account specifically.

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your dev token (required), customer ID, and OAuth paths

# 2. Generate OAuth token (opens browser for consent)
python generate_token.py

# 3. Verify setup
./gads doctor
```

## Command Taxonomy

| Group | Subcommands | Purpose | Needs dev token? |
|-------|-----------|---------|-----------------|
| `auth` | `status`, `setup`, `login`, `revoke`, `test` | Credential management and diagnostics | No |
| `audit` | *(top-level)* `[--days N] [--format md\|json]` | 12-section structural-compliance audit — `overall_score` (0-100), `grade` (A-F), per-section scores; wraps `analyze audit` | Yes |
| `analyze` | `landing-page`, `wasted-spend`, `ngrams`, `ad-copy`, `competition`, `rsa-lengths`, `rsa-duplicates`, `dki`, `ad-schedule`, `attribution`, `budget-is`, `qs-distribution`, `audit` | Read-only account analysis (no mutations) — 5 original + 7 gap checks + full audit | Yes (except `landing-page`) |
| `campaign` | `list`, `status`, `budget`, `perf` | Campaign management and performance | Yes |
| `adgroup` | `list`, `status`, `create` | Ad group management | Yes |
| `ad` | `list`, `status`, `perf` | Ad management and ad-level metrics | Yes |
| `keyword` | `list`, `add`, `remove`, `negative`, `search-terms`, `ideas`★, `forecast`★ | Keyword research and management | Yes |
| `asset` | `list`, `sitelink`, `callout`, `call` | Asset management and extensions (two-step creation) | Yes |
| `conversion` | `list`, `create`, `set-primary`, `tag`, `perf`, `upload` | Conversion tracking, Primary/Secondary toggling, and offline upload | Yes |
| `audience` | `list`, `create`, `upload`, `job-status` | Customer Match lists and CSV upload | Yes |
| `data-manager` | `conversion-ingest`, `audience-upload` | Data Manager API — modern async events/audience ingestion, parallel to `conversion upload` / `audience upload` | No |
| `report` | `geo`, `hourly`, `devices`, `search-terms` | Specialized performance breakdowns | Yes |
| `gbp` | `accounts`, `locations`, `location`, `reviews`, `reply-review`, `delete-reply`, `perf`, `perf-all`, `search-keywords`, `metrics-list`, `ads-perf`, `ads-daily`, `batch-reviews`, `local-posts`, `create-post`, `delete-post` | Google Business Profile management + performance analytics + local posts CRUD | No (except `ads-perf`, `ads-daily`) |
| `gsc` | `sites`, `queries`, `pages`, `performance`, `inspect`, `sitemaps` | Google Search Console — queries, pages, daily performance, URL Inspection API, sitemaps | No |
| `merchant` | `account`, `status`, `products`, `product-status`, `feeds`, `shipping`, `returns`, `register-gcp` | Merchant Center product management (Merchant API v1); `register-gcp` fixes GCP_NOT_REGISTERED (one-time setup) | No |
| `ga4` | `report`, `realtime`, `metadata`, `batch-report`, `pivot-report`, `check-compatibility`, `key-events` (`list`/`create`/`bulk`/`delete`) | GA4 Data API + Admin API — reporting, batch/pivot, compatibility check, key events | No |
| `kb` | `check`, `list`, `show` | API knowledge-base drift check (CI-able), listing, and display | No |
| Top-level | `query`, `perf`, `config`, `refresh`, `snapshot`, `log`, `accounts`, `doctor`, `catalog`, `db`, `changelog`, `decisions`, `milestones`, `mutate`, `batch-mutate` | GAQL queries, syncing, snapshots, command catalog, history-DB passthrough, generic mutations | Yes (except `doctor`, `catalog`, `db`, `changelog`, `decisions`, `milestones`) |

> ★ Requires Standard Access developer token

## Authentication Requirements by Service

### Google Ads Commands
- **Developer token:** Required (from Google Ads API Center)
- **OAuth scopes:** `adwords` scope
- **Access level:** Explorer for most commands; Standard for Keyword Planner / Forecasting
- **Credentials:** `GOOGLE_ADS_DEVELOPER_TOKEN`, `GOOGLE_ADS_CUSTOMER_ID`
- **Important:** Without the developer token, ALL Google Ads API commands fail

### Google Business Profile Commands
- **Developer token:** NOT needed
- **OAuth scopes:** `business.manage` scope
- **Credentials:** `GOOGLE_ADS_LOGIN_CUSTOMER_ID` (optional, for account selection)

### Merchant Center Commands
- **Developer token:** NOT needed
- **OAuth scopes:** `content` scope
- **Credentials:** `GOOGLE_MERCHANT_CENTER_ID`

### GA4 Commands
- **Developer token:** NOT needed
- **OAuth scopes:**
  - `analytics.readonly` — for `report`, `realtime`, `metadata`, and `key-events list`
  - `analytics.edit` — required for `key-events create`, `key-events bulk`, `key-events delete` (uses the GA4 Admin API). The project's `tools/generate_token.py` and `gads-cli/generate_token.py` both include this scope already; if you see `403 Forbidden` on write calls, regenerate the token.
- **APIs to enable:** GA4 Data API (`analyticsdata.googleapis.com`) for reporting; GA4 Admin API (`analyticsadmin.googleapis.com`) for key events.
- **Credentials:** `GOOGLE_GA4_PROPERTY_ID`

### Data Manager API Commands
- **Developer token:** NOT needed, no `login-customer-id` header (that "acting as" relationship is expressed in the JSON body's `Destination.loginAccount` instead — see `kb/data-manager-api.md`)
- **OAuth scopes:** `https://www.googleapis.com/auth/datamanager` — added to `generate_token.py`'s unified scope list; existing tokens must be regenerated (`python generate_token.py`) to pick it up
- **APIs to enable:** Data Manager API (`datamanager.googleapis.com`)
- **Credentials:** reuses `GOOGLE_ADS_CUSTOMER_ID` / `GOOGLE_ADS_LOGIN_CUSTOMER_ID` (built into the request body's `Destination`, not headers)
- **Important:** responses are asynchronous — `{"requestId": "..."}` only, no per-event/-member success confirmation. See `kb/data-manager-api.md`.

## Common GAQL Patterns

```bash
# Basic query
./gads query "SELECT campaign.name, campaign.id FROM campaign"

# With metrics
./gads query "SELECT campaign.name, metrics.clicks, metrics.conversions FROM campaign WHERE metrics.clicks > 0"

# Date-based filtering (yesterday only)
./gads query "SELECT campaign.name, metrics.cost_micros FROM campaign WHERE segments.date = '2026-03-27'"

# Filter by campaign type
./gads query "SELECT campaign.name FROM campaign WHERE campaign.advertising_channel_type = 'SEARCH'"

# Order and limit
./gads query "SELECT campaign.name, metrics.clicks FROM campaign ORDER BY metrics.clicks DESC LIMIT 10"

# Ad group criteria (keywords)
./gads query "SELECT campaign.name, ad_group.name, ad_group_criterion.keyword.text FROM ad_group_criterion"

# Smart/Performance Max campaigns
./gads query "SELECT campaign.name FROM campaign WHERE campaign.advertising_channel_type = 'PERFORMANCE_MAX'"
```

## Key Environment Variables

```bash
# REQUIRED for Google Ads operations
GOOGLE_ADS_DEVELOPER_TOKEN=xxxxxxxxxxxxxxxx      # From API Center
GOOGLE_ADS_CUSTOMER_ID=1234567890                # 10 digits, no dashes

# REQUIRED for specific services (optional overall)
GOOGLE_ADS_LOGIN_CUSTOMER_ID=9999999999          # MCC manager account ID
GOOGLE_MERCHANT_CENTER_ID=12345678               # MC account
GOOGLE_GA4_PROPERTY_ID=271773771                 # GA4 property ID

# Optional configuration
GADS_TIMEZONE=Asia/Dubai                         # Default: UTC
GADS_CURRENCY=AED                                # Default: USD
GADS_API_VERSION=v24                             # Default: v24

# Paths (auto-detected by default)
GADS_CREDENTIALS_PATH=credentials/google-ads-oauth.json
GADS_DB_PATH=data/gads.db
GADS_SNAPSHOTS_DIR=snapshots
```

## Architecture

```
gads-cli/
├── gads                     # Main CLI entry point (thin shim)
├── gads_lib/
│   ├── cli.py              # Click command groups and entry point (110 commands)
│   ├── config.py           # Environment-driven configuration (Ads v24 default)
│   ├── auth.py             # OAuth credential management + refresh
│   ├── ads.py              # Google Ads REST client + GAQL runner (v24)
│   ├── gbp.py              # GBP client (4 base URLs: account mgmt, business info, legacy v4, performance)
│   ├── gsc.py              # Search Console client (webmasters/v3 + URL Inspection v1)
│   ├── merchant.py         # Merchant Center client (Merchant API v1)
│   ├── ga4.py              # GA4 Data API v1beta + Admin API v1beta
│   ├── datamanager.py      # Data Manager API client (events:ingest, audienceMembers:ingest)
│   ├── catalog.py          # Live Click-tree catalog emitter (gads catalog --json)
│   ├── dbread.py           # SELECT-only history-DB passthrough (gads db / changelog / decisions / milestones)
│   ├── analyze/            # 5 read-only analysis modules
│   │   ├── lp_score.py     # Landing-page scoring (0-100)
│   │   ├── wasted_spend.py # Zero-conv + below-avg-CPA spend identification
│   │   ├── ngrams.py       # 1/2/3-gram search-term clustering (Arabic + English)
│   │   ├── adcopy.py       # RSA ad copy validation against business rules
│   │   └── competitive.py  # Impression-share competitive pressure analysis
│   ├── http.py             # HTTP helpers + graceful error classifier (4 error classes)
│   ├── db.py               # SQLite connection manager
│   ├── output.py           # Table/JSON formatting + classify_api_error + offer_gcloud_enable
│   └── timeutil.py         # Timezone-aware time helpers
├── kb/                     # API knowledge base (5 API docs + INDEX.md + manifest.json)
├── tests/                  # 127 tests — offline/CI-safe, covers all service modules
├── fetch_daily.py          # Cron-friendly daily data fetcher
├── generate_token.py       # Interactive OAuth token generator (6 scopes)
├── pyproject.toml          # Package metadata
├── AGENTS.md               # Agent-driveable capability index
├── llms.txt                # LLM-optimised quick reference
└── README.md, CLAUDE.md    # Documentation
```

**REST API design:** The CLI uses Google's REST APIs directly (`requests` + `google-auth`), NOT the Python client library. This keeps dependencies minimal and makes debugging straightforward.

## Known Gotchas

### Google Ads API

1. **Developer token is absolutely required** — without it, every Ads API call fails immediately. GBP/MC/GA4 don't need it.

2. **Tilde (~) in resource names for ad group criteria** — resource names use tilde format: `customers/{CID}/adGroupCriteria/{adGroupId}~{criterionId}`. A slash instead of tilde causes 404 errors. Same pattern for campaign criteria.

3. **mutateOperations key in batch operations** — use `{"mutateOperations": [...]}` not `{"operations": [...]}` for cross-resource mutations. Single-resource mutations use `"operations"`.

4. **Sitelink finalUrls placement** — when creating a sitelink asset, `finalUrls` must be at the top level of the create object, NOT nested inside `sitelinkAsset`. Nesting causes silent URL drops.

5. **Customer Match uploads and April 2026 deprecation** — starting April 1, 2026, `OfflineUserDataJobService` uploads (`audience upload`) fail if your token has never sent a successful Customer Match request. Pre-upload before that date, or use `gads data-manager audience-upload` — the modern Data Manager API path (`gads_lib/datamanager.py`, `kb/data-manager-api.md`), unaffected by this deprecation. It's a parallel command, not an in-place replacement: same CSV shape (`Phone,Email,First Name,Last Name,Country`), but its `events:ingest`/`audienceMembers:ingest` response is asynchronous (`{requestId}` only, no per-row confirmation) unlike the legacy job-status-pollable path.

6. **Asset creation is two-step** — create the asset via `assets:mutate`, then link it to the campaign via `campaignAssets:mutate`. Cannot do both in one call.

7. **Keyword special characters** — endpoints like `generateKeywordIdeas` reject keywords with `! @ % , * '` characters. Always sanitize input.

8. **addyInfo with empty names in Customer Match** — sending `{"addressInfo": {"countryCode": "AE"}}` with no valid names is silently dropped. Validate names before including addressInfo.

### GBP

**Four different base URLs:**
- `mybusinessaccountmanagement.googleapis.com` (v1) — accounts, locations
- `mybusinessbusinessinformation.googleapis.com` (v1) — location details, hours, attributes
- `mybusiness.googleapis.com` (v4, legacy) — reviews, media, posts, Q&A
- `businessprofileperformance.googleapis.com` (v1) — directions, calls, impressions, search keywords

Each endpoint must use its correct base URL or requests fail.

**GBP Performance daily metrics:** BUSINESS_DIRECTION_REQUESTS, CALL_CLICKS, WEBSITE_CLICKS, BUSINESS_IMPRESSIONS_DESKTOP_MAPS, BUSINESS_IMPRESSIONS_DESKTOP_SEARCH, BUSINESS_IMPRESSIONS_MOBILE_MAPS, BUSINESS_IMPRESSIONS_MOBILE_SEARCH, BUSINESS_CONVERSATIONS, BUSINESS_BOOKINGS, BUSINESS_FOOD_ORDERS, BUSINESS_FOOD_MENU_CLICKS.

**GBP Performance reporting lag:** Data takes 2-3 days to populate. Recent days may show zero.

### GSC (Search Console)

- Base URL: `www.googleapis.com/webmasters/v3`
- Requires `webmasters.readonly` OAuth scope (added in v3.3.0)
- Data lags ~3 days (GSC default processing delay)
- Site URL must match verified property exactly (URL-prefix or domain property)

### Merchant Center (Merchant API v1)

- Uses **Merchant API v1** (`merchantapi.googleapis.com`), the successor to the
  Content API for Shopping v2.1 (which sunsets **2026-08-18**). OAuth scope is
  unchanged: `https://www.googleapis.com/auth/content`.
- **No single base URL** — each sub-API has its own version segment before the
  resource name: `accounts/v1` (account, issues, shippingSettings,
  onlineReturnPolicies), `products/v1` (products), `datasources/v1` (dataSources).
  Account ID embeds as `accounts/{ID}`.
- **`merchantapi.googleapis.com` must be enabled** on the GCP project behind the
  OAuth client (Cloud Console → APIs & Services → Enable APIs). If it isn't, every
  merchant command returns `403 SERVICE_DISABLED` even though credentials are valid.
- **Response-shape differences vs v2.1** (`--json` consumers): products array is
  `products` (not `resources`); price is `productAttributes.price.{amountMicros,
  currencyCode}` in micros (÷ 1e6); product id is `offerId`; product statuses are
  folded into the products resource under `productStatus`; data sources array is
  `dataSources` (`displayName`, `fileInput.fileName`); account issues array is
  `accountIssues`; shipping services use `serviceName`/`deliveryCountries[]`;
  return policies array is `onlineReturnPolicies`.

### Database

- **Append-only:** SQLite tables for campaigns, ad groups, keywords, and performance metrics are append-only. No deletions. Use `gads refresh` to pull fresh data; old rows stay.
- **Schema:** Run `python -m gads_lib.db init` to create tables if missing.

### Time and Currency

- **No same-day data:** Google Ads has 24-48h attribution lag. Never analyze today's performance — use yesterday or earlier.
- **All costs in configured currency:** Default is USD. Set `GADS_CURRENCY=AED` if working in AED. All cost_micros from the API are already in that currency.

## CLI Usage Examples

```bash
# Verify setup
./gads doctor
./gads auth status --json

# Agent discovery — always start here
./gads catalog --json

# History DB (read-only SELECT)
./gads db "SELECT * FROM campaign_performance ORDER BY date DESC LIMIT 10" --json
./gads changelog --json -n 20
./gads decisions --json
./gads milestones --json

# Analyze (no mutations, safe to run anytime)
./gads analyze wasted-spend --days 14 --json
./gads analyze ngrams --days 14
./gads analyze ad-copy --json
./gads analyze landing-page --branch qz3
./gads analyze competition --days 14 --json

# KB drift check (CI-able)
./gads kb check
./gads kb list
./gads kb show google-ads

# Query campaigns
./gads query "SELECT campaign.name, campaign.status FROM campaign"
./gads campaign list
./gads campaign list --json

# Performance from local database
./gads perf --days 7
./gads perf --campaign "my-campaign" --json

# Refresh local database from API
./gads refresh --days 3
./gads refresh --days 7 --config --push

# Snapshots (save config before mutations)
./gads snapshot pre-budget-change --save-file
./gads snapshot baseline

# Changelog
./gads log "budget_change" "PMax 25 → 30 AED" --reason "strong cpa"
./gads log "paused_keywords" "15 low-intent keywords" --campaign "Search - Tesla"

# Keyword research (requires Standard access)
./gads keyword ideas --keywords "tesla parts" --language en --geo AE
./gads keyword forecast --keywords "tesla parts" --language en

# Customer Match upload (deprecated April 2026)
./gads audience upload contacts.csv --list-name "Website Visitors" --create-if-missing

# Google Business Profile
./gads gbp accounts
./gads gbp locations --account accounts/123456789
./gads gbp reviews locations/987654321
./gads gbp reply-review accounts/123/locations/456/reviews/789 "Thank you for your review!"
./gads gbp perf -l 17303088970776446827 -d 14
./gads gbp perf-all -d 7 -m "BUSINESS_DIRECTION_REQUESTS,CALL_CLICKS,WEBSITE_CLICKS"
./gads gbp search-keywords -l 17303088970776446827 --months 3
./gads gbp metrics-list

# GBP local posts
./gads gbp local-posts --account accounts/123456789 --location locations/987654321
./gads gbp create-post --account accounts/123456789 --location locations/987654321 --summary "Summer sale"
./gads gbp delete-post accounts/123456789/locations/987654321/localPosts/abc123

# GBP batch reviews
./gads gbp batch-reviews locations/987654321 locations/111222333

# GBP location asset performance in Google Ads
./gads gbp ads-perf -d 30
./gads gbp ads-daily -d 14

# Google Search Console
./gads gsc sites
./gads gsc queries -s "https://shop.talas.ae/" -d 28
./gads gsc pages -s "https://shop.talas.ae/" -d 28
./gads gsc performance -s "https://shop.talas.ae/" -d 28
./gads gsc inspect "https://shop.talas.ae/products/tesla" -s "https://shop.talas.ae/"
./gads gsc sitemaps -s "https://shop.talas.ae/"

# Merchant Center
./gads merchant account
./gads merchant status
./gads merchant products            # pages full catalogue; --limit caps rows shown, not rows fetched
./gads merchant product-status      # full catalogue + per-destination approve/disapprove summary

# GA4 reporting
./gads ga4 metadata
./gads ga4 report --dimensions date,country --metrics activeUsers,sessions --start 7daysAgo
./gads ga4 realtime --dimensions city --metrics activeUsers

# GA4 batch and pivot reports
./gads ga4 batch-report
./gads ga4 pivot-report --pivot-dimension country --dimensions date --metrics activeUsers
./gads ga4 check-compatibility --dimensions date,country --metrics activeUsers,sessions

# GA4 key events (conversions). Write ops need analytics.edit scope.
./gads ga4 key-events list
./gads ga4 key-events create whatsapp_click
./gads ga4 key-events bulk "whatsapp_click,phone_click,form_submit,add_to_cart,begin_checkout,add_payment_info"
./gads ga4 key-events delete whatsapp_click --yes
```
