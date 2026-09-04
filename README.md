# gads-cli

**Google Ads CLI** — a unified command-line tool for managing Google Ads campaigns, with built-in support for Google Business Profile, Google Merchant Center, and Google Analytics (GA4).

Built for AI coding agents (Claude Code, Cursor, etc.) and human operators. Every command supports `--json` for machine-readable output and `--help` for full documentation.

> The name `gads` stands for **G**oogle **Ads**. While Google Ads is the primary focus, the CLI also provides commands for related Google services (GBP, Merchant Center, GA4) that are commonly used alongside ad campaigns.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)
[![CI](https://github.com/talas9/gads-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/talas9/gads-cli/actions/workflows/ci.yml)

---

## Features

**129 commands** across 20 groups covering the full Google Ads operational surface:

| Group | Commands | Description |
|-------|----------|-------------|
| **Core** | `query`, `perf`, `config`, `refresh`, `snapshot`, `log`, `accounts`, `doctor`, `db`, `changelog`, `decisions`, `milestones`, `catalog`, `mutate`, `batch-mutate` | GAQL queries, local DB reports, campaign snapshots, structured logs, history-DB passthrough, machine-readable command catalog |
| **Audit** | `audit [--days N] [--format md\|json]` | Top-level 12-section structural-compliance audit (0-100 score, A-F grade); wraps `analyze audit` |
| **Analyze** | `analyze landing-page`, `wasted-spend`, `ngrams`, `ad-copy`, `competition`, `rsa-lengths`, `rsa-duplicates`, `dki`, `ad-schedule`, `attribution`, `budget-is`, `qs-distribution`, `audit` | Read-only account analysis — landing page scoring, wasted spend, n-gram clusters, ad-copy rule violations, impression-share competitive pressure, 7 gap checks, full compliance audit |
| **Campaign** | `campaign list`, `status`, `budget`, `perf` | List, enable/pause, change budget, campaign-level metrics from API |
| **Ad Group** | `adgroup list`, `status`, `create` | List, enable/pause, create ad groups |
| **Ad** | `ad list`, `status`, `perf` | List ads with creatives, enable/pause, ad-level metrics |
| **Keyword** | `keyword list`, `add`, `remove`, `negative`, `search-terms`, `ideas`★, `forecast`★, `account-negative list`, `account-negative add` | Keyword management, search terms report, Keyword Planner research; `account-negative` mutates account-wide negative criteria (all campaigns), vs. campaign-level `negative` |
| **Asset** | `asset list`, `sitelink`, `callout`, `call` | List assets, add sitelinks/callouts/call extensions (two-step creation) |
| **Conversion** | `conversion list`, `create`, `set-primary`, `tag`, `perf`, `upload` | Conversion actions, tracking tags, Primary/Secondary toggling, performance by action, offline upload |
| **Audience** | `audience list`, `create`, `upload`, `job-status` | Customer Match user lists, CSV upload with SHA-256 hashing + consent |
| **Data Manager** | `data-manager conversion-ingest`, `audience-upload` | Modern events/audience ingestion via the Data Manager API — async `{requestId}`-only response, parallel to (not a replacement for) the legacy Conversion Upload / Customer Match paths |
| **Pmax** | `pmax asset-groups`, `signals`, `listing-groups`, `search-terms` | Performance Max (read-only) — asset groups with ad strength, audience/search-theme signals, listing group filters (product partitions), search-term category insights |
| **Report** | `report geo`, `hourly`, `devices`, `search-terms`, `shopping` | Geographic, hourly, device, search term, and per-SKU Shopping (`shopping_performance_view`) performance breakdowns |
| **GBP** | `gbp accounts`, `locations`, `location`, `reviews`, `reply-review`, `delete-reply`, `perf`, `perf-all`, `search-keywords`, `metrics-list`, `ads-perf`, `ads-daily`, `batch-reviews`, `local-posts`, `create-post`, `delete-post` | Google Business Profile management + performance analytics + local posts CRUD |
| **GSC** | `gsc sites`, `queries`, `pages`, `performance`, `inspect`, `sitemaps` | Google Search Console — search queries, pages, daily performance, URL Inspection API, sitemaps list |
| **Merchant** | `merchant account`, `status`, `products`, `product-status`, `feeds`, `shipping`, `returns`, `register-gcp`, `report`, `report-product-performance` | Merchant Center (Merchant API v1) — no dev token needed; `register-gcp` fixes GCP_NOT_REGISTERED; `report`/`report-product-performance` use the separate Merchant reports sub-API (its own query dialect, not GAQL) |
| **GA4** | `ga4 report`, `realtime`, `metadata`, `batch-report`, `pivot-report`, `check-compatibility`, `key-events list/create/bulk/delete` | GA4 Data API + Admin API — reporting, batch/pivot, compatibility check, key-event management |
| **KB** | `kb check`, `kb list`, `kb show` | API knowledge-base drift check (CI-able), listing, and display |
| **Auth** | `auth status`, `setup`, `login`, `revoke`, `test` | Interactive setup wizard, OAuth flow, credential diagnostics |
| **Mutate** | `mutate <type> <json>`, `batch-mutate <json>` | Generic escape hatch for any Google Ads API mutation |

> ★ Requires Standard Access developer token

**Cross-cutting:**
- `--json` on every command for machine-readable output
- `--dry-run` and `--yes` on all mutation commands
- Auto-logging to changelog after successful mutations
- Scope-aware config — auto-detects project (`./`) vs global (`~/.config/gads/`)
- Agent caller enforcement for multi-agent architectures (optional)
- Configurable timezone (IANA) and currency (ISO 4217)

---

## Install

### One-liner (recommended)

```bash
pip install git+https://github.com/talas9/gads-cli.git
```

### Interactive installer

Downloads the CLI, detects your AI platforms (Claude Code, gsd-pi), wires up agents + skills, and runs auth setup:

```bash
curl -fsSL https://raw.githubusercontent.com/talas9/gads-cli/main/scripts/install.sh | bash
```

### From source

```bash
git clone https://github.com/talas9/gads-cli.git
cd gads-cli
pip install .
```

### Upgrade

```bash
pip install --upgrade git+https://github.com/talas9/gads-cli.git
```

### Pin a version

```bash
pip install git+https://github.com/talas9/gads-cli.git@v3.2.0
```

---

## Quick Start

```bash
# 1. Run the interactive setup wizard (walks through everything)
gads auth setup

# 2. Verify
gads doctor

# 3. Try it
gads campaign list
gads perf --days 7
gads query "SELECT campaign.name, metrics.clicks FROM campaign"
```

The setup wizard handles: GCP project creation, API enablement, OAuth consent screen, credential download, developer token, customer IDs, timezone, currency, and OAuth login — all interactively.

If you prefer manual setup, see [Manual Setup](#manual-setup) below.

---

## Command Reference

### Core

```bash
gads doctor                          # Check credentials, config, API access
gads auth status --json              # Credential status (never prints secrets)
gads accounts                        # List accessible Google Ads accounts
gads query "SELECT campaign.name FROM campaign"  # Run any GAQL query
gads perf --days 7                   # Performance from local database
gads config --json                   # Campaign configs from API
gads refresh --days 3                # Pull API data into local DB
gads snapshot pre-change --save-file # Snapshot configs before mutations
gads log "action" "details"          # Append to changelog
```

### Campaign Management

```bash
gads campaign list                   # All campaigns with status/budget
gads campaign perf --days 7          # Campaign metrics from API
gads campaign status 12345 PAUSED    # Pause a campaign (--dry-run, --yes)
gads campaign budget 12345 25.00     # Change daily budget (--dry-run, --yes)
```

### Ad Groups & Ads

```bash
gads adgroup list --campaign 12345   # List ad groups in a campaign
gads adgroup create 12345 "My Group" # Create ad group
gads adgroup status 67890 PAUSED     # Pause an ad group
gads ad list --campaign 12345        # List ads with creatives
gads ad perf --days 7                # Ad-level performance
gads ad status 67890 11111 PAUSED    # Pause an ad
```

### Keywords

```bash
gads keyword list --campaign 12345 --days 30  # Keyword performance
gads keyword add 67890 "tesla parts" -m PHRASE  # Add keyword to ad group
gads keyword remove 67890 99999               # Remove by criterion ID
gads keyword negative 12345 "free" -m BROAD   # Add negative keyword
gads keyword search-terms --days 7 --min-clicks 2  # Search terms report
gads keyword ideas -k "tesla parts,used parts" --geo 2784  # Keyword Planner ★
gads keyword forecast -k "tesla parts" --geo 2784           # Volume forecast ★

# Account-level negatives (block a term in EVERY campaign at once)
gads keyword account-negative list                          # All account-wide negative criteria
gads keyword account-negative add "installation" -m PHRASE  # Auto-provisions the shared set on first use
```

### Assets & Extensions

```bash
gads asset list                      # List all assets
gads asset list --type SITELINK      # Filter by type
gads asset sitelink 12345 --link-text "Contact Us" --url "https://..." --desc1 "..."
gads asset callout 12345 --text "Free Shipping"
gads asset call 12345 --phone "+1234567890" --country-code US
```

### Conversions

```bash
gads conversion list                 # All conversion actions
gads conversion perf --days 7        # Performance by conversion action
gads conversion tag 12345            # Get tracking snippet
gads conversion create "My Action" --type WEBPAGE
gads conversion set-primary 12345 --primary          # Promote to Primary (drives Smart Bidding)
gads conversion set-primary 12345 --secondary        # Demote to Secondary (observation-only)
gads conversion upload --gclid xxx --action-id yyy --time "2026-03-27T12:00:00"
```

### Audiences (Customer Match)

```bash
gads audience list                   # All user lists with sizes/match rates
gads audience create "My List" --life-span 540
gads audience upload data.csv --list-name "My List" --create  # Full pipeline
gads audience job-status 12345       # Check upload job status
```

CSV format: `Phone,Email,First Name,Last Name,Country` — all PII is SHA-256 hashed automatically.

### Data Manager API (modern conversion/audience ingestion)

```bash
# Conversion events — JSON-lines input, one Event object per line
gads data-manager conversion-ingest events.jsonl --action-id 123456789 --dry-run
gads data-manager conversion-ingest events.jsonl --action-id 123456789 --batch-size 2000 --yes --json

# Audience upload — same CSV shape as `audience upload`, parallel path (not a replacement)
gads data-manager audience-upload data.csv --list-resource-name 987654321 --dry-run
gads data-manager audience-upload data.csv --list-resource-name 987654321 --yes --json
```

> ⚠️ Both commands only ever report *"N submitted — ingestion is asynchronous, no per-item status
> available in this response"* — the Data Manager API's `events:ingest` / `audienceMembers:ingest`
> return only `{"requestId": "..."}` on success, with no per-event/-member confirmation (unlike the
> legacy `conversion upload` / `audience upload` commands above). See
> [`kb/data-manager-api.md`](kb/data-manager-api.md) for the full schema reference.

### Performance Max (read-only)

```bash
gads pmax asset-groups                        # Asset groups: status, ad strength, performance
gads pmax asset-groups --campaign 12345        # Filter to one campaign
gads pmax signals --campaign 12345             # Audience + search-theme signals
gads pmax listing-groups --campaign 12345      # Listing group filters (product partitions)
gads pmax search-terms --campaign 12345 --days 30  # Search-term category insights (--campaign required)
```

### Reports

```bash
gads report geo --days 7             # Geographic breakdown
gads report hourly --days 7          # Hourly performance
gads report devices --days 7         # Device breakdown
gads report search-terms --days 7    # Search terms report
gads report shopping --days 7        # Per-SKU Shopping performance (shopping_performance_view)
```

### Generic Mutations (escape hatch)

```bash
gads mutate campaigns '[{"update": {"resourceName": "...", "status": "PAUSED"}, "updateMask": "status"}]'
gads batch-mutate '[{"campaignOperation": {"update": ...}}]'
```

> ⚠️ `batch-mutate` sends `partialFailure=true`: if some operations in the batch fail, the
> successful ones are still applied (not rejected atomically), per-operation results are printed,
> and the command exits non-zero.

### Google Business Profile

```bash
gads gbp accounts
gads gbp locations --account accounts/123456789
gads gbp location locations/987654321
gads gbp reviews locations/987654321
gads gbp reply-review accounts/123/locations/456/reviews/789 "Thank you!"
gads gbp delete-reply accounts/123/locations/456/reviews/789
```

### Google Merchant Center

```bash
gads merchant account                # Account info
gads merchant status                 # Account issues
gads merchant products               # Product listings (pages full catalogue; --limit caps rows shown)
gads merchant product-status         # Approval statuses + account-wide cascade summary (full catalogue)
gads merchant feeds                  # Data feeds
gads merchant shipping               # Shipping settings
gads merchant returns                # Return policy

# Merchant reports sub-API (its own SQL-like query dialect — NOT GAQL)
gads merchant report -q "SELECT offer_id, title, clicks FROM product_performance_view WHERE date BETWEEN '2026-08-01' AND '2026-08-30' ORDER BY clicks DESC LIMIT 50"
gads merchant report-product-performance --days 30   # Canned per-SKU clicks/impressions/CTR (no cost; free-traffic conversions only)
```

### Google Analytics (GA4)

```bash
gads ga4 metadata                    # Available dimensions/metrics
gads ga4 report -d date -m activeUsers,sessions --start 7daysAgo
gads ga4 realtime -d country -m activeUsers

# Key events (the GA4 replacement for "conversions"). List is read-only
# (analytics.readonly). Create / bulk / delete need the analytics.edit
# scope — regenerate the token via tools/generate_token.py if missing.
gads ga4 key-events list
gads ga4 key-events create whatsapp_click
gads ga4 key-events bulk "whatsapp_click,phone_click,form_submit,add_to_cart"
gads ga4 key-events delete whatsapp_click --yes
```

### Automation (cron)

```bash
# Daily data fetch
python fetch_daily.py --days 3 --push

# Cron example (3:30 AM daily)
30 3 * * * cd /path/to/project && gads refresh --days 3 --push
```

---

## Configuration

All configuration via environment variables or `.env` file. See [`.env.example`](.env.example).

### Required vs Optional

| Variable | Required for | Description |
|----------|-------------|-------------|
| `GOOGLE_ADS_DEVELOPER_TOKEN` | **All Google Ads commands** | Developer token from [API Center](https://ads.google.com/aw/apicenter) |
| `GOOGLE_ADS_CUSTOMER_ID` | **All Google Ads commands** | 10-digit account ID (no dashes) |
| `GOOGLE_ADS_LOGIN_CUSTOMER_ID` | MCC setups | Manager account ID |
| `GOOGLE_MERCHANT_CENTER_ID` | Merchant Center commands | MC account ID |
| `GOOGLE_GA4_PROPERTY_ID` | GA4 commands | Property ID (digits only) |
| `GADS_TIMEZONE` | Optional (default: `UTC`) | IANA timezone (e.g. `America/New_York`) |
| `GADS_CURRENCY` | Optional (default: `USD`) | ISO 4217 code (e.g. `AED`, `EUR`) |
| `GOOGLE_ADS_API_VERSION` | Optional (default: `v24`) | API version |
| `GADS_HTTP_RETRIES` | Optional (default: `4`) | Max attempts for retryable HTTP requests (429/5xx/connection errors) |
| `GADS_HTTP_TIMEOUT` | Optional (default: `30`) | Per-request timeout in seconds |

> **GBP, GSC, Merchant Center, and GA4 commands do NOT need a developer token** — only OAuth credentials.

### Which commands need what

| Commands | Dev token | OAuth scope | Min access level |
|----------|-----------|-------------|-----------------|
| `gbp accounts/locations/reviews/reply-review/delete-reply` | No | `business.manage` | — |
| `gbp perf/perf-all/search-keywords/metrics-list` | No | `business.manage` | — |
| `gbp ads-perf/ads-daily` | Yes | `adwords` | Explorer |
| `gsc *` | No | `webmasters.readonly` | — |
| `merchant *` | No | `content` | — |
| `ga4 *` | No | `analytics.readonly` | — |
| `query`, `perf`, `campaign *`, `adgroup *`, `ad *`, `report *` | Yes | `adwords` | Explorer |
| `keyword add/remove/negative/search-terms/account-negative` | Yes | `adwords` | Explorer |
| `keyword ideas`, `keyword forecast` | Yes | `adwords` | **Standard** |
| `pmax *` | Yes | `adwords` | Explorer |
| `merchant report`, `merchant report-product-performance` | No | `content` | — |
| `audience upload` | Yes | `adwords` | Basic |
| `data-manager conversion-ingest`, `data-manager audience-upload` | No | `datamanager` | — |
| `campaign status/budget`, `asset *`, `mutate *` | Yes | `adwords` | Explorer |

### Agent Enforcement (optional)

```bash
GADS_ENFORCE_CALLER=1
GADS_EXPECTED_CALLER=my-operator-agent
GADS_CALLER_AGENT=my-operator-agent  # Set by the calling agent
```

---

## Manual Setup

If you prefer not to use `gads auth setup`, here's the manual process:

### 1. Prerequisites

- Python 3.10+
- A [Google Cloud project](https://console.cloud.google.com/projectcreate)
- A [Google Ads Manager (MCC) account](https://ads.google.com/intl/en/home/tools/manager-accounts/) for the developer token

### 2. Enable APIs

Click each link → click "ENABLE" (only enable what you need):

| API | For | Link |
|-----|-----|------|
| Google Ads API | **Required** | [Enable](https://console.cloud.google.com/apis/library/googleads.googleapis.com) |
| My Business Account Mgmt API | GBP | [Enable](https://console.cloud.google.com/apis/library/mybusinessaccountmanagement.googleapis.com) |
| My Business Business Info API | GBP | [Enable](https://console.cloud.google.com/apis/library/mybusinessbusinessinformation.googleapis.com) |
| My Business v4 (legacy) | GBP reviews | [Enable](https://console.cloud.google.com/apis/library/mybusiness.googleapis.com) |
| Merchant API v1 (`merchantapi.googleapis.com`) | Merchant Center | [Enable](https://console.cloud.google.com/apis/library/merchantapi.googleapis.com) |
| GA4 Data API | GA4 | [Enable](https://console.cloud.google.com/apis/library/analyticsdata.googleapis.com) |
| GA4 Admin API | GA4 | [Enable](https://console.cloud.google.com/apis/library/analyticsadmin.googleapis.com) |
| Data Manager API (`datamanager.googleapis.com`) | `data-manager *` | [Enable](https://console.cloud.google.com/apis/library/datamanager.googleapis.com) |

### 3. OAuth Consent Screen

1. Go to [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent)
2. User Type: **External**
3. App name, support email, developer contact → fill in
4. Scopes → skip
5. Test Users → **add your Google account email**
6. Save → your app stays in "Testing" mode (fine, no need to publish)

### 4. OAuth Credentials

1. Go to [Credentials](https://console.cloud.google.com/apis/credentials)
2. **+ CREATE CREDENTIALS** → **OAuth client ID** → **Desktop app**
3. **DOWNLOAD JSON** → save as `credentials/client_secret.json`

### 5. Developer Token

Developer tokens are created from **Manager (MCC) accounts**, not regular ad accounts.

1. [Create an MCC](https://ads.google.com/intl/en/home/tools/manager-accounts/) if you don't have one
2. Link your ad account(s) to it
3. Go to [API Center](https://ads.google.com/aw/apicenter) in the MCC
4. Apply for Basic Access (1-3 days approval)
5. Copy the token → set `GOOGLE_ADS_DEVELOPER_TOKEN` in `.env`

#### Access Levels

| Level | Approval | Ops/day | What you get |
|-------|----------|---------|-------------|
| **Test** | Instant | 15,000 | Test accounts only |
| **Explorer** | Auto | 2,880 prod | Most features — sufficient for basic automation |
| **Basic** | ~2 days | 15,000 | Production access, most CLI commands |
| **Standard** | ~10 days | Unlimited | + Keyword Planner, Audience Insights, Reach Planner, Billing |

### 6. Configure & Login

```bash
cp .env.example .env   # Edit with your values
gads auth login        # Opens browser for OAuth
gads doctor            # Verify everything
```

> **WSL/headless:** if the local callback listener is unreliable (dies, or its `state` token mismatches a stale tab), skip it entirely with the two-step flow:
> ```bash
> gads auth login --print-url-only              # prints the consent URL, doesn't touch the token
> # open it, grant access, then paste the resulting http://localhost:9090/?...&code=... URL back:
> gads auth login --callback-url '<pasted URL>'  # or --code '<code>' with just the code
> ```
> `--port` (default `9090`) must match across both steps. This goes through the same scope-regression guard as the browser flow — a token missing scopes vs. the existing one is refused unless `--allow-partial` is passed.

> ⚠️ **Customer Match deprecation:** Starting April 1, 2026, `audience upload` will fail if your token has never sent a successful Customer Match request. Upload before that date, or use `gads data-manager audience-upload` (the modern Data Manager API path — see [`kb/data-manager-api.md`](kb/data-manager-api.md)), which is unaffected by this deprecation.

---

## Architecture

```
gads-cli/
├── gads                  # CLI entry point (thin shim)
├── gads.sh               # Shell wrapper with .env loading
├── gads_lib/
│   ├── __init__.py       # Version + public API exports
│   ├── cli.py            # All Click command groups (129 commands)
│   ├── config.py         # Scope-aware env config
│   ├── auth.py           # OAuth credential management
│   ├── ads.py            # Google Ads REST client + GAQL + mutations (Ads v24)
│   ├── gbp.py            # GBP client (4 base URLs: account mgmt, business info, legacy v4, performance)
│   ├── gsc.py            # Search Console client (webmasters/v3 + URL Inspection v1)
│   ├── merchant.py       # Merchant Center client (Merchant API v1)
│   ├── ga4.py            # GA4 Data API v1beta + Admin API v1beta
│   ├── datamanager.py    # Data Manager API client (events:ingest, audienceMembers:ingest)
│   ├── catalog.py        # Live Click-tree catalog emitter
│   ├── dbread.py         # SELECT-only history-DB passthrough
│   ├── analyze/          # 5 read-only analysis modules (lp_score, wasted_spend, ngrams, adcopy, competitive)
│   ├── http.py           # HTTP helpers + graceful error classifier (4-class)
│   ├── db.py             # SQLite connection manager
│   ├── output.py         # Table/JSON formatters + classify_api_error + offer_gcloud_enable
│   └── timeutil.py       # Timezone-aware helpers
├── kb/                   # API knowledge base (5 md files + INDEX.md + manifest.json)
├── tests/                # 373 tests (offline/CI-safe)
├── fetch_daily.py        # Cron-friendly daily data fetcher
├── generate_token.py     # OAuth token generator (6 scopes incl. webmasters.readonly)
├── scripts/install.sh    # Interactive installer
├── .github/workflows/    # CI pipeline (Python 3.10-3.13 × Ubuntu + macOS)
├── pyproject.toml        # Package metadata
├── .env.example          # Configuration template
├── AGENTS.md             # Agent-driveable capability index
├── llms.txt              # LLM-optimised quick reference
├── CLAUDE.md             # AI agent reference
├── CHANGELOG.md          # Version history
└── README.md
```

Uses Google REST APIs directly (`requests` + `google-auth`) — no protobuf, no `google-ads` client library.

---

## Using with Claude Code

The included `CLAUDE.md` gives Claude full context about commands, auth, and known gotchas.

```bash
claude "Run gads perf --days 7 and analyze the trends"
claude "Check my GBP reviews and draft replies for any negative ones"
claude "Pull fresh data and compare this week vs last week"
```

---

## Sister tool

For **Meta (Facebook/Instagram) Ads** — Marketing API campaigns/ad sets/ads/creatives, Business
Manager, Conversions API (CAPI), and Commerce Manager — see the sister CLI **mads-cli**:
https://github.com/talas9/mads-cli

`mads-cli` shares the same architecture conventions as `gads-cli` — scope-aware config, `--json`/
`--plain`/`--quiet`, structured error envelope + stable exit codes, `snapshot → mutate → log`
discipline, `catalog --json` self-description, and read-only `db`/`changelog`/`decisions`/
`milestones` history access. If you manage both Google Ads and Meta Ads for the same business,
both CLIs can share a single history DB (their `changelog` tables use identical column names), and
`gads doctor` reports whether `mads` is installed via a `sibling_cli` field (and vice versa).

---

## Contributing

1. Fork → feature branch → make changes
2. `gads doctor` to verify
3. Push → open PR

CI runs Python 3.10-3.13 on Ubuntu + macOS automatically.

## License

MIT — see [LICENSE](LICENSE).
