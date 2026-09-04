"""Competitive intelligence via impression-share metrics and auction insights.

PRIMARY signal: keyword-level impression-share metrics from keyword_view —
reliably available and directly quantify competitive pressure:
  - search_impression_share          → fraction of auctions we showed
  - search_top_impression_share      → fraction of auctions we showed above results
  - search_absolute_top_impression_share → fraction at absolute #1 position
  - search_rank_lost_impression_share   → IS lost due to Ad Rank (competitors outranking us)
  - search_budget_lost_impression_share → IS lost due to budget constraints

SECONDARY (best-effort): true auction_insight query via the
``campaign`` resource. Google Ads REST API v19+ does NOT expose a dedicated
auction-insights endpoint in GAQL; the data only appears in the UI and
reports. We attempt a known segmented query and catch failures gracefully.

All impression-share values come from the API as floats (0–1). We display
them as percentages (multiply by 100).

READ-ONLY: only run_gaql (or direct requests) is used here. Nothing mutates
the account.
Date window always ends YESTERDAY (never same-day — 24-48h attribution lag).
"""

from datetime import datetime, timedelta

import requests

from ..ads import run_gaql, get_ads_headers
from ..output import print_table, print_json
from ..config import CURRENCY, API_VERSION, CUSTOMER_ID


# ── helpers ─────────────────────────────────────────────────────────────────

def _window(days: int):
    """Return (d_from, d_to) as YYYY-MM-DD strings. d_to = yesterday."""
    d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    d_from = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    return d_from, d_to


def _pct(val) -> float | None:
    """Convert a 0–1 fraction from the API to a 0–100 percentage, or None."""
    if val is None:
        return None
    try:
        f = float(val)
        # The API occasionally returns sentinel values outside [0,1]
        # (e.g. 9223372036854775807 meaning "unknown/unavailable").
        if f > 1.5 or f < 0:
            return None
        return round(f * 100, 2)
    except (TypeError, ValueError):
        return None


def _pressure_label(rank_lost_is_pct: float | None) -> str:
    """Classify competitive pressure from rank-lost IS percentage."""
    if rank_lost_is_pct is None:
        return "unknown"
    if rank_lost_is_pct >= 50:
        return "high"
    if rank_lost_is_pct >= 20:
        return "medium"
    return "low"


def _run_gaql_safe(creds, query: str) -> tuple[list, str | None]:
    """Run a GAQL query via searchStream but NEVER raise/SystemExit on error.

    Returns (results, error_string_or_None).
    Used for the optional auction-insights attempt so the module never crashes.
    """
    try:
        resp = requests.post(
            f"https://googleads.googleapis.com/{API_VERSION}"
            f"/customers/{CUSTOMER_ID}/googleAds:searchStream",
            headers=get_ads_headers(creds),
            json={"query": query},
            timeout=30,
        )
        if resp.status_code != 200:
            return [], f"HTTP {resp.status_code}: {resp.text[:400]}"
        results = []
        for batch in resp.json():
            results.extend(batch.get("results", []))
        return results, None
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


# ── primary analysis ─────────────────────────────────────────────────────────

def _fetch_keyword_pressure(creds, d_from: str, d_to: str, top: int) -> list[dict]:
    """Query keyword_view impression-share metrics for SEARCH campaigns.

    Note: search_budget_lost_impression_share is NOT available on keyword_view
    (PROHIBITED_METRIC error). It is only compatible with the campaign resource.
    We omit it here and derive competitive pressure from rank_lost_is only.
    """
    rows = run_gaql(creds, f"""
        SELECT
            ad_group_criterion.keyword.text,
            campaign.name,
            campaign.advertising_channel_type,
            metrics.impressions,
            metrics.clicks,
            metrics.search_impression_share,
            metrics.search_top_impression_share,
            metrics.search_absolute_top_impression_share,
            metrics.search_rank_lost_impression_share
        FROM keyword_view
        WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
          AND campaign.advertising_channel_type = 'SEARCH'
          AND campaign.status != 'REMOVED'
          AND ad_group.status != 'REMOVED'
          AND ad_group_criterion.status != 'REMOVED'
        ORDER BY metrics.search_rank_lost_impression_share DESC
        LIMIT {top * 5}
    """)

    # Aggregate per (keyword_text, campaign_name) — API may return one row per
    # date segment even when segments.date is in WHERE but not SELECT.
    agg: dict[tuple, dict] = {}
    for r in rows:
        kw = r.get("adGroupCriterion", {}).get("keyword", {})
        camp = r.get("campaign", {})
        m = r.get("metrics", {})

        text = kw.get("text", "")
        camp_name = camp.get("name", "")
        key = (text, camp_name)

        entry = agg.setdefault(key, {
            "keyword": text,
            "campaign": camp_name,
            "impr": 0,
            "clicks": 0,
            # IS metrics: accumulate raw values + count for averaging
            "_is_sum": 0.0, "_is_n": 0,
            "_top_sum": 0.0, "_top_n": 0,
            "_abs_sum": 0.0, "_abs_n": 0,
            "_rank_sum": 0.0, "_rank_n": 0,
        })
        entry["impr"] += int(m.get("impressions", 0))
        entry["clicks"] += int(m.get("clicks", 0))

        def _accum(key_sum, key_n, raw_val):
            v = _pct(raw_val)
            if v is not None:
                entry[key_sum] += v
                entry[key_n] += 1

        _accum("_is_sum", "_is_n", m.get("searchImpressionShare"))
        _accum("_top_sum", "_top_n", m.get("searchTopImpressionShare"))
        _accum("_abs_sum", "_abs_n", m.get("searchAbsoluteTopImpressionShare"))
        _accum("_rank_sum", "_rank_n", m.get("searchRankLostImpressionShare"))

    def _avg(entry, s_key, n_key):
        n = entry[n_key]
        return round(entry[s_key] / n, 2) if n > 0 else None

    results = []
    for entry in agg.values():
        rank_lost = _avg(entry, "_rank_sum", "_rank_n")
        row = {
            "keyword": entry["keyword"],
            "campaign": entry["campaign"],
            "impr": entry["impr"],
            "clicks": entry["clicks"],
            "impression_share": _avg(entry, "_is_sum", "_is_n"),
            "top_is": _avg(entry, "_top_sum", "_top_n"),
            "abs_top_is": _avg(entry, "_abs_sum", "_abs_n"),
            "rank_lost_is": rank_lost,
            "budget_lost_is": None,  # not available on keyword_view resource
            "pressure": _pressure_label(rank_lost),
        }
        results.append(row)

    # Sort by rank_lost_is descending (None → treat as 0)
    results.sort(key=lambda x: (x["rank_lost_is"] or 0), reverse=True)
    return results[:top]


# ── auction insights (best-effort) ───────────────────────────────────────────

#: Canonical GAQL field names for the auction-insight segment/metrics on the
#: ``campaign`` resource — verified live against the v25 API 2026-09-04 (see
#: kb/google-ads.md Gotcha #19). The competitor domain is a SEGMENT
#: (``segments.auction_insight_domain``), not a resource field, and the two
#: "impression share" fields are actually named ``..._impression_percentage``.
AUCTION_INSIGHT_DOMAIN_FIELD = "segments.auction_insight_domain"
AUCTION_INSIGHT_METRIC_FIELDS = [
    "metrics.auction_insight_search_impression_share",
    "metrics.auction_insight_search_overlap_rate",
    "metrics.auction_insight_search_position_above_rate",
    "metrics.auction_insight_search_top_impression_percentage",
    "metrics.auction_insight_search_absolute_top_impression_percentage",
    "metrics.auction_insight_search_outranking_share",
]


def _fetch_auction_insights(creds, d_from: str, d_to: str) -> tuple[list[dict], str | None]:
    """Attempt true auction-insight query.

    Google Ads GAQL does not expose a dedicated auction_insight *resource*;
    the competitor domain is a SEGMENT field (``segments.auction_insight_domain``)
    on the ``campaign`` resource, joined with ``metrics.auction_insight_search_*``
    metrics. Two of those metrics are named ``..._impression_percentage``, not
    ``..._impression_share`` (verified live 2026-09-04 — see kb/google-ads.md
    Gotcha #19). The metrics themselves are allowlist-gated: an account without
    Auction Insights API access gets PERMISSION_DENIED even with correct field
    names, which this function surfaces as ``err`` rather than masking.

    Returns (rows_or_empty, error_string_or_None).
    """
    select_fields = ", ".join([AUCTION_INSIGHT_DOMAIN_FIELD, *AUCTION_INSIGHT_METRIC_FIELDS])
    rows, err = _run_gaql_safe(creds, f"""
        SELECT
            campaign.name,
            {select_fields}
        FROM campaign
        WHERE segments.date BETWEEN '{d_from}' AND '{d_to}'
          AND campaign.advertising_channel_type = 'SEARCH'
          AND campaign.status != 'REMOVED'
        LIMIT 200
    """)

    if err:
        return [], err

    # Parse rows
    insights: dict[str, dict] = {}
    for r in rows:
        m = r.get("metrics", {})
        domain = r.get("segments", {}).get("auctionInsightDomain", "")
        if not domain:
            continue
        entry = insights.setdefault(domain, {
            "domain": domain,
            "impression_share": None,
            "overlap_rate": None,
            "position_above_rate": None,
            "top_is": None,
            "abs_top_is": None,
            "outranking_share": None,
            "_counts": {},
        })
        # Average IS metrics across campaigns/dates
        for api_key, out_key in [
            ("auctionInsightSearchImpressionShare", "impression_share"),
            ("auctionInsightSearchOverlapRate", "overlap_rate"),
            ("auctionInsightSearchPositionAboveRate", "position_above_rate"),
            ("auctionInsightSearchTopImpressionPercentage", "top_is"),
            ("auctionInsightSearchAbsoluteTopImpressionPercentage", "abs_top_is"),
            ("auctionInsightSearchOutrankingShare", "outranking_share"),
        ]:
            raw = m.get(api_key)
            pct = _pct(raw)
            if pct is not None:
                cnts = entry["_counts"]
                s_key, n_key = f"{out_key}_s", f"{out_key}_n"
                cnts[s_key] = cnts.get(s_key, 0.0) + pct
                cnts[n_key] = cnts.get(n_key, 0) + 1

    result_list = []
    for domain, entry in insights.items():
        cnts = entry.pop("_counts", {})
        for out_key in ["impression_share", "overlap_rate", "position_above_rate",
                        "top_is", "abs_top_is", "outranking_share"]:
            s_key, n_key = f"{out_key}_s", f"{out_key}_n"
            n = cnts.get(n_key, 0)
            entry[out_key] = round(cnts[s_key] / n, 2) if n > 0 else None
        result_list.append(entry)

    # Sort by impression_share desc
    result_list.sort(key=lambda x: (x["impression_share"] or 0), reverse=True)
    return result_list, None


# ── public interface ─────────────────────────────────────────────────────────

def analyze_competitive(creds, days: int = 30, top: int = 50) -> dict:
    """Competitive intelligence — impression-share pressure + auction insights.

    Parameters
    ----------
    creds   : OAuth credentials from gads_lib.get_credentials()
    days    : look-back window ending YESTERDAY (24-48h attribution lag)
    top     : max keyword rows to return (ranked by rank_lost_is desc)

    Returns
    -------
    {
      "window": {"from": str, "to": str, "days": int},
      "currency": str,
      "keyword_pressure": [
          {
            "keyword": str, "campaign": str,
            "impr": int, "clicks": int,
            "impression_share": float|None,   # % of eligible auctions shown
            "top_is": float|None,             # % shown above organic results
            "abs_top_is": float|None,         # % at absolute #1
            "rank_lost_is": float|None,       # % lost to Ad Rank (competitor pressure)
            "budget_lost_is": float|None,     # % lost to budget
            "pressure": str,                  # "high"|"medium"|"low"|"unknown"
          }, ...
      ],  # sorted by rank_lost_is desc
      "auction_insights_available": bool,
      "auction_insights": [
          {
            "domain": str,
            "impression_share": float|None,
            "overlap_rate": float|None,
            "position_above_rate": float|None,
            "top_is": float|None,
            "abs_top_is": float|None,
            "outranking_share": float|None,
          }, ...
      ],
      "auction_insights_error": str|None,
      "summary": {
          "avg_impression_share": float|None,
          "avg_rank_lost": float|None,
      },
    }
    """
    d_from, d_to = _window(days)

    # ── Primary: keyword impression-share pressure ────────────────────────
    keyword_pressure = _fetch_keyword_pressure(creds, d_from, d_to, top)

    # ── Summary stats ─────────────────────────────────────────────────────
    is_values = [r["impression_share"] for r in keyword_pressure if r["impression_share"] is not None]
    rl_values = [r["rank_lost_is"] for r in keyword_pressure if r["rank_lost_is"] is not None]
    avg_is = round(sum(is_values) / len(is_values), 2) if is_values else None
    avg_rl = round(sum(rl_values) / len(rl_values), 2) if rl_values else None

    # ── Secondary: auction insights (best-effort, never crashes) ─────────
    ai_rows, ai_err = _fetch_auction_insights(creds, d_from, d_to)
    ai_available = len(ai_rows) > 0

    return {
        "window": {"from": d_from, "to": d_to, "days": days},
        "currency": CURRENCY,
        "keyword_pressure": keyword_pressure,
        "auction_insights_available": ai_available,
        "auction_insights": ai_rows,
        "auction_insights_error": ai_err,
        "summary": {
            "avg_impression_share": avg_is,
            "avg_rank_lost": avg_rl,
        },
    }


# ── rendering ────────────────────────────────────────────────────────────────

def render_competitive(result: dict, as_json: bool = False, top: int = 25) -> None:
    """Print competitive intelligence report to stdout.

    If as_json=True, dumps the full result dict as JSON.
    Otherwise, prints:
      1. A keyword-pressure table (top N rows, sorted by rank_lost_is desc)
      2. An auction-insights table (if available)
      3. A summary line with average impression-share / rank-lost IS
    """
    import click

    if as_json:
        return print_json(result)

    w = result["window"]
    summary = result.get("summary", {})
    avg_is = summary.get("avg_impression_share")
    avg_rl = summary.get("avg_rank_lost")

    click.secho(
        f"\nCompetitive intelligence — {w['from']} → {w['to']} ({w['days']}d)",
        fg="yellow", bold=True,
    )

    # ── Keyword pressure table ────────────────────────────────────────────
    kp = result.get("keyword_pressure", [])[:top]
    click.secho(
        f"\nKeyword competitive pressure ({len(kp)} keywords, sorted by rank-lost IS ↓):",
        fg="white", bold=True,
    )
    if kp:
        # Format percentages for display: replace None with "—"
        table_rows = []
        for r in kp:
            def _fmt(v):
                return f"{v:.1f}%" if v is not None else "—"

            table_rows.append({
                "keyword": (r["keyword"][:40] + "…") if len(r["keyword"]) > 41 else r["keyword"],
                "campaign": (r["campaign"][:28] + "…") if len(r["campaign"]) > 29 else r["campaign"],
                "impr": r["impr"],
                "clicks": r["clicks"],
                "IS%": _fmt(r["impression_share"]),
                "top_IS%": _fmt(r["top_is"]),
                "abs_top%": _fmt(r["abs_top_is"]),
                "rank_lost%": _fmt(r["rank_lost_is"]),
                "bgt_lost%": _fmt(r["budget_lost_is"]),
                "pressure": r["pressure"],
            })
        print_table(
            table_rows,
            ["keyword", "campaign", "impr", "clicks", "IS%", "top_IS%",
             "abs_top%", "rank_lost%", "bgt_lost%", "pressure"],
        )
    else:
        click.echo("  (no SEARCH keyword data in window)")

    # ── Auction insights table ────────────────────────────────────────────
    click.secho("\nAuction insights (competitor domains):", fg="white", bold=True)
    ai_rows = result.get("auction_insights", [])
    ai_err = result.get("auction_insights_error")

    if ai_rows:
        ai_table = []
        for row in ai_rows:
            def _fmt(v):
                return f"{v:.1f}%" if v is not None else "—"
            ai_table.append({
                "domain": row["domain"],
                "IS%": _fmt(row["impression_share"]),
                "overlap%": _fmt(row["overlap_rate"]),
                "pos_above%": _fmt(row["position_above_rate"]),
                "top_IS%": _fmt(row["top_is"]),
                "abs_top%": _fmt(row["abs_top_is"]),
                "outrank%": _fmt(row["outranking_share"]),
            })
        print_table(
            ai_table,
            ["domain", "IS%", "overlap%", "pos_above%", "top_IS%", "abs_top%", "outrank%"],
        )
    elif ai_err:
        click.secho(
            f"  Auction insights unavailable: {ai_err}",
            fg="yellow",
        )
    else:
        click.secho(
            "  Auction insights returned no data (feature may not be available via REST API).",
            fg="yellow",
        )

    # ── Summary line ─────────────────────────────────────────────────────
    is_str = f"{avg_is:.1f}%" if avg_is is not None else "n/a"
    rl_str = f"{avg_rl:.1f}%" if avg_rl is not None else "n/a"
    click.secho(
        f"\nAvg impression share: {is_str}  |  Avg rank-lost IS: {rl_str}",
        fg="cyan", bold=True,
    )
