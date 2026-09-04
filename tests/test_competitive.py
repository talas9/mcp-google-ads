"""Offline pytest tests for gads_lib/analyze/competitive.py.

ALL Google Ads API calls are mocked (requests.post, never live HTTP).

Regression coverage for the 2026-09-04 auction-insights fix: the module used
to query ``auction_insight.domain`` (UNRECOGNIZED_FIELD — the domain is a
SEGMENT, not a resource field) and ``..._impression_share`` for the "top" /
"absolute top" metrics (also UNRECOGNIZED_FIELD — the real names end in
``..._impression_percentage``). Both bugs were caught by
``queryError: UNRECOGNIZED_FIELD`` on live v25, but `_run_gaql_safe` swallows
GAQL errors into `auction_insights_error` so the CLI exited 0 with an empty
section, silently hiding the defect. See kb/google-ads.md Gotcha #19.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest

from gads_lib.analyze.competitive import (
    AUCTION_INSIGHT_DOMAIN_FIELD,
    AUCTION_INSIGHT_METRIC_FIELDS,
    _fetch_auction_insights,
)

# ---------------------------------------------------------------------------
# The canonical, doc-verified field list (kb/google-ads.md Gotcha #19,
# verified live against the v25 API 2026-09-04). Any drift between this list
# and the constants the module actually queries with is the regression this
# file guards against.
# ---------------------------------------------------------------------------
KB_AUCTION_INSIGHT_DOMAIN_FIELD = "segments.auction_insight_domain"
KB_AUCTION_INSIGHT_METRIC_FIELDS = [
    "metrics.auction_insight_search_impression_share",
    "metrics.auction_insight_search_overlap_rate",
    "metrics.auction_insight_search_position_above_rate",
    "metrics.auction_insight_search_top_impression_percentage",
    "metrics.auction_insight_search_absolute_top_impression_percentage",
    "metrics.auction_insight_search_outranking_share",
]

# Field names that are confirmed WRONG (UNRECOGNIZED_FIELD on live v25) and
# must never reappear in the query.
KNOWN_BAD_FIELDS = [
    "auction_insight.domain",  # domain is a segment, not a resource field
    "metrics.auction_insight_search_top_impression_share",
    "metrics.auction_insight_search_absolute_top_impression_share",
]


class TestAuctionInsightFieldNames:
    """GAQL field names must match the KB-documented, live-verified list."""

    def test_module_constants_match_kb(self):
        assert AUCTION_INSIGHT_DOMAIN_FIELD == KB_AUCTION_INSIGHT_DOMAIN_FIELD
        assert AUCTION_INSIGHT_METRIC_FIELDS == KB_AUCTION_INSIGHT_METRIC_FIELDS

    def test_query_uses_segment_field_for_domain(self, fake_creds):
        """The competitor domain must be selected as segments.auction_insight_domain."""
        captured = {}

        def fake_safe(creds, query):
            captured["query"] = query
            return [], None

        with patch("gads_lib.analyze.competitive._run_gaql_safe", side_effect=fake_safe):
            _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert "segments.auction_insight_domain" in captured["query"]

    def test_query_uses_percentage_not_share_for_top_metrics(self, fake_creds):
        """top / absolute-top fields must end in _percentage, not _share."""
        captured = {}

        def fake_safe(creds, query):
            captured["query"] = query
            return [], None

        with patch("gads_lib.analyze.competitive._run_gaql_safe", side_effect=fake_safe):
            _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        query = captured["query"]
        assert "metrics.auction_insight_search_top_impression_percentage" in query
        assert "metrics.auction_insight_search_absolute_top_impression_percentage" in query

    def test_query_never_contains_known_bad_fields(self, fake_creds):
        captured = {}

        def fake_safe(creds, query):
            captured["query"] = query
            return [], None

        with patch("gads_lib.analyze.competitive._run_gaql_safe", side_effect=fake_safe):
            _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        query = captured["query"]
        for bad_field in KNOWN_BAD_FIELDS:
            assert bad_field not in query, f"regression: bad field {bad_field!r} reappeared in query"

    def test_query_selects_all_kb_metric_fields(self, fake_creds):
        captured = {}

        def fake_safe(creds, query):
            captured["query"] = query
            return [], None

        with patch("gads_lib.analyze.competitive._run_gaql_safe", side_effect=fake_safe):
            _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        query = captured["query"]
        for field in KB_AUCTION_INSIGHT_METRIC_FIELDS:
            assert field in query


class TestFetchAuctionInsightsParsing:
    """Row parsing must read the domain from `segments`, not `auctionInsight`."""

    def test_parses_domain_from_segments(self, fake_creds):
        rows = [
            {
                "campaign": {"name": "Camp-A"},
                "segments": {"auctionInsightDomain": "amazon.ae"},
                "metrics": {
                    "auctionInsightSearchImpressionShare": 0.42,
                    "auctionInsightSearchOverlapRate": 0.31,
                    "auctionInsightSearchPositionAboveRate": 0.55,
                    "auctionInsightSearchTopImpressionPercentage": 0.20,
                    "auctionInsightSearchAbsoluteTopImpressionPercentage": 0.10,
                    "auctionInsightSearchOutrankingShare": 0.15,
                },
            },
        ]
        with patch("gads_lib.analyze.competitive._run_gaql_safe", return_value=(rows, None)):
            result, err = _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert err is None
        assert len(result) == 1
        entry = result[0]
        assert entry["domain"] == "amazon.ae"
        assert entry["impression_share"] == 42.0
        assert entry["overlap_rate"] == 31.0
        assert entry["position_above_rate"] == 55.0
        assert entry["top_is"] == 20.0
        assert entry["abs_top_is"] == 10.0
        assert entry["outranking_share"] == 15.0

    def test_rows_with_empty_domain_are_skipped(self, fake_creds):
        rows = [
            {"campaign": {"name": "Camp-A"}, "segments": {"auctionInsightDomain": ""},
             "metrics": {"auctionInsightSearchImpressionShare": 0.5}},
        ]
        with patch("gads_lib.analyze.competitive._run_gaql_safe", return_value=(rows, None)):
            result, err = _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert err is None
        assert result == []

    def test_legacy_auction_insight_key_is_ignored(self, fake_creds):
        """A row shaped like the OLD (wrong) response parse target must not
        produce a domain — proves parsing now reads `segments`, not
        `auctionInsight`."""
        rows = [
            {"campaign": {"name": "Camp-A"}, "auctionInsight": {"domain": "old-shape.example"},
             "metrics": {"auctionInsightSearchImpressionShare": 0.5}},
        ]
        with patch("gads_lib.analyze.competitive._run_gaql_safe", return_value=(rows, None)):
            result, err = _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert err is None
        assert result == []  # no `segments` key → domain resolves empty → skipped

    def test_empty_response_no_crash(self, fake_creds):
        with patch("gads_lib.analyze.competitive._run_gaql_safe", return_value=([], None)):
            result, err = _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert result == []
        assert err is None


class TestFetchAuctionInsightsErrorPassthrough:
    """PERMISSION_DENIED (account not allowlisted for the metrics) must
    surface as a real error, not be masked as an empty-but-successful result."""

    def test_permission_denied_surfaces_as_error_not_silent_empty(self, fake_creds):
        err_text = (
            "HTTP 403: authorizationError METRIC_ACCESS_DENIED — "
            "The developer doesn't have access to metrics: "
            "'auction_insight_search_impression_share'."
        )
        with patch("gads_lib.analyze.competitive._run_gaql_safe", return_value=([], err_text)):
            result, err = _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert result == []
        assert err == err_text  # error must propagate, not be swallowed

    def test_never_raises_on_malformed_row(self, fake_creds):
        """A malformed row (missing metrics/segments) must not crash the module."""
        rows = [{"campaign": {"name": "Camp-A"}}]
        with patch("gads_lib.analyze.competitive._run_gaql_safe", return_value=(rows, None)):
            result, err = _fetch_auction_insights(fake_creds, "2026-08-20", "2026-09-02")

        assert err is None
        assert result == []
