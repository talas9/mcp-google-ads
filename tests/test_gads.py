"""
Comprehensive offline pytest test suite for gads-cli.

ALL HTTP calls are mocked — no live API calls.
Run from the gads-cli root:
    cd /home/talas9/talas-ads/gads-cli && python -m pytest tests/ -v
"""

import json
import io
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# ── Ensure conftest env stubs are loaded before any gads_lib import ────────────
# (conftest.py sets os.environ stubs; this file only imports after that runs)


# =============================================================================
# GROUP A — Request construction (unit tests with mocked HTTP)
# =============================================================================


class TestGA4RunReportRequestShape:
    """A — ga4_run_report posts the correct JSON body."""

    def test_ga4_run_report_request_shape(self, fake_creds):
        """ga4_run_report builds the expected JSON body with dimensions/metrics/dateRanges/limit."""
        from gads_lib.ga4 import ga4_run_report

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"rows": []}'
        fake_resp.json.return_value = {"rows": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_run_report(
                fake_creds,
                dimensions=["date", "country"],
                metrics=["sessions", "activeUsers"],
                date_ranges=[{"startDate": "7daysAgo", "endDate": "yesterday"}],
                property_id="271773771",
                limit=500,
            )

        assert mock_req.called, "requests.request was never called"
        _, kwargs = mock_req.call_args
        body = kwargs.get("json") or {}

        assert "dimensions" in body, "body missing 'dimensions'"
        assert "metrics" in body, "body missing 'metrics'"
        assert "dateRanges" in body, "body missing 'dateRanges'"
        assert "limit" in body, "body missing 'limit'"

        # Dimensions are wrapped as {name: ...} objects
        dim_names = [d["name"] for d in body["dimensions"]]
        assert "date" in dim_names
        assert "country" in dim_names

        metric_names = [m["name"] for m in body["metrics"]]
        assert "sessions" in metric_names
        assert "activeUsers" in metric_names

        assert body["limit"] == 500


class TestGA4KeyEventsUsesV1Beta:
    """A — list_key_events() hits the v1beta Admin API URL."""

    def test_ga4_key_events_list_uses_v1beta(self, fake_creds):
        """list_key_events uses analyticsadmin.googleapis.com/v1beta (not v1alpha)."""
        from gads_lib.ga4 import list_key_events

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"keyEvents": []}'
        fake_resp.json.return_value = {"keyEvents": []}

        with patch("gads_lib.ga4._send_with_retry", return_value=fake_resp) as mock_send:
            result = list_key_events("271773771", fake_creds)

        assert mock_send.called
        called_url = mock_send.call_args[0][1]  # (method, url, ...)
        assert "v1beta" in called_url, f"URL should contain 'v1beta', got: {called_url}"
        assert "analyticsadmin.googleapis.com" in called_url
        assert "v1alpha" not in called_url, "URL should not use v1alpha"
        assert result == []


class TestGSCSearchAnalyticsIncludesStartRow:
    """A — gsc_search_analytics includes startRow in the POST body."""

    def test_gsc_search_analytics_includes_startrow(self, fake_creds):
        """gsc_search_analytics sends 'startRow' in its POST JSON body."""
        from gads_lib.gsc import gsc_search_analytics

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"rows": []}'
        fake_resp.json.return_value = {"rows": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_search_analytics(
                fake_creds,
                site_url="https://shop.talas.ae/",
                start_date="2026-06-01",
                end_date="2026-06-22",
                dimensions=["query"],
                row_limit=25,
                start_row=50,
            )

        assert mock_req.called
        _, kwargs = mock_req.call_args
        body = kwargs.get("json") or {}

        assert "startRow" in body, f"body missing 'startRow'; got keys: {list(body.keys())}"
        assert body["startRow"] == 50
        assert body["startDate"] == "2026-06-01"
        assert body["endDate"] == "2026-06-22"
        assert body["rowLimit"] == 25


class TestMerchantListProductsURL:
    """A — mc_list_products() hits merchantapi.googleapis.com/products/v1."""

    def test_merchant_list_products_url(self, fake_creds):
        """mc_list_products uses the Merchant API v1 products sub-API URL."""
        from gads_lib.merchant import mc_list_products

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"products": []}'
        fake_resp.json.return_value = {"products": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_list_products(fake_creds, max_results=10)

        assert mock_req.called
        _, kwargs = mock_req.call_args
        # The URL is passed as the second positional arg to requests.request(method, url, ...)
        called_url = mock_req.call_args[0][1]

        assert "merchantapi.googleapis.com" in called_url, (
            f"URL should contain 'merchantapi.googleapis.com', got: {called_url}"
        )
        assert "products/v1" in called_url, (
            f"URL should contain 'products/v1', got: {called_url}"
        )


class TestGBPDailyMetricsURL:
    """A — gbp_daily_metrics() hits businessprofileperformance.googleapis.com."""

    def test_gbp_daily_metrics_url(self, fake_creds):
        """gbp_daily_metrics uses the GBP Performance API base URL."""
        from gads_lib.gbp import gbp_daily_metrics

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"timeSeries": {"datedValues": []}}'
        fake_resp.json.return_value = {"timeSeries": {"datedValues": []}}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_daily_metrics(
                fake_creds,
                location_name="locations/123456",
                metric="CALL_CLICKS",
                start_date=(2026, 6, 1),
                end_date=(2026, 6, 22),
            )

        assert mock_req.called
        called_url = mock_req.call_args[0][1]
        assert "businessprofileperformance.googleapis.com" in called_url, (
            f"URL should contain 'businessprofileperformance.googleapis.com', got: {called_url}"
        )


# =============================================================================
# GROUP B — --json output structure
# =============================================================================


class TestOutputFlatten:
    """B — flatten() returns a flat dict."""

    def test_output_flatten_dict_simple(self):
        """flatten({a: 1}) returns {"a": 1} (trivial case)."""
        from gads_lib.output import flatten

        result = flatten({"a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}

    def test_output_flatten_dict_nested(self):
        """flatten({a: {b: {c: 3}}}) returns {"a.b.c": 3}."""
        from gads_lib.output import flatten

        nested = {"campaign": {"name": "Tesla Parts", "budget": {"amountMicros": 50000000}}}
        result = flatten(nested)
        assert "campaign.name" in result
        assert result["campaign.name"] == "Tesla Parts"
        assert "campaign.budget.amountMicros" in result
        assert result["campaign.budget.amountMicros"] == 50000000
        # No sub-dicts in output
        for v in result.values():
            assert not isinstance(v, dict), f"Expected flat value, got dict: {v}"

    def test_output_flatten_dict_with_prefix(self):
        """flatten with a prefix prepends it to all keys."""
        from gads_lib.output import flatten

        result = flatten({"x": 1}, prefix="top")
        assert "top.x" in result
        assert result["top.x"] == 1

    def test_output_flatten_non_dict_input(self):
        """flatten with non-dict input returns empty dict (graceful)."""
        from gads_lib.output import flatten

        result = flatten("not-a-dict")
        assert result == {}

    def test_output_flatten_lists_preserved(self):
        """flatten does not recurse into list values — keeps them as-is."""
        from gads_lib.output import flatten

        result = flatten({"tags": ["a", "b", "c"], "count": 3})
        assert result["tags"] == ["a", "b", "c"]
        assert result["count"] == 3


class TestPrintJsonProducesValidJson:
    """B — print_json([...]) emits valid, parseable JSON."""

    def test_print_json_produces_valid_json(self, capsys):
        """print_json([{"key": "val"}]) outputs JSON that json.loads parses cleanly."""
        from gads_lib.output import print_json

        payload = [{"key": "val", "num": 42}]
        print_json(payload)

        captured = capsys.readouterr()
        output = captured.out.strip()
        assert output, "print_json produced no output"

        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert parsed[0]["key"] == "val"
        assert parsed[0]["num"] == 42

    def test_print_json_produces_valid_json_dict(self, capsys):
        """print_json({}) outputs valid JSON for a dict."""
        from gads_lib.output import print_json

        print_json({"status": "ok", "count": 0})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["status"] == "ok"

    def test_print_json_handles_non_serializable_with_default_str(self, capsys):
        """print_json serializes non-JSON-native types via default=str."""
        from gads_lib.output import print_json
        from datetime import date

        print_json({"date": date(2026, 6, 22)})
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        # date becomes a string via default=str
        assert "2026" in parsed["date"]


# =============================================================================
# GROUP C — SELECT-only guard
# =============================================================================


class TestGAQLSelectOnlyGuard:
    """C — run_gaql passes SELECT queries and rejects non-SELECT (via API error)."""

    def test_gaql_select_only_accepted(self, fake_creds):
        """run_gaql with a SELECT query calls the searchStream endpoint."""
        from gads_lib.ads import run_gaql

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '[{"results": [{"campaign": {"name": "Test"}}]}]'
        fake_resp.json.return_value = [{"results": [{"campaign": {"name": "Test"}}]}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            result = run_gaql(fake_creds, "SELECT campaign.name FROM campaign LIMIT 1")

        assert mock_req.called
        called_url = mock_req.call_args[0][1]  # 2nd positional arg is url
        assert "searchStream" in called_url

        assert result == [{"campaign": {"name": "Test"}}]

    def test_ads_mutate_non_select_raises_on_api_error(self, fake_creds):
        """ads_mutate on a 4xx response raises SystemExit (gate via API error path)."""
        from gads_lib.ads import ads_mutate

        fake_resp = MagicMock()
        fake_resp.status_code = 400
        fake_resp.text = "Bad Request: invalid operation"

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit):
                ads_mutate(fake_creds, "campaigns", [{"badOp": {}}])

    def test_run_gaql_raises_sysexit_on_api_error(self, fake_creds):
        """run_gaql raises SystemExit(5) when the API returns a non-200 status."""
        from gads_lib.ads import run_gaql

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = "Forbidden"

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                run_gaql(fake_creds, "SELECT campaign.name FROM campaign")
        assert exc_info.value.code == 5  # EXIT_CODES["API"] after routing through request_json


# =============================================================================
# GROUP D — Error envelope / request_json behavior
# =============================================================================


class TestRequestJsonErrorBehavior:
    """D — request_json raises SystemExit on 4xx (no error envelope returned)."""

    def test_request_json_raises_sysexit_on_4xx(self, fake_creds):
        """request_json raises SystemExit(5) on 400 — does NOT return an error dict."""
        from gads_lib.http import request_json

        fake_resp = MagicMock()
        fake_resp.status_code = 400
        fake_resp.text = '{"error": {"code": 400, "message": "Bad Request"}}'

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                request_json("GET", "https://example.com/api")
        assert exc_info.value.code == 5  # EXIT_CODES["API"]

    def test_request_json_raises_sysexit_on_403(self, fake_creds):
        """request_json raises SystemExit(1) on 403 Forbidden."""
        from gads_lib.http import request_json

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = "Forbidden"

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit):
                request_json("POST", "https://example.com/api", json_body={"q": 1})

    def test_request_json_returns_dict_on_200(self):
        """request_json returns parsed JSON dict on 200 success."""
        from gads_lib.http import request_json

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"result": "ok"}'
        fake_resp.json.return_value = {"result": "ok"}

        with patch("requests.Session.request", return_value=fake_resp):
            result = request_json("GET", "https://example.com/api")

        assert result == {"result": "ok"}

    def test_request_json_returns_empty_dict_on_empty_body(self):
        """request_json returns {} when response body is empty (e.g. 204-like)."""
        from gads_lib.http import request_json

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = ""  # empty body

        with patch("requests.Session.request", return_value=fake_resp):
            result = request_json("DELETE", "https://example.com/api/item/1")

        assert result == {}

    def test_request_json_passes_correct_method_and_url(self):
        """request_json forwards method and URL correctly to requests.request."""
        from gads_lib.http import request_json

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = "{}"
        fake_resp.json.return_value = {}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            request_json("POST", "https://api.example.com/v1/resource", json_body={"k": "v"})

        mock_req.assert_called_once()
        args = mock_req.call_args[0]
        assert args[0] == "POST"
        assert args[1] == "https://api.example.com/v1/resource"
        assert mock_req.call_args[1]["json"] == {"k": "v"}


# =============================================================================
# GROUP E — KB check
# =============================================================================


class TestKBManifestIsValidJSON:
    """E — kb/manifest.json is valid JSON with expected structure per entry."""

    def test_kb_manifest_json_is_valid(self):
        """Load kb/manifest.json and verify it's a non-empty list with required keys."""
        manifest_path = Path(__file__).resolve().parent.parent / "kb" / "manifest.json"
        assert manifest_path.exists(), f"manifest.json not found at {manifest_path}"

        with open(manifest_path) as f:
            data = json.load(f)

        assert isinstance(data, list), "manifest.json must be a JSON array"
        assert len(data) > 0, "manifest.json must have at least one entry"

        required_keys = {"api", "slug", "current_version", "base_url", "status", "kb_file"}
        for i, entry in enumerate(data):
            missing = required_keys - set(entry.keys())
            assert not missing, (
                f"manifest entry {i} (api={entry.get('api')!r}) "
                f"missing required keys: {missing}"
            )
            assert isinstance(entry["api"], str) and entry["api"], (
                f"entry {i}: 'api' must be a non-empty string"
            )
            assert isinstance(entry["slug"], str) and entry["slug"], (
                f"entry {i}: 'slug' must be a non-empty string"
            )
            assert isinstance(entry["current_version"], str) and entry["current_version"], (
                f"entry {i}: 'current_version' must be a non-empty string"
            )

    def test_kb_manifest_contains_expected_slugs(self):
        """manifest.json contains entries for all major APIs."""
        manifest_path = Path(__file__).resolve().parent.parent / "kb" / "manifest.json"
        with open(manifest_path) as f:
            data = json.load(f)

        slugs = {entry["slug"] for entry in data}
        expected_slugs = {"google-ads", "ga4", "gbp", "search-console", "merchant-api"}
        missing = expected_slugs - slugs
        assert not missing, f"manifest.json missing expected slugs: {missing}"


class TestKBCheckDriftNoFalsePositives:
    """E — check_drift() runs without error and returns structured results."""

    def test_kb_check_drift_returns_list(self):
        """check_drift() returns a list of result dicts without raising."""
        from gads_lib.kb import check_drift

        results = check_drift()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_kb_check_drift_result_structure(self):
        """Each check_drift() result has the expected keys."""
        from gads_lib.kb import check_drift

        results = check_drift()
        required_keys = {"api", "slug", "manifest_version", "code_version", "drift", "status"}
        for entry in results:
            missing = required_keys - set(entry.keys())
            assert not missing, f"check_drift entry missing keys: {missing}"
            assert entry["status"] in ("OK", "DRIFT"), (
                f"status must be 'OK' or 'DRIFT', got {entry['status']!r}"
            )
            assert isinstance(entry["drift"], bool)

    def test_kb_check_drift_exits_0_when_aligned(self):
        """Entries with no drift have status='OK' and drift=False (code matches manifest)."""
        from gads_lib.kb import check_drift

        results = check_drift()
        # Find entries we actually track in code (code_version != "n/a")
        tracked = [r for r in results if r["code_version"] != "n/a"]
        assert len(tracked) > 0, "Expected at least one tracked entry"

        # For GA4 (v1beta in code and manifest), expect no drift
        ga4_entries = [r for r in tracked if r["slug"] == "ga4"]
        for entry in ga4_entries:
            assert not entry["drift"], (
                f"Unexpected drift for {entry['api']}: "
                f"manifest={entry['manifest_version']!r}, code={entry['code_version']!r}"
            )

    def test_kb_normalize_version_strips_minor(self):
        """_normalize_version strips minor patch from 'v24.1' → 'v24'."""
        from gads_lib.kb import _normalize_version

        assert _normalize_version("v24.1") == "v24"
        assert _normalize_version("v24") == "v24"
        assert _normalize_version("v1beta") == "v1beta"
        assert _normalize_version("v1alpha") == "v1alpha"
        assert _normalize_version("v3") == "v3"


# =============================================================================
# GROUP F — Version
# =============================================================================


class TestVersion:
    """F — Package version assertions."""

    def test_version_exists(self):
        """gads_lib.__version__ is a non-empty string."""
        import gads_lib

        assert hasattr(gads_lib, "__version__"), "gads_lib missing __version__"
        assert isinstance(gads_lib.__version__, str)
        assert gads_lib.__version__, "__version__ is empty"

    def test_version_is_semver_format(self):
        """gads_lib.__version__ follows MAJOR.MINOR.PATCH format."""
        import gads_lib

        parts = gads_lib.__version__.split(".")
        assert len(parts) == 3, f"Expected MAJOR.MINOR.PATCH, got {gads_lib.__version__!r}"
        for part in parts:
            assert part.isdigit(), (
                f"Version part {part!r} is not numeric in {gads_lib.__version__!r}"
            )

    def test_version_is_3_10_0(self):
        """gads_lib.__version__ == '3.10.0'."""
        import gads_lib

        assert gads_lib.__version__ == "3.10.0", (
            f"Expected version 3.10.0, got {gads_lib.__version__!r}. "
            "Bump __version__ in gads_lib/__init__.py when releasing v3.10.0."
        )


# =============================================================================
# Additional unit tests for core utility functions
# =============================================================================


class TestSanitizeKeyword:
    """Bonus — sanitize_keyword removes special chars and collapses whitespace."""

    def test_removes_special_chars(self):
        from gads_lib.ads import sanitize_keyword

        assert sanitize_keyword("tesla!parts") == "teslaparts"
        assert sanitize_keyword("buy@tesla") == "buytesla"
        assert sanitize_keyword("a,b") == "ab"
        assert sanitize_keyword("it's") == "its"
        assert sanitize_keyword("50% off") == "50 off"

    def test_collapses_whitespace(self):
        from gads_lib.ads import sanitize_keyword

        assert sanitize_keyword("tesla  parts   uae") == "tesla parts uae"

    def test_strips_leading_trailing_whitespace(self):
        from gads_lib.ads import sanitize_keyword

        assert sanitize_keyword("  tesla parts  ") == "tesla parts"

    def test_empty_string(self):
        from gads_lib.ads import sanitize_keyword

        assert sanitize_keyword("") == ""

    def test_clean_keyword_unchanged(self):
        from gads_lib.ads import sanitize_keyword

        assert sanitize_keyword("tesla parts uae") == "tesla parts uae"


class TestExtractTargetCpaRoas:
    """extract_target_cpa/extract_target_roas -- MAXIMIZE_CONVERSIONS(_VALUE)
    carries its optional target in a different sub-message than
    TARGET_CPA/TARGET_ROAS. Checking only the latter silently reports a real
    target as "no target" (talas-ads 2026-08-29 incident: a live AED 3.84
    MAXIMIZE_CONVERSIONS tCPA read back as 0.0)."""

    def test_target_cpa_direct(self):
        from gads_lib.ads import extract_target_cpa

        camp = {"targetCpa": {"targetCpaMicros": "3840000"}}
        assert extract_target_cpa(camp) == 3.84

    def test_target_cpa_from_maximize_conversions(self):
        from gads_lib.ads import extract_target_cpa

        camp = {"biddingStrategyType": "MAXIMIZE_CONVERSIONS",
                "maximizeConversions": {"targetCpaMicros": "640625"}}
        assert extract_target_cpa(camp) == 0.640625

    def test_target_cpa_none_when_absent(self):
        """TARGET_SPEND (and any strategy with no target set) has neither
        sub-message -- must return None, not 0."""
        from gads_lib.ads import extract_target_cpa

        camp = {"biddingStrategyType": "TARGET_SPEND"}
        assert extract_target_cpa(camp) is None

    def test_target_cpa_none_when_maximize_conversions_has_no_target(self):
        """MAXIMIZE_CONVERSIONS with the sub-message present but no target
        set (spend-maximizing, unconstrained) -- still None, not 0."""
        from gads_lib.ads import extract_target_cpa

        camp = {"biddingStrategyType": "MAXIMIZE_CONVERSIONS", "maximizeConversions": {}}
        assert extract_target_cpa(camp) is None

    def test_target_roas_direct(self):
        from gads_lib.ads import extract_target_roas

        camp = {"targetRoas": {"targetRoas": 3.5}}
        assert extract_target_roas(camp) == 3.5

    def test_target_roas_from_maximize_conversion_value(self):
        from gads_lib.ads import extract_target_roas

        camp = {"biddingStrategyType": "MAXIMIZE_CONVERSION_VALUE",
                "maximizeConversionValue": {"targetRoas": 4.2}}
        assert extract_target_roas(camp) == 4.2

    def test_target_roas_none_when_absent(self):
        from gads_lib.ads import extract_target_roas

        assert extract_target_roas({"biddingStrategyType": "TARGET_SPEND"}) is None


class TestNormalizePhone:
    """Bonus — _normalize_phone converts UAE numbers to E.164."""

    def test_uae_mobile_05(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("0501234567") == "+971501234567"

    def test_uae_mobile_5_nine_digits(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("501234567") == "+971501234567"

    def test_international_plus(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("+971501234567") == "+971501234567"

    def test_double_zero_prefix(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("00971501234567") == "+971501234567"

    def test_short_number_returns_none(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("123") is None

    def test_empty_returns_none(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("") is None

    def test_none_returns_none(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone(None) is None

    def test_leading_apostrophe_spreadsheet_guard(self):
        """Zoho MobilePhone export leaves a leading ' text-guard on numeric
        cells (e.g. "'+971527935444"). Before the fix this silently produced
        a WRONG number missing its country code, not None -- worse than
        dropping, since it looked normalized but would never match."""
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("'+971527935444") == "+971527935444"
        assert _normalize_phone("'0501234567") == "+971501234567"
        assert _normalize_phone("'00971501234567") == "+971501234567"

    def test_leading_double_quote_guard(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone('"0501234567"'.rstrip('"')) == "+971501234567"

    def test_unicode_dash_variants(self):
        """En dash / em dash from spreadsheet autocorrect, not just ASCII
        hyphen."""
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("050–123–4567") == "+971501234567"  # en dash
        assert _normalize_phone("050—123—4567") == "+971501234567"  # em dash

    def test_arabic_indic_digits(self):
        """Plausible for a UAE CRM with Arabic-locale data entry -- must
        convert to ASCII digit values, not survive as literal Unicode
        digit characters that would hash to something unmatchable."""
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("٠٥٠١٢٣٤٥٦٧") == "+971501234567"

    def test_fullwidth_digits(self):
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("０５０１２３４５６７") == "+971501234567"

    def test_apostrophe_alone_returns_none(self):
        """A guard character with nothing usable behind it must still be
        rejected, not turned into a bogus '+' number."""
        from gads_lib.ads import _normalize_phone

        assert _normalize_phone("'") is None


class TestBuildUserOpPhoneDropped:
    """_build_user_op's (op, phone_dropped) contract -- an unparseable phone
    must be visible to the caller, not silently vanish (2026-08-29 fix)."""

    def test_valid_phone_not_dropped(self):
        from gads_lib.ads import _build_user_op

        op, dropped = _build_user_op(phone="0501234567")
        assert dropped is False
        assert op is not None

    def test_unparseable_phone_flagged_dropped(self):
        from gads_lib.ads import _build_user_op

        op, dropped = _build_user_op(phone="123")
        assert dropped is True
        assert op is None

    def test_unparseable_phone_but_email_present_still_flagged(self):
        """The op still succeeds via email, but the phone loss must still be
        reported -- this is the case a bare success/failure return would
        hide completely."""
        from gads_lib.ads import _build_user_op

        op, dropped = _build_user_op(phone="123", email="a@b.com")
        assert dropped is True
        assert op is not None

    def test_no_phone_not_dropped(self):
        from gads_lib.ads import _build_user_op

        op, dropped = _build_user_op(email="a@b.com")
        assert dropped is False
        assert op is not None


class TestPrintError:
    """Bonus — print_error returns the correct numeric exit code."""

    def test_print_error_returns_numeric_code(self):
        from gads_lib.output import print_error

        code = print_error("something went wrong", code="GENERAL")
        assert code == 1

    def test_print_error_auth_code(self):
        from gads_lib.output import print_error

        code = print_error("auth failed", code="AUTH")
        assert code == 3

    def test_print_error_override_exit_code(self):
        from gads_lib.output import print_error

        code = print_error("custom error", exit_code=42)
        assert code == 42

    def test_print_error_json_mode(self, capsys):
        from gads_lib.output import print_error

        code = print_error("test message", code="AUTH", as_json=True)
        captured = capsys.readouterr()
        # JSON output goes to stderr
        parsed = json.loads(captured.err.strip())
        assert "error" in parsed
        assert parsed["error"]["code"] == "AUTH"
        assert "test message" in parsed["error"]["message"]
        assert code == 3


class TestGetBearerHeaders:
    """Bonus — get_bearer_headers builds Authorization: Bearer ... header."""

    def test_get_bearer_headers_structure(self, fake_creds):
        from gads_lib.http import get_bearer_headers

        headers = get_bearer_headers(fake_creds)
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer ya29.fake-access-token"
        assert "Content-Type" in headers
        assert headers["Content-Type"] == "application/json"


class TestGSCBaseURL:
    """Bonus — GSC uses the correct webmasters/v3 base URL."""

    def test_gsc_list_sites_url(self, fake_creds):
        from gads_lib.gsc import gsc_list_sites

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"siteEntry": []}'
        fake_resp.json.return_value = {"siteEntry": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_list_sites(fake_creds)

        assert mock_req.called
        called_url = mock_req.call_args[0][1]
        assert "webmasters/v3" in called_url, f"Expected webmasters/v3 in URL, got: {called_url}"

    def test_gsc_search_analytics_url_encodes_site(self, fake_creds):
        """gsc_search_analytics URL-encodes the site_url in the path."""
        from gads_lib.gsc import gsc_search_analytics

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"rows": []}'
        fake_resp.json.return_value = {"rows": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_search_analytics(
                fake_creds,
                site_url="https://shop.talas.ae/",
                start_date="2026-06-01",
                end_date="2026-06-22",
            )

        called_url = mock_req.call_args[0][1]
        # The : and / in the site URL should be percent-encoded in the path
        assert "https%3A" in called_url or "https%3a" in called_url, (
            f"Expected URL-encoded site in path, got: {called_url}"
        )


class TestAdsSearchPagination:
    """Bonus — ads_search follows nextPageToken pagination."""

    def test_ads_search_single_page(self, fake_creds):
        """ads_search returns all results from a single-page response."""
        from gads_lib.ads import ads_search

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = '{"results": [{"campaign": {"name": "A"}}, {"campaign": {"name": "B"}}]}'
        fake_resp.json.return_value = {
            "results": [{"campaign": {"name": "A"}}, {"campaign": {"name": "B"}}]
        }

        with patch("requests.Session.request", return_value=fake_resp):
            results = ads_search(fake_creds, "SELECT campaign.name FROM campaign")

        assert len(results) == 2
        assert results[0]["campaign"]["name"] == "A"

    def test_ads_search_follows_next_page_token(self, fake_creds):
        """ads_search keeps paginating until nextPageToken is absent."""
        from gads_lib.ads import ads_search

        page1 = MagicMock()
        page1.status_code = 200
        page1.text = '{"results": [{"campaign": {"name": "P1"}}], "nextPageToken": "tok123"}'
        page1.json.return_value = {
            "results": [{"campaign": {"name": "P1"}}],
            "nextPageToken": "tok123",
        }
        page2 = MagicMock()
        page2.status_code = 200
        page2.text = '{"results": [{"campaign": {"name": "P2"}}]}'
        page2.json.return_value = {
            "results": [{"campaign": {"name": "P2"}}],
            # no nextPageToken → stop
        }

        with patch("requests.Session.request", side_effect=[page1, page2]):
            results = ads_search(fake_creds, "SELECT campaign.name FROM campaign")

        assert len(results) == 2
        assert results[0]["campaign"]["name"] == "P1"
        assert results[1]["campaign"]["name"] == "P2"


# =============================================================================
# GROUP G — Graceful API error handling
# =============================================================================


class TestGracefulErrorHandling:
    """Tests for classify_api_error() and offer_gcloud_enable()."""

    def test_api_not_enabled_403_service_disabled(self):
        """SERVICE_DISABLED → API_NOT_ENABLED classification."""
        from gads_lib.output import classify_api_error

        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": (
                    "merchantapi.googleapis.com has not been used in project 123456789 before"
                    " or it is disabled. Enable it by visiting"
                    " https://console.cloud.google.com/apis/library/merchantapi.googleapis.com"
                    "?project=123456789"
                ),
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.Help",
                    "links": [{"description": "Google APIs Console",
                               "url": "https://console.cloud.google.com/apis/library/"
                                      "merchantapi.googleapis.com?project=123456789"}]
                }]
            }
        })
        result = classify_api_error(
            403,
            body,
            url="https://merchantapi.googleapis.com/products/v1/accounts/123/products",
        )
        assert result is not None
        assert result["code"] == "API_NOT_ENABLED"
        assert result["action"] == "run_gcloud"
        assert "merchantapi" in result.get("service", "")

    def test_api_not_enabled_gcloud_present(self, monkeypatch):
        """When gcloud is present and user says yes, subprocess.run is called."""
        from gads_lib import output
        import subprocess

        inputs = iter(["y"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))

        run_calls = []

        def fake_run(cmd, **kwargs):
            run_calls.append(cmd)
            return MagicMock(returncode=0)

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = output.offer_gcloud_enable("merchantapi", project_id="my-project", yes=False)
        assert result is True
        assert any("merchantapi.googleapis.com" in str(c) for c in run_calls)

    def test_api_not_enabled_gcloud_absent(self, monkeypatch, capsys):
        """When gcloud is absent (FileNotFoundError), falls back to console link."""
        from gads_lib import output
        import subprocess

        monkeypatch.setattr("builtins.input", lambda _: "y")

        def fake_run(cmd, **kwargs):
            raise FileNotFoundError("gcloud not found")

        monkeypatch.setattr(subprocess, "run", fake_run)
        result = output.offer_gcloud_enable("merchantapi", project_id="my-project", yes=False)
        assert result is False
        # Should print the console link fallback
        captured = capsys.readouterr()
        assert (
            "console.cloud.google.com" in captured.out
            or "console.cloud.google.com" in captured.err
        )

    def test_merchant_not_registered_401(self):
        """GCP_NOT_REGISTERED on merchant URL → MERCHANT_NOT_REGISTERED."""
        from gads_lib.output import classify_api_error

        body = json.dumps({
            "error": {"code": 401, "status": "UNAUTHENTICATED", "message": "GCP_NOT_REGISTERED"}
        })
        result = classify_api_error(
            401,
            body,
            url="https://merchantapi.googleapis.com/accounts/v1/accounts/123",
        )
        assert result is not None
        assert result["code"] == "MERCHANT_NOT_REGISTERED"
        assert result["action"] == "register_merchant"
        assert "developers.google.com/merchant" in result.get("url", "")

    def test_insufficient_scope_403_names_scope(self):
        """INSUFFICIENT_AUTHENTICATION_SCOPES on GSC URL → INSUFFICIENT_SCOPE with webmasters scope."""
        from gads_lib.output import classify_api_error

        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes.",
            }
        })
        result = classify_api_error(
            403,
            body,
            url="https://www.googleapis.com/webmasters/v3/sites",
        )
        assert result is not None
        assert result["code"] == "INSUFFICIENT_SCOPE"
        assert result["action"] == "regen_token"
        assert "webmasters" in result.get("scope", "")

    def test_permission_denied_gbp_allowlist(self):
        """PERMISSION_DENIED on GBP URL → PERMISSION_DENIED with allowlist link."""
        from gads_lib.output import classify_api_error

        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "The caller does not have permission",
            }
        })
        result = classify_api_error(
            403,
            body,
            url="https://mybusinessbusinessinformation.googleapis.com/v1/accounts/123/locations",
        )
        assert result is not None
        assert result["code"] == "PERMISSION_DENIED"
        assert result["action"] == "request_allowlist"

    def test_request_json_exits_with_api_code_on_classified_error(self, monkeypatch):
        """request_json raises SystemExit(5) on a classified API error."""
        from gads_lib import http

        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = json.dumps({
            "error": {
                "message": "Request had insufficient authentication scopes.",
                "status": "PERMISSION_DENIED",
            }
        })
        monkeypatch.setattr("builtins.input", lambda _: "n")

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                http.request_json(
                    "GET",
                    "https://www.googleapis.com/webmasters/v3/sites",
                    headers={},
                )
        assert exc_info.value.code == 5  # EXIT_CODES["API"]


# =============================================================================
# GROUP H — JSON mode access error envelope
# =============================================================================


class TestJsonModeAccessErrors:
    """H — --json mode emits machine-readable error envelopes on STDOUT for classified errors."""

    _EXPECTED_KEYS = {"code", "message", "action", "service", "scope", "url", "project_id"}

    def _capture_json_exit(self, monkeypatch, status_code, body, url):
        """Helper: call request_json(as_json=True), capture stdout, return (parsed_json, exit_code)."""
        from gads_lib.http import request_json

        fake_resp = MagicMock()
        fake_resp.status_code = status_code
        fake_resp.text = body

        captured_output = io.StringIO()
        exit_code = None

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                import contextlib
                with contextlib.redirect_stdout(captured_output):
                    request_json("GET", url, headers={}, as_json=True)
        exit_code = exc_info.value.code
        output = captured_output.getvalue().strip()
        return json.loads(output), exit_code

    def test_api_not_enabled_json_mode(self, monkeypatch):
        """API_NOT_ENABLED: as_json=True emits JSON envelope to STDOUT and exits 5."""
        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": (
                    "merchantapi.googleapis.com has not been used in project my-project-123 before"
                    " or it is disabled. Enable it by visiting"
                    " https://console.cloud.google.com/apis/library/merchantapi.googleapis.com"
                    "?project=my-project-123 SERVICE_DISABLED"
                ),
            }
        })
        d, code = self._capture_json_exit(
            monkeypatch,
            status_code=403,
            body=body,
            url="https://merchantapi.googleapis.com/products/v1/accounts/123/products",
        )
        assert code == 5
        assert "error" in d
        assert d["error"]["code"] == "API_NOT_ENABLED"
        missing = self._EXPECTED_KEYS - set(d["error"].keys())
        assert not missing, f"JSON error envelope missing keys: {missing}"

    def test_merchant_not_registered_json_mode(self, monkeypatch):
        """MERCHANT_NOT_REGISTERED: as_json=True emits JSON envelope to STDOUT and exits 5."""
        body = json.dumps({
            "error": {"code": 401, "status": "UNAUTHENTICATED", "message": "GCP_NOT_REGISTERED"}
        })
        d, code = self._capture_json_exit(
            monkeypatch,
            status_code=401,
            body=body,
            url="https://merchantapi.googleapis.com/accounts/v1/accounts/123",
        )
        assert code == 5
        assert "error" in d
        assert d["error"]["code"] == "MERCHANT_NOT_REGISTERED"
        missing = self._EXPECTED_KEYS - set(d["error"].keys())
        assert not missing, f"JSON error envelope missing keys: {missing}"

    def test_insufficient_scope_json_mode(self, monkeypatch):
        """INSUFFICIENT_SCOPE: as_json=True emits JSON envelope to STDOUT and exits 5."""
        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes. INSUFFICIENT_AUTHENTICATION_SCOPES",
            }
        })
        d, code = self._capture_json_exit(
            monkeypatch,
            status_code=403,
            body=body,
            url="https://www.googleapis.com/webmasters/v3/sites",
        )
        assert code == 5
        assert "error" in d
        assert d["error"]["code"] == "INSUFFICIENT_SCOPE"
        assert "webmasters" in (d["error"].get("scope") or "")
        missing = self._EXPECTED_KEYS - set(d["error"].keys())
        assert not missing, f"JSON error envelope missing keys: {missing}"

    def test_permission_denied_json_mode(self, monkeypatch):
        """PERMISSION_DENIED: as_json=True emits JSON envelope to STDOUT and exits 5."""
        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "The caller does not have PERMISSION_DENIED access.",
            }
        })
        d, code = self._capture_json_exit(
            monkeypatch,
            status_code=403,
            body=body,
            url="https://mybusinessbusinessinformation.googleapis.com/v1/accounts/123/locations",
        )
        assert code == 5
        assert "error" in d
        assert d["error"]["code"] == "PERMISSION_DENIED"
        missing = self._EXPECTED_KEYS - set(d["error"].keys())
        assert not missing, f"JSON error envelope missing keys: {missing}"

    def test_merchant_not_registered_non_json_mode_stdout_empty(self, monkeypatch, capsys):
        """Non-JSON mode: MERCHANT_NOT_REGISTERED prints human text to STDERR, STDOUT is empty."""
        from gads_lib.http import request_json

        body = json.dumps({
            "error": {"code": 401, "status": "UNAUTHENTICATED", "message": "GCP_NOT_REGISTERED"}
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 401
        fake_resp.text = body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                request_json(
                    "GET",
                    "https://merchantapi.googleapis.com/accounts/v1/accounts/123",
                    headers={},
                    as_json=False,
                )
        assert exc_info.value.code == 5
        captured = capsys.readouterr()
        assert captured.out == "", f"Expected empty STDOUT in non-JSON mode, got: {captured.out!r}"
        assert captured.err, "Expected human-readable advisory on STDERR in non-JSON mode"

    def test_insufficient_scope_non_json_mode_stdout_empty(self, monkeypatch, capsys):
        """Non-JSON mode: INSUFFICIENT_SCOPE prints human text to STDERR, STDOUT is empty."""
        from gads_lib.http import request_json

        body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes. INSUFFICIENT_AUTHENTICATION_SCOPES",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                request_json(
                    "GET",
                    "https://www.googleapis.com/webmasters/v3/sites",
                    headers={},
                    as_json=False,
                )
        assert exc_info.value.code == 5
        captured = capsys.readouterr()
        assert captured.out == "", f"Expected empty STDOUT in non-JSON mode, got: {captured.out!r}"
        assert captured.err, "Expected human-readable advisory on STDERR in non-JSON mode"


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP A — ads.py: mutate URL construction (P0 regression coverage)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdsMutateUrlConstruction:
    """ads_mutate — verify correct URL is built for single-resource mutations.

    This class was added after the P0 bug where passing snake_case resource names
    (e.g. 'campaign_criterion') built a URL with that literal string, resulting in
    HTTP 404 from Google's servers (HTML error page, not a JSON API error).
    The fix adds _canonicalize_resource() in ads.py which converts snake_case
    aliases to camelCase plural REST form before URL construction.
    """

    def test_snake_case_campaign_criterion_maps_to_campaign_criteria(self, fake_creds):
        """'campaign_criterion' (snake) must map to 'campaignCriteria' (camelCase plural).

        This is the exact bug that caused HTTP 404: the URL segment was
        'campaign_criterion:mutate' instead of 'campaignCriteria:mutate'.
        """
        from gads_lib.ads import ads_mutate

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_mutate(fake_creds, "campaign_criterion", [{"remove": "customers/1/campaignCriteria/1~2"}])

        called_url = mock_req.call_args[0][1]
        assert "campaignCriteria:mutate" in called_url, (
            f"URL must contain 'campaignCriteria:mutate' not 'campaign_criterion:mutate', got: {called_url}"
        )
        assert "campaign_criterion" not in called_url, (
            f"URL must NOT contain snake_case 'campaign_criterion', got: {called_url}"
        )
        assert "googleads.googleapis.com" in called_url
        assert "v24" in called_url

    def test_snake_case_ad_group_criterion_maps_to_ad_group_criteria(self, fake_creds):
        """'ad_group_criterion' (snake) must map to 'adGroupCriteria'."""
        from gads_lib.ads import ads_mutate

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_mutate(fake_creds, "ad_group_criterion", [{"remove": "customers/1/adGroupCriteria/1~2"}])

        called_url = mock_req.call_args[0][1]
        assert "adGroupCriteria:mutate" in called_url, (
            f"Expected 'adGroupCriteria:mutate' in URL, got: {called_url}"
        )
        assert "ad_group_criterion" not in called_url

    def test_camelcase_passthrough_campaign_criteria(self, fake_creds):
        """Passing the canonical 'campaignCriteria' (camelCase) must pass through unchanged."""
        from gads_lib.ads import ads_mutate

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_mutate(fake_creds, "campaignCriteria", [{"remove": "customers/1/campaignCriteria/1~2"}])

        called_url = mock_req.call_args[0][1]
        assert "campaignCriteria:mutate" in called_url
        assert "campaign_criterion" not in called_url

    def test_mutate_url_contains_version_and_customer(self, fake_creds):
        """ads_mutate URL must embed API_VERSION and CUSTOMER_ID (not be a generic path)."""
        from gads_lib.ads import ads_mutate
        import os

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_mutate(fake_creds, "campaigns", [{"create": {"name": "test"}}])

        called_url = mock_req.call_args[0][1]
        assert "googleads.googleapis.com" in called_url, "URL must target googleads.googleapis.com"
        # API version segment must be present (v24 or whatever API_VERSION is)
        from gads_lib.config import API_VERSION, CUSTOMER_ID
        assert API_VERSION in called_url, f"URL must contain API version '{API_VERSION}', got: {called_url}"
        assert CUSTOMER_ID in called_url, f"URL must contain customer ID '{CUSTOMER_ID}', got: {called_url}"
        assert ":mutate" in called_url, "URL must end with ':mutate' action"

    def test_unknown_snake_resource_raises_value_error(self):
        """An unrecognized snake_case resource name raises ValueError before any HTTP call."""
        from gads_lib.ads import _canonicalize_resource
        import pytest as _pytest

        with _pytest.raises(ValueError, match="Unknown resource alias"):
            _canonicalize_resource("totally_unknown_resource")

    def test_canonicalize_all_known_aliases_return_camelcase(self):
        """Every entry in _RESOURCE_ALIASES maps to a camelCase (no underscore) value."""
        from gads_lib.ads import _RESOURCE_ALIASES

        for alias, canonical in _RESOURCE_ALIASES.items():
            assert "_" not in canonical, (
                f"Alias '{alias}' maps to '{canonical}' which still contains underscores — "
                f"must be camelCase plural"
            )
            assert canonical[0].islower(), (
                f"Alias '{alias}' maps to '{canonical}' which does not start lowercase"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP A — ads.py: batch mutate + conversion upload + keyword ideas/forecast
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdsBatchMutate:
    """ads_batch_mutate — cross-resource batch operation."""

    def test_url_contains_googleads_mutate(self, fake_creds):
        """URL must use googleAds:mutate, not a resource-specific path."""
        from gads_lib.ads import ads_batch_mutate

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"mutateOperationResponses": []})
        fake_resp.json.return_value = {"mutateOperationResponses": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_batch_mutate(fake_creds, [{"campaignOperation": {"create": {}}}])

        called_url = mock_req.call_args[0][1]
        assert "googleAds:mutate" in called_url, f"Expected 'googleAds:mutate' in URL, got: {called_url}"

    def test_body_uses_mutate_operations_key(self, fake_creds):
        """Body must use 'mutateOperations' NOT 'operations' key (key API gotcha)."""
        from gads_lib.ads import ads_batch_mutate

        ops = [{"adGroupOperation": {"create": {"name": "test"}}}]
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"mutateOperationResponses": []})
        fake_resp.json.return_value = {"mutateOperationResponses": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_batch_mutate(fake_creds, ops)

        sent_body = mock_req.call_args[1]["json"]
        assert "mutateOperations" in sent_body, "Body must have 'mutateOperations' key"
        assert "operations" not in sent_body, "Body must NOT have bare 'operations' key"
        assert sent_body["mutateOperations"] == ops


class TestAdsUploadClickConversions:
    """ads_upload_click_conversions — offline click conversion upload."""

    def test_url_contains_upload_click_conversions(self, fake_creds):
        from gads_lib.ads import ads_upload_click_conversions

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        conversions = [{"gclid": "abc123", "conversionDateTime": "2026-01-01 10:00:00+00:00"}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_upload_click_conversions(fake_creds, conversions, "customers/1/conversionActions/42")

        called_url = mock_req.call_args[0][1]
        assert "uploadClickConversions" in called_url

    def test_body_has_conversions_and_partial_failure(self, fake_creds):
        from gads_lib.ads import ads_upload_click_conversions

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        conversions = [{"gclid": "abc123", "conversionDateTime": "2026-01-01 10:00:00+00:00"}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_upload_click_conversions(fake_creds, conversions, "customers/1/conversionActions/42")

        sent_body = mock_req.call_args[1]["json"]
        assert "conversions" in sent_body
        assert sent_body["partialFailure"] is True

    def test_conversion_action_injected_into_each_item(self, fake_creds):
        from gads_lib.ads import ads_upload_click_conversions

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        conversions = [
            {"gclid": "abc1", "conversionDateTime": "2026-01-01 10:00:00+00:00"},
            {"gclid": "abc2", "conversionDateTime": "2026-01-02 10:00:00+00:00"},
        ]
        action_id = "customers/1/conversionActions/99"

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_upload_click_conversions(fake_creds, conversions, action_id)

        sent_body = mock_req.call_args[1]["json"]
        for item in sent_body["conversions"]:
            assert item["conversionAction"] == action_id


class TestAdsUploadClickConversionsPartialFailure:
    """ads_upload_click_conversions — partialFailureError passthrough."""

    def test_partial_failure_error_returned_as_dict(self, fake_creds):
        """When API returns partialFailureError the caller gets the raw dict."""
        from gads_lib.ads import ads_upload_click_conversions

        api_resp = {
            "results": [{}],
            "partialFailureError": {
                "code": 3,
                "message": "Partial failure",
                "details": [],
            },
        }
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("requests.Session.request", return_value=fake_resp):
            result = ads_upload_click_conversions(
                fake_creds,
                [{"gclid": "x"}],
                "customers/1/conversionActions/5",
            )

        assert "partialFailureError" in result
        assert result["partialFailureError"]["code"] == 3


class TestGenerateKeywordIdeas:
    """generate_keyword_ideas — keyword planner ideas endpoint."""

    def test_url_contains_generate_keyword_ideas(self, fake_creds):
        from gads_lib.ads import generate_keyword_ideas

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            generate_keyword_ideas(fake_creds, keywords=["tesla parts"])

        called_url = mock_req.call_args[0][1]
        assert "generateKeywordIdeas" in called_url

    def test_keyword_only_uses_keyword_seed(self, fake_creds):
        from gads_lib.ads import generate_keyword_ideas

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            generate_keyword_ideas(fake_creds, keywords=["tesla parts", "tesla bumper"])

        sent_body = mock_req.call_args[1]["json"]
        assert "keywordSeed" in sent_body
        assert "urlSeed" not in sent_body
        assert "keywordAndUrlSeed" not in sent_body
        assert "keywords" in sent_body["keywordSeed"]

    def test_url_only_uses_url_seed(self, fake_creds):
        from gads_lib.ads import generate_keyword_ideas

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"results": []})
        fake_resp.json.return_value = {"results": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            generate_keyword_ideas(fake_creds, url="https://talas.ae")

        sent_body = mock_req.call_args[1]["json"]
        assert "urlSeed" in sent_body
        assert "keywordSeed" not in sent_body

    def test_403_as_json_emits_envelope_and_exits_5(self, fake_creds, capsys):
        """403 with as_json=True should emit JSON envelope to stdout and raise SystemExit(5)."""
        from gads_lib.ads import generate_keyword_ideas

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "The caller does not have permission",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                generate_keyword_ideas(fake_creds, keywords=["tesla parts"], as_json=True)

        assert exc_info.value.code == 5
        captured = capsys.readouterr()
        assert captured.out.strip(), "Expected JSON envelope on stdout"
        data = json.loads(captured.out)
        assert "error" in data


class TestGenerateKeywordForecast:
    """generate_keyword_forecast — keyword planner forecast endpoint."""

    def test_url_contains_generate_keyword_forecast(self, fake_creds):
        from gads_lib.ads import generate_keyword_forecast

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"campaignForecast": {}})
        fake_resp.json.return_value = {"campaignForecast": {}}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            generate_keyword_forecast(fake_creds, keywords=["tesla parts"])

        called_url = mock_req.call_args[0][1]
        assert "generateKeywordForecastMetrics" in called_url

    def test_body_has_campaign_with_ad_groups(self, fake_creds):
        from gads_lib.ads import generate_keyword_forecast

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"campaignForecast": {}})
        fake_resp.json.return_value = {"campaignForecast": {}}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            generate_keyword_forecast(fake_creds, keywords=["tesla parts", "tesla bumper"])

        sent_body = mock_req.call_args[1]["json"]
        assert "campaign" in sent_body
        assert "adGroups" in sent_body["campaign"]
        assert len(sent_body["campaign"]["adGroups"]) > 0
        assert "keywords" in sent_body["campaign"]["adGroups"][0]

    def test_forecast_period_present_in_body(self, fake_creds):
        from gads_lib.ads import generate_keyword_forecast

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"campaignForecast": {}})
        fake_resp.json.return_value = {"campaignForecast": {}}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            generate_keyword_forecast(fake_creds, keywords=["tesla"])

        sent_body = mock_req.call_args[1]["json"]
        assert "forecastPeriod" in sent_body
        assert "startDate" in sent_body["forecastPeriod"]
        assert "endDate" in sent_body["forecastPeriod"]


class TestAudienceUploadCsv:
    """audience_upload_csv — Customer Match CSV upload (3 HTTP calls)."""

    def test_job_create_add_and_run_calls(self, fake_creds, tmp_path):
        """All 3 HTTP calls happen: job create, addOperations, run."""
        from gads_lib.ads import audience_upload_csv

        # Write a minimal CSV
        csv_file = tmp_path / "contacts.csv"
        csv_file.write_text(
            "Phone,Email,First Name,Last Name,Country\n"
            "+971501234567,user@example.com,John,Doe,AE\n"
        )

        job_rn = "customers/1234567890/offlineUserDataJobs/job-001"

        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.text = json.dumps({"resourceName": job_rn})
        create_resp.json.return_value = {"resourceName": job_rn}

        run_resp = MagicMock()
        run_resp.status_code = 200
        run_resp.text = json.dumps({})
        run_resp.json.return_value = {}

        batch_resp = MagicMock()
        batch_resp.status_code = 200
        batch_resp.text = json.dumps({"totalOperationsCount": 1})
        batch_resp.json.return_value = {"totalOperationsCount": 1}

        with patch("requests.Session.request", side_effect=[create_resp, run_resp]) as mock_request, \
             patch("requests.post", return_value=batch_resp) as mock_post:
            returned_job, stats = audience_upload_csv(
                fake_creds,
                "customers/1234567890/userLists/list-001",
                str(csv_file),
            )

        assert returned_job == job_rn
        assert stats["job"] == job_rn
        assert stats["rows_uploaded"] >= 1

        # Verify job create call (first requests.request call)
        assert mock_request.call_count == 2
        create_call_url = mock_request.call_args_list[0][0][1]
        assert "offlineUserDataJobs:create" in create_call_url

        # Verify run call (second requests.request call)
        run_call_url = mock_request.call_args_list[1][0][1]
        assert ":run" in run_call_url

        # Verify addOperations batch call used requests.post
        assert mock_post.called
        add_url = mock_post.call_args[0][0]
        assert "addOperations" in add_url

    def test_job_payload_includes_consent(self, fake_creds, tmp_path):
        """Job creation payload must include consent fields."""
        from gads_lib.ads import audience_upload_csv

        csv_file = tmp_path / "contacts2.csv"
        csv_file.write_text(
            "Phone,Email,First Name,Last Name,Country\n"
            "+971501234567,user@example.com,Alice,Smith,AE\n"
        )
        job_rn = "customers/1234567890/offlineUserDataJobs/j2"

        create_resp = MagicMock()
        create_resp.status_code = 200
        create_resp.text = json.dumps({"resourceName": job_rn})
        create_resp.json.return_value = {"resourceName": job_rn}

        run_resp = MagicMock()
        run_resp.status_code = 200
        run_resp.text = json.dumps({})
        run_resp.json.return_value = {}

        batch_resp = MagicMock()
        batch_resp.status_code = 200
        batch_resp.text = json.dumps({})
        batch_resp.json.return_value = {}

        with patch("requests.Session.request", side_effect=[create_resp, run_resp]) as mock_request, \
             patch("requests.post", return_value=batch_resp):
            audience_upload_csv(
                fake_creds,
                "customers/1234567890/userLists/list-001",
                str(csv_file),
            )

        create_body = mock_request.call_args_list[0][1]["json"]
        consent = create_body["job"]["customerMatchUserListMetadata"]["consent"]
        assert consent["adUserData"] == "GRANTED"
        assert consent["adPersonalization"] == "GRANTED"


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP B — ga4.py: key events (list / create / delete) + batch/pivot/compat
# ═══════════════════════════════════════════════════════════════════════════════

class TestListKeyEvents:
    """list_key_events — GA4 Admin API, routed through gads_lib.http._send_with_retry."""

    def test_url_contains_v1beta_and_key_events(self, fake_creds):
        from gads_lib.ga4 import list_key_events

        api_resp = {"keyEvents": [{"eventName": "purchase", "countingMethod": "ONCE_PER_EVENT"}]}
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("gads_lib.ga4._send_with_retry", return_value=fake_resp) as mock_send:
            result = list_key_events("271773771", fake_creds)

        method, called_url = mock_send.call_args[0]
        assert method == "GET"
        assert "v1beta" in called_url
        assert "keyEvents" in called_url
        assert result[0]["eventName"] == "purchase"

    def test_403_as_json_emits_envelope_and_exits_5(self, fake_creds, capsys):
        from gads_lib.ga4 import list_key_events

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes. INSUFFICIENT_AUTHENTICATION_SCOPES",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("gads_lib.ga4._send_with_retry", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                list_key_events("271773771", fake_creds, as_json=True)

        assert exc_info.value.code == 5
        captured = capsys.readouterr()
        assert captured.out.strip()
        data = json.loads(captured.out)
        assert "error" in data

    def test_pagination_collects_all_events(self, fake_creds):
        """Pagination loop: two pages are merged into one list."""
        from gads_lib.ga4 import list_key_events

        page1 = {"keyEvents": [{"eventName": "purchase"}], "nextPageToken": "tok1"}
        page2 = {"keyEvents": [{"eventName": "add_to_cart"}]}

        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.text = json.dumps(page1)
        resp1.json.return_value = page1

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.text = json.dumps(page2)
        resp2.json.return_value = page2

        with patch("gads_lib.ga4._send_with_retry", side_effect=[resp1, resp2]):
            result = list_key_events("271773771", fake_creds)

        assert len(result) == 2
        names = {e["eventName"] for e in result}
        assert names == {"purchase", "add_to_cart"}


class TestCreateKeyEvent:
    """create_key_event — GA4 Admin API, routed through gads_lib.http._send_with_retry."""

    def test_body_has_event_name_and_counting_method(self, fake_creds):
        from gads_lib.ga4 import create_key_event

        api_resp = {
            "eventName": "whatsapp_click",
            "countingMethod": "ONCE_PER_SESSION",
            "name": "properties/271773771/keyEvents/ke123",
        }
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("gads_lib.ga4._send_with_retry", return_value=fake_resp) as mock_send:
            result = create_key_event("271773771", fake_creds, "whatsapp_click")

        method, _url = mock_send.call_args[0]
        assert method == "POST"
        sent_body = mock_send.call_args[1]["json_body"]
        assert "eventName" in sent_body
        assert "countingMethod" in sent_body
        assert result["_already_exists"] is False

    def test_409_returns_existing_event(self, fake_creds):
        """409 Conflict: function lists existing events and returns matching one."""
        from gads_lib.ga4 import create_key_event

        conflict_resp = MagicMock()
        conflict_resp.status_code = 409
        conflict_resp.text = "Conflict"

        existing_events = {"keyEvents": [
            {
                "eventName": "whatsapp_click",
                "countingMethod": "ONCE_PER_SESSION",
                "name": "properties/271773771/keyEvents/ke42",
            }
        ]}
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.text = json.dumps(existing_events)
        list_resp.json.return_value = existing_events

        def fake_send(method, url, **kwargs):
            return conflict_resp if method == "POST" else list_resp

        with patch("gads_lib.ga4._send_with_retry", side_effect=fake_send):
            result = create_key_event("271773771", fake_creds, "whatsapp_click")

        assert result["eventName"] == "whatsapp_click"
        assert result["_already_exists"] is True

    def test_invalid_counting_method_raises(self, fake_creds):
        from gads_lib.ga4 import create_key_event

        with pytest.raises(ValueError, match="counting_method"):
            create_key_event("271773771", fake_creds, "purchase", counting_method="INVALID")

    def test_403_as_json_emits_envelope_and_exits_5(self, fake_creds, capsys):
        from gads_lib.ga4 import create_key_event

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes. INSUFFICIENT_AUTHENTICATION_SCOPES",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("gads_lib.ga4._send_with_retry", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                create_key_event("271773771", fake_creds, "purchase", as_json=True)

        assert exc_info.value.code == 5
        captured = capsys.readouterr()
        assert captured.out.strip()
        data = json.loads(captured.out)
        assert "error" in data


class TestDeleteKeyEvent:
    """delete_key_event — lists first, then deletes by resource name."""

    def test_200_returns_true(self, fake_creds):
        from gads_lib.ga4 import delete_key_event

        existing_events = {"keyEvents": [
            {
                "eventName": "purchase",
                "countingMethod": "ONCE_PER_EVENT",
                "name": "properties/271773771/keyEvents/ke99",
            }
        ]}
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.text = json.dumps(existing_events)
        list_resp.json.return_value = existing_events

        delete_resp = MagicMock()
        delete_resp.status_code = 200
        delete_resp.text = json.dumps({})
        delete_resp.json.return_value = {}

        def fake_send(method, url, **kwargs):
            return list_resp if method == "GET" else delete_resp

        with patch("gads_lib.ga4._send_with_retry", side_effect=fake_send):
            result = delete_key_event("271773771", fake_creds, "purchase")

        assert result is True

    def test_not_found_returns_false(self, fake_creds):
        """Event not in list: returns False without making delete call."""
        from gads_lib.ga4 import delete_key_event

        existing_events = {"keyEvents": []}
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.text = json.dumps(existing_events)
        list_resp.json.return_value = existing_events

        with patch("gads_lib.ga4._send_with_retry", return_value=list_resp) as mock_send:
            result = delete_key_event("271773771", fake_creds, "nonexistent_event")

        assert result is False
        # Only the list GET happened -- no DELETE call was made.
        assert all(c.args[0] == "GET" for c in mock_send.call_args_list)

    def test_delete_url_uses_resource_name(self, fake_creds):
        """Delete call URL contains the resource name returned by list."""
        from gads_lib.ga4 import delete_key_event

        resource_name = "properties/271773771/keyEvents/ke55"
        existing_events = {"keyEvents": [
            {"eventName": "purchase", "name": resource_name, "countingMethod": "ONCE_PER_EVENT"}
        ]}
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.text = json.dumps(existing_events)
        list_resp.json.return_value = existing_events

        delete_resp = MagicMock()
        delete_resp.status_code = 200
        delete_resp.text = json.dumps({})
        delete_resp.json.return_value = {}

        def fake_send(method, url, **kwargs):
            return list_resp if method == "GET" else delete_resp

        with patch("gads_lib.ga4._send_with_retry", side_effect=fake_send) as mock_send:
            delete_key_event("271773771", fake_creds, "purchase")

        delete_calls = [c for c in mock_send.call_args_list if c.args[0] == "DELETE"]
        assert len(delete_calls) == 1
        delete_url = delete_calls[0].args[1]
        assert resource_name in delete_url


class TestGa4BatchRunReports:
    """ga4_batch_run_reports — body must have 'requests' key."""

    def test_body_has_requests_key(self, fake_creds):
        from gads_lib.ga4 import ga4_batch_run_reports

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"reports": []})
        fake_resp.json.return_value = {"reports": []}

        requests_list = [
            {
                "dimensions": [{"name": "date"}],
                "metrics": [{"name": "sessions"}],
                "dateRanges": [{"startDate": "7daysAgo", "endDate": "yesterday"}],
            }
        ]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_batch_run_reports(fake_creds, requests_list, property_id="271773771")

        sent_body = mock_req.call_args[1]["json"]
        assert "requests" in sent_body
        assert sent_body["requests"] == requests_list

    def test_url_contains_batch_run_reports(self, fake_creds):
        from gads_lib.ga4 import ga4_batch_run_reports

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"reports": []})
        fake_resp.json.return_value = {"reports": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_batch_run_reports(fake_creds, [], property_id="271773771")

        called_url = mock_req.call_args[0][1]
        assert "batchRunReports" in called_url


class TestGa4RunPivotReport:
    """ga4_run_pivot_report — body must have 'pivots' key."""

    def test_body_has_pivots_key(self, fake_creds):
        from gads_lib.ga4 import ga4_run_pivot_report

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"pivotHeaders": [], "rows": []})
        fake_resp.json.return_value = {"pivotHeaders": [], "rows": []}

        pivots = [{"fieldNames": ["date"], "limit": 10}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_run_pivot_report(
                fake_creds,
                dimensions=["date", "country"],
                metrics=["sessions"],
                date_ranges=[{"startDate": "7daysAgo", "endDate": "yesterday"}],
                pivots=pivots,
                property_id="271773771",
            )

        sent_body = mock_req.call_args[1]["json"]
        assert "pivots" in sent_body
        assert sent_body["pivots"] == pivots

    def test_url_contains_run_pivot_report(self, fake_creds):
        from gads_lib.ga4 import ga4_run_pivot_report

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"rows": []})
        fake_resp.json.return_value = {"rows": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_run_pivot_report(
                fake_creds,
                dimensions=["date"],
                metrics=["sessions"],
                date_ranges=[{"startDate": "7daysAgo", "endDate": "yesterday"}],
                pivots=[],
                property_id="271773771",
            )

        called_url = mock_req.call_args[0][1]
        assert "runPivotReport" in called_url


class TestGa4CheckCompatibility:
    """ga4_check_compatibility — body must have 'dimensions' and 'metrics' keys."""

    def test_body_has_dimensions_and_metrics(self, fake_creds):
        from gads_lib.ga4 import ga4_check_compatibility

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"dimensionCompatibilities": [], "metricCompatibilities": []})
        fake_resp.json.return_value = {"dimensionCompatibilities": [], "metricCompatibilities": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_check_compatibility(
                fake_creds,
                dimensions=["date", "country"],
                metrics=["sessions", "activeUsers"],
                property_id="271773771",
            )

        sent_body = mock_req.call_args[1]["json"]
        assert "dimensions" in sent_body
        assert "metrics" in sent_body
        dim_names = [d["name"] for d in sent_body["dimensions"]]
        assert "date" in dim_names
        assert "country" in dim_names

    def test_url_contains_check_compatibility(self, fake_creds):
        from gads_lib.ga4 import ga4_check_compatibility

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({})
        fake_resp.json.return_value = {}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ga4_check_compatibility(
                fake_creds,
                dimensions=["date"],
                metrics=["sessions"],
                property_id="271773771",
            )

        called_url = mock_req.call_args[0][1]
        assert "checkCompatibility" in called_url


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP C — gbp.py: reply review, delete reply, multi daily metrics, search
#           keywords, local posts CRUD
# ═══════════════════════════════════════════════════════════════════════════════

class TestGbpLocationReadMaskCli:
    """gads gbp location --read-mask — CLI surface for gbp_get_location's read_mask.

    The command's default read_mask omits `categories`, `openInfo` and `latlng`, so
    those fields are unreachable without an override; these cover the override and
    the unchanged default.
    """

    def test_read_mask_option_is_forwarded(self, fake_creds):
        """--read-mask overrides the command's built-in default mask."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.gbp_get_location", return_value={}) as mock_get:
            result = runner.invoke(
                cli,
                ["gbp", "location", "locations/123",
                 "--read-mask", "name,title,categories,openInfo,latlng", "--json"],
            )

        assert result.exit_code == 0, result.output
        assert mock_get.call_args.kwargs["read_mask"] == "name,title,categories,openInfo,latlng"

    def test_default_read_mask_unchanged_when_option_omitted(self, fake_creds):
        """Omitting --read-mask keeps the previous default mask verbatim."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.gbp_get_location", return_value={}) as mock_get:
            result = runner.invoke(cli, ["gbp", "location", "locations/123", "--json"])

        assert result.exit_code == 0, result.output
        mask = mock_get.call_args.kwargs["read_mask"]
        assert mask.startswith("name,title,storeCode,phoneNumbers")
        assert "categories" not in mask


class TestGbpReplyReview:
    """gbp_reply_review — PUT request with 'comment' in body."""

    def test_put_request_with_comment_in_body(self, fake_creds):
        from gads_lib.gbp import gbp_reply_review

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"comment": "Thank you!"})
        fake_resp.json.return_value = {"comment": "Thank you!"}

        review_name = "accounts/123/locations/456/reviews/review-789"
        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_reply_review(fake_creds, review_name, "Thank you for your review!")

        assert mock_req.call_args[0][0] == "PUT"
        sent_body = mock_req.call_args[1]["json"]
        assert "comment" in sent_body
        assert "Thank you" in sent_body["comment"]

    def test_url_contains_review_name_and_reply(self, fake_creds):
        from gads_lib.gbp import gbp_reply_review

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({})
        fake_resp.json.return_value = {}

        review_name = "accounts/123/locations/456/reviews/rev-001"
        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_reply_review(fake_creds, review_name, "Great!")

        called_url = mock_req.call_args[0][1]
        assert review_name in called_url
        assert "reply" in called_url


class TestGbpDeleteReply:
    """gbp_delete_reply — DELETE request."""

    def test_delete_method_used(self, fake_creds):
        from gads_lib.gbp import gbp_delete_reply

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({})
        fake_resp.json.return_value = {}

        review_name = "accounts/123/locations/456/reviews/rev-002"
        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_delete_reply(fake_creds, review_name)

        assert mock_req.call_args[0][0] == "DELETE"
        called_url = mock_req.call_args[0][1]
        assert review_name in called_url
        assert "reply" in called_url


class TestGbpListReviews:
    """gbp_list_reviews — account-path qualification + full pagination accumulation."""

    def test_bare_location_gets_account_prefixed(self, fake_creds):
        """A bare 'locations/X' name must be auto-prefixed with the resolved GBP account."""
        import gads_lib.gbp as gbp_mod
        gbp_mod._resolved_account_cache["name"] = None

        accounts_body = {"accounts": [{"name": "accounts/999", "type": "LOCATION_GROUP"}]}
        accounts_resp = MagicMock()
        accounts_resp.status_code = 200
        accounts_resp.text = json.dumps(accounts_body)
        accounts_resp.json.return_value = accounts_body

        reviews_body = {"reviews": [], "averageRating": 0, "totalReviewCount": 0}
        reviews_resp = MagicMock()
        reviews_resp.status_code = 200
        reviews_resp.text = json.dumps(reviews_body)
        reviews_resp.json.return_value = reviews_body

        with patch("requests.Session.request", side_effect=[accounts_resp, reviews_resp]) as mock_req:
            gbp_mod.gbp_list_reviews(fake_creds, "locations/123")

        called_url = mock_req.call_args_list[-1][0][1]
        assert called_url.startswith(
            "https://mybusiness.googleapis.com/v4/accounts/999/locations/123/reviews"
        )

    def test_already_qualified_name_not_double_prefixed(self, fake_creds):
        """A name already starting with 'accounts/' must be used as-is."""
        from gads_lib.gbp import gbp_list_reviews

        reviews_body = {"reviews": [], "averageRating": 0, "totalReviewCount": 0}
        reviews_resp = MagicMock()
        reviews_resp.status_code = 200
        reviews_resp.text = json.dumps(reviews_body)
        reviews_resp.json.return_value = reviews_body

        with patch("requests.Session.request", return_value=reviews_resp) as mock_req:
            gbp_list_reviews(fake_creds, "accounts/1/locations/2")

        called_url = mock_req.call_args[0][1]
        assert called_url.count("accounts/") == 1

    def test_follows_next_page_token_until_exhausted(self, fake_creds):
        """All pages must be accumulated into one reviews list, not just page 1."""
        from gads_lib.gbp import gbp_list_reviews

        body1 = {"reviews": [{"name": "r1"}], "averageRating": 4.5,
                 "totalReviewCount": 3, "nextPageToken": "tok1"}
        page1 = MagicMock(status_code=200, text=json.dumps(body1))
        page1.json.return_value = body1

        body2 = {"reviews": [{"name": "r2"}], "nextPageToken": "tok2"}
        page2 = MagicMock(status_code=200, text=json.dumps(body2))
        page2.json.return_value = body2

        body3 = {"reviews": [{"name": "r3"}]}
        page3 = MagicMock(status_code=200, text=json.dumps(body3))
        page3.json.return_value = body3

        with patch("requests.Session.request", side_effect=[page1, page2, page3]):
            result = gbp_list_reviews(fake_creds, "accounts/1/locations/2")

        assert [r["name"] for r in result["reviews"]] == ["r1", "r2", "r3"]
        assert result["fetchedReviewCount"] == 3
        assert result["totalReviewCount"] == 3
        assert result["averageRating"] == 4.5
        assert result["complete"] is True

    def test_repeated_token_stops_loop_and_flags_incomplete(self, fake_creds):
        """A misbehaving API repeating the same nextPageToken must not loop forever,
        and the shortfall must surface as complete=False rather than being silent."""
        from gads_lib.gbp import gbp_list_reviews

        body1 = {"reviews": [{"name": "r1"}], "totalReviewCount": 5, "nextPageToken": "stuck"}
        page1 = MagicMock(status_code=200, text=json.dumps(body1))
        page1.json.return_value = body1

        body2 = {"reviews": [{"name": "r2"}], "totalReviewCount": 5, "nextPageToken": "stuck"}
        page2 = MagicMock(status_code=200, text=json.dumps(body2))
        page2.json.return_value = body2

        with patch("requests.Session.request", side_effect=[page1, page2]):
            result = gbp_list_reviews(fake_creds, "accounts/1/locations/2")

        assert result["fetchedReviewCount"] == 2
        assert result["totalReviewCount"] == 5
        assert result["complete"] is False

    def test_limit_stops_fetch_early(self, fake_creds):
        """An explicit limit truncates accumulation without requiring extra pages."""
        from gads_lib.gbp import gbp_list_reviews

        body1 = {"reviews": [{"name": "r1"}, {"name": "r2"}],
                 "totalReviewCount": 5, "nextPageToken": "tok"}
        page1 = MagicMock(status_code=200, text=json.dumps(body1))
        page1.json.return_value = body1

        with patch("requests.Session.request", return_value=page1) as mock_req:
            result = gbp_list_reviews(fake_creds, "accounts/1/locations/2", limit=1)

        assert result["fetchedReviewCount"] == 1
        assert len(result["reviews"]) == 1
        assert mock_req.call_count == 1


class TestGbpBatchGetReviews:
    """gbp_batch_get_reviews — per-location full gbp_list_reviews() payload, not a bare list."""

    def test_returns_full_payload_per_location(self, fake_creds):
        from gads_lib.gbp import gbp_batch_get_reviews

        body = {"reviews": [{"name": "r1"}], "averageRating": 5, "totalReviewCount": 1}
        resp = MagicMock(status_code=200, text=json.dumps(body))
        resp.json.return_value = body

        with patch("requests.Session.request", return_value=resp):
            result = gbp_batch_get_reviews(fake_creds, "accounts/1", ["accounts/1/locations/2"])

        payload = result["accounts/1/locations/2"]
        assert payload["reviews"][0]["name"] == "r1"
        assert payload["totalReviewCount"] == 1
        assert payload["complete"] is True


class TestGbpMultiDailyMetrics:
    """gbp_multi_daily_metrics — uses request_json (requests.request) with pre-built URL."""

    def test_url_contains_fetch_multi_daily(self, fake_creds):
        from gads_lib.gbp import gbp_multi_daily_metrics

        api_resp = {"multiDailyMetricTimeSeries": []}
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_multi_daily_metrics(
                fake_creds,
                "locations/12345",
                ["CALL_CLICKS", "WEBSITE_CLICKS"],
                (2026, 4, 1),
                (2026, 4, 7),
            )

        called_url = mock_req.call_args[0][1]
        assert "fetchMultiDailyMetricsTimeSeries" in called_url

    def test_metrics_in_url_as_repeated_params(self, fake_creds):
        """Metrics are added as repeated dailyMetrics= params in the pre-built URL."""
        from gads_lib.gbp import gbp_multi_daily_metrics

        api_resp = {"multiDailyMetricTimeSeries": []}
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        metrics = ["CALL_CLICKS", "WEBSITE_CLICKS"]
        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_multi_daily_metrics(
                fake_creds,
                "locations/12345",
                metrics,
                (2026, 4, 1),
                (2026, 4, 7),
            )

        called_url = mock_req.call_args[0][1]
        for m in metrics:
            assert f"dailyMetrics={m}" in called_url

    def test_parses_response_into_dict(self, fake_creds):
        """Returned dict maps metric names to lists of date/value dicts."""
        from gads_lib.gbp import gbp_multi_daily_metrics

        api_resp = {
            "multiDailyMetricTimeSeries": [
                {
                    "dailyMetricTimeSeries": [
                        {
                            "dailyMetric": "CALL_CLICKS",
                            "timeSeries": {
                                "datedValues": [
                                    {"date": {"year": 2026, "month": 4, "day": 1}, "value": 5},
                                ]
                            },
                        }
                    ]
                }
            ]
        }
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("requests.Session.request", return_value=fake_resp):
            result = gbp_multi_daily_metrics(
                fake_creds,
                "locations/12345",
                ["CALL_CLICKS"],
                (2026, 4, 1),
                (2026, 4, 1),
            )

        assert "CALL_CLICKS" in result
        assert result["CALL_CLICKS"][0]["value"] == 5
        assert result["CALL_CLICKS"][0]["date"] == "2026-04-01"

    def test_403_exits_with_code_5(self, fake_creds):
        """403 from the API raises SystemExit with code 5, not 1."""
        from gads_lib.gbp import gbp_multi_daily_metrics

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "The caller does not have permission",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                gbp_multi_daily_metrics(
                    fake_creds,
                    "locations/12345",
                    ["CALL_CLICKS"],
                    (2026, 4, 1),
                    (2026, 4, 7),
                )

        assert exc_info.value.code == 5


class TestGbpSearchKeywordsMonthly:
    """gbp_search_keywords_monthly — URL contains searchkeywords/impressions/monthly."""

    def test_url_contains_search_keywords_monthly(self, fake_creds):
        from gads_lib.gbp import gbp_search_keywords_monthly

        api_resp = {"searchKeywordsCounts": []}
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_search_keywords_monthly(
                fake_creds,
                "locations/12345",
                start_month=(2026, 1),
                end_month=(2026, 3),
            )

        called_url = mock_req.call_args[0][1]
        assert "searchkeywords/impressions/monthly" in called_url

    def test_returns_sorted_keywords_descending(self, fake_creds):
        """Result is sorted by impressions descending."""
        from gads_lib.gbp import gbp_search_keywords_monthly

        api_resp = {
            "searchKeywordsCounts": [
                {"searchKeyword": "tesla parts", "insightsValue": {"value": 100}},
                {"searchKeyword": "tesla bumper", "insightsValue": {"value": 200}},
            ]
        }
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(api_resp)
        fake_resp.json.return_value = api_resp

        with patch("requests.Session.request", return_value=fake_resp):
            result = gbp_search_keywords_monthly(
                fake_creds,
                "locations/12345",
                start_month=(2026, 1),
                end_month=(2026, 3),
            )

        assert result[0]["keyword"] == "tesla bumper"
        assert result[0]["impressions"] == 200


class TestGbpListLocalPosts:
    """gbp_list_local_posts — URL contains localPosts."""

    def test_url_contains_local_posts(self, fake_creds):
        from gads_lib.gbp import gbp_list_local_posts

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"localPosts": []})
        fake_resp.json.return_value = {"localPosts": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_list_local_posts(fake_creds, "accounts/123", "456")

        called_url = mock_req.call_args[0][1]
        assert "localPosts" in called_url
        assert "accounts/123" in called_url


class TestGbpCreateLocalPost:
    """gbp_create_local_post — POST with body."""

    def test_post_with_body(self, fake_creds):
        from gads_lib.gbp import gbp_create_local_post

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"name": "accounts/123/locations/456/localPosts/789"})
        fake_resp.json.return_value = {"name": "accounts/123/locations/456/localPosts/789"}

        post_body = {
            "languageCode": "en",
            "summary": "New Tesla parts now available",
            "callToAction": {"actionType": "LEARN_MORE", "url": "https://talas.ae"},
            "topicType": "STANDARD",
        }

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_create_local_post(fake_creds, "accounts/123", "456", post_body)

        assert mock_req.call_args[0][0] == "POST"
        called_url = mock_req.call_args[0][1]
        assert "localPosts" in called_url
        sent_body = mock_req.call_args[1]["json"]
        assert sent_body["summary"] == "New Tesla parts now available"


class TestGbpDeleteLocalPost:
    """gbp_delete_local_post — DELETE request."""

    def test_delete_request(self, fake_creds):
        from gads_lib.gbp import gbp_delete_local_post

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({})
        fake_resp.json.return_value = {}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gbp_delete_local_post(fake_creds, "accounts/123", "456", "post-789")

        assert mock_req.call_args[0][0] == "DELETE"
        called_url = mock_req.call_args[0][1]
        assert "post-789" in called_url
        assert "localPosts" in called_url


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP D — gsc.py: list_sites, url_inspect, list_sitemaps
# ═══════════════════════════════════════════════════════════════════════════════

class TestGscListSites:
    """gsc_list_sites — URL contains 'sites'."""

    def test_url_contains_sites(self, fake_creds):
        from gads_lib.gsc import gsc_list_sites

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"siteEntry": []})
        fake_resp.json.return_value = {"siteEntry": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_list_sites(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "sites" in called_url
        assert "webmasters/v3" in called_url

    def test_returns_api_response(self, fake_creds):
        from gads_lib.gsc import gsc_list_sites

        expected = {"siteEntry": [{"siteUrl": "https://talas.ae/", "permissionLevel": "siteOwner"}]}
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps(expected)
        fake_resp.json.return_value = expected

        with patch("requests.Session.request", return_value=fake_resp):
            result = gsc_list_sites(fake_creds)

        assert result == expected


class TestGscUrlInspect:
    """gsc_url_inspect — POST to searchconsole.googleapis.com/v1."""

    def test_url_contains_url_inspection(self, fake_creds):
        from gads_lib.gsc import gsc_url_inspect

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"inspectionResult": {}})
        fake_resp.json.return_value = {"inspectionResult": {}}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_url_inspect(
                fake_creds,
                inspection_url="https://talas.ae/products/tesla-bumper",
                site_url="https://talas.ae/",
            )

        called_url = mock_req.call_args[0][1]
        assert "searchconsole.googleapis.com" in called_url
        assert "urlInspection" in called_url

    def test_body_has_inspection_url_and_site_url(self, fake_creds):
        from gads_lib.gsc import gsc_url_inspect

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"inspectionResult": {}})
        fake_resp.json.return_value = {"inspectionResult": {}}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_url_inspect(
                fake_creds,
                inspection_url="https://talas.ae/products/tesla-bumper",
                site_url="https://talas.ae/",
            )

        assert mock_req.call_args[0][0] == "POST"
        sent_body = mock_req.call_args[1]["json"]
        assert "inspectionUrl" in sent_body
        assert "siteUrl" in sent_body
        assert sent_body["inspectionUrl"] == "https://talas.ae/products/tesla-bumper"
        assert sent_body["siteUrl"] == "https://talas.ae/"

    def test_language_code_included_in_body(self, fake_creds):
        from gads_lib.gsc import gsc_url_inspect

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({})
        fake_resp.json.return_value = {}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_url_inspect(
                fake_creds,
                inspection_url="https://talas.ae/",
                site_url="https://talas.ae/",
                language_code="ar",
            )

        sent_body = mock_req.call_args[1]["json"]
        assert sent_body["languageCode"] == "ar"


class TestGscListSitemaps:
    """gsc_list_sitemaps — GET URL contains 'sitemaps'."""

    def test_url_contains_sitemaps(self, fake_creds):
        from gads_lib.gsc import gsc_list_sitemaps

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"sitemap": []})
        fake_resp.json.return_value = {"sitemap": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_list_sitemaps(fake_creds, "https://talas.ae/")

        called_url = mock_req.call_args[0][1]
        assert "sitemaps" in called_url
        assert "webmasters/v3" in called_url

    def test_site_url_encoded_in_path(self, fake_creds):
        """Site URL is URL-encoded and embedded in the path."""
        from gads_lib.gsc import gsc_list_sitemaps

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"sitemap": []})
        fake_resp.json.return_value = {"sitemap": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_list_sitemaps(fake_creds, "https://talas.ae/")

        called_url = mock_req.call_args[0][1]
        # URL encoding: ':' -> %3A; the encoded site URL is in the path
        assert "https%3A" in called_url or "talas.ae" in called_url

    def test_sitemap_index_passed_as_param(self, fake_creds):
        from gads_lib.gsc import gsc_list_sitemaps

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"sitemap": []})
        fake_resp.json.return_value = {"sitemap": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            gsc_list_sitemaps(
                fake_creds,
                "https://talas.ae/",
                sitemap_index="https://talas.ae/sitemap-index.xml",
            )

        params = mock_req.call_args[1].get("params")
        assert params is not None
        assert "sitemapIndex" in params


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP E — merchant.py: account, status, shipping, return policy, feeds, products
# ═══════════════════════════════════════════════════════════════════════════════

class TestMcGetAccount:
    """mc_get_account — URL shape contains accounts/v1."""

    def test_url_shape(self, fake_creds):
        from gads_lib.merchant import mc_get_account

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"accountId": "88887777", "accountName": "Talas"})
        fake_resp.json.return_value = {"accountId": "88887777", "accountName": "Talas"}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_get_account(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "merchantapi.googleapis.com" in called_url
        assert "accounts/v1" in called_url
        assert "88887777" in called_url  # MERCHANT_CENTER_ID from conftest env

    def test_get_method(self, fake_creds):
        from gads_lib.merchant import mc_get_account

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({})
        fake_resp.json.return_value = {}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_get_account(fake_creds)

        assert mock_req.call_args[0][0] == "GET"


class TestMcGetAccountStatus:
    """mc_get_account_status — URL contains 'issues'."""

    def test_url_contains_issues(self, fake_creds):
        from gads_lib.merchant import mc_get_account_status

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"accountIssues": []})
        fake_resp.json.return_value = {"accountIssues": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_get_account_status(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "issues" in called_url


class TestMcGetShipping:
    """mc_get_shipping — URL contains 'shippingSettings'."""

    def test_url_contains_shipping_settings(self, fake_creds):
        from gads_lib.merchant import mc_get_shipping

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"services": []})
        fake_resp.json.return_value = {"services": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_get_shipping(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "shippingSettings" in called_url


class TestMcGetReturnPolicy:
    """mc_get_return_policy — URL contains 'onlineReturnPolicies'."""

    def test_url_contains_online_return_policies(self, fake_creds):
        from gads_lib.merchant import mc_get_return_policy

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"onlineReturnPolicies": []})
        fake_resp.json.return_value = {"onlineReturnPolicies": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_get_return_policy(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "onlineReturnPolicies" in called_url


class TestMcListDatafeeds:
    """mc_list_datafeeds — URL contains 'dataSources'."""

    def test_url_contains_data_sources(self, fake_creds):
        from gads_lib.merchant import mc_list_datafeeds

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"dataSources": []})
        fake_resp.json.return_value = {"dataSources": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_list_datafeeds(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "dataSources" in called_url
        assert "datasources/v1" in called_url


class TestMcListProductStatuses:
    """mc_list_product_statuses — URL contains products/v1."""

    def test_url_contains_products_v1(self, fake_creds):
        from gads_lib.merchant import mc_list_product_statuses

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"products": []})
        fake_resp.json.return_value = {"products": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            mc_list_product_statuses(fake_creds)

        called_url = mock_req.call_args[0][1]
        assert "products/v1" in called_url

    def test_response_has_products_key(self, fake_creds):
        """Merchant API v1 folds productStatus into the products response."""
        from gads_lib.merchant import mc_list_product_statuses

        products = [
            {
                "name": "accounts/88887777/products/p1",
                "offerId": "SKU-001",
                "productStatus": {"destinationStatuses": [{"destination": "Shopping"}]},
            }
        ]
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"products": products})
        fake_resp.json.return_value = {"products": products}

        with patch("requests.Session.request", return_value=fake_resp):
            result = mc_list_product_statuses(fake_creds)

        assert "products" in result
        assert result["products"][0]["offerId"] == "SKU-001"


class TestMcRegisterGcp:
    """mc_register_gcp — POST to developerRegistration:registerGcp."""

    def _fake_ok_resp(self):
        """Minimal HTTP 200 response with empty body (API acks with {})."""
        r = MagicMock()
        r.status_code = 200
        r.text = "{}"
        r.json.return_value = {}
        return r

    def test_post_method(self, fake_creds):
        """mc_register_gcp uses POST, not GET."""
        from gads_lib.merchant import mc_register_gcp

        with patch("requests.Session.request", return_value=self._fake_ok_resp()) as mock_req:
            mc_register_gcp(fake_creds, developer_email="admin@example.com")

        assert mock_req.call_args[0][0] == "POST"

    def test_url_contains_developer_registration(self, fake_creds):
        """URL path includes developerRegistration:registerGcp."""
        from gads_lib.merchant import mc_register_gcp

        with patch("requests.Session.request", return_value=self._fake_ok_resp()) as mock_req:
            mc_register_gcp(fake_creds, developer_email="admin@example.com")

        called_url = mock_req.call_args[0][1]
        assert "developerRegistration:registerGcp" in called_url
        assert "merchantapi.googleapis.com" in called_url

    def test_url_uses_configured_account(self, fake_creds):
        """URL embeds the configured MERCHANT_CENTER_ID (88887777 from conftest env)."""
        from gads_lib.merchant import mc_register_gcp

        with patch("requests.Session.request", return_value=self._fake_ok_resp()) as mock_req:
            mc_register_gcp(fake_creds, developer_email="admin@example.com")

        called_url = mock_req.call_args[0][1]
        assert "88887777" in called_url

    def test_url_uses_explicit_account(self, fake_creds):
        """When account_id is passed, it overrides the configured ID."""
        from gads_lib.merchant import mc_register_gcp

        with patch("requests.Session.request", return_value=self._fake_ok_resp()) as mock_req:
            mc_register_gcp(fake_creds, developer_email="admin@example.com",
                            account_id="99999999")

        called_url = mock_req.call_args[0][1]
        assert "99999999" in called_url

    def test_request_body_contains_developer_email(self, fake_creds):
        """POST body is {"developerEmail": email}."""
        from gads_lib.merchant import mc_register_gcp

        with patch("requests.Session.request", return_value=self._fake_ok_resp()) as mock_req:
            mc_register_gcp(fake_creds, developer_email="dev@company.com")

        _, kwargs = mock_req.call_args
        body = kwargs.get("json") or {}
        assert body.get("developerEmail") == "dev@company.com"

    def test_error_envelope_on_403(self, fake_creds, capsys):
        """as_json=True routes 403 through the JSON error envelope and exits 5."""
        from gads_lib.merchant import mc_register_gcp

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "GCP project not authorized",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                mc_register_gcp(fake_creds, developer_email="admin@example.com", as_json=True)

        assert exc_info.value.code == 5
        out = capsys.readouterr().out
        envelope = json.loads(out)
        assert "error" in envelope

    def test_cli_help_exits_0(self):
        """gads merchant register-gcp --help exits 0."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["merchant", "register-gcp", "--help"])
        assert result.exit_code == 0, result.output
        assert "register" in result.output.lower()
        assert "--developer-email" in result.output

    def test_cli_json_output_on_success(self, fake_creds, capsys):
        """gads merchant register-gcp --json emits status:registered JSON."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.mc_register_gcp", return_value={}):
            result = runner.invoke(
                cli,
                ["merchant", "register-gcp",
                 "--developer-email", "admin@talas.ae",
                 "--json"],
            )

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["status"] == "registered"
        assert parsed["developer_email"] == "admin@talas.ae"
        assert "next_step" in parsed


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP F — Error envelope tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestErrorEnvelopes:
    """Verify as_json=True error routing emits JSON envelope + exits 5."""

    def test_generate_keyword_ideas_403_json_envelope(self, fake_creds, capsys):
        from gads_lib.ads import generate_keyword_ideas

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "The caller does not have permission",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                generate_keyword_ideas(fake_creds, keywords=["tesla"], as_json=True)

        assert exc_info.value.code == 5
        out = capsys.readouterr().out
        assert out.strip()
        envelope = json.loads(out)
        assert "error" in envelope

    def test_list_key_events_403_insufficient_scope_json_envelope(self, fake_creds, capsys):
        from gads_lib.ga4 import list_key_events

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "Request had insufficient authentication scopes. INSUFFICIENT_AUTHENTICATION_SCOPES",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("gads_lib.ga4._send_with_retry", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                list_key_events("271773771", fake_creds, as_json=True)

        assert exc_info.value.code == 5
        out = capsys.readouterr().out
        assert out.strip()
        envelope = json.loads(out)
        assert "error" in envelope

    def test_gbp_multi_daily_metrics_403_exits_5_not_1(self, fake_creds):
        """403 from gbp_multi_daily_metrics raises SystemExit(5), not SystemExit(1)."""
        from gads_lib.gbp import gbp_multi_daily_metrics

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "The caller does not have permission",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("requests.Session.request", return_value=fake_resp):
            with pytest.raises(SystemExit) as exc_info:
                gbp_multi_daily_metrics(
                    fake_creds,
                    "locations/12345",
                    ["CALL_CLICKS"],
                    (2026, 4, 1),
                    (2026, 4, 7),
                )

        assert exc_info.value.code == 5, (
            f"Expected exit code 5 for API permission error, got {exc_info.value.code}"
        )

    def test_merchant_403_exits_5(self, fake_creds):
        """Merchant API 403 exits with code 5; offer_gcloud_enable is mocked to avoid stdin prompt."""
        from gads_lib.merchant import mc_get_account

        error_body = json.dumps({
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "message": "merchantapi.googleapis.com has not been used in project",
            }
        })
        fake_resp = MagicMock()
        fake_resp.status_code = 403
        fake_resp.text = error_body

        with patch("requests.Session.request", return_value=fake_resp), \
             patch("gads_lib.http.offer_gcloud_enable"):
            with pytest.raises(SystemExit) as exc_info:
                mc_get_account(fake_creds)

        assert exc_info.value.code == 5


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP G — SystemExit-escape hardening (audit: broad `except Exception` blocks
# must not let SystemExit from get_db()/get_credentials() escape and abort an
# already-successful operation or a per-service diagnostic loop) + OAuth
# refresh-failure messaging.
# ═══════════════════════════════════════════════════════════════════════════════


class TestAutoLogNeverAbortsOnDbFailure:
    """`_auto_log()` is a best-effort changelog write. `get_db()` raises
    SystemExit(1) (not a plain Exception) when the local DB is missing —
    it must be swallowed too, or a missing DB would mask an already-successful
    live mutation."""

    def test_auto_log_swallows_systemexit_from_get_db(self):
        from gads_lib.cli import _auto_log

        with patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            # Must not raise — this is the whole point of the best-effort wrapper.
            _auto_log("campaign_status", "999 -> PAUSED", campaign_id="999")

    def test_campaign_status_still_reports_success_when_db_missing(self):
        """End-to-end: the live mutation succeeds; the local changelog DB is
        missing. The command must still exit 0 and print the success message
        — not silently die inside the best-effort _auto_log() call."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.ads_mutate", return_value={"results": [{"resourceName": "customers/1/campaigns/999"}]}), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(cli, ["campaign", "status", "999", "PAUSED", "--yes"])

        assert result.exit_code == 0, result.output
        assert "999" in result.output and "PAUSED" in result.output


class TestAuthTestContinuesPastPerServiceSystemExit:
    """`gads auth test` probes 5 services in independent try/except blocks.
    `get_credentials()` / the HTTP error-routing layer raise SystemExit (not a
    plain Exception) for missing creds / classified API errors. A SystemExit
    from one service must not abort the whole diagnostic loop."""

    def test_one_service_systemexit_does_not_abort_the_others(self):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.run_gaql", return_value=[{"customer": {"id": "123"}}]), \
             patch("gads_lib.cli.gbp_list_accounts", side_effect=SystemExit(5)), \
             patch("gads_lib.cli.mc_get_account", return_value={}), \
             patch("gads_lib.cli.ga4_get_metadata", return_value={}), \
             patch("gads_lib.cli.gsc_list_sites", return_value={"siteEntry": []}):
            result = runner.invoke(cli, ["auth", "test", "--json"])

        # NOTE: `--json` mode currently exits 0 regardless of per-service
        # failures (only the human-readable path raises SystemExit(1) on
        # failures) — that is pre-existing, separate behavior, not part of
        # this test. What matters here is that the loop actually completed
        # and printed a full per-service report instead of aborting after
        # the first SystemExit.
        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        services = {r["service"]: r for r in parsed}
        assert services["Google Ads"]["status"] == "ok"
        assert services["Google Business Profile"]["status"] == "fail"
        assert services["Merchant Center"]["status"] == "ok"
        assert services["GA4"]["status"] == "ok"
        assert services["Search Console"]["status"] == "ok"


class TestGetCredentialsRefreshFailure:
    """get_credentials() must translate a revoked/expired refresh token into a
    clear, actionable message (pointing at generate_token.py) and a stable
    AUTH exit code, instead of leaking a raw google-auth exception repr."""

    def test_refresh_error_gives_actionable_message_and_auth_exit_code(self, capsys):
        from google.auth.exceptions import RefreshError
        from gads_lib.auth import get_credentials
        from gads_lib.output import EXIT_CODES

        def fake_refresh(self, request):
            raise RefreshError("invalid_grant: Token has been expired or revoked.")

        fake_creds_json = json.dumps({
            "token": "x", "refresh_token": "y", "client_id": "a",
            "client_secret": "b", "token_uri": "https://oauth2.googleapis.com/token",
        })

        with patch("gads_lib.auth.CREDS_PATH") as mock_path, \
             patch("google.oauth2.credentials.Credentials.expired",
                   new_callable=__import__("unittest.mock", fromlist=["PropertyMock"]).PropertyMock,
                   return_value=True), \
             patch("google.oauth2.credentials.Credentials.refresh", fake_refresh), \
             patch("builtins.open", MagicMock(return_value=io.StringIO(fake_creds_json))):
            mock_path.exists.return_value = True
            with pytest.raises(SystemExit) as exc_info:
                get_credentials()

        assert exc_info.value.code == EXIT_CODES["AUTH"]
        stderr = capsys.readouterr().err
        assert "generate_token.py" in stderr
        assert "refresh" in stderr.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP H — Data Manager API (gads_lib/datamanager.py + `gads data-manager *`)
# ═══════════════════════════════════════════════════════════════════════════════


class TestDatamanagerIngestEvents:
    """datamanager_ingest_events — POST /v1/events:ingest."""

    def test_url_contains_events_ingest(self, fake_creds):
        from gads_lib.datamanager import datamanager_ingest_events

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"requestId": "req-1"})
        fake_resp.json.return_value = {"requestId": "req-1"}

        events = [{"eventTimestamp": "2026-01-01T10:00:00+04:00", "adIdentifiers": {"gclid": "abc"}}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            datamanager_ingest_events(fake_creds, events, "999")

        called_url = mock_req.call_args[0][1]
        assert "events:ingest" in called_url
        assert "datamanager.googleapis.com" in called_url

    def test_body_has_destinations_and_events(self, fake_creds):
        from gads_lib.datamanager import datamanager_ingest_events

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"requestId": "req-1"})
        fake_resp.json.return_value = {"requestId": "req-1"}

        events = [
            {"eventTimestamp": "2026-01-01T10:00:00+04:00", "adIdentifiers": {"gclid": "abc"}},
            {"eventTimestamp": "2026-01-02T10:00:00+04:00", "adIdentifiers": {"gclid": "def"}},
        ]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            datamanager_ingest_events(fake_creds, events, "999")

        sent_body = mock_req.call_args[1]["json"]
        assert "destinations" in sent_body
        assert "events" in sent_body
        assert len(sent_body["events"]) == 2
        assert sent_body["destinations"][0]["productDestinationId"] == "999"
        assert sent_body["destinations"][0]["operatingAccount"]["accountType"] == "GOOGLE_ADS"

    def test_uses_bearer_headers_not_ads_headers(self, fake_creds):
        """Data Manager needs only Authorization + Content-Type -- no developer-token
        / login-customer-id headers (those are Ads-REST-specific)."""
        from gads_lib.datamanager import datamanager_ingest_events

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"requestId": "req-1"})
        fake_resp.json.return_value = {"requestId": "req-1"}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            datamanager_ingest_events(fake_creds, [{"eventTimestamp": "2026-01-01T10:00:00+04:00"}], "999")

        sent_headers = mock_req.call_args[1]["headers"]
        assert "developer-token" not in sent_headers
        assert "login-customer-id" not in sent_headers
        assert sent_headers["Authorization"] == f"Bearer {fake_creds.token}"

    def test_raises_valueerror_over_max_events(self, fake_creds):
        from gads_lib.datamanager import datamanager_ingest_events, MAX_EVENTS_PER_REQUEST

        events = [{"eventTimestamp": "2026-01-01T10:00:00+04:00"}] * (MAX_EVENTS_PER_REQUEST + 1)

        with patch("requests.Session.request") as mock_req:
            with pytest.raises(ValueError):
                datamanager_ingest_events(fake_creds, events, "999")

        assert not mock_req.called


class TestDatamanagerIngestAudienceMembers:
    """datamanager_ingest_audience_members — POST /v1/audienceMembers:ingest."""

    def test_url_contains_audience_members_ingest(self, fake_creds):
        from gads_lib.datamanager import datamanager_ingest_audience_members

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"requestId": "req-2"})
        fake_resp.json.return_value = {"requestId": "req-2"}

        members = [{"userData": {"userIdentifiers": [{"emailAddress": "hash"}]}}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            datamanager_ingest_audience_members(fake_creds, members, "888")

        called_url = mock_req.call_args[0][1]
        assert "audienceMembers:ingest" in called_url
        assert "datamanager.googleapis.com" in called_url

    def test_body_has_destinations_and_audience_members(self, fake_creds):
        from gads_lib.datamanager import datamanager_ingest_audience_members

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"requestId": "req-2"})
        fake_resp.json.return_value = {"requestId": "req-2"}

        members = [{"userData": {"userIdentifiers": [{"emailAddress": "hash"}]}}]

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            datamanager_ingest_audience_members(fake_creds, members, "888")

        sent_body = mock_req.call_args[1]["json"]
        assert "destinations" in sent_body
        assert "audienceMembers" in sent_body
        assert sent_body["destinations"][0]["productDestinationId"] == "888"

    def test_raises_valueerror_over_max_members(self, fake_creds):
        from gads_lib.datamanager import (
            datamanager_ingest_audience_members,
            MAX_AUDIENCE_MEMBERS_PER_REQUEST,
        )

        members = [{"userData": {"userIdentifiers": [{"emailAddress": "hash"}]}}] * (
            MAX_AUDIENCE_MEMBERS_PER_REQUEST + 1
        )

        with patch("requests.Session.request") as mock_req:
            with pytest.raises(ValueError):
                datamanager_ingest_audience_members(fake_creds, members, "888")

        assert not mock_req.called


class TestBuildUserIdentifiers:
    """build_user_identifiers — SHA-256 hex hashing of phone/email for Data Manager."""

    def test_phone_and_email_hashed(self):
        from gads_lib.datamanager import build_user_identifiers

        ids = build_user_identifiers(phone="+971501234567", email="User@Example.com")
        keys = {list(i.keys())[0] for i in ids}
        assert keys == {"phoneNumber", "emailAddress"}
        for i in ids:
            val = list(i.values())[0]
            assert len(val) == 64  # sha256 hex digest length
            assert val == val.lower()

    def test_invalid_phone_and_no_email_returns_empty(self):
        from gads_lib.datamanager import build_user_identifiers

        assert build_user_identifiers(phone="123", email="") == []
        assert build_user_identifiers(phone=None, email=None) == []

    def test_email_without_at_sign_skipped(self):
        from gads_lib.datamanager import build_user_identifiers

        ids = build_user_identifiers(phone=None, email="not-an-email")
        assert ids == []


class TestDataManagerConversionIngestCli:
    """`gads data-manager conversion-ingest` — CLI-level behavior."""

    def test_cli_help_exits_0(self):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["data-manager", "conversion-ingest", "--help"])
        assert result.exit_code == 0, result.output
        assert "--action-id" in result.output
        assert "--batch-size" in result.output

    def test_dry_run_makes_zero_network_calls(self, tmp_path):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        events_file = tmp_path / "events.jsonl"
        events_file.write_text(
            '{"eventTimestamp": "2026-01-01T10:00:00+04:00", "adIdentifiers": {"gclid": "abc"}}\n'
        )

        runner = CliRunner()
        with patch("requests.Session.request") as mock_req:
            result = runner.invoke(
                cli,
                ["data-manager", "conversion-ingest", str(events_file), "--action-id", "999", "--dry-run", "--json"],
            )

        assert result.exit_code == 0, result.output
        assert not mock_req.called
        parsed = json.loads(result.output)
        assert parsed["status"] == "dry_run"
        assert parsed["event_count"] == 1

    def test_missing_eventtimestamp_exits_validation_with_zero_network_calls(self, tmp_path):
        from click.testing import CliRunner
        from gads_lib.cli import cli
        from gads_lib.output import EXIT_CODES

        events_file = tmp_path / "bad_events.jsonl"
        events_file.write_text('{"transactionId": "no-timestamp"}\n')

        runner = CliRunner()
        with patch("requests.Session.request") as mock_req:
            result = runner.invoke(
                cli,
                ["data-manager", "conversion-ingest", str(events_file), "--action-id", "999", "--dry-run"],
            )

        assert result.exit_code == EXIT_CODES["VALIDATION"], result.output
        assert not mock_req.called
        assert "eventTimestamp" in result.output

    def test_batch_size_chunks_into_multiple_calls(self, tmp_path):
        """3 events with --batch-size 2 must issue 2 datamanager_ingest_events calls (2 + 1)."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        events_file = tmp_path / "events.jsonl"
        lines = [
            json.dumps({"eventTimestamp": f"2026-01-0{i}T10:00:00+04:00", "adIdentifiers": {"gclid": f"g{i}"}})
            for i in range(1, 4)
        ]
        events_file.write_text("\n".join(lines) + "\n")

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.datamanager_ingest_events", return_value={"requestId": "req-x"}) as mock_ingest, \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["data-manager", "conversion-ingest", str(events_file), "--action-id", "999",
                 "--batch-size", "2", "--yes", "--json"],
            )

        assert result.exit_code == 0, result.output
        assert mock_ingest.call_count == 2
        first_batch = mock_ingest.call_args_list[0][0][1]
        second_batch = mock_ingest.call_args_list[1][0][1]
        assert len(first_batch) == 2
        assert len(second_batch) == 1

    def test_json_output_never_claims_per_event_success(self, tmp_path):
        """The submitted-response output must carry the async caveat, never a
        false 'N conversions uploaded successfully' style claim (unlike the
        legacy sync-ish `conversion upload` command, Data Manager gives no
        per-event confirmation)."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        events_file = tmp_path / "events.jsonl"
        events_file.write_text(
            '{"eventTimestamp": "2026-01-01T10:00:00+04:00", "adIdentifiers": {"gclid": "abc"}}\n'
        )

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.datamanager_ingest_events", return_value={"requestId": "req-y"}), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["data-manager", "conversion-ingest", str(events_file), "--action-id", "999", "--yes", "--json"],
            )

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["status"] == "submitted"
        assert "asynchronous" in parsed["note"].lower()
        assert "no per-event status" in parsed["note"].lower()
        # Must not fabricate a per-event confirmation.
        assert "uploaded successfully" not in parsed["note"].lower()

    def test_human_readable_output_never_claims_per_event_success(self, tmp_path):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        events_file = tmp_path / "events.jsonl"
        events_file.write_text(
            '{"eventTimestamp": "2026-01-01T10:00:00+04:00", "adIdentifiers": {"gclid": "abc"}}\n'
        )

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.datamanager_ingest_events", return_value={"requestId": "req-z"}), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["data-manager", "conversion-ingest", str(events_file), "--action-id", "999", "--yes"],
            )

        assert result.exit_code == 0, result.output
        assert "asynchronous" in result.output.lower()
        assert "uploaded successfully" not in result.output.lower()


class TestDataManagerAudienceUploadCli:
    """`gads data-manager audience-upload` — CLI-level behavior."""

    def test_cli_help_exits_0(self):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["data-manager", "audience-upload", "--help"])
        assert result.exit_code == 0, result.output
        assert "--list-resource-name" in result.output

    def test_dry_run_makes_zero_network_calls(self, tmp_path):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        csv_file = tmp_path / "contacts.csv"
        csv_file.write_text(
            "Phone,Email,First Name,Last Name,Country\n"
            "+971501234567,user@example.com,John,Doe,AE\n"
        )

        runner = CliRunner()
        with patch("requests.Session.request") as mock_req:
            result = runner.invoke(
                cli,
                ["data-manager", "audience-upload", str(csv_file),
                 "--list-resource-name", "777", "--dry-run", "--json"],
            )

        assert result.exit_code == 0, result.output
        assert not mock_req.called
        parsed = json.loads(result.output)
        assert parsed["status"] == "dry_run"
        assert parsed["member_count"] == 1

    def test_json_output_includes_async_note_and_requestid(self, tmp_path):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        csv_file = tmp_path / "contacts.csv"
        csv_file.write_text(
            "Phone,Email,First Name,Last Name,Country\n"
            "+971501234567,user@example.com,John,Doe,AE\n"
        )

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.datamanager_ingest_audience_members",
                   return_value={"requestId": "req-aud-1"}), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["data-manager", "audience-upload", str(csv_file),
                 "--list-resource-name", "777", "--yes", "--json"],
            )

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed["status"] == "submitted"
        assert parsed["requestId"] == "req-aud-1"
        assert "asynchronous" in parsed["note"].lower()

    def test_no_valid_identifiers_exits_validation(self, tmp_path):
        from click.testing import CliRunner
        from gads_lib.cli import cli
        from gads_lib.output import EXIT_CODES

        csv_file = tmp_path / "empty_contacts.csv"
        csv_file.write_text("Phone,Email,First Name,Last Name,Country\n,,,,\n")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["data-manager", "audience-upload", str(csv_file), "--list-resource-name", "777", "--dry-run"],
        )
        assert result.exit_code == EXIT_CODES["VALIDATION"], result.output


# =============================================================================
# GROUP — analyze_wasted_spend: per-channel-type CPA baseline segmentation
# =============================================================================

def _wasted_camp_row(name, channel_type, cost_micros, conversions, conversions_value=0):
    return {
        "campaign": {
            "name": name,
            "status": "ENABLED",
            "advertisingChannelType": channel_type,
        },
        "metrics": {
            "costMicros": str(cost_micros),
            "conversions": conversions,
            "conversionsValue": conversions_value,
        },
    }


def _wasted_st_row(term, campaign_name, channel_type, cost_micros, conversions, clicks=10):
    return {
        "searchTermView": {"searchTerm": term},
        "campaign": {"name": campaign_name, "advertisingChannelType": channel_type},
        "metrics": {
            "costMicros": str(cost_micros),
            "conversions": conversions,
            "clicks": clicks,
        },
    }


class TestAnalyzeWastedSpendChannelSegmentation:
    """Wasted-spend CPA baselines must be computed PER campaign.advertising_channel_type,
    never as one blended figure across SEARCH/SMART/PERFORMANCE_MAX (the currency-mismatch
    bug: Smart campaigns' cheap-but-normal local-action CPA looked wasteful against a
    blended average contaminated by much-cheaper Search/PMax WhatsApp-pixel conversions)."""

    def test_smart_campaign_normal_cpa_not_flagged_against_own_peer_group(self, fake_creds):
        """A Smart campaign with a CPA that is normal for OTHER Smart campaigns must not be
        flagged, even though a much-cheaper Search campaign is present in the same window.

        Under the old (buggy) single blended average, campaign A's cpa (1.58) would have
        exceeded the blended threshold (~1.55, dragged down by the huge cheap SEARCH volume).
        Segmented by channel type, SMART's own peer-group average (~1.56) makes A's cpa
        nowhere near its 2x threshold (~3.12).
        """
        from gads_lib.analyze.wasted_spend import analyze_wasted_spend

        camp_rows = [
            _wasted_camp_row("9-QZ3-TESLA-English", "SMART", 158_000_000, 100),   # cpa 1.58
            _wasted_camp_row("9-IND4-Korean-English", "SMART", 154_000_000, 100),  # cpa 1.54
            _wasted_camp_row("9-Search-HighIntent", "SEARCH", 38_500_000_000, 50_000),  # cpa 0.77
        ]

        with patch("gads_lib.analyze.wasted_spend.run_gaql", side_effect=[camp_rows, []]):
            result = analyze_wasted_spend(fake_creds, days=30, min_cost=1.0, cpa_multiple=2.0)

        flagged_names = {c["campaign"] for c in result["campaigns"]}
        assert "9-QZ3-TESLA-English" not in flagged_names
        assert "9-IND4-Korean-English" not in flagged_names

        # Segmented baselines are exposed per channel type, not one blended figure.
        assert result["avg_cpa"]["SMART"] == pytest.approx(1.56, abs=0.01)
        assert result["avg_cpa"]["SEARCH"] == pytest.approx(0.77, abs=0.01)

    def test_genuinely_wasteful_campaign_still_flagged_within_own_peer_group(self, fake_creds):
        """A Smart campaign whose CPA is high even relative to OTHER Smart campaigns (not
        just relative to a cross-type blend) must still be flagged as wasted."""
        from gads_lib.analyze.wasted_spend import analyze_wasted_spend

        camp_rows = [
            _wasted_camp_row("9-QZ3-TESLA-English", "SMART", 158_000_000, 100),   # cpa 1.58
            _wasted_camp_row("9-IND4-Korean-English", "SMART", 154_000_000, 100),  # cpa 1.54
            _wasted_camp_row("9-Bad-Smart-Campaign", "SMART", 1_000_000_000, 50),  # cpa 20.00
        ]

        with patch("gads_lib.analyze.wasted_spend.run_gaql", side_effect=[camp_rows, []]):
            result = analyze_wasted_spend(fake_creds, days=30, min_cost=1.0, cpa_multiple=2.0)

        flagged = {c["campaign"]: c for c in result["campaigns"]}
        assert "9-Bad-Smart-Campaign" in flagged
        assert flagged["9-Bad-Smart-Campaign"]["reason"].startswith("below_average")
        assert "SMART" in flagged["9-Bad-Smart-Campaign"]["reason"]
        assert flagged["9-Bad-Smart-Campaign"]["wasted"] > 0
        # The two normal-for-SMART campaigns remain unflagged even with the bad one present.
        assert "9-QZ3-TESLA-English" not in flagged
        assert "9-IND4-Korean-English" not in flagged

    def test_zero_conversion_campaign_flagged_regardless_of_channel_type(self, fake_creds):
        """Zero-conversion spend is always wasted, independent of channel-type baselines."""
        from gads_lib.analyze.wasted_spend import analyze_wasted_spend

        camp_rows = [
            _wasted_camp_row("9-PMax-AllLocations", "PERFORMANCE_MAX", 50_000_000, 0),
        ]

        with patch("gads_lib.analyze.wasted_spend.run_gaql", side_effect=[camp_rows, []]):
            result = analyze_wasted_spend(fake_creds, days=30, min_cost=1.0, cpa_multiple=2.0)

        flagged = {c["campaign"]: c for c in result["campaigns"]}
        assert flagged["9-PMax-AllLocations"]["reason"] == "zero_conversion"
        assert flagged["9-PMax-AllLocations"]["wasted"] == pytest.approx(50.0)

    def test_search_terms_segmented_by_their_campaigns_channel_type(self, fake_creds):
        """Search-term wasted-spend classification uses the search term's own campaign's
        channel-type baseline too — the same blended-average bug would otherwise leak into
        the search-term list via the shared `_classify` helper."""
        from gads_lib.analyze.wasted_spend import analyze_wasted_spend

        camp_rows = [
            _wasted_camp_row("9-QZ3-TESLA-English", "SMART", 158_000_000, 100),
            _wasted_camp_row("9-Search-HighIntent", "SEARCH", 38_500_000_000, 50_000),
        ]
        st_rows = [
            # Same per-unit CPA as the SMART campaign average (~1.58) — normal for SMART,
            # must not be flagged just because SEARCH's average is far cheaper.
            _wasted_st_row("tesla parts uae", "9-QZ3-TESLA-English", "SMART", 15_800_000, 10),
        ]

        with patch("gads_lib.analyze.wasted_spend.run_gaql", side_effect=[camp_rows, st_rows]):
            result = analyze_wasted_spend(fake_creds, days=30, min_cost=1.0, cpa_multiple=2.0)

        flagged_terms = {s["search_term"] for s in result["search_terms"]}
        assert "tesla parts uae" not in flagged_terms
