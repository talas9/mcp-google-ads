"""
Offline pytest suite for `gads pmax` — Performance Max read-only reporting.

Covers: gads pmax asset-groups | signals | listing-groups | search-terms.
ALL HTTP calls are mocked at the run_gaql boundary (patch
"gads_lib.cli.run_gaql"), matching the repo's CLI-level test convention
(see tests/test_gads.py TestAuthTestContinuesPastPerServiceSystemExit).

Run from the gads-cli root:
    cd /home/talas9/talas-ads/gads-cli && python -m pytest tests/test_pmax.py -v
"""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gads_lib.cli import cli


# ═══════════════════════════════════════════════════════════════════════════
# gads pmax asset-groups
# ═══════════════════════════════════════════════════════════════════════════

class TestPmaxAssetGroups:
    def _fake_row(self):
        return {
            "campaign": {"id": "23566187470", "name": "9-PMax-AllLocations-Feb2026"},
            "assetGroup": {
                "id": "6673792593", "name": "QZ3 - Universal", "status": "ENABLED",
                "primaryStatus": "LIMITED", "primaryStatusReasons": ["ASSET_GROUP_LIMITED"],
                "adStrength": "AVERAGE",
            },
            "metrics": {
                "impressions": "505767", "clicks": "33995", "conversions": 12026.56,
                "costMicros": "4715141276", "conversionsValue": 12026.56,
            },
        }

    def test_happy_path_renders_table(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row()]) as mock_gaql:
            result = runner.invoke(cli, ["pmax", "asset-groups", "--campaign", "23566187470"])

        assert result.exit_code == 0, result.output
        assert "QZ3 - Universal" in result.output
        assert "AVERAGE" in result.output
        assert "4,715.14" in result.output  # cost_micros -> AED, rounded 2dp
        assert mock_gaql.called

    def test_campaign_filter_appears_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["pmax", "asset-groups", "--campaign", "999888777"])

        query = mock_gaql.call_args[0][1]
        assert "campaign.id = 999888777" in query
        assert "FROM asset_group" in query

    def test_campaign_filter_optional(self, fake_creds):
        """--campaign is optional for asset-groups (lists whole account when omitted)."""
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            result = runner.invoke(cli, ["pmax", "asset-groups"])

        assert result.exit_code == 0, result.output
        query = mock_gaql.call_args[0][1]
        assert "WHERE" not in query

    def test_json_shape(self, fake_creds):
        rows = [self._fake_row()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["pmax", "asset-groups", "--campaign", "1", "--json"])

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed == rows

    def test_empty_results_exits_zero(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]):
            result = runner.invoke(cli, ["pmax", "asset-groups", "--campaign", "1"])

        assert result.exit_code == 0, result.output
        assert "(no results)" in result.output


# ═══════════════════════════════════════════════════════════════════════════
# gads pmax signals
# ═══════════════════════════════════════════════════════════════════════════

class TestPmaxSignals:
    def _fake_audience_row(self):
        return {
            "campaign": {"id": "23566187470", "name": "9-PMax-AllLocations-Feb2026"},
            "assetGroup": {"id": "6673792593", "name": "QZ3 - Universal"},
            "assetGroupSignal": {
                "resourceName": "customers/3552856345/assetGroupSignals/6673792593~2471556861488",
                "audience": {"audience": "customers/3552856345/audiences/341722377"},
            },
        }

    def _fake_search_theme_row(self):
        return {
            "campaign": {"id": "23566187470", "name": "9-PMax-AllLocations-Feb2026"},
            "assetGroup": {"id": "6673792593", "name": "QZ3 - Universal"},
            "assetGroupSignal": {
                "resourceName": "customers/3552856345/assetGroupSignals/6673792593~999",
                "searchTheme": {"text": "tesla parts sharjah"},
            },
        }

    def test_happy_path_audience_and_search_theme(self, fake_creds):
        runner = CliRunner()
        rows = [self._fake_audience_row(), self._fake_search_theme_row()]
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["pmax", "signals", "--campaign", "23566187470"])

        assert result.exit_code == 0, result.output
        assert "audience" in result.output
        assert "customers/3552856345/audiences/341722377" in result.output
        assert "search_theme" in result.output
        assert "tesla parts sharjah" in result.output

    def test_campaign_filter_appears_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["pmax", "signals", "--campaign", "42"])

        query = mock_gaql.call_args[0][1]
        assert "campaign.id = 42" in query
        assert "FROM asset_group_signal" in query
        assert "asset_group_signal.audience.audience" in query
        assert "asset_group_signal.search_theme.text" in query

    def test_json_shape(self, fake_creds):
        rows = [self._fake_audience_row()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["pmax", "signals", "--campaign", "1", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == rows

    def test_empty_results_exits_zero(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]):
            result = runner.invoke(cli, ["pmax", "signals", "--campaign", "1"])

        assert result.exit_code == 0, result.output
        assert "(no results)" in result.output


# ═══════════════════════════════════════════════════════════════════════════
# gads pmax listing-groups
# ═══════════════════════════════════════════════════════════════════════════

class TestPmaxListingGroups:
    def _fake_root_row(self):
        return {
            "campaign": {"id": "23159635175", "name": "Talas Shop Products"},
            "assetGroup": {"id": "6621445229", "name": "Talas Shop Products"},
            "assetGroupListingGroupFilter": {
                "resourceName": "customers/3552856345/assetGroupListingGroupFilters/6621445229~13151266817",
                "id": "13151266817", "type": "UNIT_INCLUDED", "listingSource": "SHOPPING",
            },
        }

    def _fake_brand_row(self):
        return {
            "campaign": {"id": "23159635175", "name": "Talas Shop Products"},
            "assetGroup": {"id": "6621445229", "name": "Talas Shop Products"},
            "assetGroupListingGroupFilter": {
                "id": "999", "type": "UNIT_INCLUDED", "listingSource": "SHOPPING",
                "caseValue": {"productBrand": {"value": "Tesla"}},
                "parentListingGroupFilter": "customers/3552856345/assetGroupListingGroupFilters/6621445229~13151266817",
            },
        }

    def test_happy_path_catch_all_and_dimension(self, fake_creds):
        runner = CliRunner()
        rows = [self._fake_root_row(), self._fake_brand_row()]
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["pmax", "listing-groups", "--campaign", "23159635175"])

        assert result.exit_code == 0, result.output
        assert "(everything else)" in result.output
        assert "brand:Tesla" in result.output

    def test_campaign_filter_appears_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["pmax", "listing-groups", "--campaign", "77"])

        query = mock_gaql.call_args[0][1]
        assert "campaign.id = 77" in query
        assert "FROM asset_group_listing_group_filter" in query
        assert "asset_group_listing_group_filter.case_value.product_category.category_id" in query

    def test_json_shape(self, fake_creds):
        rows = [self._fake_root_row()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["pmax", "listing-groups", "--campaign", "1", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == rows

    def test_empty_results_exits_zero(self, fake_creds):
        """A feed-only PMax campaign with no Shopping partitions legitimately
        returns zero listing-group-filter rows — must exit 0, not error."""
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]):
            result = runner.invoke(cli, ["pmax", "listing-groups", "--campaign", "23566187470"])

        assert result.exit_code == 0, result.output
        assert "(no results)" in result.output


# ═══════════════════════════════════════════════════════════════════════════
# gads pmax search-terms
# ═══════════════════════════════════════════════════════════════════════════

class TestPmaxSearchTerms:
    def _fake_row(self):
        return {
            "campaignSearchTermInsight": {
                "campaignId": "23566187470", "categoryLabel": "talas tesla auto parts sajaa sharjah",
                "id": "4483469149570669568",
            },
            "metrics": {"impressions": "71", "clicks": "2", "conversions": 2, "conversionsValue": 2},
        }

    def test_campaign_is_required(self, fake_creds):
        """The resource only accepts a single-campaign filter (verified live:
        REQUIRES_FILTER_BY_SINGLE_RESOURCE without it) — --campaign must be
        required at the CLI level, with a clear error when omitted."""
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql") as mock_gaql:
            result = runner.invoke(cli, ["pmax", "search-terms"])

        assert result.exit_code != 0
        assert "--campaign" in result.output or "campaign" in result.output.lower()
        mock_gaql.assert_not_called()

    def test_happy_path_renders_table(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row()]):
            result = runner.invoke(cli, ["pmax", "search-terms", "--campaign", "23566187470"])

        assert result.exit_code == 0, result.output
        assert "talas tesla auto parts sajaa sharjah" in result.output
        assert "4483469149570669568" in result.output

    def test_campaign_filter_and_no_cost_metric_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["pmax", "search-terms", "--campaign", "23566187470"])

        query = mock_gaql.call_args[0][1]
        assert "campaign_search_term_insight.campaign_id = 23566187470" in query
        assert "FROM campaign_search_term_insight" in query
        assert "cost_micros" not in query  # no cost metric on this resource
        assert "segments.date" in query

    def test_default_days_is_30_ending_yesterday(self, fake_creds):
        """Default window matches the report_geo/keyword_search_terms convention:
        never same-day data (attribution lag)."""
        from datetime import datetime, timedelta
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["pmax", "search-terms", "--campaign", "1"])

        query = mock_gaql.call_args[0][1]
        d_to = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        d_from = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
        assert d_to in query
        assert d_from in query

    def test_days_option_overrides_default(self, fake_creds):
        from datetime import datetime, timedelta
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["pmax", "search-terms", "--campaign", "1", "--days", "7"])

        query = mock_gaql.call_args[0][1]
        d_from = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")
        assert d_from in query

    def test_json_shape(self, fake_creds):
        rows = [self._fake_row()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["pmax", "search-terms", "--campaign", "1", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == rows

    def test_empty_results_exits_zero(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]):
            result = runner.invoke(cli, ["pmax", "search-terms", "--campaign", "1"])

        assert result.exit_code == 0, result.output
        assert "(no results)" in result.output
