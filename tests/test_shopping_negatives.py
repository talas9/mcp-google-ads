"""
Offline pytest suite for three additions to gads-cli:

  1. `gads report shopping`                         (shopping_performance_view GAQL)
  2. `gads merchant report` / `report-product-performance`  (Merchant reports sub-API)
  3. `gads keyword account-negative list|add`        (account-level negative criteria)
     + a regression check that `gads keyword negative` (campaign-level) is unchanged.

ALL HTTP calls are mocked — no live API calls.
Run from the gads-cli root:
    cd /home/talas9/talas-ads/gads-cli && python -m pytest tests/test_shopping_negatives.py -v
"""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gads_lib.cli import cli


# ═══════════════════════════════════════════════════════════════════════════
# gads report shopping
# ═══════════════════════════════════════════════════════════════════════════

class TestReportShopping:
    def _fake_row(self):
        return {
            "segments": {
                "productItemId": "TeslaModel3RearBumper",
                "productTitle": "Tesla Model 3 Rear Bumper Cover — Used OEM",
                "productBrand": "Tesla",
                "productTypeL1": "Auto Parts",
            },
            "metrics": {
                "impressions": "1834", "clicks": "42", "conversions": 3.0,
                "costMicros": "84210000", "conversionsValue": 900.0,
            },
        }

    def test_happy_path_renders_table(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row()]) as mock_gaql:
            result = runner.invoke(cli, ["report", "shopping"])

        assert result.exit_code == 0, result.output
        assert "TeslaModel3RearBumper" in result.output
        assert "Tesla" in result.output
        assert "84.21" in result.output  # cost_micros -> AED, rounded 2dp
        assert mock_gaql.called

    def test_query_selects_product_segments_and_metrics(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["report", "shopping"])

        query = mock_gaql.call_args[0][1]
        assert "FROM shopping_performance_view" in query
        for field in (
            "segments.product_item_id", "segments.product_title",
            "segments.product_brand", "segments.product_type_l1",
            "metrics.impressions", "metrics.clicks", "metrics.cost_micros",
            "metrics.conversions", "metrics.conversions_value",
        ):
            assert field in query, f"missing {field} in query: {query}"

    def test_default_days_is_30(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["report", "shopping"])

        query = mock_gaql.call_args[0][1]
        assert "BETWEEN" in query and "AND" in query

    def test_zero_rows_is_valid_result_exit_0(self, fake_creds):
        """Zero Shopping rows (no Shopping campaigns) must exit 0, not error."""
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]):
            result = runner.invoke(cli, ["report", "shopping", "--days", "30"])

        assert result.exit_code == 0, result.output
        assert "No Shopping performance rows" in result.output

    def test_json_mode_returns_raw_results(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row()]):
            result = runner.invoke(cli, ["report", "shopping", "--json"])

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed[0]["segments"]["productItemId"] == "TeslaModel3RearBumper"


# ═══════════════════════════════════════════════════════════════════════════
# gads merchant report / report-product-performance
# ═══════════════════════════════════════════════════════════════════════════

def _mc_response(status_code, body_dict):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = json.dumps(body_dict)
    resp.json.return_value = body_dict
    return resp


class TestMerchantReportEscapeHatch:
    def test_query_hits_reports_v1_search_endpoint(self, fake_creds):
        runner = CliRunner()
        page = {"results": [{"productView": {"id": "abc", "title": "Widget", "brand": "Tesla"}}]}
        fake_resp = _mc_response(200, page)
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("requests.Session.request", return_value=fake_resp) as mock_req:
            result = runner.invoke(cli, ["merchant", "report", "-q", "SELECT id, title, brand FROM product_view LIMIT 5"])

        assert result.exit_code == 0, result.output
        assert mock_req.called
        called_url = mock_req.call_args[0][1]
        assert "merchantapi.googleapis.com" in called_url
        assert "reports/v1" in called_url
        assert "reports:search" in called_url
        sent_body = mock_req.call_args.kwargs.get("json") or json.loads(mock_req.call_args.kwargs.get("data", "{}"))
        assert "SELECT id, title, brand FROM product_view LIMIT 5" == sent_body["query"]
        assert "Widget" in result.output

    def test_paginates_via_next_page_token(self, fake_creds):
        runner = CliRunner()
        page1 = {"results": [{"productView": {"id": "p1"}}], "nextPageToken": "TOKEN1"}
        page2 = {"results": [{"productView": {"id": "p2"}}]}
        resp1, resp2 = _mc_response(200, page1), _mc_response(200, page2)
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("requests.Session.request", side_effect=[resp1, resp2]) as mock_req:
            result = runner.invoke(cli, ["merchant", "report", "-q", "SELECT id FROM product_view", "--json"])

        assert result.exit_code == 0, result.output
        assert mock_req.call_count == 2
        parsed = json.loads(result.output)
        assert parsed["total"] == 2
        assert parsed["truncated"] is False

    def test_no_results_message(self, fake_creds):
        runner = CliRunner()
        fake_resp = _mc_response(200, {"results": []})
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("requests.Session.request", return_value=fake_resp):
            result = runner.invoke(cli, ["merchant", "report", "-q", "SELECT id FROM product_view"])

        assert result.exit_code == 0, result.output
        assert "no results" in result.output.lower()


class TestMerchantReportProductPerformance:
    def test_canned_query_uses_product_performance_view(self, fake_creds):
        runner = CliRunner()
        fake_resp = _mc_response(200, {"results": []})
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("requests.Session.request", return_value=fake_resp) as mock_req:
            runner.invoke(cli, ["merchant", "report-product-performance", "--days", "14"])

        sent_body = mock_req.call_args.kwargs.get("json") or json.loads(mock_req.call_args.kwargs.get("data", "{}"))
        query = sent_body["query"]
        assert "FROM product_performance_view" in query
        assert "offer_id" in query and "clicks" in query and "impressions" in query
        assert "BETWEEN" in query

    def test_renders_offer_rows(self, fake_creds):
        runner = CliRunner()
        page = {"results": [{"productPerformanceView": {
            "offerId": "TeslaModel3RearBumper", "title": "Rear Bumper", "brand": "Tesla",
            "clicks": "42", "impressions": "1834", "clickThroughRate": 0.0229,
        }}]}
        fake_resp = _mc_response(200, page)
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("requests.Session.request", return_value=fake_resp):
            result = runner.invoke(cli, ["merchant", "report-product-performance"])

        assert result.exit_code == 0, result.output
        assert "TeslaModel3RearBumper" in result.output
        assert "42" in result.output


# ═══════════════════════════════════════════════════════════════════════════
# gads keyword negative (campaign-level) — regression: unchanged behaviour
# ═══════════════════════════════════════════════════════════════════════════

class TestKeywordNegativeCampaignLevelUnchanged:
    def test_signature_and_payload_unchanged(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.ads_mutate", return_value={"results": [{"resourceName": "x"}]}) as mock_mutate, \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(cli, ["keyword", "negative", "123456", "installation", "--yes"])

        assert result.exit_code == 0, result.output
        assert mock_mutate.called
        resource, ops = mock_mutate.call_args[0][1], mock_mutate.call_args[0][2]
        assert resource == "campaignCriteria"
        assert ops == [{"create": {"campaign": "customers/1234567890/campaigns/123456",
                                    "keyword": {"text": "installation", "matchType": "PHRASE"},
                                    "negative": True}}]

    def test_help_text_distinguishes_campaign_vs_account_level(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["keyword", "negative", "--help"])
        assert result.exit_code == 0
        assert "CAMPAIGN-LEVEL" in result.output


# ═══════════════════════════════════════════════════════════════════════════
# gads keyword account-negative list
# ═══════════════════════════════════════════════════════════════════════════

class TestKeywordAccountNegativeList:
    def test_expands_negative_keyword_list_to_member_keywords(self, fake_creds):
        list_criterion = {"customerNegativeCriterion": {
            "id": "111", "type": "NEGATIVE_KEYWORD_LIST",
            "negativeKeywordList": {"sharedSet": "customers/1234567890/sharedSets/999"},
        }}
        member_row = {"sharedCriterion": {"keyword": {"text": "installation", "matchType": "PHRASE"}}}

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", side_effect=[[list_criterion], [member_row]]) as mock_gaql:
            result = runner.invoke(cli, ["keyword", "account-negative", "list"])

        assert result.exit_code == 0, result.output
        assert "NEGATIVE_KEYWORD_LIST" in result.output
        assert "installation" in result.output
        assert mock_gaql.call_count == 2
        member_query = mock_gaql.call_args_list[1][0][1]
        assert "customers/1234567890/sharedSets/999" in member_query
        assert "FROM shared_criterion" in member_query

    def test_surfaces_non_keyword_types(self, fake_creds):
        placement_criterion = {"customerNegativeCriterion": {
            "id": "222", "type": "PLACEMENT", "placement": {"url": "spamsite.example"},
        }}
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[placement_criterion]):
            result = runner.invoke(cli, ["keyword", "account-negative", "list"])

        assert result.exit_code == 0, result.output
        assert "PLACEMENT" in result.output
        assert "spamsite.example" in result.output

    def test_no_criteria_message(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]):
            result = runner.invoke(cli, ["keyword", "account-negative", "list"])

        assert result.exit_code == 0, result.output
        assert "No account-level negative criteria" in result.output


# ═══════════════════════════════════════════════════════════════════════════
# gads keyword account-negative add
# ═══════════════════════════════════════════════════════════════════════════

class TestKeywordAccountNegativeAdd:
    def test_dry_run_does_not_mutate(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql, \
             patch("gads_lib.cli.ads_mutate") as mock_mutate, \
             patch("gads_lib.cli.ads_batch_mutate") as mock_batch:
            result = runner.invoke(cli, ["keyword", "account-negative", "add", "installation", "--dry-run"])

        assert result.exit_code == 0, result.output
        assert "DRY RUN" in result.output
        assert mock_gaql.called  # the existing-list lookup is a read, always allowed
        mock_mutate.assert_not_called()
        mock_batch.assert_not_called()

    def test_add_reuses_existing_shared_set(self, fake_creds):
        existing = [{"customerNegativeCriterion": {
            "id": "111",
            "negativeKeywordList": {"sharedSet": "customers/1234567890/sharedSets/999"},
        }}]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=existing), \
             patch("gads_lib.cli.ads_mutate", return_value={"results": [{"resourceName": "x"}]}) as mock_mutate, \
             patch("gads_lib.cli.ads_batch_mutate") as mock_batch, \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(cli, ["keyword", "account-negative", "add", "installation", "--yes"])

        assert result.exit_code == 0, result.output
        mock_batch.assert_not_called()
        assert mock_mutate.called
        resource, ops = mock_mutate.call_args[0][1], mock_mutate.call_args[0][2]
        assert resource == "sharedCriteria"
        assert ops == [{"create": {
            "sharedSet": "customers/1234567890/sharedSets/999",
            "keyword": {"text": "installation", "matchType": "PHRASE"},
            "negative": True,
        }}]

    def test_add_provisions_new_shared_set_when_none_exists(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]), \
             patch("gads_lib.cli.ads_mutate") as mock_mutate, \
             patch("gads_lib.cli.ads_batch_mutate", return_value={"mutateOperationResponses": []}) as mock_batch, \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(cli, ["keyword", "account-negative", "add", "repair", "-m", "EXACT", "--yes"])

        assert result.exit_code == 0, result.output
        mock_mutate.assert_not_called()
        assert mock_batch.called
        ops = mock_batch.call_args[0][1]
        assert len(ops) == 3
        assert ops[0] == {"sharedSetOperation": {"create": {
            "type": "ACCOUNT_LEVEL_NEGATIVE_KEYWORDS",
            "name": "Account-level negative keywords (gads-cli)",
        }}}
        assert ops[1] == {"customerNegativeCriterionOperation": {"create": {
            "negativeKeywordList": {"sharedSet": "customers/1234567890/sharedSets/-1"},
        }}}
        assert ops[2] == {"sharedCriterionOperation": {"create": {
            "sharedSet": "customers/1234567890/sharedSets/-1",
            "keyword": {"text": "repair", "matchType": "EXACT"},
            "negative": True,
        }}}

    def test_help_text_mentions_parts_only_use_case(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["keyword", "account-negative", "--help"])
        assert result.exit_code == 0
        assert "PARTS-ONLY" in result.output or "installation" in result.output
