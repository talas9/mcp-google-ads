"""
Offline pytest suite for the Google Ads API v25 / v25.1 feature additions:

  gads campaign goals      — unified-goals schema (replaces removed v24
                              campaign_lifecycle_goal / customer_lifecycle_goal)
  gads campaign migration  — v25.1 AI Max auto-migration schedule fields
  gads conversion perf     — extended with metrics.original_conversion_value

ALL HTTP calls are mocked at the run_gaql boundary (patch
"gads_lib.cli.run_gaql"), matching the repo's CLI-level test convention
(see tests/test_pmax.py).

Run from the gads-cli root:
    cd /home/talas9/talas-ads/gads-cli && python -m pytest tests/test_v25_features.py -v
"""

import json
from unittest.mock import patch

from click.testing import CliRunner

from gads_lib.cli import cli


# ═══════════════════════════════════════════════════════════════════════════
# gads campaign goals
# ═══════════════════════════════════════════════════════════════════════════

class TestCampaignGoals:
    def _fake_goal_row(self):
        return {
            "goal": {
                "resourceName": "customers/3552856345/goals/6547439698",
                "goalId": "6547439698",
                "goalType": "NEW_CUSTOMER_ACQUISITION",
                "optimizationEligibility": "ELIGIBLE",
                "newCustomerAcquisitionGoalSettings": {"valueSettings": {"additionalValue": 7}},
            }
        }

    def _fake_config_row(self):
        return {
            "campaign": {
                "resourceName": "customers/3552856345/campaigns/23556258912",
                "name": "9-Search-HighIntent-Feb2026",
                "id": "23556258912",
            },
            "campaignGoalConfig": {
                "resourceName": "customers/3552856345/campaignGoalConfigs/23556258912~6547439698",
                "goal": "customers/3552856345/goals/6547439698",
                "goalType": "NEW_CUSTOMER_ACQUISITION",
                "campaignNewCustomerAcquisitionSettings": {"targetOption": "TARGET_ALL"},
            },
        }

    def test_happy_path_renders_both_sections(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql",
                   side_effect=[[self._fake_goal_row()], [self._fake_config_row()]]) as mock_gaql:
            result = runner.invoke(cli, ["campaign", "goals"])

        assert result.exit_code == 0, result.output
        assert "Account goals" in result.output
        assert "Campaign goal configs" in result.output
        assert "6547439698" in result.output
        assert "NEW_CUSTOMER_ACQUISITION" in result.output
        assert "ELIGIBLE" in result.output
        assert "7" in result.output  # additional_value
        assert "9-Search-HighIntent-Feb2026" in result.output
        assert "TARGET_ALL" in result.output
        assert mock_gaql.call_count == 2

    def test_field_list_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", side_effect=[[], []]) as mock_gaql:
            runner.invoke(cli, ["campaign", "goals"])

        assert mock_gaql.call_count == 2
        goal_query = mock_gaql.call_args_list[0][0][1]
        config_query = mock_gaql.call_args_list[1][0][1]

        assert "goal.goal_type" in goal_query
        assert "goal.new_customer_acquisition_goal_settings.value_settings.additional_value" in goal_query
        assert "FROM goal" in goal_query

        assert "goal.retention_goal_settings.value_settings.value_multiplier" in goal_query
        assert "goal.retention_goal_settings.value_settings.additional_value" in goal_query
        assert "goal.loyalty_retention_goal_settings.value_settings.value_multiplier" in goal_query

        assert "campaign_goal_config.campaign_new_customer_acquisition_settings.target_option" in config_query
        assert "campaign_goal_config.campaign_retention_settings.target_option" in config_query
        assert ("campaign_goal_config.campaign_loyalty_retention_settings"
                ".enable_bid_adjustments_for_loyalty_members") in config_query
        assert "FROM campaign_goal_config" in config_query

    def test_missing_nested_settings_no_crash(self, fake_creds):
        """Goal/config rows with absent nested settings blocks must not KeyError."""
        sparse_goal = {"goal": {"resourceName": "customers/3552856345/goals/1", "goalId": "1",
                                 "goalType": "RETENTION", "optimizationEligibility": "ELIGIBLE"}}
        sparse_config = {"campaign": {"name": "Bare Campaign", "id": "2"},
                          "campaignGoalConfig": {"goal": "customers/3552856345/goals/1",
                                                  "goalType": "RETENTION"}}
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", side_effect=[[sparse_goal], [sparse_config]]):
            result = runner.invoke(cli, ["campaign", "goals"])

        assert result.exit_code == 0, result.output
        assert "RETENTION" in result.output
        assert "Bare Campaign" in result.output

    def test_retention_goal_settings_are_rendered(self, fake_creds):
        """A RETENTION goal must render its own settings block, not em-dashes.

        Regression guard: the first implementation read only
        newCustomerAcquisitionGoalSettings, so RETENTION and LOYALTY_RETENTION
        goals silently showed "-" even though the API returned real values.
        """
        retention_goal = {"goal": {
            "resourceName": "customers/3552856345/goals/55", "goalId": "55",
            "goalType": "RETENTION", "optimizationEligibility": "ELIGIBLE",
            "retentionGoalSettings": {"valueSettings": {
                "valueMultiplier": 1.75, "additionalValue": 42}},
        }}
        retention_config = {
            "campaign": {"name": "Retention Campaign", "id": "77"},
            "campaignGoalConfig": {
                "goal": "customers/3552856345/goals/55", "goalType": "RETENTION",
                "campaignRetentionSettings": {
                    "targetOption": "TARGET_ALL",
                    "valueSettingsOverride": {"valueMultiplier": 2.5,
                                               "additionalValue": 13}},
            },
        }
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql",
                   side_effect=[[retention_goal], [retention_config]]):
            result = runner.invoke(cli, ["campaign", "goals"])

        assert result.exit_code == 0, result.output
        assert "1.75" in result.output      # goal retention value_multiplier
        assert "42" in result.output        # goal retention additional_value
        assert "TARGET_ALL" in result.output  # from campaignRetentionSettings
        assert "2.5" in result.output       # config override value_multiplier
        assert "13" in result.output        # config override additional_value

    def test_loyalty_retention_settings_are_rendered(self, fake_creds):
        """A LOYALTY_RETENTION goal renders its block and the bid-adjust flag."""
        loyalty_goal = {"goal": {
            "resourceName": "customers/3552856345/goals/66", "goalId": "66",
            "goalType": "LOYALTY_RETENTION", "optimizationEligibility": "ELIGIBLE",
            "loyaltyRetentionGoalSettings": {
                "valueSettings": {"valueMultiplier": 3.25}},
        }}
        loyalty_config = {
            "campaign": {"name": "Loyalty Campaign", "id": "88"},
            "campaignGoalConfig": {
                "goal": "customers/3552856345/goals/66",
                "goalType": "LOYALTY_RETENTION",
                "campaignLoyaltyRetentionSettings": {
                    "enableBidAdjustmentsForLoyaltyMembers": True,
                    "valueSettingsOverride": {"valueMultiplier": 4.5}},
            },
        }
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql",
                   side_effect=[[loyalty_goal], [loyalty_config]]):
            result = runner.invoke(cli, ["campaign", "goals"])

        assert result.exit_code == 0, result.output
        assert "3.25" in result.output   # goal loyalty value_multiplier
        assert "4.5" in result.output    # config override value_multiplier
        assert "True" in result.output   # enable_bid_adjustments_for_loyalty_members
        assert "—" in result.output  # em-dash for missing numeric values

    def test_zero_rows_prints_none(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", side_effect=[[], []]):
            result = runner.invoke(cli, ["campaign", "goals"])

        assert result.exit_code == 0, result.output
        assert result.output.count("(none)") == 2

    def test_json_shape(self, fake_creds):
        goal_rows = [self._fake_goal_row()]
        config_rows = [self._fake_config_row()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", side_effect=[goal_rows, config_rows]):
            result = runner.invoke(cli, ["campaign", "goals", "--json"])

        assert result.exit_code == 0, result.output
        parsed = json.loads(result.output)
        assert parsed == {"goals": goal_rows, "campaign_goal_configs": config_rows}


# ═══════════════════════════════════════════════════════════════════════════
# gads campaign migration
# ═══════════════════════════════════════════════════════════════════════════

class TestCampaignMigration:
    def _fake_row_scheduled(self):
        return {
            "campaign": {
                "id": "23556258912", "name": "9-Search-HighIntent-Feb2026", "status": "ENABLED",
                "advertisingChannelType": "SEARCH",
                "acaMigrationDateTime": "2026-10-01",
                "broadMatchMigrationDateTime": "2026-11-01",
            }
        }

    def _fake_row_unscheduled(self):
        return {
            "campaign": {
                "id": "23566187470", "name": "9-PMax-AllLocations-Feb2026", "status": "ENABLED",
                "advertisingChannelType": "PERFORMANCE_MAX",
            }
        }

    def test_happy_path_renders_table(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row_scheduled()]):
            result = runner.invoke(cli, ["campaign", "migration"])

        assert result.exit_code == 0, result.output
        assert "9-Search-HighIntent-Feb2026" in result.output
        assert "2026-10-01" in result.output
        assert "2026-11-01" in result.output
        assert "No AI Max auto-migration" not in result.output

    def test_field_list_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["campaign", "migration"])

        query = mock_gaql.call_args[0][1]
        assert "campaign.aca_migration_date_time" in query
        assert "campaign.broad_match_migration_date_time" in query
        assert "FROM campaign" in query

    def test_missing_migration_fields_no_crash_and_healthy_message(self, fake_creds):
        """When no campaign has either migration field set (the normal state
        today), the command must not crash and must print the healthy-state
        informational line, not a warning."""
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row_unscheduled()]):
            result = runner.invoke(cli, ["campaign", "migration"])

        assert result.exit_code == 0, result.output
        assert "9-PMax-AllLocations-Feb2026" in result.output
        assert "—" in result.output
        assert "No AI Max auto-migration is currently scheduled for any campaign." in result.output

    def test_json_shape(self, fake_creds):
        rows = [self._fake_row_unscheduled()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["campaign", "migration", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == rows


# ═══════════════════════════════════════════════════════════════════════════
# gads conversion perf — extended with metrics.original_conversion_value
# ═══════════════════════════════════════════════════════════════════════════

class TestConversionPerfOriginalValue:
    def _fake_row(self):
        return {
            "segments": {"conversionActionName": "WhatsApp Click"},
            "metrics": {
                "conversions": 10, "allConversions": 12,
                "conversionsValue": 500.0, "originalConversionValue": 450.0,
            },
        }

    def test_happy_path_renders_orig_value_column(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[self._fake_row()]):
            result = runner.invoke(cli, ["conversion", "perf", "-d", "30"])

        assert result.exit_code == 0, result.output
        assert "orig_value" in result.output
        assert "WhatsApp Click" in result.output
        assert "500.00" in result.output
        assert "450.00" in result.output
        # existing columns still present
        assert "all_conv" in result.output

    def test_field_list_in_gaql(self, fake_creds):
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[]) as mock_gaql:
            runner.invoke(cli, ["conversion", "perf"])

        query = mock_gaql.call_args[0][1]
        assert "metrics.original_conversion_value" in query
        # existing fields still present (added column, not a replacement)
        assert "metrics.conversions_value" in query
        assert "metrics.all_conversions" in query
        assert "segments.conversion_action_name" in query

    def test_missing_original_value_no_crash(self, fake_creds):
        """Rows lacking originalConversionValue must not crash and default to 0."""
        sparse_row = {
            "segments": {"conversionActionName": "GBP Call"},
            "metrics": {"conversions": 3, "allConversions": 3, "conversionsValue": 100.0},
        }
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=[sparse_row]):
            result = runner.invoke(cli, ["conversion", "perf"])

        assert result.exit_code == 0, result.output
        assert "GBP Call" in result.output
        assert "0.00" in result.output

    def test_json_shape(self, fake_creds):
        rows = [self._fake_row()]
        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=fake_creds), \
             patch("gads_lib.cli.run_gaql", return_value=rows):
            result = runner.invoke(cli, ["conversion", "perf", "--json"])

        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == rows
