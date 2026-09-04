"""
Offline pytest coverage for the `gads batch-mutate` partial-failure fix.

Covers:
  - ads_batch_mutate() sends "partialFailure": true in the request body.
  - parse_partial_failure() correctly splits a mixed success/failure response
    into a per-operation list.
  - `gads batch-mutate` CLI: all-succeed exits 0; partial failure prints each
    failed operation and exits non-zero; --json output is parseable and
    carries the per-operation list + failed_count.

ALL HTTP calls are mocked — no live API calls.
Run from the gads-cli root:
    cd /home/talas9/talas-ads/gads-cli && python -m pytest tests/test_batch_mutate.py -v
"""

import json
from unittest.mock import MagicMock, patch

import pytest


def _partial_failure_response(total_ops, failed_indices):
    """Build a realistic customers.googleAds:mutate partial-failure response.

    `failed_indices` maps operation index -> error message. Succeeded indices
    get a placeholder mutateOperationResponse; failed indices get an empty
    `{}` entry (matching the real API's per-index alignment).
    """
    mutate_operation_responses = []
    for i in range(total_ops):
        if i in failed_indices:
            mutate_operation_responses.append({})
        else:
            mutate_operation_responses.append(
                {"campaignResult": {"resourceName": f"customers/1/campaigns/{i}"}}
            )

    errors = []
    for idx, msg in failed_indices.items():
        errors.append({
            "errorCode": {"mutateError": "MUTATE_NOT_ALLOWED"},
            "message": msg,
            "location": {"fieldPathElements": [{"fieldName": "mutateOperations", "index": idx}]},
        })

    response = {"mutateOperationResponses": mutate_operation_responses}
    if failed_indices:
        response["partialFailureError"] = {
            "code": 3,
            "message": f"{len(failed_indices)} operation(s) failed.",
            "details": [
                {
                    "@type": "type.googleapis.com/google.ads.googleads.v24.errors.GoogleAdsFailure",
                    "errors": errors,
                }
            ],
        }
    return response


# ═══════════════════════════════════════════════════════════════════════════
# ads_batch_mutate() — request body must set partialFailure: true
# ═══════════════════════════════════════════════════════════════════════════

class TestAdsBatchMutatePartialFailureFlag:

    def test_request_body_sets_partial_failure_true(self, fake_creds):
        from gads_lib.ads import ads_batch_mutate

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.text = json.dumps({"mutateOperationResponses": []})
        fake_resp.json.return_value = {"mutateOperationResponses": []}

        with patch("requests.Session.request", return_value=fake_resp) as mock_req:
            ads_batch_mutate(fake_creds, [{"campaignOperation": {"create": {}}}])

        sent_body = mock_req.call_args[1]["json"]
        assert sent_body["partialFailure"] is True
        assert sent_body["mutateOperations"] == [{"campaignOperation": {"create": {}}}]


# ═══════════════════════════════════════════════════════════════════════════
# parse_partial_failure() — pure response-parsing unit tests
# ═══════════════════════════════════════════════════════════════════════════

class TestParsePartialFailure:

    def test_all_succeed(self):
        from gads_lib.ads import parse_partial_failure

        response = _partial_failure_response(3, {})
        out, unattributed = parse_partial_failure(response, 3)

        assert len(out) == 3
        assert all(op["ok"] for op in out)
        assert [op["index"] for op in out] == [0, 1, 2]
        assert out[0]["result"] == {"campaignResult": {"resourceName": "customers/1/campaigns/0"}}
        assert unattributed == []

    def test_3_of_5_fail(self):
        from gads_lib.ads import parse_partial_failure

        failed = {1: "duplicate name", 2: "invalid budget", 4: "resource not found"}
        response = _partial_failure_response(5, failed)
        out, unattributed = parse_partial_failure(response, 5)

        assert len(out) == 5
        ok_flags = [op["ok"] for op in out]
        assert ok_flags == [True, False, False, True, False]
        assert out[1]["error_message"] == "duplicate name"
        assert out[2]["error_message"] == "invalid budget"
        assert out[4]["error_message"] == "resource not found"
        # succeeded ops still carry their result
        assert out[0]["result"] is not None
        assert out[3]["result"] is not None
        assert unattributed == []

    def test_custom_results_key(self):
        """parse_partial_failure works with a different aligned-results key,
        e.g. "results" for :uploadClickConversions / single-resource :mutate."""
        from gads_lib.ads import parse_partial_failure

        response = {
            "results": [{"gclid": "abc"}, {}],
            "partialFailureError": {
                "details": [{
                    "errors": [{
                        "message": "invalid gclid",
                        "location": {"fieldPathElements": [{"fieldName": "operations", "index": 1}]},
                    }]
                }]
            },
        }
        out, unattributed = parse_partial_failure(response, 2, results_key="results")
        assert out[0]["ok"] is True
        assert out[1]["ok"] is False
        assert out[1]["error_message"] == "invalid gclid"
        assert unattributed == []

    def test_unindexed_error_is_surfaced_as_unattributed_not_silently_ok(self):
        """A request-level error whose location.fieldPathElements carries no
        'index' cannot be tied to an operation -- it must come back via
        unattributed_errors, and every attributed op still reports its own
        (here: all-ok) status. Silently discarding it would let a caller
        report success on a batch that actually failed at the request level.
        """
        from gads_lib.ads import parse_partial_failure

        response = {
            "mutateOperationResponses": [
                {"campaignResult": {"resourceName": "customers/1/campaigns/0"}},
            ],
            "partialFailureError": {
                "message": "1 operation(s) failed.",
                "details": [{
                    "errors": [{
                        "message": "internal error, no operation attributable",
                        "location": {"fieldPathElements": [{"fieldName": "mutateOperations"}]},
                    }]
                }],
            },
        }
        out, unattributed = parse_partial_failure(response, 1)
        assert out == [{"index": 0, "ok": True, "result": {"campaignResult": {"resourceName": "customers/1/campaigns/0"}}}]
        assert unattributed == ["internal error, no operation attributable"]

    def test_string_index_is_coerced_not_dropped(self):
        """The REST API may serialise the index as a string ("1" instead of 1).
        Without int() coercion, `1 in {"1": ...}` is False, so the error would
        never match its operation and index 1 would wrongly report ok:True."""
        from gads_lib.ads import parse_partial_failure

        response = {
            "mutateOperationResponses": [{}, {}],
            "partialFailureError": {
                "details": [{
                    "errors": [{
                        "message": "duplicate name",
                        "location": {"fieldPathElements": [{"fieldName": "mutateOperations", "index": "1"}]},
                    }]
                }]
            },
        }
        out, unattributed = parse_partial_failure(response, 2)
        assert out[0]["ok"] is True
        assert out[1]["ok"] is False
        assert out[1]["error_message"] == "duplicate name"
        assert unattributed == []

    def test_duplicate_index_collects_all_messages_not_last_write_wins(self):
        """Two errors attributed to the same index must both survive -- not
        have the second silently overwrite the first."""
        from gads_lib.ads import parse_partial_failure

        response = {
            "mutateOperationResponses": [{}],
            "partialFailureError": {
                "details": [{
                    "errors": [
                        {
                            "message": "duplicate name",
                            "location": {"fieldPathElements": [{"fieldName": "mutateOperations", "index": 0}]},
                        },
                        {
                            "message": "invalid budget",
                            "location": {"fieldPathElements": [{"fieldName": "mutateOperations", "index": 0}]},
                        },
                    ]
                }]
            },
        }
        out, unattributed = parse_partial_failure(response, 1)
        assert out[0]["ok"] is False
        assert "duplicate name" in out[0]["error_message"]
        assert "invalid budget" in out[0]["error_message"]
        assert unattributed == []


# ═══════════════════════════════════════════════════════════════════════════
# `gads batch-mutate` CLI
# ═══════════════════════════════════════════════════════════════════════════

class TestBatchMutateCli:

    def test_all_succeed_exits_0(self):
        from click.testing import CliRunner
        from gads_lib.cli import cli

        ops = [{"campaignOperation": {"create": {"name": f"c{i}"}}} for i in range(2)]
        response = _partial_failure_response(2, {})

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.ads_batch_mutate", return_value=response) as mock_mutate, \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["batch-mutate", json.dumps(ops), "--yes", "--json"],
            )

        assert result.exit_code == 0, result.output
        assert mock_mutate.called
        parsed = json.loads(result.output)
        assert parsed["status"] == "success"
        assert parsed["failed_count"] == 0
        assert len(parsed["operations"]) == 2
        assert all(op["ok"] for op in parsed["operations"])

    def test_3_of_5_fail_prints_each_failure_and_exits_nonzero(self):
        from click.testing import CliRunner
        from gads_lib.cli import cli
        from gads_lib.output import EXIT_CODES

        ops = [{"campaignOperation": {"create": {"name": f"c{i}"}}} for i in range(5)]
        failed = {0: "duplicate name", 2: "invalid budget", 3: "resource not found"}
        response = _partial_failure_response(5, failed)

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.ads_batch_mutate", return_value=response), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["batch-mutate", json.dumps(ops), "--yes"],
            )

        assert result.exit_code == EXIT_CODES["API"], result.output
        # each failed index and its message must appear in the human output
        assert "duplicate name" in result.output
        assert "invalid budget" in result.output
        assert "resource not found" in result.output
        assert "[0]" in result.output
        assert "[2]" in result.output
        assert "[3]" in result.output
        assert "3/5" in result.output

    def test_json_output_on_partial_failure_is_parseable_with_per_op_list(self):
        from click.testing import CliRunner
        from gads_lib.cli import cli
        from gads_lib.output import EXIT_CODES

        ops = [{"campaignOperation": {"create": {"name": f"c{i}"}}} for i in range(3)]
        failed = {1: "duplicate name"}
        response = _partial_failure_response(3, failed)

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.ads_batch_mutate", return_value=response), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["batch-mutate", json.dumps(ops), "--yes", "--json"],
            )

        assert result.exit_code == EXIT_CODES["API"], result.output
        parsed = json.loads(result.output)
        assert parsed["status"] == "partial_failure"
        assert parsed["failed_count"] == 1
        assert parsed["total"] == 3
        ops_out = parsed["operations"]
        assert len(ops_out) == 3
        assert ops_out[1]["ok"] is False
        assert ops_out[1]["error_message"] == "duplicate name"
        assert ops_out[0]["ok"] is True
        assert ops_out[2]["ok"] is True

    def test_request_body_actually_contains_partial_failure_true_end_to_end(self, fake_creds):
        """No mocking of ads_batch_mutate itself -- mock requests.request at
        the HTTP boundary to prove the CLI's real call path sets the flag."""
        from click.testing import CliRunner
        from gads_lib.cli import cli

        ops = [{"campaignOperation": {"create": {"name": "c0"}}}]
        fake_resp = MagicMock()
        fake_resp.status_code = 200
        response = _partial_failure_response(1, {})
        fake_resp.text = json.dumps(response)
        fake_resp.json.return_value = response

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)), \
             patch("requests.Session.request", return_value=fake_resp) as mock_req:
            result = runner.invoke(
                cli,
                ["batch-mutate", json.dumps(ops), "--yes", "--json"],
            )

        assert result.exit_code == 0, result.output
        sent_body = mock_req.call_args[1]["json"]
        assert sent_body["partialFailure"] is True

    def test_unattributed_error_fails_even_when_every_indexed_op_reports_ok(self):
        """An error with no operation index (a request-level failure) must
        block a 'success' report even though every attributed op is ok --
        this is the P1-2 bug: without this, batch_mutate_cmd would print
        success and exit 0 on a batch that actually failed."""
        from click.testing import CliRunner
        from gads_lib.cli import cli
        from gads_lib.output import EXIT_CODES

        ops = [{"campaignOperation": {"create": {"name": "c0"}}}]
        response = {
            "mutateOperationResponses": [
                {"campaignResult": {"resourceName": "customers/1/campaigns/0"}},
            ],
            "partialFailureError": {
                "message": "1 operation(s) failed.",
                "details": [{
                    "errors": [{
                        "message": "internal error, no operation attributable",
                        "location": {"fieldPathElements": [{"fieldName": "mutateOperations"}]},
                    }]
                }],
            },
        }

        runner = CliRunner()
        with patch("gads_lib.cli.get_credentials", return_value=MagicMock()), \
             patch("gads_lib.cli.ads_batch_mutate", return_value=response), \
             patch("gads_lib.cli.get_db", side_effect=SystemExit(1)):
            result = runner.invoke(
                cli,
                ["batch-mutate", json.dumps(ops), "--yes", "--json"],
            )

        assert result.exit_code == EXIT_CODES["API"], result.output
        parsed = json.loads(result.output)
        assert parsed["status"] == "partial_failure"
        assert parsed["unattributed_errors"] == ["internal error, no operation attributable"]
        # the one attributed op is still reported as ok -- it's the
        # unattributed error alone that must trip the failure.
        assert parsed["operations"][0]["ok"] is True
