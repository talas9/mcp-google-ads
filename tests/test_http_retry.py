"""
Offline pytest tests for gads_lib.http's retry/backoff/session layer and the
--json error-envelope fix (run_gaql -> request_json forwarding via click context).

ALL HTTP calls are mocked — no live API calls.
Run from the gads-cli root:
    cd /home/talas9/talas-ads/gads-cli && python -m pytest tests/test_http_retry.py -v
"""

import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import MagicMock, patch

import click
import pytest
import requests
from click.testing import CliRunner

from gads_lib import http
from gads_lib.output import EXIT_CODES


def _resp(status_code, text="{}", headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {}
    try:
        resp.json.return_value = json.loads(text) if text else {}
    except json.JSONDecodeError:
        resp.json.side_effect = json.JSONDecodeError("mock", text, 0)
    return resp


@pytest.fixture(autouse=True)
def _fresh_session(monkeypatch):
    """Each test starts with a clean lazily-created session."""
    monkeypatch.setattr(http, "_session", None, raising=False)


@pytest.fixture
def no_sleep(monkeypatch):
    """Capture (rather than actually perform) every backoff sleep."""
    calls = []
    monkeypatch.setattr(http.time, "sleep", lambda s: calls.append(s))
    return calls


class TestRetryOnTransientStatus:
    """Retries on 429/500/502/503/504, gives up after max attempts."""

    def test_retries_on_503_then_succeeds(self, no_sleep):
        err = _resp(503, "Service Unavailable")
        ok = _resp(200, "{}")

        with patch("requests.Session.request", side_effect=[err, err, ok]) as mock_req:
            result = http.request_json("GET", "https://example.com/api")

        assert result == {}
        assert mock_req.call_count == 3
        # Two sleeps (before the 2nd and 3rd attempts), backoff increasing.
        assert len(no_sleep) == 2
        assert no_sleep[0] < no_sleep[1]

    def test_gives_up_after_max_attempts_exits_with_api_code(self, no_sleep):
        err = _resp(503, "Service Unavailable")

        with patch("requests.Session.request", return_value=err) as mock_req:
            with pytest.raises(SystemExit) as exc_info:
                http.request_json("GET", "https://example.com/api")

        assert exc_info.value.code == EXIT_CODES["API"]
        # Default max attempts is 4 -- never sleeps after the final attempt.
        assert mock_req.call_count == 4
        assert len(no_sleep) == 3


class TestRetryAfterHeader:
    """A Retry-After header (seconds or HTTP-date) drives the backoff wait."""

    def test_respects_retry_after_seconds(self, no_sleep):
        err = _resp(503, "unavailable", headers={"Retry-After": "5"})
        ok = _resp(200, "{}")

        with patch("requests.Session.request", side_effect=[err, ok]):
            http.request_json("GET", "https://example.com/api")

        assert no_sleep == [5.0]

    def test_retry_after_capped_at_max_wait(self, no_sleep):
        err = _resp(503, "unavailable", headers={"Retry-After": "9999"})
        ok = _resp(200, "{}")

        with patch("requests.Session.request", side_effect=[err, ok]):
            http.request_json("GET", "https://example.com/api")

        assert no_sleep == [60.0]

    def test_parse_retry_after_http_date_form(self):
        future = datetime.now(timezone.utc) + timedelta(seconds=30)
        http_date = format_datetime(future, usegmt=True)

        seconds = http._parse_retry_after(http_date)

        assert seconds is not None
        assert 20 <= seconds <= 31

    def test_parse_retry_after_unparseable_returns_none(self):
        assert http._parse_retry_after("not-a-valid-value") is None
        assert http._parse_retry_after(None) is None


class TestNonIdempotentMutateRetries:
    """POST calls to mutate-style colon-RPC URLs must not be retried on HTTP errors."""

    MUTATE_URL = "https://googleads.googleapis.com/v24/customers/123/campaigns:mutate"

    def test_mutate_post_not_retried_on_503(self, no_sleep):
        err = _resp(503, "unavailable")

        with patch("requests.Session.request", return_value=err) as mock_req:
            with pytest.raises(SystemExit):
                http.request_json("POST", self.MUTATE_URL, json_body={})

        assert mock_req.call_count == 1
        assert no_sleep == []

    def test_mutate_post_retried_on_connection_error(self, no_sleep):
        ok = _resp(200, "{}")

        with patch(
            "requests.Session.request",
            side_effect=[requests.exceptions.ConnectionError("boom"), ok],
        ) as mock_req:
            result = http.request_json("POST", self.MUTATE_URL, json_body={})

        assert result == {}
        assert mock_req.call_count == 2
        assert len(no_sleep) == 1

    def test_mutate_post_not_retried_on_read_timeout(self, no_sleep):
        with patch(
            "requests.Session.request",
            side_effect=requests.exceptions.ReadTimeout("timed out"),
        ) as mock_req:
            with pytest.raises(requests.exceptions.ReadTimeout):
                http.request_json("POST", self.MUTATE_URL, json_body={})

        assert mock_req.call_count == 1
        assert no_sleep == []

    def test_mutate_post_IS_retried_on_429(self, no_sleep):
        """429 means the server throttled the request without processing it.

        Retrying therefore cannot double-apply the mutation, so it must be
        retried even for a non-idempotent call -- unlike an ambiguous 5xx.
        """
        ok = _resp(200, "{}")

        with patch(
            "requests.Session.request",
            side_effect=[_resp(429, "rate limited"), ok],
        ) as mock_req:
            result = http.request_json("POST", self.MUTATE_URL, json_body={})

        assert result == {}
        assert mock_req.call_count == 2
        assert len(no_sleep) == 1

    def test_mutate_post_429_honours_retry_after(self, no_sleep):
        ok = _resp(200, "{}")

        with patch(
            "requests.Session.request",
            side_effect=[_resp(429, "slow down", headers={"Retry-After": "7"}), ok],
        ):
            http.request_json("POST", self.MUTATE_URL, json_body={})

        assert no_sleep == [7.0]

    def test_get_and_search_stream_are_idempotent(self):
        assert http._is_idempotent("GET", self.MUTATE_URL) is True
        assert http._is_idempotent(
            "POST",
            "https://googleads.googleapis.com/v24/customers/123/googleAds:searchStream",
        ) is True
        assert http._is_idempotent("POST", self.MUTATE_URL) is False


class TestEnvConfig:
    """GADS_HTTP_RETRIES / GADS_HTTP_TIMEOUT are read at call time."""

    def test_retries_env_override_honoured(self, monkeypatch, no_sleep):
        monkeypatch.setenv("GADS_HTTP_RETRIES", "2")
        err = _resp(503, "unavailable")

        with patch("requests.Session.request", return_value=err) as mock_req:
            with pytest.raises(SystemExit):
                http.request_json("GET", "https://example.com/api")

        assert mock_req.call_count == 2

    def test_retries_env_clamped_to_at_least_one(self, monkeypatch, no_sleep):
        monkeypatch.setenv("GADS_HTTP_RETRIES", "0")
        err = _resp(503, "unavailable")

        with patch("requests.Session.request", return_value=err) as mock_req:
            with pytest.raises(SystemExit):
                http.request_json("GET", "https://example.com/api")

        assert mock_req.call_count == 1

    def test_timeout_env_override_honoured(self, monkeypatch):
        monkeypatch.setenv("GADS_HTTP_TIMEOUT", "7.5")
        ok = _resp(200, "{}")

        with patch("requests.Session.request", return_value=ok) as mock_req:
            http.request_json("GET", "https://example.com/api")

        assert mock_req.call_args.kwargs["timeout"] == 7.5

    def test_explicit_timeout_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("GADS_HTTP_TIMEOUT", "7.5")
        ok = _resp(200, "{}")

        with patch("requests.Session.request", return_value=ok) as mock_req:
            http.request_json("GET", "https://example.com/api", timeout=12)

        assert mock_req.call_args.kwargs["timeout"] == 12

    def test_no_env_defaults_to_30s_timeout_and_4_retries(self):
        ok = _resp(200, "{}")

        with patch("requests.Session.request", return_value=ok) as mock_req:
            http.request_json("GET", "https://example.com/api")

        assert mock_req.call_args.kwargs["timeout"] == 30.0


class TestSessionReuse:
    """A single requests.Session is created lazily and reused across calls."""

    def test_get_session_returns_same_object(self):
        first = http._get_session()
        second = http._get_session()
        assert first is second
        assert isinstance(first, requests.Session)

    def test_session_reused_across_request_json_calls(self):
        ok = _resp(200, "{}")
        seen_sessions = []

        original_request = requests.Session.request

        def spy(self, *args, **kwargs):
            seen_sessions.append(self)
            return ok

        with patch("requests.Session.request", spy):
            http.request_json("GET", "https://example.com/a")
            http.request_json("GET", "https://example.com/b")

        assert len(seen_sessions) == 2
        assert seen_sessions[0] is seen_sessions[1]
        assert seen_sessions[0] is http._get_session()


class TestJsonErrorWithoutExplicitAsJson:
    """A2 regression: run_gaql() forwards no as_json, but --json must still
    produce a JSON error envelope on stdout instead of a human stderr message.
    """

    def test_run_gaql_error_under_click_json_flag_emits_parseable_json(self, fake_creds):
        from gads_lib.ads import run_gaql

        err = _resp(400, "bad request")

        @click.command()
        @click.option("--json", "as_json", is_flag=True)
        def fake_query(as_json):
            run_gaql(fake_creds, "SELECT campaign.id FROM campaign")

        runner = CliRunner()
        with patch("requests.Session.request", return_value=err):
            result = runner.invoke(fake_query, ["--json"])

        assert result.exit_code == EXIT_CODES["API"]
        assert result.output.strip(), "expected JSON on stdout, got nothing"
        data = json.loads(result.output.strip().splitlines()[-1])
        assert "error" in data

    def test_run_gaql_error_without_json_flag_stays_human_readable(self, fake_creds):
        """Sanity check: without --json, the old human-readable path still runs
        (no accidental JSON leaking when the flag wasn't passed)."""
        from gads_lib.ads import run_gaql

        err = _resp(400, "bad request")

        @click.command()
        @click.option("--json", "as_json", is_flag=True)
        def fake_query(as_json):
            run_gaql(fake_creds, "SELECT campaign.id FROM campaign")

        runner = CliRunner()
        with patch("requests.Session.request", return_value=err):
            result = runner.invoke(fake_query, [])

        assert result.exit_code == EXIT_CODES["API"]
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.output.strip())

    def test_wants_json_true_without_click_context(self):
        assert http._wants_json(True) is True

    def test_wants_json_false_without_click_context_or_flag(self):
        # No active click context here -- must not raise, must return False.
        assert http._wants_json(False) is False


class TestGa4AdminCallsRetryViaSharedHelper:
    """ga4.py's list/create/delete key-event calls route through
    gads_lib.http._send_with_retry, so they inherit retry + session reuse.
    """

    def test_list_key_events_retries_on_503(self, fake_creds, no_sleep):
        from gads_lib.ga4 import list_key_events

        err = _resp(503, "unavailable")
        ok = _resp(200, '{"keyEvents": []}')

        with patch("requests.Session.request", side_effect=[err, ok]) as mock_req:
            result = list_key_events("271773771", fake_creds)

        assert result == []
        assert mock_req.call_count == 2
        assert len(no_sleep) == 1
