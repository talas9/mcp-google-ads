"""Offline tests for the two-step OAuth flow (--callback-url / --code).

Covers:
  - gads_lib.auth.parse_callback_url — URL/code parsing, error paths
  - gads_lib.auth.exchange_authorization_code — calls InstalledAppFlow with
    the right redirect_uri, no local server involved
  - `gads auth login --callback-url` — reuses the same scope-regression
    guard and atomic token-write path as the browser flow

ALL calls to Google are mocked — no live API calls, no local server started,
no OAuth code/token values are ever asserted or printed.
"""
import json

import pytest
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from gads_lib.auth import parse_callback_url, exchange_authorization_code
from gads_lib.cli import cli

CANONICAL_SCOPES = [
    "https://www.googleapis.com/auth/adwords",
    "https://www.googleapis.com/auth/business.manage",
    "https://www.googleapis.com/auth/content",
    "https://www.googleapis.com/auth/analytics.readonly",
    "https://www.googleapis.com/auth/analytics.edit",
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/datamanager",
]


# =============================================================================
# parse_callback_url — URL/code parsing
# =============================================================================


class TestParseCallbackUrl:
    def test_extracts_code_state_and_ignores_scope_param(self):
        url = (
            "http://localhost:9090/?state=xyz123&"
            "code=4%2F0AVGzR1abcDEF&scope=https://www.googleapis.com/auth/adwords"
        )
        code, state = parse_callback_url(url)
        assert code == "4/0AVGzR1abcDEF"
        assert state == "xyz123"

    def test_accepts_bare_code_with_no_url_scheme(self):
        code, state = parse_callback_url("4/0AVGzR1abcDEF")
        assert code == "4/0AVGzR1abcDEF"
        assert state is None

    def test_strips_surrounding_whitespace(self):
        code, _state = parse_callback_url("  4/0AVGzR1abcDEF  \n")
        assert code == "4/0AVGzR1abcDEF"

    def test_missing_code_param_raises_clear_error(self):
        with pytest.raises(ValueError, match="no 'code' parameter"):
            parse_callback_url("http://localhost:9090/?state=xyz123&scope=adwords")

    def test_empty_input_raises_clear_error(self):
        with pytest.raises(ValueError, match="empty"):
            parse_callback_url("")

    def test_none_input_raises_clear_error(self):
        with pytest.raises(ValueError, match="empty"):
            parse_callback_url(None)

    def test_oauth_error_param_surfaces_the_error_reason(self):
        url = "http://localhost:9090/?state=xyz&error=access_denied"
        with pytest.raises(ValueError, match="access_denied"):
            parse_callback_url(url)

    def test_oauth_error_includes_description_when_present(self):
        url = (
            "http://localhost:9090/?state=xyz&error=access_denied"
            "&error_description=User+denied+access"
        )
        with pytest.raises(ValueError, match="User denied access"):
            parse_callback_url(url)


# =============================================================================
# exchange_authorization_code — calls InstalledAppFlow correctly
# =============================================================================


class TestExchangeAuthorizationCode:
    def test_builds_flow_with_client_secret_and_scopes_then_fetches_token(self, tmp_path):
        client_secret = tmp_path / "client_secret.json"
        client_secret.write_text("{}")

        fake_flow = MagicMock()
        fake_creds = MagicMock()
        fake_flow.credentials = fake_creds

        with patch(
            "google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file",
            return_value=fake_flow,
        ) as mock_from_secrets:
            result = exchange_authorization_code(
                client_secret, "4/0Acode", "http://localhost:9090/", CANONICAL_SCOPES
            )

        mock_from_secrets.assert_called_once_with(str(client_secret), CANONICAL_SCOPES)
        assert fake_flow.redirect_uri == "http://localhost:9090/"
        fake_flow.fetch_token.assert_called_once_with(code="4/0Acode")
        assert result is fake_creds

    def test_uses_canonical_scopes_when_scopes_arg_omitted(self, tmp_path):
        client_secret = tmp_path / "client_secret.json"
        client_secret.write_text("{}")
        fake_flow = MagicMock()

        with patch(
            "google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file",
            return_value=fake_flow,
        ) as mock_from_secrets:
            exchange_authorization_code(client_secret, "code123", "http://localhost:9090/")

        args, _kwargs = mock_from_secrets.call_args
        assert args[1] == CANONICAL_SCOPES

    def test_redirect_uri_is_reconstructed_from_the_given_port_style_uri(self, tmp_path):
        """A different port must produce a different redirect_uri passed to the flow —
        this is what makes --port matter for the two-step exchange."""
        client_secret = tmp_path / "client_secret.json"
        client_secret.write_text("{}")
        fake_flow = MagicMock()

        with patch(
            "google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file",
            return_value=fake_flow,
        ):
            exchange_authorization_code(client_secret, "code123", "http://localhost:8888/")

        assert fake_flow.redirect_uri == "http://localhost:8888/"


# =============================================================================
# `gads auth login --callback-url` — integration through the CLI command
# =============================================================================


def _make_creds(scopes, refresh_token="rt-123", token_json=None):
    creds = MagicMock()
    creds.scopes = scopes
    creds.refresh_token = refresh_token
    creds.to_json.return_value = token_json or json.dumps({
        "token": "at-1", "refresh_token": refresh_token, "scopes": scopes,
    })
    return creds


class TestAuthLoginCallbackUrlIntegration:
    """`gads auth login --callback-url` must skip the local server, exchange
    the code, and then go through the SAME scope-regression guard + atomic
    write path the browser flow uses."""

    def _setup(self, tmp_path):
        creds_dir = tmp_path / "credentials"
        creds_dir.mkdir()
        client_secret = creds_dir / "client_secret.json"
        client_secret.write_text("{}")
        token_path = creds_dir / "google-ads-oauth.json"
        return token_path

    def test_full_scope_grant_writes_the_token_without_starting_a_local_server(self, tmp_path):
        token_path = self._setup(tmp_path)
        runner = CliRunner()
        creds = _make_creds(CANONICAL_SCOPES)
        callback_url = "http://localhost:9090/?state=abc&code=4%2F0Acode&scope=x"

        with patch("gads_lib.cli.CREDS_PATH", token_path), \
             patch("gads_lib.auth.exchange_authorization_code", return_value=creds) as mock_exchange, \
             patch("google_auth_oauthlib.flow.InstalledAppFlow.run_local_server") as mock_local_server:
            result = runner.invoke(cli, ["auth", "login", "--callback-url", callback_url])

        assert result.exit_code == 0, result.output
        mock_local_server.assert_not_called()
        mock_exchange.assert_called_once()
        call_args = mock_exchange.call_args
        # code, redirect_uri (matching the default --port 9090)
        assert call_args[0][1] == "4/0Acode"
        assert call_args[0][2] == "http://localhost:9090/"
        assert token_path.exists()
        assert "4/0Acode" not in result.output  # the raw code value is never printed

    def test_bare_code_flag_is_equivalent_to_callback_url(self, tmp_path):
        token_path = self._setup(tmp_path)
        runner = CliRunner()
        creds = _make_creds(CANONICAL_SCOPES)

        with patch("gads_lib.cli.CREDS_PATH", token_path), \
             patch("gads_lib.auth.exchange_authorization_code", return_value=creds) as mock_exchange:
            result = runner.invoke(cli, ["auth", "login", "--code", "4/0Acode"])

        assert result.exit_code == 0, result.output
        assert mock_exchange.call_args[0][1] == "4/0Acode"
        assert token_path.exists()

    def test_missing_code_in_callback_url_errors_clearly_and_leaves_token_untouched(self, tmp_path):
        token_path = self._setup(tmp_path)
        token_path.write_text(json.dumps({"scopes": CANONICAL_SCOPES, "refresh_token": "old"}))
        runner = CliRunner()

        with patch("gads_lib.cli.CREDS_PATH", token_path):
            result = runner.invoke(
                cli, ["auth", "login", "--force", "--callback-url", "http://localhost:9090/?state=abc"]
            )

        assert result.exit_code != 0
        assert "no 'code' parameter" in result.output
        assert "NOT modified" in result.output
        # token content is unchanged
        assert json.loads(token_path.read_text())["refresh_token"] == "old"

    def test_scope_regression_guard_refuses_a_five_of_seven_scope_result(self, tmp_path):
        """The scope guard must apply identically on the --callback-url path:
        a token that comes back with only 5 of the 7 canonical scopes must be
        refused (existing token preserved) unless --allow-partial is passed."""
        token_path = self._setup(tmp_path)
        prior = {"scopes": CANONICAL_SCOPES, "refresh_token": "old-rt"}
        token_path.write_text(json.dumps(prior))

        partial_scopes = CANONICAL_SCOPES[:5]  # missing 2 of 7
        creds = _make_creds(partial_scopes)
        runner = CliRunner()
        callback_url = "http://localhost:9090/?state=abc&code=4%2F0Acode"

        with patch("gads_lib.cli.CREDS_PATH", token_path), \
             patch("gads_lib.auth.exchange_authorization_code", return_value=creds):
            result = runner.invoke(
                cli, ["auth", "login", "--force", "--callback-url", callback_url]
            )

        assert result.exit_code != 0
        assert "REFUSING TO REPLACE" in result.output
        # existing (7-scope) token must be untouched
        assert json.loads(token_path.read_text()) == prior

    def test_allow_partial_overrides_the_scope_guard_on_callback_url_path(self, tmp_path):
        token_path = self._setup(tmp_path)
        token_path.write_text(json.dumps({"scopes": CANONICAL_SCOPES, "refresh_token": "old-rt"}))

        partial_scopes = CANONICAL_SCOPES[:5]
        creds = _make_creds(partial_scopes, refresh_token="new-rt")
        runner = CliRunner()
        callback_url = "http://localhost:9090/?state=abc&code=4%2F0Acode"

        with patch("gads_lib.cli.CREDS_PATH", token_path), \
             patch("gads_lib.auth.exchange_authorization_code", return_value=creds):
            result = runner.invoke(
                cli, ["auth", "login", "--force", "--allow-partial", "--callback-url", callback_url]
            )

        assert result.exit_code == 0, result.output
        written = json.loads(token_path.read_text())
        assert written["scopes"] == partial_scopes

    def test_print_url_only_never_calls_exchange_or_touches_the_token(self, tmp_path):
        token_path = self._setup(tmp_path)
        runner = CliRunner()

        with patch("gads_lib.cli.CREDS_PATH", token_path), \
             patch("gads_lib.auth.exchange_authorization_code") as mock_exchange, \
             patch(
                 "google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file",
                 return_value=MagicMock(**{
                     "authorization_url.return_value": ("https://accounts.google.com/o/oauth2/auth?x=1", "state1"),
                 }),
             ):
            result = runner.invoke(cli, ["auth", "login", "--print-url-only"])

        assert result.exit_code == 0, result.output
        assert "https://accounts.google.com" in result.output
        assert "--callback-url" in result.output
        mock_exchange.assert_not_called()
        assert not token_path.exists()
