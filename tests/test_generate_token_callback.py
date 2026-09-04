"""Offline tests for generate_token.py's --callback-url / --code path.

Verifies the script-level two-step flow shares the same
gads_lib.auth.exchange_authorization_code / parse_callback_url helpers as
`gads auth login --callback-url`, skips the local server entirely, and
surfaces a clear error when no code can be parsed. No live API calls, no
local server, no OAuth code/token values are ever asserted or printed.
"""
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, ".")
import generate_token  # noqa: E402


@pytest.fixture
def token_paths(tmp_path, monkeypatch):
    creds_dir = tmp_path / "credentials"
    creds_dir.mkdir()
    client_secret = creds_dir / "client_secret.json"
    client_secret.write_text("{}")
    token_output = creds_dir / "google-ads-oauth.json"

    monkeypatch.setattr(generate_token, "CLIENT_SECRET", client_secret)
    monkeypatch.setattr(generate_token, "CREDENTIALS_DIR", creds_dir)
    monkeypatch.setattr(generate_token, "TOKEN_OUTPUT", token_output)
    monkeypatch.setattr(generate_token, "AUTH_URL_FILE", creds_dir / ".oauth-auth-url.txt")
    return client_secret, token_output


class TestGenerateTokenCallbackUrl:
    def test_callback_url_writes_token_without_local_server(self, token_paths, monkeypatch):
        _client_secret, token_output = token_paths
        creds = MagicMock()
        creds.scopes = ["https://www.googleapis.com/auth/adwords"]
        creds.to_json.return_value = json.dumps({"token": "at-1"})

        monkeypatch.setattr(sys, "argv", [
            "generate_token.py", "--callback-url",
            "http://localhost:9090/?state=abc&code=4%2F0Acode",
        ])

        with patch.object(generate_token, "exchange_authorization_code", return_value=creds) as mock_exchange, \
             patch("google_auth_oauthlib.flow.InstalledAppFlow.run_local_server") as mock_local_server:
            rc = generate_token.main()

        assert rc == 0
        mock_local_server.assert_not_called()
        call_args = mock_exchange.call_args[0]
        assert call_args[1] == "4/0Acode"
        assert call_args[2] == "http://localhost:9090/"
        assert token_output.exists()

    def test_code_flag_uses_port_to_build_redirect_uri(self, token_paths, monkeypatch):
        _client_secret, token_output = token_paths
        creds = MagicMock()
        creds.scopes = []
        creds.to_json.return_value = "{}"

        monkeypatch.setattr(sys, "argv", [
            "generate_token.py", "--port", "8888", "--code", "4/0Acode",
        ])

        with patch.object(generate_token, "exchange_authorization_code", return_value=creds) as mock_exchange:
            rc = generate_token.main()

        assert rc == 0
        assert mock_exchange.call_args[0][2] == "http://localhost:8888/"
        assert token_output.exists()

    def test_missing_code_in_callback_url_errors_clearly(self, token_paths, monkeypatch, capsys):
        _client_secret, token_output = token_paths
        monkeypatch.setattr(sys, "argv", [
            "generate_token.py", "--callback-url", "http://localhost:9090/?state=abc",
        ])

        rc = generate_token.main()

        assert rc != 0
        assert not token_output.exists()
        out = capsys.readouterr().out
        assert "no 'code' parameter" in out
