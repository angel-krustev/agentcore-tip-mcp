# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""OIDC browser login with PKCE and automatic callback handling."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import secrets
import threading
import time
import urllib.parse
import urllib.request
import webbrowser

from .config import build_oidc_settings


class OidcCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP handler that captures the OIDC authorization callback."""

    server_version = "AgentCoreTIPOidcCallback/0.1"

    def do_GET(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        self.server.authorization_response = {  # type: ignore[attr-defined]
            key: values[0] for key, values in query.items()
        }
        if "error" in query:
            message = f"OIDC login failed: {query.get('error_description', query['error'])[0]}"
            status = 400
        else:
            message = "Authentication complete. You can close this browser tab."
            status = 200
        body = f"<html><body><h2>{message}</h2></body></html>".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass  # Suppress default logging


def _json_request(url: str, data: dict[str, str] | None = None) -> dict:
    """Perform a POST/GET request and return JSON."""
    import json
    encoded = None
    headers: dict[str, str] = {}
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    request = urllib.request.Request(url, data=encoded, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code verifier and challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii").rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    return verifier, challenge


def listen_for_callback(redirect_uri: str, timeout_seconds: int = 300) -> dict[str, str]:
    """Start a local HTTP server and wait for the OIDC authorization callback."""
    parsed = urllib.parse.urlparse(redirect_uri)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError(
            "OIDC login requires a loopback redirect URI (e.g. http://127.0.0.1:8765/callback)."
        )
    if parsed.port is None:
        raise ValueError("The redirect URI must include an explicit port.")

    server = http.server.HTTPServer((parsed.hostname, parsed.port), OidcCallbackHandler)
    server.authorization_response = {}  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    deadline = time.monotonic() + timeout_seconds
    while thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.2)
    server.server_close()
    if thread.is_alive():
        raise TimeoutError(f"Timed out after {timeout_seconds}s waiting for OIDC redirect.")

    response = server.authorization_response  # type: ignore[attr-defined]
    if response.get("error"):
        raise RuntimeError(response.get("error_description") or response["error"])
    if not response.get("code"):
        raise RuntimeError("OIDC redirect did not include an authorization code.")
    return response


def interactive_login(
    idp: str | None = None,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    scopes: str | None = None,
    oidc_discovery_url: str | None = None,
    oidc_prompt: str = "login",
    timeout_seconds: int = 300,
) -> str:
    """
    Perform an interactive OIDC authorization-code + PKCE login.

    Opens the browser, lets the IdP enforce MFA, captures the callback,
    exchanges the authorization code for an ID token, and returns the token.

    Returns
    -------
    str
        The OIDC id_token (JWT) from the IdP.
    """
    settings = build_oidc_settings(idp)
    resolved_id = settings["idp"]
    resolved_cid = client_id or settings["client_id"]
    resolved_uri = redirect_uri or settings["redirect_uri"]
    resolved_scopes = scopes or settings["scopes"]

    if resolved_id == "entra-id":
        discovery_url = oidc_discovery_url or settings["discovery_url"]
        if not discovery_url:
            raise ValueError(
                "Set OIDC_DISCOVERY_URL (or ENTRA_TENANT_ID) for Entra ID login."
            )
        metadata = _json_request(discovery_url)
        auth_ep = metadata["authorization_endpoint"]
        token_ep = metadata["token_endpoint"]
    else:
        auth_ep = settings["authorization_endpoint"]
        token_ep = settings["token_endpoint"]
        if not auth_ep or not token_ep:
            raise ValueError(
                f"Cannot derive endpoints for {resolved_id}. Set OKTA_URL or COGNITO_DOMAIN."
            )

    if not resolved_cid:
        raise ValueError("Set OIDC_CLIENT_ID or pass client_id.")

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    params = {
        "client_id": resolved_cid,
        "response_type": "code",
        "redirect_uri": resolved_uri,
        "scope": resolved_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": oidc_prompt,
    }
    auth_url = f"{auth_ep}?{urllib.parse.urlencode(params)}"
    print(f"Opening browser for MFA login ({resolved_id})...")
    if not webbrowser.open(auth_url):
        print(f"Open this URL manually:\n{auth_url}")

    callback = listen_for_callback(resolved_uri, timeout_seconds)
    if callback.get("state") != state:
        raise RuntimeError("OIDC state mismatch.")

    token_resp = _json_request(
        token_ep,
        {
            "grant_type": "authorization_code",
            "client_id": resolved_cid,
            "code": callback["code"],
            "redirect_uri": resolved_uri,
            "code_verifier": verifier,
        },
    )
    id_token = token_resp.get("id_token")
    if not id_token:
        raise RuntimeError("OIDC token response did not include an id_token.")
    return str(id_token)
