"""MFA-capable local client for testing the AgentCore-compatible Athena runner.

The client initiates an OIDC authorization-code + PKCE login, opens the browser,
lets the identity provider enforce MFA, captures the local redirect, and sends
the resulting ID token to the AgentCore-TIP-MCP-Broker agent as the inbound user token.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser

from agentcore_tip.core.config import build_oidc_settings


class _OidcCallbackHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AgentCoreTIPOidcCallback/0.1"

    def do_GET(self) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        self.server.authorization_response = {key: values[0] for key, values in query.items()}  # type: ignore[attr-defined]
        if "error" in query:
            message = f"OIDC login failed: {query.get('error_description', query['error'])[0]}"
            status = 400
        else:
            message = "Authentication complete. You can close this browser tab and return to the terminal."
            status = 200
        body = f"<html><body><h2>{message}</h2></body></html>".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def _json_request(url: str, data: dict[str, str] | None = None, headers: dict[str, str] | None = None) -> dict:
    encoded = None
    request_headers = headers or {}
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        request_headers = {"Content-Type": "application/x-www-form-urlencoded", **request_headers}
    request = urllib.request.Request(url, data=encoded, headers=request_headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii").rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return verifier, challenge


def _listen_for_callback(redirect_uri: str, timeout_seconds: int) -> dict[str, str]:
    parsed = urllib.parse.urlparse(redirect_uri)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Automatic MFA login requires a loopback redirect URI, for example http://127.0.0.1:8765/callback.")
    if parsed.port is None:
        raise ValueError("The redirect URI must include an explicit port.")

    server = http.server.HTTPServer((parsed.hostname, parsed.port), _OidcCallbackHandler)
    server.authorization_response = {}
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    deadline = time.monotonic() + timeout_seconds
    while thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.2)
    server.server_close()
    if thread.is_alive():
        raise TimeoutError(f"Timed out waiting {timeout_seconds} seconds for OIDC redirect.")
    response = server.authorization_response
    if response.get("error"):
        raise RuntimeError(response.get("error_description") or response["error"])
    if not response.get("code"):
        raise RuntimeError("OIDC redirect did not include an authorization code.")
    return response


def _interactive_oidc_login(args: argparse.Namespace) -> str:
    config_settings = build_oidc_settings(args.config_file, args.idp)
    client_id = args.oidc_client_id or config_settings["client_id"]
    redirect_uri = args.oidc_redirect_uri or config_settings["redirect_uri"]
    scopes = args.oidc_scopes or config_settings["scopes"]
    idp = config_settings["idp"]

    if idp == "entra-id":
        # Entra ID exposes a standard OIDC discovery document; resolve the
        # authorization/token endpoints from it rather than hardcoding them.
        discovery_url = args.oidc_discovery_url or config_settings["discovery_url"]
        if not discovery_url:
            raise ValueError("Set OIDC_DISCOVERY_URL (or entra_tenant_id in the config file), or pass --oidc-discovery-url.")
        metadata = _json_request(discovery_url)
        authorization_endpoint = metadata["authorization_endpoint"]
        token_endpoint = metadata["token_endpoint"]
    else:
        # Okta and Cognito hosted-UI endpoints are derived directly from the
        # provider's base URL/domain (matching aws-oidc-tip's okta_auth.py /
        # cognito_auth.py), no discovery document lookup required.
        authorization_endpoint = args.oidc_authorization_endpoint or config_settings["authorization_endpoint"]
        token_endpoint = args.oidc_token_endpoint or config_settings["token_endpoint"]
        if not authorization_endpoint or not token_endpoint:
            if idp == "okta":
                raise ValueError("Set OKTA_URL (or okta_url in the config file), e.g. https://dev-12345.okta.com/oauth2/default.")
            raise ValueError("Set COGNITO_DOMAIN (or cognito_domain in the config file), e.g. https://your-domain.auth.us-east-1.amazoncognito.com.")

    if not client_id:
        raise ValueError("Set OIDC_CLIENT_ID (or the provider-specific *_client_id config field), or pass --oidc-client-id.")

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": args.oidc_prompt,
    }
    authorization_url = f"{authorization_endpoint}?{urllib.parse.urlencode(params)}"
    print(f"Opening browser for MFA login ({idp})...")
    if not webbrowser.open(authorization_url):
        print(f"Open this URL manually:\n{authorization_url}")
    callback = _listen_for_callback(redirect_uri, args.oidc_timeout_seconds)
    if callback.get("state") != state:
        raise RuntimeError("OIDC state mismatch.")
    token_response = _json_request(
        token_endpoint,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": callback["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    id_token = token_response.get("id_token")
    if not id_token:
        raise RuntimeError("OIDC token response did not include an id_token.")
    return str(id_token)


def _read_token(args: argparse.Namespace) -> str:
    token = args.token or os.environ.get("USER_TOKEN")
    if token:
        return token.strip()
    if args.no_browser_login:
        return getpass.getpass("Paste post-MFA user JWT (input hidden): ").strip()
    return _interactive_oidc_login(args)


def main() -> int:
    parser = argparse.ArgumentParser(description="Invoke AgentCore-TIP-MCP-Broker Athena LF test agent with a post-MFA user token.")
    parser.add_argument("--url", default=os.environ.get("AGENT_URL", "http://127.0.0.1:8080/invocations"))
    parser.add_argument("--token", help="Post-MFA user JWT. If omitted, the client starts an OIDC browser/MFA flow.")
    parser.add_argument("--no-browser-login", action="store_true", help="Do not start OIDC login; prompt for an existing post-MFA JWT.")
    parser.add_argument(
        "--idp",
        choices=["entra-id", "okta", "cognito"],
        default=os.environ.get("IDP"),
        help="Identity provider for the browser MFA login. Env: IDP. "
        "Falls back to the config file's 'idp' field, then 'entra-id'.",
    )
    parser.add_argument("--oidc-discovery-url", help="Entra ID OIDC discovery URL. Env: OIDC_DISCOVERY_URL")
    parser.add_argument("--oidc-authorization-endpoint", help="Okta/Cognito authorize endpoint override. Env: derived from okta_url/cognito_domain.")
    parser.add_argument("--oidc-token-endpoint", help="Okta/Cognito token endpoint override. Env: derived from okta_url/cognito_domain.")
    parser.add_argument("--oidc-client-id", help="Public/native OIDC client ID. Env: OIDC_CLIENT_ID")
    parser.add_argument("--oidc-redirect-uri", help="Loopback redirect URI registered on the OIDC client.")
    parser.add_argument("--config-file", help="aws-oidc-tip-compatible JSON config file. Env: CONFIG_FILE")
    parser.add_argument("--oidc-scopes", default=os.environ.get("OIDC_SCOPES"), help="Defaults to the selected IdP's standard scopes if omitted.")
    parser.add_argument("--oidc-prompt", default=os.environ.get("OIDC_PROMPT", "login"))
    parser.add_argument("--oidc-timeout-seconds", type=int, default=int(os.environ.get("OIDC_TIMEOUT_SECONDS", "300")))
    parser.add_argument("--user-id", default=os.environ.get("USER_ID", "mfa-test-user"))
    parser.add_argument("--session-id", default=os.environ.get("SESSION_ID") or f"mfa-test-{uuid.uuid4()}")
    parser.add_argument("--database", default="lfdb")
    parser.add_argument("--table", default="clients")
    parser.add_argument("--workgroup", default="idc-wg")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--query", help="Optional explicit Athena SQL query.")
    parser.add_argument("--output-location", help="Optional s3:// output location if the workgroup does not enforce one.")
    args = parser.parse_args()

    token = _read_token(args)
    if not token:
        print("A post-MFA user JWT is required.", file=sys.stderr)
        return 2

    payload = {
        "database": args.database,
        "table": args.table,
        "workgroup": args.workgroup,
        "limit": args.limit,
    }
    if args.query:
        payload["query"] = args.query
    if args.output_location:
        payload["output_location"] = args.output_location

    request = urllib.request.Request(
        args.url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "x-amzn-bedrock-agentcore-runtime-session-id": args.session_id,
            "X-Amzn-Bedrock-AgentCore-Runtime-User-Id": args.user_id,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            response_json = json.loads(response.read().decode("utf-8"))
            print(json.dumps(response_json, indent=2))
            if "query_execution_id" not in response_json:
                print(
                    "Response did not include query_execution_id. This request did not hit the Athena/Lake Formation test runner.",
                    file=sys.stderr,
                )
                print(
                    "Start the runner with: python -m uvicorn agents.athena_lf_agent:app --host 0.0.0.0 --port 8080",
                    file=sys.stderr,
                )
                return 1
            return 0
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8"), file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Could not reach agent at {args.url}. Start it with: python -m uvicorn agents.athena_lf_agent:app --host 0.0.0.0 --port 8080", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1
    except ConnectionResetError as exc:
        print("The agent closed the connection while processing the request.", file=sys.stderr)
        print("Restart the Athena/Lake Formation runner in the foreground and check its traceback/log output.", file=sys.stderr)
        print("Expected runner: python -m uvicorn agents.athena_lf_agent:app --host 0.0.0.0 --port 8080", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        print("The HTTP connection failed while reading the agent response.", file=sys.stderr)
        print("Restart the Athena/Lake Formation runner in the foreground and check its traceback/log output.", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
