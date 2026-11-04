# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""CLI entry point for the AgentCoreTIP client.

Usage:
    python -m agentcore_tip_client --help
    python -m agentcore_tip_client --token <jwt>
    python -m agentcore_tip_client --no-browser-login
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid

from .config import get_env
from .oidc import interactive_login
from .agent import AgentCoreTIPClient


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AgentCoreTIP client — OIDC login + agent invocation."
    )
    parser.add_argument(
        "--url",
        default=get_env("AGENT_URL", "http://127.0.0.1:8080/invocations"),
        help="Agent server URL. Env: AGENT_URL",
    )
    parser.add_argument(
        "--token",
        help="Post-MFA user JWT (skips browser login if provided). Env: USER_TOKEN",
    )
    parser.add_argument(
        "--no-browser-login",
        action="store_true",
        help="Prompt for a JWT instead of starting a browser login.",
    )
    parser.add_argument(
        "--idp",
        choices=["entra-id", "okta", "cognito"],
        default=get_env("IDP"),
        help="Identity provider. Env: IDP",
    )
    parser.add_argument(
        "--oidc-discovery-url",
        help="Entra ID OIDC discovery URL. Env: OIDC_DISCOVERY_URL",
    )
    parser.add_argument(
        "--oidc-client-id",
        help="OIDC client ID. Env: OIDC_CLIENT_ID",
    )
    parser.add_argument(
        "--oidc-redirect-uri",
        help="Loopback redirect URI. Env: OIDC_REDIRECT_URI",
    )
    parser.add_argument(
        "--oidc-scopes",
        default=get_env("OIDC_SCOPES"),
        help="OIDC scopes. Env: OIDC_SCOPES",
    )
    parser.add_argument(
        "--oidc-prompt",
        default=get_env("OIDC_PROMPT", "login"),
        help="OIDC prompt. Env: OIDC_PROMPT",
    )
    parser.add_argument(
        "--oidc-timeout-seconds",
        type=int,
        default=int(get_env("OIDC_TIMEOUT_SECONDS", "300")),
        help="Browser login timeout. Env: OIDC_TIMEOUT_SECONDS",
    )
    parser.add_argument(
        "--user-id",
        default=get_env("USER_ID", "mfa-test-user"),
        help="End-user identifier. Env: USER_ID",
    )
    parser.add_argument(
        "--session-id",
        default=get_env("SESSION_ID") or f"vt-{uuid.uuid4()}",
        help="Session ID. Env: SESSION_ID",
    )
    parser.add_argument(
        "--database",
        default="lfdb",
        help="Athena database name.",
    )
    parser.add_argument(
        "--table",
        default="clients",
        help="Athena table name.",
    )
    parser.add_argument(
        "--workgroup",
        default="idc-wg",
        help="Athena workgroup.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Query result limit.",
    )
    parser.add_argument(
        "--query",
        help="Explicit Athena SQL query.",
    )
    args = parser.parse_args()

    # Step 1: Get a valid JWT
    import getpass
    token = args.token or get_env("USER_TOKEN")
    if token:
        token = token.strip()
    elif args.no_browser_login:
        token = getpass.getpass("Paste post-MFA user JWT (input hidden): ").strip()
    else:
        token = interactive_login(
            idp=args.idp,
            client_id=args.oidc_client_id,
            redirect_uri=args.oidc_redirect_uri,
            scopes=args.oidc_scopes,
            oidc_discovery_url=args.oidc_discovery_url,
            oidc_prompt=args.oidc_prompt,
            timeout_seconds=args.oidc_timeout_seconds,
        )

    if not token:
        print("Error: A post-MFA user JWT is required.", file=sys.stderr)
        return 2

    # Step 2: Build payload and invoke agent
    payload = {
        "database": args.database,
        "table": args.table,
        "workgroup": args.workgroup,
        "limit": args.limit,
    }
    if args.query:
        payload["query"] = args.query

    client = AgentCoreTIPClient(url=args.url)
    result = client.invoke(
        token=token,
        payload=payload,
        user_id=args.user_id,
        session_id=args.session_id,
    )

    if result.error:
        print(f"Error: {result.error}", file=sys.stderr)
        return 1

    print(json.dumps(result.data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
