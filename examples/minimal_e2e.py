"""Minimal-config end-to-end test: OIDC MFA login → AI agent invocation.

Requires zero manual configuration on the command line. All settings are
resolved automatically, in this order of precedence:

    1. .env file  (project root, next to this examples/ folder)
    2. JSON config file  (aws-oidc-tip compatible, path via CONFIG_FILE env var)
    3. Built-in defaults

The only thing the user types is the natural-language question.

Usage:
    # Minimal — everything loaded from .env / defaults:
    python examples/minimal_e2e.py "show me the top 5 customers by revenue"

    # Skip browser login (reuse a cached token or paste one):
    python examples/minimal_e2e.py "list tables" --no-browser-login

    # Override the agent URL (defaults to localhost:8081):
    python examples/minimal_e2e.py "who is the top buyer" --url http://host:9090/invocations
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# 0. Load .env from project root so OIDC + server settings are available
#    Tries multiple strategies since MSYS Git Bash may report __file__ as
#    /c/... paths rather than native Windows paths.
# ---------------------------------------------------------------------------
def _find_env():
    """Find the .env file in the project root."""
    candidates = [
        # Running from project root (most reliable in MSYS)
        os.path.join(os.getcwd(), ".env"),
        # Normal Python __file__ resolution
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"),
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", ".env"),
    ]
    # MSYS /c/ path conversion
    base = os.path.dirname(os.path.abspath(__file__))
    msys_match = re.match(r"^/([a-z])/(.*)", base)
    if msys_match:
        win_base = f"{msys_match.group(1)}:\\{msys_match.group(2)}"
        candidates.append(os.path.join(win_base, "..", ".env"))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None

_ENV_FILE = _find_env()
if _ENV_FILE:
    with open(_ENV_FILE) as _fh:
        for _line in _fh:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())
else:
    import sys as _sys
    print(f"\nWarning: .env not found — using shell env vars.\n"
          f"  __file__={__file__}\n"
          f"  abspath={os.path.abspath(__file__)}\n"
          f"  cwd={os.getcwd()}\n"
          f"  candidates tried: _find_env()={_find_env.__code__}\n",
          file=_sys.stderr)

# ---------------------------------------------------------------------------
# Imports (after .env is loaded so env-var defaults are active)
# ---------------------------------------------------------------------------
from agentcore_tip_client import (
    interactive_login,
    AgentCoreTIPClient,
    InvocationResult,
    get_env,
)
from agentcore_tip.core.config import build_oidc_settings, load_tip_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_user_id() -> str:
    """Best-effort user ID from env, config, or a generated default."""
    explicit = get_env("USER_ID")
    if explicit:
        return explicit
    config = load_tip_config()
    config_user = config.get("user_id")
    if config_user:
        return str(config_user)
    return f"agentcore-tip-e2e-{uuid.uuid4().hex[:8]}"


def _obtain_token(args: argparse.Namespace) -> str:
    """Obtain a post-MFA JWT token.

    Tries in order:
      1. USER_TOKEN env var
      2. Browser-based OIDC login (unless --no-browser-login)
      3. Interactive prompt for a token
    """
    token = get_env("USER_TOKEN", "").strip()
    if token:
        return token

    if args.no_browser_login:
        import getpass
        token = getpass.getpass("Paste post-MFA JWT (input hidden): ").strip()
        return token

    # Auto-detect IdP from env/config
    idp = get_env("IDP")
    timeout = int(get_env("OIDC_TIMEOUT_SECONDS", "300"))

    # build_oidc_settings validates that required fields (client_id, etc.)
    # are present — if not, interactive_login will raise a clear error.
    settings = build_oidc_settings(idp)
    if not settings.get("client_id"):
        print(
            "\nError: OIDC_CLIENT_ID is not set.\n"
            "  Set it in your .env file or export OIDC_CLIENT_ID=...",
            file=sys.stderr,
        )
        sys.exit(1)

    print("=" * 60)
    print("  Step 1/3: Initiating OIDC MFA login...")
    print(f"  IdP:    {settings['idp']}")
    print("=" * 60)
    try:
        token = interactive_login(
            idp=settings["idp"],
            timeout_seconds=timeout,
        )
    except KeyboardInterrupt:
        print("\nLogin cancelled.")
        sys.exit(130)
    except Exception as exc:
        print(f"\nMFA login failed: {exc}", file=sys.stderr)
        sys.exit(1)

    return token


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Minimal-config E2E test: OIDC login → AI agent invocation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variables (all optional, loaded from .env auto-magically):\n"
            "  AGENT_URL            Agent invocation endpoint (default: http://127.0.0.1:8081/invocations)\n"
            "  IDP                  Identity provider: entra-id, okta, cognito\n"
            "  OIDC_CLIENT_ID       OIDC client ID\n"
            "  USER_TOKEN           Cached post-MFA JWT (skips login if set)\n"
            "  USER_ID              User ID to propagate\n"
            "  OIDC_TIMEOUT_SECONDS Browser login timeout (default: 300)\n"
        ),
    )
    parser.add_argument(
        "question",
        nargs="?",
        default="find the tables in database lfdb. discover the table structure on the tables and list the names of the customers and their address grouped by state",
        help="Natural language question for the AI agent",
    )
    parser.add_argument(
        "--url",
        default=get_env("AGENT_URL", "http://127.0.0.1:8081/invocations"),
        help="Agent invocation URL",
    )
    parser.add_argument(
        "--no-browser-login",
        action="store_true",
        help="Skip browser login; reuse USER_TOKEN or prompt for one",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full JSON response from agent",
    )
    parser.add_argument(
        "--mcp-tool",
        default=None,
        help="Call a specific MCP tool directly (e.g. query_data, generate_sql, list_tables)",
    )
    parser.add_argument(
        "--mcp-tool-args",
        default="{}",
        help="JSON arguments for MCP tool (default: empty dict)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all available MCP tools and exit",
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # --list-tools: show available tools and exit early
    # -----------------------------------------------------------------------
    if args.list_tools:
        base_url = args.url.replace("/invocations", "") if "/invocations" in args.url else args.url
        tools_url = f"{base_url}/mcp/tools"
        with urllib.request.urlopen(tools_url, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        print("\nAvailable MCP Tools:")
        print("=" * 60)
        for tool in data.get("tools", []):
            print(f"  {tool['name']}")
            print(f"    {tool['description'][:100]}...")
        print(f"\n  Total: {len(data.get('tools', []))} tools")
        return 0

    # -----------------------------------------------------------------------
    # Step 1: Obtain a post-MFA JWT token (required for MCP + agent calls)
    # -----------------------------------------------------------------------
    try:
        token = _obtain_token(args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"\nFailed to obtain token: {exc}", file=sys.stderr)
        return 1

    if not token:
        print("No token obtained. Aborting.", file=sys.stderr)
        return 2

    user_id = _resolve_user_id()
    print(f"  Token obtained ({len(token)} chars)")
    print(f"  User ID:  {user_id}")

    # -----------------------------------------------------------------------
    # --mcp-tool: invoke a tool directly via MCP (after MFA login)
    # -----------------------------------------------------------------------
    if args.mcp_tool:
        print()
        print("=" * 60)
        print("  Step 2/2: Invoking MCP tool...")
        print("=" * 60)
        print(f"  Tool:     {args.mcp_tool}")
        print(f"  Args:     {args.mcp_tool_args}")
        print()

        base_url = args.url.replace("/invocations", "") if "/invocations" in args.url else args.url
        mcp_endpoint = f"{base_url}/mcp/tools/{args.mcp_tool}/call"

        try:
            tool_args = json.loads(args.mcp_tool_args)
        except json.JSONDecodeError as e:
            print(f"\n  Failed to parse MCP tool args: {e}", file=sys.stderr)
            return 1

        body = json.dumps({"tool": args.mcp_tool, "arguments": tool_args}).encode("utf-8")
        session_id_mcp = f"agentcore-tip-e2e-{uuid.uuid4().hex[:8]}"
        req = urllib.request.Request(
            mcp_endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"******",
                "x-amzn-bedrock-agentcore-runtime-custom-usertoken": token,
                "x-amzn-bedrock-agentcore-runtime-session-id": session_id_mcp,
                "X-Amzn-Bedrock-AgentCore-Runtime-User-Id": user_id,
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result_data = json.loads(resp.read().decode("utf-8"))

        print("=" * 60)
        print("  Step 2/2: MCP Tool Results")
        print("=" * 60)
        print(json.dumps(result_data, indent=2))
        return 0

    # -----------------------------------------------------------------------
    # Step 2: Invoke the AI agent
    # -----------------------------------------------------------------------
    print()
    print("=" * 60)
    print("  Step 2/3: Invoking AI agent...")
    print("=" * 60)
    print(f"  URL:      {args.url}")
    print(f"  Question: {args.question}")
    print()

    client = AgentCoreTIPClient(url=args.url)
    session_id = get_env("SESSION_ID") or f"agentcore-tip-e2e-{uuid.uuid4().hex[:8]}"
    result: InvocationResult = client.invoke(
        token=token,
        payload={"question": args.question},
        user_id=user_id,
        session_id=session_id,
    )

    # -----------------------------------------------------------------------
    # Step 3: Display results
    # -----------------------------------------------------------------------
    print("=" * 60)
    print("  Step 3/3: Results")
    print("=" * 60)

    if not result.ok:
        print(f"\n  FAILED: {result.error or 'Unknown error'}")
        if result.error_type:
            print(f"  Type:   {result.error_type}")
        # Show server-side error details if available
        server_error = result.data.get("error")
        if server_error:
            print(f"  Detail: {server_error}")
        # If still no useful info, dump the raw data
        if not result.error and not server_error:
            print(f"  Raw response: {json.dumps(result.data, indent=4)}")
        return 1

    if args.verbose:
        print(f"\n{json.dumps(result.data, indent=2)}")
    else:
        # Friendly summary — mirrors the ai_data_agent response shape
        data = result.data
        error = data.get("error")
        if error:
            print(f"\n  Agent returned an error: {error}")
            return 1

        sql = data.get("sql", "")
        answer = data.get("answer", "")
        rows_returned = data.get("rows_returned", 0)
        access_denials = data.get("access_denials", [])

        if sql:
            print(f"\n  SQL:  {sql}")
        if rows_returned:
            print(f"  Rows: {rows_returned}")

        if answer:
            print(f"\n  --- AI Answer ---")
            import textwrap
            for line in textwrap.wrap(answer, width=72):
                print(f"  {line}")
            print(f"  --- end ---")

        if access_denials:
            print(f"\n  Access Denials: {', '.join(access_denials)}")

        # Fallback: if none of the above matched, print the raw data
        if not sql and not answer and not rows_returned and not access_denials:
            print(f"\n  Response: {json.dumps(data, indent=2)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
