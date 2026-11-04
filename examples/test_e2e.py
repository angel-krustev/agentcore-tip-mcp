"""End-to-end integration test: MFA login via agentcore-tip-client → AI agent invocation.

This script performs a full OIDC browser login (with MFA), obtains a JWT,
and sends it to the AI agent for natural language query execution.

Usage:
    # Run against local agent (default):
    python examples/test_e2e.py "show me the top 5 customers by revenue"

    # Run against a different agent URL:
    python examples/test_e2e.py "list all tables" --url http://localhost:8082/invocations

    # Skip browser login, use an existing token:
    USER_TOKEN="eyJ..." python examples/test_e2e.py "show recent orders"

    # Skip browser login, prompt for token instead:
    python examples/test_e2e.py "who is the top buyer" --no-browser-login
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Load .env from project root so OIDC config is available to the client
_ENV_FILE = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.isfile(_ENV_FILE):
    with open(_ENV_FILE) as _fh:
        for _line in _fh:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

# Import from the standalone client package
from agentcore_tip_client import (
    interactive_login,
    AgentCoreTIPClient,
    InvocationResult,
    get_env,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="E2E test: OIDC MFA login -> AI agent invocation"
    )
    parser.add_argument(
        "question",
        nargs="?",
        default="find the tables in database lfdb. discover the table sctriucture on the tables and list the names of the customers and their addredss grouped by state",
        help="Natural language question for the AI agent (default: 'find the tables in database lfdb. ')",
    )
    parser.add_argument(
        "--url",
        default=get_env("AGENT_URL", "http://127.0.0.1:8081/invocations"),
        help="Agent invocation URL (default: http://127.0.0.1:8081/invocations)",
    )
    parser.add_argument(
        "--idp",
        choices=["entra-id", "okta", "cognito"],
        default=get_env("IDP"),
        help="Identity provider for MFA login",
    )
    parser.add_argument(
        "--no-browser-login",
        action="store_true",
        help="Skip browser login; reuse USER_TOKEN env var or prompt for one",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(get_env("OIDC_TIMEOUT_SECONDS", "300")),
        help="OIDC login timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--user-id",
        default=get_env("USER_ID", "e2e-test-user"),
        help="User ID to propagate (default: e2e-test-user)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print full JSON response from agent",
    )
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Step 1: Obtain a post-MFA JWT token
    # -----------------------------------------------------------------------
    token = get_env("USER_TOKEN", "").strip()

    if not token:
        if args.no_browser_login:
            import getpass
            token = getpass.getpass("Paste post-MFA JWT (input hidden): ").strip()
        else:
            print("=" * 60)
            print("  Step 1/3: Initiating OIDC MFA login...")
            print("=" * 60)
            try:
                token = interactive_login(
                    idp=args.idp,
                    timeout_seconds=args.timeout,
                )
            except KeyboardInterrupt:
                print("\nLogin cancelled.")
                return 130
            except Exception as exc:
                print(f"\nMFA login failed: {exc}", file=sys.stderr)
                return 1

    if not token:
        print("No token obtained. Aborting.", file=sys.stderr)
        return 2

    print(f"  Token obtained ({len(token)} chars, first 20: {token[:20]}...)")

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
    result: InvocationResult = client.invoke(
        token=token,
        payload={"question": args.question},
        user_id=args.user_id,
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
        return 1

    # Pretty-print key fields
    data = result.data
    answer = data.get("answer", "")
    sql = data.get("sql", "")
    rows_returned = data.get("rows_returned", 0)
    access_denials = data.get("access_denials", [])
    s3_fetched = data.get("s3_files_fetched", [])

    print(f"\n  SQL Generated:  {sql}")
    print(f"  Rows Returned:  {rows_returned}")

    if answer:
        print(f"\n  --- AI Answer ---")
        # Word-wrap the answer for terminal display
        import textwrap
        for line in textwrap.wrap(answer, width=70):
            print(f"  {line}")
        print(f"  --- end ---")

    if access_denials:
        print(f"\n  ⚠ Access Denied for:")
        for resource in access_denials:
            print(f"    - {resource}")

    if s3_fetched:
        print(f"\n  ✓ S3 Files Fetched:")
        for uri in s3_fetched:
            print(f"    - {uri}")

    if args.verbose:
        print(f"\n  Full response:")
        print(json.dumps(data, indent=2))

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
