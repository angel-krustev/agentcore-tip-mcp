"""Decode and display JWT claims from the IdP — no AWS calls required.

Obtains a post-MFA JWT via the OIDC browser login flow, decodes the payload,
and pretty-prints all claims including MFA-related assertions (amr, acr).

Usage:
    # Full OIDC login → decode
    python examples/inspect_jwt.py

    # Paste an existing token
    python examples/inspect_jwt.py --token "eyJ..."

    # Decode from USER_TOKEN env var
    USER_TOKEN="eyJ..." python examples/inspect_jwt.py
"""

from __future__ import annotations

import json
import os
import sys
import base64

# Load .env from project root
_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
if os.path.isfile(_ENV_FILE):
    with open(_ENV_FILE) as _fh:
        for _line in _fh:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

import argparse
import base64
import json


def _decode_jwt(token: str) -> dict:
    """Decode a JWT payload without verifying the signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have 3 parts (header.payload.signature)")

    # Add padding if needed
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)


def _print_claims(claims: dict) -> None:
    """Pretty-print JWT claims with special highlighting for MFA assertions."""
    # MFA-relevant claims to highlight
    mfa_keys = {"amr", "acr", "auth_time", "mfa", "multi_factor_authentication_completed"}
    identity_keys = {"sub", "preferred_username", "email", "upn", "oid", "name", "tid"}

    print("\n" + "=" * 60)
    print("  JWT Claims")
    print("=" * 60)

    # Identity section
    identity = {k: v for k, v in claims.items() if k in identity_keys}
    if identity:
        print("\n  ── Identity ──")
        for key, value in identity.items():
            print(f"    {key:25s} {value}")

    # MFA section
    mfa = {k: v for k, v in claims.items() if k in mfa_keys}
    if mfa:
        print("\n  ── MFA Assertions ──")
        for key, value in mfa.items():
            print(f"    {key:25s} {value}")
    else:
        print("\n  ── MFA Assertions ──")
        print("    (none found)")

    # Timing section
    time_keys = {"exp", "nbf", "iat", "auth_time"}
    timing = {k: v for k, v in claims.items() if k in time_keys}
    if timing:
        print("\n  ── Timing ──")
        for key, value in timing.items():
            print(f"    {key:25s} {value}")

    # All other claims
    shown = identity_keys | mfa_keys | time_keys
    other = {k: v for k, v in claims.items() if k not in shown}
    if other:
        print("\n  ── Other Claims ──")
        for key, value in other.items():
            val_str = str(value) if not isinstance(value, (dict, list)) else json.dumps(value)
            print(f"    {key:25s} {val_str}")

    print("\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode and display JWT claims from the IdP"
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("USER_TOKEN", ""),
        help="JWT token to decode (or set USER_TOKEN env var)",
    )
    args = parser.parse_args()

    # If no token provided, do OIDC browser login
    if not args.token:
        print("=" * 60)
        print("  Initiating OIDC MFA login...")
        print("=" * 60)
        try:
            from agentcore_tip_client import interactive_login
            from agentcore_tip.core.config import build_oidc_settings
            idp = os.environ.get("IDP", "entra-id")
            timeout = int(os.environ.get("OIDC_TIMEOUT_SECONDS", "300"))
            settings = build_oidc_settings(idp)
            if not settings.get("client_id"):
                print(
                    "\nError: OIDC_CLIENT_ID is not set.\n"
                    "  Set it in your .env file or export OIDC_CLIENT_ID=...",
                    file=sys.stderr,
                )
                return 1
            token = interactive_login(idp=settings["idp"], timeout_seconds=timeout)
        except KeyboardInterrupt:
            print("\nLogin cancelled.")
            return 130
        except Exception as exc:
            print(f"\nLogin failed: {exc}", file=sys.stderr)
            return 1
    else:
        token = args.token
        print("Using provided token.")

    # Decode and display
    try:
        claims = _decode_jwt(token)
    except Exception as exc:
        print(f"\nFailed to decode JWT: {exc}", file=sys.stderr)
        return 1

    print(f"\nToken length: {len(token)} chars")
    print(f"Header: {json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))}")
    _print_claims(claims)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
