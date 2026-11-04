# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""OIDC configuration — standalone, no Cython dependency."""

from __future__ import annotations

import os
from typing import Any


DEFAULT_IDP_SCOPES: dict[str, str] = {
    "entra-id": "openid profile email",
    "okta": "openid offline_access email",
    "cognito": "openid email",
}


def get_env(name: str, default: str = "") -> str:
    """Read an environment variable with a default."""
    return os.environ.get(name, default)


def set_env(name: str, value: str) -> None:
    """Set an environment variable for the current process."""
    os.environ[name] = value


def build_oidc_settings(idp: str | None = None) -> dict[str, str]:
    """Return OIDC login settings for the selected identity provider.

    Env-var precedence (same names used by both the client and the server):

        IDP                        — provider selector
        OIDC_DISCOVERY_URL         — Entra ID discovery URL
        OIDC_CLIENT_ID             — public/native client ID
        OIDC_REDIRECT_URI          — loopback callback URI
        OIDC_SCOPES                — space-separated scope list
        OIDC_PROMPT                — "login" / "consent" / "none"
        OIDC_TIMEOUT_SECONDS       — seconds to wait for browser redirect
        AGENT_URL                  — AgentCoreTIP agent invocation endpoint
    """
    resolved_idp = (idp or get_env("IDP", "entra-id")).lower()
    redirect_uri = get_env("OIDC_REDIRECT_URI", "http://127.0.0.1:8765/callback")
    scopes = get_env("OIDC_SCOPES") or DEFAULT_IDP_SCOPES.get(resolved_idp, "openid profile email")

    if resolved_idp in ("entra-id", "entra", "azure-ad", "azuread"):
        tenant_id = get_env("ENTRA_TENANT_ID")
        discovery_url = get_env("OIDC_DISCOVERY_URL")
        if not discovery_url and tenant_id:
            discovery_url = (
                f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
            )
        return {
            "idp": "entra-id",
            "discovery_url": discovery_url or "",
            "authorization_endpoint": "",
            "token_endpoint": "",
            "client_id": get_env("OIDC_CLIENT_ID"),
            "redirect_uri": redirect_uri,
            "scopes": scopes,
        }

    if resolved_idp == "okta":
        okta_url = get_env("OKTA_URL").rstrip("/")
        return {
            "idp": "okta",
            "discovery_url": "",
            "authorization_endpoint": f"{okta_url}/v1/authorize" if okta_url else "",
            "token_endpoint": f"{okta_url}/v1/token" if okta_url else "",
            "client_id": get_env("OIDC_CLIENT_ID"),
            "redirect_uri": redirect_uri,
            "scopes": scopes,
        }

    if resolved_idp == "cognito":
        cognito_domain = get_env("COGNITO_DOMAIN").rstrip("/")
        return {
            "idp": "cognito",
            "discovery_url": "",
            "authorization_endpoint": f"{cognito_domain}/oauth2/authorize" if cognito_domain else "",
            "token_endpoint": f"{cognito_domain}/oauth2/token" if cognito_domain else "",
            "client_id": get_env("OIDC_CLIENT_ID"),
            "redirect_uri": redirect_uri,
            "scopes": scopes,
        }

    raise ValueError(
        f"Unsupported IdP {resolved_idp!r}. Supported values: entra-id, okta, cognito."
    )
