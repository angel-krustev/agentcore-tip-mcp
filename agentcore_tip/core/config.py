# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Configuration helpers compatible with aws-oidc-tip style config files."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


def load_tip_config(path: str | None = None) -> dict[str, Any]:
    """Load an optional aws-oidc-tip-compatible JSON config file.

    The path can be supplied directly, through CONFIG_FILE, or
    omitted. Missing config files are treated as empty config so env-only
    deployments continue to work.
    """
    config_path = path or os.environ.get("CONFIG_FILE")
    if not config_path:
        return {}
    resolved = Path(config_path).expanduser()
    if not resolved.exists():
        return {}
    with resolved.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"AgentCoreTIP config file must contain a JSON object: {resolved}")
    return data


def get_config_value(config: dict[str, Any], env_name: str, config_name: str, default: str = "") -> str:
    """Return an env var first, then a JSON config value, then a default."""
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value
    config_value = config.get(config_name)
    if config_value is None:
        return default
    return str(config_value)


def build_agent_actor_context(user_id: str, custom_headers: dict[str, str]) -> dict[str, Any]:
    """Build actor context using env vars plus aws-oidc-tip-compatible names."""
    config = load_tip_config()
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or str(config.get("region", "us-east-1"))
    return {
        "user_id": user_id,
        "region": region,
        "client_id": get_config_value(config, "SSO_CLIENT_ID", "token_exchange_application_arn"),
        "role_arn": get_config_value(config, "TIP_ROLE_ARN", "id_enhanced_role_arn"),
        "intermediary_role_arn": get_config_value(config, "OIDC_ROLE_ARN", "oidc_role_arn"),
        "duration_seconds": int(get_config_value(config, "SESSION_DURATION_SECONDS", "session_duration_seconds", "3600")),
        "grant_type": os.environ.get("SSO_GRANT_TYPE", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        "custom_headers": custom_headers,
    }


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return int(raw.replace("_", ""))


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass
class PEPConfig:
    """Settings for the Secure Broker / Policy Enforcement Point.

    Values are read from the environment (then the optional aws-oidc-tip JSON
    config file) when the instance is built, not when the module is imported.
    """

    aws_region: str = "us-east-1"
    sso_client_id: str = ""
    carrier_role_arn: str = ""
    oidc_role_arn: str = ""
    redis_url: Optional[str] = None
    # Fernet key(s) for session records in Redis (PEP_ENCRYPTION_KEY). Comma-separated for rotation:
    # the first key encrypts, every key can decrypt. repr=False keeps it out of logs and tracebacks.
    encryption_key: Optional[str] = field(default=None, repr=False)
    session_ttl_seconds: int = 3600
    athena_workgroup: str = "idc-wg"
    athena_catalog: str = "AwsDataCatalog"
    athena_database: str = "lfdb"
    athena_output_location: Optional[str] = None
    athena_timeout_seconds: int = 90
    athena_poll_seconds: float = 1.0
    max_request_body_bytes: int = 1_048_576
    max_response_bytes: int = 5_242_880
    # Port separation: Plane A (user/VPN-facing) and Plane B (agent network only).
    plane_a_port: int = 8080
    plane_b_port: int = 8081
    # Header injected by the SigV4-verifying front end (ALB / VPC Lattice).
    caller_arn_header: str = "x-amzn-caller-arn"
    # Empty means any authenticated agent role may call the tools.
    allowed_agent_roles: tuple[str, ...] = field(default_factory=tuple)
    # Proxies (e.g. the Lambda in front of Plane B) whose verified caller ARN is trusted to forward
    # the real agent role in ``agent_arn_header``. Empty means the header is never read.
    trusted_proxy_roles: tuple[str, ...] = field(default_factory=tuple)
    agent_arn_header: str = "x-pep-agent-role-arn"

    @classmethod
    def from_env(cls) -> "PEPConfig":
        file_config = load_tip_config()
        region = (
            os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or str(file_config.get("region", "us-east-1"))
        )
        return cls(
            aws_region=region,
            sso_client_id=get_config_value(file_config, "SSO_CLIENT_ID", "token_exchange_application_arn"),
            carrier_role_arn=get_config_value(file_config, "TIP_ROLE_ARN", "id_enhanced_role_arn"),
            oidc_role_arn=get_config_value(file_config, "OIDC_ROLE_ARN", "oidc_role_arn"),
            redis_url=os.environ.get("REDIS_URL") or None,
            encryption_key=os.environ.get("PEP_ENCRYPTION_KEY") or None,
            session_ttl_seconds=_env_int("CONTEXT_TTL_SECONDS", 3600),
            athena_workgroup=os.environ.get("ATHENA_WORKGROUP", "idc-wg"),
            athena_catalog=os.environ.get("ATHENA_CATALOG", "AwsDataCatalog"),
            athena_database=os.environ.get("ATHENA_DATABASE", "lfdb"),
            athena_output_location=os.environ.get("ATHENA_OUTPUT_LOCATION") or None,
            athena_timeout_seconds=_env_int("ATHENA_TIMEOUT_SECONDS", 90),
            athena_poll_seconds=float(os.environ.get("ATHENA_POLL_SECONDS", "1")),
            max_request_body_bytes=_env_int("MAX_REQUEST_BODY_BYTES", 1_048_576),
            max_response_bytes=_env_int("MAX_RESPONSE_BYTES", 5_242_880),
            plane_a_port=_env_int("PEP_PLANE_A_PORT", 8080),
            plane_b_port=_env_int("PEP_PLANE_B_PORT", 8081),
            caller_arn_header=os.environ.get("PEP_CALLER_ARN_HEADER", "x-amzn-caller-arn").lower(),
            allowed_agent_roles=_split_csv(os.environ.get("PEP_ALLOWED_AGENT_ROLES", "")),
            trusted_proxy_roles=_split_csv(os.environ.get("PEP_TRUSTED_PROXY_ROLES", "")),
            agent_arn_header=os.environ.get("PEP_AGENT_ARN_HEADER", "x-pep-agent-role-arn").lower(),
        )


pep_config = PEPConfig.from_env()


# IdP identifiers mirror aws-oidc-tip's cihi_auth.auth.base_auth.SUPPORTED_IDPS
# ("entra-id", "okta", "cognito") so the same config file's "idp" field, or
# IDP, selects the right provider without extra mapping.
DEFAULT_IDP_SCOPES = {
    "entra-id": "openid profile email",
    "okta": "openid offline_access email",
    "cognito": "openid email",
}


def build_entra_oidc_settings(config_path: str | None = None) -> dict[str, str]:
    """Return OIDC browser-login settings from env or an aws-oidc-tip config.

    Deprecated: kept for backward compatibility. Prefer build_oidc_settings(),
    which also supports Okta and Cognito in addition to Entra ID.
    """
    config = load_tip_config(config_path)
    tenant_id = get_config_value(config, "ENTRA_TENANT_ID", "entra_tenant_id")
    discovery_url = os.environ.get("OIDC_DISCOVERY_URL")
    if not discovery_url and tenant_id:
        discovery_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
    return {
        "discovery_url": discovery_url or "",
        "client_id": get_config_value(config, "OIDC_CLIENT_ID", "entra_client_id"),
        "redirect_uri": os.environ.get("OIDC_REDIRECT_URI", "http://127.0.0.1:8765/callback"),
    }


def build_oidc_settings(config_path: str | None = None, idp: str | None = None) -> dict[str, str]:
    """Return OIDC browser-login settings for any supported identity provider.

    Supports the same identity providers as aws-oidc-tip's cihi_auth.auth
    package: "entra-id" (Microsoft Entra ID / Azure AD), "okta", and
    "cognito" (Amazon Cognito hosted UI). The provider is resolved, in order
    of precedence, from: the "idp" argument, IDP, the "idp"
    field in an aws-oidc-tip-compatible config file, then defaults to
    "entra-id".

    Returns a dict with:
        idp, client_id, redirect_uri, scopes, discovery_url (Entra ID only;
        authorization_endpoint/token_endpoint are derived from it),
        authorization_endpoint, token_endpoint (Okta/Cognito; derived
        directly from their base URL, no discovery document lookup needed).
    """
    config = load_tip_config(config_path)
    resolved_idp = (idp or os.environ.get("IDP") or config.get("idp") or "entra-id").lower()
    redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "http://127.0.0.1:8765/callback")
    scopes = os.environ.get("OIDC_SCOPES") or DEFAULT_IDP_SCOPES.get(resolved_idp, "openid profile email")

    if resolved_idp in ("entra-id", "entra", "azure-ad", "azuread"):
        tenant_id = get_config_value(config, "ENTRA_TENANT_ID", "entra_tenant_id")
        discovery_url = os.environ.get("OIDC_DISCOVERY_URL")
        if not discovery_url and tenant_id:
            discovery_url = f"https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration"
        return {
            "idp": "entra-id",
            "discovery_url": discovery_url or "",
            "authorization_endpoint": "",
            "token_endpoint": "",
            "client_id": get_config_value(config, "OIDC_CLIENT_ID", "entra_client_id"),
            "redirect_uri": redirect_uri,
            "scopes": scopes,
        }

    if resolved_idp == "okta":
        okta_url = get_config_value(config, "OKTA_URL", "okta_url").rstrip("/")
        return {
            "idp": "okta",
            "discovery_url": "",
            "authorization_endpoint": f"{okta_url}/v1/authorize" if okta_url else "",
            "token_endpoint": f"{okta_url}/v1/token" if okta_url else "",
            "client_id": get_config_value(config, "OIDC_CLIENT_ID", "okta_client_id"),
            "redirect_uri": redirect_uri,
            "scopes": scopes,
        }

    if resolved_idp == "cognito":
        cognito_domain = get_config_value(config, "COGNITO_DOMAIN", "cognito_domain").rstrip("/")
        return {
            "idp": "cognito",
            "discovery_url": "",
            "authorization_endpoint": f"{cognito_domain}/oauth2/authorize" if cognito_domain else "",
            "token_endpoint": f"{cognito_domain}/oauth2/token" if cognito_domain else "",
            "client_id": get_config_value(config, "OIDC_CLIENT_ID", "cognito_client_id"),
            "redirect_uri": redirect_uri,
            "scopes": scopes,
        }

    raise ValueError(f"Unsupported AgentCoreTIP IdP {resolved_idp!r}. Supported values: entra-id, okta, cognito.")
