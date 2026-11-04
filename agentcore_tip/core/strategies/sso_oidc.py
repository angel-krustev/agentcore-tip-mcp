# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""IAM Identity Center / SSO OIDC token exchange strategy."""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
import jwt
from botocore import UNSIGNED
from botocore.client import Config as BotocoreConfig

from .base import BaseExchangeStrategy

_SOURCE_IDENTITY_RE = re.compile(r"^[\w+=,.@-]{2,64}$")
_SESSION_NAME_INVALID_RE = re.compile(r"[^\w+=,.@-]")
IDENTITY_CENTER_PROVIDER_ARN = "arn:aws:iam::aws:contextProvider/IdentityCenter"
_MAX_SESSION_NAME = 64  # STS RoleSessionName limit


def unique_session_name(base: str, request_id: Optional[str] = None) -> str:
    """Return ``<base>-<uuid>`` as a valid, CloudTrail-searchable RoleSessionName.

    ``request_id`` (a UUID string) lets the caller log the same id it put in CloudTrail;
    a random UUID4 is generated when it is omitted. The readable base is truncated so the
    whole name stays within STS's 64-character limit and the UUID is never cut.
    """
    suffix = str(uuid.UUID(request_id)) if request_id else str(uuid.uuid4())
    safe_base = _SESSION_NAME_INVALID_RE.sub("-", base or "") or "pep"
    return f"{safe_base[: _MAX_SESSION_NAME - len(suffix) - 1]}-{suffix}"


class SsoOidcExchangeStrategy(BaseExchangeStrategy):
    """Exchanges a workforce token for temporary AWS credentials via IAM Identity Center.

    The exchange is split in two so the PEP can decouple identity ingestion
    (Plane A) from tool execution (Plane B):

    * ``get_identity_context`` -- one-time IDP JWT -> Identity Center context assertion.
    * ``assume_downscoped_role`` -- context assertion + JIT policy -> short-lived credentials.

    ``exchange`` composes the two for callers that still want credentials directly.
    """

    def __init__(
        self,
        client_id: str,
        role_arn: str,
        region: Optional[str] = None,
        scopes: Optional[list[str]] = None,
        intermediary_role_arn: Optional[str] = None,
        call_path: Optional[str] = None,
    ):
        self.client_id = client_id
        self.role_arn = role_arn
        self.region = region
        # CreateTokenWithIAM does not accept arbitrary scope strings such as
        # "lakeformation:*" -- only omit scope (default) or pass values IAM
        # Identity Center actually recognizes. Left unset unless the caller
        # explicitly provides scopes via actor_context or the constructor.
        self.scopes = scopes
        self.intermediary_role_arn = intermediary_role_arn
        # Appears in CloudTrail userAgent as AgentCoreTIP/<call_path>.
        self.call_path = call_path

    def _client_config(self, **kwargs: Any) -> BotocoreConfig:
        if self.call_path:
            kwargs["user_agent_extra"] = f"AgentCoreTIP/{self.call_path}"
        return BotocoreConfig(**kwargs)

    def _session_for_exchange(self, incoming_jwt: str, actor_context: dict, region: Optional[str], duration_seconds: int) -> boto3.Session:
        intermediary_role_arn = actor_context.get("intermediary_role_arn") or self.intermediary_role_arn
        if not intermediary_role_arn:
            return boto3.Session(region_name=region)

        # AssumeRoleWithWebIdentity does not require ambient AWS credentials to call.
        # Use an explicitly unsigned/anonymous STS client so this step never depends on
        # the caller's default credential chain (profiles, credential_process, env vars, etc.).
        sts_client = boto3.client(
            "sts",
            region_name=region,
            config=self._client_config(signature_version=UNSIGNED),
        )
        response = sts_client.assume_role_with_web_identity(
            RoleArn=intermediary_role_arn,
            RoleSessionName=unique_session_name(
                actor_context.get("intermediary_session_name", "agentcore_tip-oidc-exchange")
            ),
            WebIdentityToken=incoming_jwt,
            DurationSeconds=duration_seconds,
        )
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )

    def _create_token_with_iam(self, session: boto3.Session, incoming_jwt: str, actor_context: dict, region: Optional[str]) -> dict:
        # Match the CreateTokenWithIAM contract used by AWS Trusted Identity
        # Propagation with IAM Identity Center: jwt-bearer grant + assertion,
        # no scope parameter unless the caller explicitly opts in.
        grant_type = actor_context.get("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
        sso_oidc = session.client("sso-oidc", region_name=region, config=self._client_config())
        request = {
            "clientId": self.client_id,
            "grantType": grant_type,
        }
        scopes = actor_context.get("scopes") or self.scopes
        if scopes:
            request["scope"] = scopes
        if grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            request["assertion"] = incoming_jwt
        else:
            request.update(
                {
                    "subjectToken": incoming_jwt,
                    "subjectTokenType": actor_context.get("subject_token_type", "urn:ietf:params:oauth:token-type:id_token"),
                    "requestedTokenType": actor_context.get(
                        "requested_token_type",
                        "urn:ietf:params:aws:token-type:identity_context",
                    ),
                }
            )
        try:
            return sso_oidc.create_token_with_iam(**request)
        except Exception:
            raise

    def _extract_identity_context(self, token_response: dict) -> str:
        identity_context = token_response.get("sts:identity_context") or token_response.get("identityContext")
        if identity_context:
            return str(identity_context)
        for token_key in ("idToken", "accessToken"):
            token = token_response.get(token_key)
            if not token:
                continue
            claims = jwt.decode(token, options={"verify_signature": False})
            identity_context = claims.get("sts:identity_context")
            if identity_context:
                return str(identity_context)
        raise RuntimeError("CreateTokenWithIAM response did not include an Identity Center STS context.")

    def _normalize_credentials(self, credentials: dict, duration_seconds: int) -> tuple[dict, float]:
        expiration = credentials.get("Expiration") or credentials.get("expiration")
        if hasattr(expiration, "timestamp"):
            expires = expiration.timestamp()
            expiration_value = expiration.isoformat()
        elif isinstance(expiration, str):
            expiration_value = expiration
            expires = datetime.fromisoformat(expiration.replace("Z", "+00:00")).timestamp()
        else:
            expires = datetime.now(timezone.utc).timestamp() + duration_seconds
            expiration_value = datetime.fromtimestamp(expires, tz=timezone.utc).isoformat()
        return {
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretAccessKey"],
            "SessionToken": credentials["SessionToken"],
            "Expiration": expiration_value,
        }, expires

    def _resolve_region(self, actor_context: dict, region: Optional[str] = None) -> Optional[str]:
        return (
            region
            or actor_context.get("region")
            or self.region
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
        )

    def _token_exchange(self, incoming_jwt: str, actor_context: dict, region: Optional[str]) -> tuple[boto3.Session, dict]:
        """Run AssumeRoleWithWebIdentity (when configured) + CreateTokenWithIAM."""
        if not incoming_jwt:
            raise ValueError("incoming_jwt is required for SSO OIDC token exchange")
        if not self.client_id:
            raise ValueError("client_id is required for SSO OIDC token exchange")
        duration_seconds = int(actor_context.get("duration_seconds", 3600))
        session = self._session_for_exchange(incoming_jwt, actor_context, region, duration_seconds)
        token_response = self._create_token_with_iam(session, incoming_jwt, actor_context, region)
        return session, token_response

    def _user_id_from_token_response(self, token_response: dict) -> Optional[str]:
        # The user id comes from the SSO OIDC idToken (same source as identity_context).
        id_token = token_response.get("idToken") or token_response.get("IdToken")
        if not id_token:
            return None
        try:
            claims = jwt.decode(id_token, options={"verify_signature": False})
        except Exception:
            return None
        subject = claims.get("sub")
        return str(subject) if subject else None

    def _assume_role(
        self,
        session: boto3.Session,
        region: Optional[str],
        role_session_name: str,
        duration_seconds: int,
        identity_context: str,
        source_identity: Optional[str] = None,
        policy: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> dict:
        sts = session.client("sts", region_name=region, config=self._client_config())
        assume_role_kwargs: dict[str, Any] = {
            "RoleArn": self.role_arn,
            # Unique per call so each assumption is individually identifiable in CloudTrail.
            "RoleSessionName": unique_session_name(role_session_name, request_id),
            "DurationSeconds": duration_seconds,
            "ProvidedContexts": [
                {
                    "ProviderArn": IDENTITY_CENTER_PROVIDER_ARN,
                    "ContextAssertion": identity_context,
                },
            ],
        }
        if source_identity:
            assume_role_kwargs["SourceIdentity"] = source_identity
        if policy:
            assume_role_kwargs["Policy"] = policy
        response = sts.assume_role(**assume_role_kwargs)
        return response["Credentials"]

    def get_identity_context(self, incoming_jwt: str, actor_context: Optional[dict] = None) -> dict[str, Any]:
        """Plane A: exchange an IDP JWT for an Identity Center context assertion.

        Returns ``{"identity_context": str, "user_id": Optional[str]}``. No AWS
        credentials are produced or returned.
        """
        actor_context = actor_context or {}
        region = self._resolve_region(actor_context)
        _, token_response = self._token_exchange(incoming_jwt, actor_context, region)
        identity_context = actor_context.get("identity_context") or self._extract_identity_context(token_response)
        user_id = self._user_id_from_token_response(token_response)
        if not user_id:
            try:
                claims = jwt.decode(incoming_jwt, options={"verify_signature": False})
                subject = claims.get("sub") or claims.get("oid")
                user_id = str(subject) if subject else None
            except Exception:
                user_id = None
        return {"identity_context": identity_context, "user_id": user_id}

    def assume_downscoped_role(
        self,
        identity_context: str,
        source_identity: str,
        policy: str,
        duration_seconds: int = 900,
        region: Optional[str] = None,
        session: Optional[boto3.Session] = None,
        session_name: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> dict:
        """Plane B: JIT STS assumption of the carrier role, locked down by ``policy``.

        ``session`` defaults to the ambient credential chain (the PEP task role).
        The RoleSessionName is ``<session_name or pep-<source_identity>>-<uuid>``; pass
        ``request_id`` (a UUID string) to correlate the CloudTrail session with a log line.
        Returns normalized credentials (AccessKeyId, SecretAccessKey, SessionToken, Expiration).
        """
        if not identity_context:
            raise ValueError("identity_context is required for downscoped role assumption")
        if not self.role_arn:
            raise ValueError("role_arn is required for final TIP role assumption")
        if not policy:
            raise ValueError("policy is required for downscoped role assumption")
        if not source_identity or not _SOURCE_IDENTITY_RE.match(source_identity):
            raise ValueError("source_identity must be 2-64 characters of [\\w+=,.@-]")
        resolved_region = self._resolve_region({}, region)
        active_session = session or boto3.Session(region_name=resolved_region)
        credentials = self._assume_role(
            active_session,
            resolved_region,
            session_name or f"pep-{source_identity}",
            int(duration_seconds),
            identity_context,
            source_identity=source_identity,
            policy=policy,
            request_id=request_id,
        )
        return self._normalize_credentials(credentials, int(duration_seconds))[0]

    def exchange(self, incoming_jwt: str, actor_context: Optional[dict] = None) -> tuple[dict, float]:
        """Legacy single-call path: ingestion + execution with no JIT policy."""
        actor_context = actor_context or {}
        region = self._resolve_region(actor_context)
        duration_seconds = int(actor_context.get("duration_seconds", 3600))
        if not self.role_arn:
            raise ValueError("role_arn is required for final TIP role assumption")

        session, token_response = self._token_exchange(incoming_jwt, actor_context, region)
        idc_user_id = self._user_id_from_token_response(token_response)

        direct_credentials = token_response.get("Credentials") or token_response.get("credentials")
        if direct_credentials:
            return self._normalize_credentials(direct_credentials, duration_seconds)

        identity_context = actor_context.get("identity_context") or self._extract_identity_context(token_response)
        credentials = self._assume_role(
            session, region, f"{idc_user_id}", duration_seconds, identity_context,
        )
        return self._normalize_credentials(credentials, duration_seconds)
