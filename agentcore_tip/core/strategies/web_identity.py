# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Fallback STS web-identity exchange strategy."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore import UNSIGNED
from botocore.client import Config as BotocoreConfig

from .base import BaseExchangeStrategy


class StsWebIdentityStrategy(BaseExchangeStrategy):
    """Fallback strategy that assumes a role using an OIDC web identity token."""

    def __init__(self, role_arn: str, session_name: str = "agentcore_tip-web-identity"):
        self.role_arn = role_arn
        self.session_name = session_name

    def exchange(self, incoming_jwt: str, actor_context: Optional[dict] = None) -> tuple[dict, float]:
        region = (actor_context or {}).get("region") or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        # AssumeRoleWithWebIdentity does not require ambient AWS credentials to call.
        # Use an explicitly unsigned/anonymous STS client so this never depends on the
        # caller's default credential chain (profiles, credential_process, env vars, etc.).
        sts_client = boto3.client(
            "sts",
            region_name=region,
            config=BotocoreConfig(signature_version=UNSIGNED),
        )
        response = sts_client.assume_role_with_web_identity(
            RoleArn=self.role_arn,
            RoleSessionName=self.session_name,
            WebIdentityToken=incoming_jwt,
            DurationSeconds=int((actor_context or {}).get("duration_seconds", 3600)),
        )
        creds = response["Credentials"]
        expires = datetime.fromtimestamp(float(creds["Expiration"].timestamp()), tz=timezone.utc).timestamp()
        return {
            "AccessKeyId": creds["AccessKeyId"],
            "SecretAccessKey": creds["SecretAccessKey"],
            "SessionToken": creds["SessionToken"],
            "Expiration": creds["Expiration"].isoformat(),
        }, expires
