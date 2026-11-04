# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Resolvers for Amazon S3 Access Grants."""

from __future__ import annotations

from urllib.parse import urlparse

import boto3

from ..core.exceptions import GrantResolutionError


class S3AccessGrantsClientResolver:
    """Builds an S3 client whose access is constrained to a grant target prefix."""

    def __init__(self, context):
        self.context = context

    def resolve(self, s3_uri: str):
        parsed = urlparse(s3_uri)
        if parsed.scheme != "s3" or not parsed.netloc:
            raise GrantResolutionError(f"Invalid S3 URI: {s3_uri}")
        bucket = parsed.netloc
        prefix = parsed.path.lstrip("/")
        session = self.context.session_for_call_path()
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        s3control = session.client("s3control")
        target = f"s3://{bucket}/{prefix}/" if prefix else f"s3://{bucket}/"
        response = s3control.get_data_access(
            AccountId=account_id,
            Target=target,
            Permission="READ",
            Privilege="Default",
            DurationSeconds=3600,
        )
        creds = response.get("Credentials", {})
        grant_session = boto3.Session(
            aws_access_key_id=creds.get("AccessKeyId"),
            aws_secret_access_key=creds.get("SecretAccessKey"),
            aws_session_token=creds.get("SessionToken"),
            region_name=session.region_name,
        )
        # The Access Grants credentials above are a brand-new session, not the
        # one tagged by context.session_for_call_path(), so re-apply the same
        # AgentCoreTIP/<call_path> CloudTrail marker here for consistency.
        tag = f"AgentCoreTIP/{self.context.call_path}"
        if grant_session._session.user_agent_extra:
            grant_session._session.user_agent_extra += f" {tag}"
        else:
            grant_session._session.user_agent_extra = tag
        return grant_session.client("s3")
