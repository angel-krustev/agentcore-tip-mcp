# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Botocore credential provider integration for user-scoped AWS sessions."""

from __future__ import annotations

import threading
from typing import Optional

from botocore.credentials import CredentialProvider, ReadOnlyCredentials


class AgentCoreTIPCredentialProvider(CredentialProvider):
    """Credential provider that supplies temporary credentials from the active user context."""

    def __init__(self, session_factory=None, credential_source: Optional[str] = None):
        self._session_factory = session_factory
        self._credential_source = credential_source or "agentcore_tip"
        self._lock = threading.RLock()
        self._last_credentials: Optional[ReadOnlyCredentials] = None

    def load(self):
        """Return the current temporary credentials for the active user session."""
        creds = None
        if self._session_factory is not None:
            with self._lock:
                creds = self._session_factory()
        if creds is None:
            raise RuntimeError("No active AgentCoreTIP session credentials are available.")

        if isinstance(creds, ReadOnlyCredentials):
            return creds

        access_key = creds.get("AccessKeyId") or creds.get("access_key")
        secret_key = creds.get("SecretAccessKey") or creds.get("secret_key")
        session_token = creds.get("SessionToken") or creds.get("token")
        if not all([access_key, secret_key, session_token]):
            raise RuntimeError("AgentCoreTIP credential provider requires AccessKeyId, SecretAccessKey, and SessionToken.")
        self._last_credentials = ReadOnlyCredentials(access_key, secret_key, session_token)
        return self._last_credentials

    def _refresh(self):
        return self.load()
