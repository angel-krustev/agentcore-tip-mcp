# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Base interfaces for token exchange strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional


class BaseExchangeStrategy(ABC):
    """Strategy contract for exchanging workforce tokens into AWS temporary credentials."""

    @abstractmethod
    def exchange(self, incoming_jwt: str, actor_context: Optional[dict] = None) -> tuple[dict, float]:
        """Return a credential dict plus expiry timestamp in Unix seconds."""
        raise NotImplementedError

    def get_identity_context(self, incoming_jwt: str, actor_context: Optional[dict] = None) -> dict[str, Any]:
        """Ingestion half: IDP token -> ``{"identity_context", "user_id"}`` (no credentials)."""
        raise NotImplementedError(f"{type(self).__name__} does not support split ingestion/execution.")

    def assume_downscoped_role(
        self,
        identity_context: str,
        source_identity: str,
        policy: str,
        duration_seconds: int = 900,
        region: Optional[str] = None,
        session: Any = None,
        session_name: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> dict:
        """Execution half: identity context + JIT policy -> short-lived credentials."""
        raise NotImplementedError(f"{type(self).__name__} does not support split ingestion/execution.")
