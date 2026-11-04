# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Telemetry hooks and redaction helpers."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)

_SENSITIVE_PATTERNS = (
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)aws_session_token=\S+"), "aws_session_token=[REDACTED]"),
    (re.compile(r"(?i)AWS_SESSION_TOKEN=\S+"), "AWS_SESSION_TOKEN=[REDACTED]"),
    (re.compile(r"(?i)(aws_secret_access_key|secret_key|secretAccessKey|SecretAccessKey)([:=]\s*)['\"]?[^'\"\s,]+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)(aws_access_key_id|access_key|accessKeyId|AccessKeyId)([:=]\s*)['\"]?[^'\"\s,]+"), r"\1\2[REDACTED]"),
)


def sanitize_for_log(value: Any) -> Any:
    """Recursively redact security-sensitive values from dictionaries, strings, and bytes."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return "[bytes-redacted]"
    if isinstance(value, str):
        masked = value
        for pattern, replacement in _SENSITIVE_PATTERNS:
            masked = pattern.sub(replacement, masked)
        return masked
    if isinstance(value, dict):
        return {str(k): sanitize_for_log(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        item_type = type(value)
        return item_type(sanitize_for_log(v) for v in value)
    return value


class BaseTelemetryHook(ABC):
    """Pluggable telemetry interface for session lifecycle events."""

    @abstractmethod
    def on_session_start(self, payload: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_token_exchange(self, payload: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_tool_execution(self, payload: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def on_session_end(self, payload: dict[str, Any]) -> None:
        raise NotImplementedError


class ConsoleTelemetryHook(BaseTelemetryHook):
    """Default telemetry hook that writes sanitized JSON to the standard logger."""

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        logger.info("%s %s", event, json.dumps(sanitize_for_log(payload), default=str, separators=(",", ":")))

    def on_session_start(self, payload: dict[str, Any]) -> None:
        self._emit("session_start", payload)

    def on_token_exchange(self, payload: dict[str, Any]) -> None:
        self._emit("token_exchange", payload)

    def on_tool_execution(self, payload: dict[str, Any]) -> None:
        self._emit("tool_execution", payload)

    def on_session_end(self, payload: dict[str, Any]) -> None:
        self._emit("session_end", payload)
