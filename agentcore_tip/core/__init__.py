# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Core credential and session primitives.

Names are resolved lazily so that importing a submodule (for example the PEP's
``agentcore_tip.core.pep_server``) does not load ``context`` and its process-wide
credential cache. Only code that actually asks for these names pays for them.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_LAZY_EXPORTS = {
    "AgentCoreTIPCredentialProvider": ".credentials",
    "AgentCoreTIPContext": ".context",
    "get_active_user_session": ".context",
    "get_lakeformation_session": ".context",
    "get_scoped_s3_client": ".context",
    "user_session": ".context",
    "AuthenticationError": ".exceptions",
    "GrantResolutionError": ".exceptions",
    "TokenExchangeError": ".exceptions",
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
