# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""AgentCore-TIP-MCP-Broker Core package.

Exports are resolved lazily so importing the package (or the PEP's
``agentcore_tip.core.pep_server``) does not load the agent-side session context
or its credential cache. The PEP routers are intentionally not exported here:
the LLM host process must never mount them.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

__version__ = "0.1.0"

_LAZY_EXPORTS = {
    "AgentCoreTIPContext": ".core.context",
    "get_active_user_session": ".core.context",
    "get_lakeformation_session": ".core.context",
    "get_scoped_s3_client": ".core.context",
    "user_session": ".core.context",
    "requires_s3_grant": ".core.decorators",
    "requires_user_session": ".core.decorators",
    "AgentCoreCredentialProvider": ".core.agentcore_provider",
    "AgentCoreAgentRuntime": ".core.agentcore_provider",
    "get_runtime": ".core.agentcore_provider",
    "invoke": ".core.agentcore_provider",
}

__all__ = ["__version__", *_LAZY_EXPORTS]


def __getattr__(name: str) -> Any:
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
