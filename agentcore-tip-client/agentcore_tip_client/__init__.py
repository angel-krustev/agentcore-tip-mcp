# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""
agentcore_tip_client
===================

Open-source client library for the AgentCoreTIP AI framework.

Handles OIDC browser-based MFA login (Entra ID, Okta, Cognito) and sends
the resulting JWT to a AgentCore-TIP-MCP-Broker agent server for identity propagation.

Install:  pip install agentcore-tip-client
Usage:   python -m agentcore_tip_client --help
"""

from __future__ import annotations

__version__ = "0.1.0"

# Public API
from .agent import AgentCoreTIPClient, InvocationResult
from .oidc import interactive_login
from .config import (
    get_env,
    set_env,
)

__all__ = [
    "interactive_login",
    "AgentCoreTIPClient",
    "InvocationResult",
    "get_env",
    "set_env",
    "__version__",
]
