# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Custom exceptions for AgentCore-TIP-MCP-Broker Core."""


class AuthenticationError(RuntimeError):
    """Raised when a user session cannot be resolved or bound."""


class TokenExchangeError(RuntimeError):
    """Raised when an outgoing token exchange fails."""


class GrantResolutionError(RuntimeError):
    """Raised when S3 Access Grant resolution fails."""
