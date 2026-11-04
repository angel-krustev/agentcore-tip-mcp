# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Exchange strategies for trusted identity propagation."""

from .base import BaseExchangeStrategy
from .sso_oidc import SsoOidcExchangeStrategy
from .web_identity import StsWebIdentityStrategy

__all__ = ["BaseExchangeStrategy", "SsoOidcExchangeStrategy", "StsWebIdentityStrategy"]
