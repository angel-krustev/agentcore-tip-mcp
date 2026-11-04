# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Shared middleware configuration — rate limiter, TLS, etc.

Kept in its own file to avoid circular imports between server.py and pep_server.py.
"""

from __future__ import annotations

import logging
import os
import ssl

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rate limiter (slowapi)
# ---------------------------------------------------------------------------
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[
        os.environ.get("RATE_LIMIT_DEFAULT", "60/minute"),
    ],
    strategy="fixed-window",
)

# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------
def tls_context() -> ssl.SSLContext | None:
    """Build an ssl.SSLContext if cert/key paths are configured.

    Env vars:
        TLS_CERT_PATH   — path to fullchain certificate (PEM)
        TLS_KEY_PATH    — path to private key (PEM)
        TLS_KEY_PASS    — optional key passphrase
        TLS_PROTOCOL    — "TLSv1.2" or "TLSv1.3" (default: TLSv1.2)

    Returns None when TLS is not configured (plain HTTP).
    """
    cert = os.environ.get("TLS_CERT_PATH")
    key = os.environ.get("TLS_KEY_PATH")
    if not (cert and key):
        return None

    ctx = ssl.SSLContext(
        getattr(ssl, os.environ.get("TLS_PROTOCOL", "TLSv1_2"))
    )
    ctx.load_cert_chain(
        cert,
        key,
        password=os.environ.get("TLS_KEY_PASS") or None,
    )
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    logger.info("TLS enabled — cert=%s, key=%s", cert, key)
    return ctx


def uvicorn_kwargs() -> dict:
    """Return kwargs dict for uvicorn.run() with TLS wired in if configured."""
    kwargs: dict = {
        "host": os.environ.get("AGENTCORE_TIP_HOST", "0.0.0.0"),
        "port": int(os.environ.get("AGENTCORE_TIP_PORT", "8080")),
    }
    ctx = tls_context()
    if ctx:
        kwargs["ssl_certfile"] = os.environ["TLS_CERT_PATH"]
        kwargs["ssl_keyfile"] = os.environ["TLS_KEY_PATH"]
        kwargs["ssl_keyfile_password"] = os.environ.get("TLS_KEY_PASS")
    return kwargs
