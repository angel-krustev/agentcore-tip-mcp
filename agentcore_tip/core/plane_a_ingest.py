# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Interface 1 -- REST ingestion plane (``/sessions/init``).

Ingests the user's IDP JWT, performs the one-time AWS token exchange
(AssumeRoleWithWebIdentity + CreateTokenWithIAM), vaults only the Identity
Center context assertion, and returns an opaque ``session_ref``. AWS
credentials and Identity Center tokens are never returned to the caller.
"""

from __future__ import annotations

import asyncio
import logging
import os
from functools import partial

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import pep_config
from .middleware import limiter
from .session_store import session_store
from .strategies.sso_oidc import SsoOidcExchangeStrategy

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sessions", tags=["Plane A - Ingestion"])

_MAX_TOKEN_CHARS = 16384


class SessionInitRequest(BaseModel):
    # Only the IDP JWT is consumed. A ``refresh_token`` (or any other) field in the body is
    # ignored: it is never parsed, validated, stored or echoed.
    token: str = Field(min_length=1, max_length=_MAX_TOKEN_CHARS)


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Replace FastAPI's default 422 body, which echoes the submitted value (``input``) of every
    failing field -- here that would be the user's IDP JWT. Only the field location and the
    validator's fixed message are returned; ``exc.body`` and per-error ``input``/``ctx`` are dropped.
    Register on the app (routers cannot hold exception handlers): see ``pep_server``.
    """
    details = [
        {"loc": [str(part)[:64] for part in error.get("loc", ())], "msg": str(error.get("msg", "Invalid value"))[:200]}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"ok": False, "error": "Invalid request.", "details": details})


class SessionInitResponse(BaseModel):
    ok: bool = True
    session_ref: str
    expires_in: int


def _build_strategy() -> SsoOidcExchangeStrategy:
    return SsoOidcExchangeStrategy(
        client_id=pep_config.sso_client_id,
        role_arn=pep_config.carrier_role_arn,
        region=pep_config.aws_region,
        intermediary_role_arn=pep_config.oidc_role_arn,
        call_path="ingest",
    )


@router.post("/init", response_model=SessionInitResponse)
@limiter.limit(os.environ.get("RATE_LIMIT_SESSION_INIT", "30/minute"))
async def init_session(request: Request, payload: SessionInitRequest) -> SessionInitResponse:
    if not pep_config.sso_client_id or not pep_config.oidc_role_arn:
        raise HTTPException(status_code=503, detail="Ingestion plane is not configured.")

    strategy = _build_strategy()
    loop = asyncio.get_running_loop()
    try:
        # Blocking STS / SSO-OIDC calls must not run on the event loop.
        identity = await loop.run_in_executor(
            None,
            partial(strategy.get_identity_context, payload.token, {"region": pep_config.aws_region}),
        )
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "Unknown")
        logger.warning("Token exchange rejected by AWS: %s", code)
        raise HTTPException(status_code=401, detail=f"AWS token exchange rejected ({code}).")
    except (BotoCoreError, ValueError, RuntimeError):
        logger.exception("Token exchange failed")
        raise HTTPException(status_code=502, detail="Token exchange failed.")
    except Exception:
        logger.exception("Unexpected ingestion failure")
        raise HTTPException(status_code=500, detail="Ingestion failed.")

    user_id = identity.get("user_id")
    if not user_id:
        raise HTTPException(status_code=502, detail="Could not resolve the authenticated user identity.")

    session_ref = await session_store.create_session(
        idc_context=identity["identity_context"],
        user_id=user_id,
        ttl=pep_config.session_ttl_seconds,
    )
    logger.info("Session created for user %s", user_id)
    return SessionInitResponse(ok=True, session_ref=session_ref, expires_in=pep_config.session_ttl_seconds)
