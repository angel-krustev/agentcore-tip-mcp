# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Request-size guard for the PEP's HTTP planes.

``BodySizeLimitMiddleware`` enforces the limit on the bytes actually received. A
``Content-Length`` header is attacker-controlled (absent for chunked requests, and it can
understate), so it is never used to *allow* a request: the body stream is read in chunks and
the request is refused with 413 as soon as the running total exceeds the limit. This happens
before the route runs, so nothing downstream (rate-limit accounting, AWS calls) sees an
oversized request. The accepted body is replayed unchanged to the application.
"""

from __future__ import annotations

import asyncio
import json
from typing import Callable, Optional

from starlette.types import ASGIApp, Message, Receive, Scope, Send

# After refusing a request we still have to consume what the client is sending: closing a TCP
# connection with unread data makes the peer see a reset instead of our 413. The leftover is
# discarded (never buffered) and bounded in size and time, so it cannot be used to tie up a worker.
_DRAIN_MIN_BYTES = 1 << 20
_DRAIN_TIMEOUT_SECONDS = 5.0


def _declared_length(scope: Scope) -> Optional[int]:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _discard_rest_of_body(receive: Receive, limit: int) -> None:
    cap = max(4 * limit, _DRAIN_MIN_BYTES)

    async def drain() -> None:
        drained = 0
        while drained < cap:
            message = await receive()
            if message["type"] != "http.request":
                return
            drained += len(message.get("body", b""))
            if not message.get("more_body", False):
                return

    try:
        await asyncio.wait_for(drain(), _DRAIN_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        pass


async def _payload_too_large(receive: Receive, send: Send, limit: int, drain: bool) -> None:
    body = json.dumps({"ok": False, "error": f"Request body too large (max {limit} bytes)."}).encode("utf-8")
    # Headers go out immediately; the final body chunk only after the upload is drained, because
    # once a response completes ASGI reports a disconnect and the rest of the upload cannot be read.
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"connection", b"close"),
        ],
    })
    if drain:
        await _discard_rest_of_body(receive, limit)
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, get_max_bytes: Callable[[], int]) -> None:
        self.app = app
        self._get_max_bytes = get_max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = int(self._get_max_bytes())
        # Early refusal only: an honest oversize declaration needs no buffering. A missing or
        # understated Content-Length falls through to the streaming count below.
        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            await _payload_too_large(receive, send, limit, drain=True)
            return

        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > limit:
                # Only drain if the client has more to send; a finished stream has nothing left to read.
                await _payload_too_large(receive, send, limit, drain=bool(message.get("more_body", False)))
                return
            if chunk:
                chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # later calls see the real stream (e.g. client disconnect)

        await self.app(scope, replay, send)
