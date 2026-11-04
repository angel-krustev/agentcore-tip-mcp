# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Decorator helpers for user-scoped tool execution."""

from __future__ import annotations

import functools
from typing import Any, Callable

from .context import get_active_user_session
from .exceptions import AuthenticationError


def requires_user_session(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        session = get_active_user_session()
        if session is None:
            raise AuthenticationError("A user session must be active before calling this tool.")
        kwargs.setdefault("session", session)
        return func(*args, **kwargs)

    return wrapped


def requires_s3_grant(uri: str):
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            session = get_active_user_session()
            if session is None:
                raise AuthenticationError("A user session must be active before resolving an S3 grant.")
            kwargs.setdefault("s3_client", session.scoped_s3_client(uri))
            return func(*args, **kwargs)

        return wrapped

    return decorator
