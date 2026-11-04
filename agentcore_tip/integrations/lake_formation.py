# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Lake Formation and Athena query context resolver."""

from __future__ import annotations

import boto3


class LakeFormationContextResolver:
    """Creates AWS data clients scoped to a user's Lake Formation identity."""

    def __init__(self, context):
        self.context = context

    def get_athena_client(self):
        session = self.context.session_for_call_path()
        return session.client("athena")

    def get_glue_client(self):
        session = self.context.session_for_call_path()
        return session.client("glue")
