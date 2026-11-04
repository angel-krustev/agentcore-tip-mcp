# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""AWS integration resolvers for data access."""

from .lake_formation import LakeFormationContextResolver
from .s3_access_grants import S3AccessGrantsClientResolver

__all__ = ["LakeFormationContextResolver", "S3AccessGrantsClientResolver"]
