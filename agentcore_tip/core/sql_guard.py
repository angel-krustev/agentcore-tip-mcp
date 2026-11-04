# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""SQL AST guard and dynamic least-privilege policy builder for the PEP."""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import sqlglot
from sqlglot import exp

SQL_DIALECT = "trino"  # Athena engine v3
MAX_SQL_LENGTH = 8000
MAX_TARGET_TABLES = 10
# STS rejects session policies longer than 2048 characters.
MAX_POLICY_CHARS = 2048

_IDENTIFIER_RE = re.compile(r"\A[A-Za-z0-9_\-]{1,128}\Z")  # \Z, not $: "$" also matches before a trailing newline
_DEFAULT_CATALOG_ALIASES = ("awsdatacatalog", "default_catalog")
# Metadata schemas that expose the whole catalog (every database, table and column)
# regardless of which tables the session policy names.
_BLOCKED_DATABASES = ("information_schema",)

_FORBIDDEN_NODES: tuple[type, ...] = tuple(
    node
    for node in (
        getattr(exp, name, None)
        for name in (
            "Drop", "Alter", "Delete", "Insert", "Update", "Create", "Command",
            "Merge", "Into", "Use", "Set", "Copy", "Grant", "Revoke", "Pragma",
            "Transaction", "Commit", "Rollback", "LoadData", "Describe", "Show",
        )
    )
    if node is not None
)
_SET_OPERATION: type = getattr(exp, "SetOperation", exp.Union)


class SQLGuardError(Exception):
    pass


def validate_identifier(value: str, label: str = "identifier") -> str:
    """Return a safe Glue/Athena identifier or raise.

    Identifiers are embedded in IAM resource ARNs, so wildcards, colons and
    slashes must never get through.
    """
    if not isinstance(value, str) or _IDENTIFIER_RE.match(value) is None:
        raise SQLGuardError(f"Invalid {label}: only letters, digits, '_' and '-' are allowed.")
    return value


def validate_database(value: str) -> str:
    """Validate a Glue database name and refuse metadata schemas such as information_schema."""
    validate_identifier(value, "database")
    if value.lower() in _BLOCKED_DATABASES:
        raise SQLGuardError("Queries against system schemas are not permitted.")
    return value


def validate_and_extract_tables(
    sql: str,
    default_db: str,
    catalog: str = "AwsDataCatalog",
) -> tuple[str, list[dict[str, str]]]:
    """Validate single-statement read-only SQL and return (cleaned_sql, tables).

    The returned SQL is regenerated from the validated AST, so what runs is
    exactly what was inspected (no parser differential with Athena).
    Tables are ``[{"database": db, "table": tbl}]`` with lower-cased names.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise SQLGuardError("Empty SQL statement.")
    if len(sql) > MAX_SQL_LENGTH:
        raise SQLGuardError(f"SQL exceeds {MAX_SQL_LENGTH} characters.")
    default_db = validate_database(default_db)

    try:
        parsed = sqlglot.parse(sql, read=SQL_DIALECT)
    except Exception as exc:
        raise SQLGuardError(f"SQL Syntax Error: {exc}") from exc

    statements = [stmt for stmt in parsed if stmt is not None]
    if not statements:
        raise SQLGuardError("Empty SQL statement.")
    if len(statements) > 1:
        raise SQLGuardError("Multi-statement SQL is strictly prohibited.")
    statement = statements[0]

    if not isinstance(statement, (exp.Select, _SET_OPERATION, exp.Subquery)):
        raise SQLGuardError("Only SELECT and WITH read-only queries are permitted.")
    if any(True for _ in statement.find_all(*_FORBIDDEN_NODES)):
        raise SQLGuardError("Mutating or DDL statements are strictly prohibited.")

    cte_names = {
        cte.alias_or_name.lower()
        for cte in statement.find_all(exp.CTE)
        if cte.alias_or_name
    }
    catalog_aliases = {catalog.lower(), *_DEFAULT_CATALOG_ALIASES}

    tables: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for table_exp in statement.find_all(exp.Table):
        if not isinstance(table_exp.this, exp.Identifier):
            raise SQLGuardError("Table functions and dynamic table references are not permitted.")
        table_name = table_exp.name
        db_name = table_exp.db
        catalog_name = table_exp.catalog

        if not db_name and not catalog_name and table_name.lower() in cte_names:
            continue
        if catalog_name and catalog_name.lower() not in catalog_aliases:
            raise SQLGuardError(f"Catalog '{catalog_name}' is not permitted.")
        if db_name and not catalog_name and db_name.lower() in catalog_aliases:
            db_name = ""

        db_name = validate_database(db_name or default_db).lower()
        table_name = validate_identifier(table_name, "table").lower()
        key = (db_name, table_name)
        if key not in seen:
            seen.add(key)
            tables.append({"database": db_name, "table": table_name})

    if not tables:
        raise SQLGuardError("Query must target at least one valid database table.")
    if len(tables) > MAX_TARGET_TABLES:
        raise SQLGuardError(f"Query references more than {MAX_TARGET_TABLES} tables.")

    return statement.sql(dialect=SQL_DIALECT), tables


def _account_id_from_arn(arn: str) -> str:
    parts = (arn or "").split(":")
    if len(parts) > 4 and parts[4].isdigit():
        return parts[4]
    return "*"


def _glue_arns(region: str, account_id: str, database: str, table: Optional[str]) -> list[str]:
    prefix = f"arn:aws:glue:{region}:{account_id}"
    resources = [f"{prefix}:catalog", f"{prefix}:database/{database}"]
    resources.append(f"{prefix}:table/{database}/{table if table else '*'}")
    return resources


def _s3_output_arns(output_location: Optional[str]) -> list[str]:
    if not output_location or not output_location.startswith("s3://"):
        return []
    bucket, _, prefix = output_location[len("s3://"):].partition("/")
    if not bucket:
        return []
    prefix = prefix.rstrip("/")
    return [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/{prefix + '/' if prefix else ''}*"]


def _dump_policy(statements: list[dict[str, Any]]) -> str:
    policy = json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        separators=(",", ":"),
    )
    if len(policy) > MAX_POLICY_CHARS:
        raise SQLGuardError("Query touches too many tables to fit in a session policy.")
    return policy


def generate_downscoped_policy(
    target_tables: list[dict[str, str]],
    catalog: str = "AwsDataCatalog",
    region: str = "us-east-1",
    account_id: str = "*",
    workgroup: str = "primary",
    output_location: Optional[str] = None,
) -> str:
    """Build an inline session policy limited to the queried tables.

    ``lakeformation:GetDataAccess`` does not support resource-level scoping;
    Lake Formation itself enforces table/column grants for the caller.
    """
    resources: list[str] = []
    for target in target_tables:
        validate_database(target["database"])
        validate_identifier(target["table"], "table")
        for arn in _glue_arns(region, account_id, target["database"], target["table"]):
            if arn not in resources:
                resources.append(arn)

    validate_identifier(workgroup, "workgroup")
    statements: list[dict[str, Any]] = [
        {"Effect": "Allow", "Action": ["lakeformation:GetDataAccess"], "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": ["athena:StartQueryExecution", "athena:GetQueryExecution",
                       "athena:GetQueryResults", "athena:StopQueryExecution", "athena:GetWorkGroup"],
            "Resource": f"arn:aws:athena:{region}:{account_id}:workgroup/{workgroup}",
        },
        {
            "Effect": "Allow",
            "Action": ["glue:GetDatabase", "glue:GetTable", "glue:GetTables",
                       "glue:GetPartition", "glue:GetPartitions"],
            "Resource": resources,
        },
    ]
    s3_arns = _s3_output_arns(output_location)
    if s3_arns:
        statements.append({
            "Effect": "Allow",
            "Action": ["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject",
                       "s3:PutObject", "s3:AbortMultipartUpload"],
            "Resource": s3_arns,
        })
    return _dump_policy(statements)


def generate_metadata_policy(
    database: str,
    table: Optional[str] = None,
    region: str = "us-east-1",
    account_id: str = "*",
) -> str:
    """Session policy for Glue schema discovery (list_tables / describe_table)."""
    validate_database(database)
    if table is not None:
        validate_identifier(table, "table")
    return _dump_policy([
        {
            "Effect": "Allow",
            "Action": ["glue:GetDatabase", "glue:GetTable", "glue:GetTables"],
            "Resource": _glue_arns(region, account_id, database, table),
        },
    ])


def account_id_for_role(role_arn: str) -> str:
    return _account_id_from_arn(role_arn)
