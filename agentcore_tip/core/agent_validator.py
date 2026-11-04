# Copyright 2026 Angel Krustev / VerticalTurn Inc.
# SPDX-License-Identifier: Apache-2.0

"""Validate agent.json manifest against AgentCore schema requirements.

Validates tool endpoints, environment variable references, model IDs,
and structural requirements at startup so misconfigurations fail fast.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Env var placeholder pattern: ${VAR} or ${VAR:default}
ENV_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)")


# ---------------------------------------------------------------------------
# JSON Schema for agent.json manifest
# ---------------------------------------------------------------------------
AGENT_SCHEMA = {
    "type": "object",
    "required": ["agent", "model", "tools"],
    "properties": {
        "agent": {
            "type": "object",
            "required": ["name", "version", "runtime"],
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "version": {"type": "string", "pattern": r"^\d+\.\d+"},
                "description": {"type": "string"},
                "runtime": {
                    "type": "object",
                    "required": ["endpoint"],
                    "properties": {
                        "endpoint": {"type": "string", "pattern": "^/"},
                        "health_check": {"type": "string", "pattern": "^/"},
                        "mcp_endpoint": {"type": "string", "pattern": "^/"},
                    },
                },
                "identity": {
                    "type": "object",
                    "properties": {
                        "tip_enabled": {"type": "boolean"},
                        "credential_provider": {"type": "string"},
                        "session_scoped": {"type": "boolean"},
                        "mfa_required": {"type": "boolean"},
                    },
                },
            },
        },
        "model": {
            "type": "object",
            "required": ["provider", "model_id"],
            "properties": {
                "provider": {"type": "string"},
                "model_id": {"type": "string"},
                "inference_config": {
                    "type": "object",
                    "properties": {
                        "max_tokens": {"type": "integer", "exclusiveMinimum": 0},
                        "temperature": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    },
                },
            },
        },
        "tools": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "description", "endpoint", "schema"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                    "description": {"type": "string", "minLength": 1},
                    "endpoint": {"type": "string", "pattern": "^/mcp/tools/"},
                    "schema": {
                        "type": "object",
                        "required": ["type", "properties"],
                        "properties": {
                            "type": {"const": "object"},
                            "properties": {"type": "object"},
                            "required": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
            },
        },
        "instructions": {
            "type": "object",
            "properties": {
                "system_prompt": {"type": "string"},
                "constraints": {"type": "array", "items": {"type": "string"}},
            },
        },
        "aws": {
            "type": "object",
            "properties": {
                "services": {"type": "array", "items": {"type": "string"}},
                "iam": {
                    "type": "object",
                    "properties": {
                        "role_arn": {"type": "string"},
                        "intermediary_role_arn": {"type": "string"},
                        "sso_client_id": {"type": "string"},
                    },
                },
            },
        },
        "deployment": {
            "type": "object",
            "properties": {
                "container_image": {"type": "string"},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "memory_mb": {"type": "integer", "exclusiveMinimum": 0},
                "timeout_seconds": {"type": "integer", "exclusiveMinimum": 0},
                "environment": {"type": "object", "additionalProperties": {"type": "string"}},
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Known valid endpoints (mapped from FastAPI routes)
# ---------------------------------------------------------------------------
def _build_known_endpoints() -> set[str]:
    """Return the set of tool names that the MCP router actually exposes."""
    # These are the registered tool names from plane_b_mcp.py
    return {
        "query_lake_formation",
        "list_tables",
        "describe_table",
    }


KNOWN_ENDPOINTS = _build_known_endpoints()


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
class AgentValidationError(Exception):
    """Raised when agent.json fails validation."""


def _extract_env_refs(value: str) -> list[str]:
    """Extract ${VAR} references from a string value."""
    return ENV_VAR_RE.findall(value)


def _collect_env_refs(obj: Any, paths: list[str] | None = None, results: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
    """Walk agent.json tree and collect all ${VAR} references per path."""
    if results is None:
        results = {}
    if paths is None:
        paths = []
    current_path = ".".join(paths) if paths else "(root)"

    if isinstance(obj, dict):
        for k, v in obj.items():
            _collect_env_refs(v, [*paths, k], results)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _collect_env_refs(item, [*paths, f"[{i}]"], results)
    elif isinstance(obj, str):
        refs = _extract_env_refs(obj)
        if refs:
            results[current_path] = refs

    return results


# ---------------------------------------------------------------------------
# Main validation
# ---------------------------------------------------------------------------
def validate_agent_json(path: str | Path | None = None, /, *, data: dict | None = None) -> dict:
    """Validate an agent.json manifest and return validation report.

    Args:
        path: Path to agent.json file (default: agent.json next to this module's parent).
        data: Pre-loaded dict to validate (skips file read).

    Returns:
        Dict with ok (bool), errors (list), warnings (list), tool_map (dict).

    Raises:
        AgentValidationError: If critical schema violations exist.
    """
    errors: list[str] = []
    warnings: list[str] = []
    tool_map: dict[str, str] = {}

    # -- Load data --
    manifest: dict | None = data
    if manifest is None and path is not None:
        path_obj = Path(path)
        if not path_obj.is_file():
            errors.append(f"agent.json not found at {path}")
            return _report(errors, warnings, tool_map)
        with open(path_obj) as f:
            manifest = json.load(f)
    elif manifest is None:
        # Try default locations
        for candidate in [
            Path("agent.json"),
            Path(__file__).resolve().parent.parent.parent / "agent.json",
        ]:
            if candidate.is_file():
                with open(candidate) as f:
                    manifest = json.load(f)
                break
        else:
            errors.append("agent.json not found in any default location")
            return _report(errors, warnings, tool_map)

    # -- Schema validation --
    try:
        from jsonschema import validate, ValidationError, Draft7Validator

        validate(instance=manifest, schema=AGENT_SCHEMA, format_checker=Draft7Validator.FORMAT_CHECKER)
    except ImportError:
        warnings.append("jsonschema not installed; skipping JSON Schema validation (pip install jsonschema)")
    except ValidationError as exc:
        errors.append(f"Schema violation at {exc.json_path}: {exc.message}")

    # -- Tool endpoint validation --
    tools = manifest.get("tools", [])
    for tool in tools:
        name = tool.get("name", "<unknown>")
        endpoint = tool.get("endpoint", "")
        tool_map[name] = endpoint

        # Verify endpoint pattern matches /mcp/tools/{name}/call
        expected = f"/mcp/tools/{name}/call"
        if endpoint != expected:
            errors.append(f"Tool '{name}' endpoint '{endpoint}' != expected '{expected}'")

        # Verify tool name is in the known handlers
        if name not in KNOWN_ENDPOINTS:
            errors.append(f"Tool '{name}' has no registered handler in plane_b_mcp.py")

        # Validate required fields in schema match tool requirements
        schema_required = tool.get("schema", {}).get("required", [])
        for req_field in schema_required:
            props = tool.get("schema", {}).get("properties", {})
            if req_field not in props:
                errors.append(
                    f"Tool '{name}' requires '{req_field}' but it's not defined in schema properties"
                )

    # -- Runtime endpoint consistency --
    runtime = manifest.get("runtime", {})
    if runtime.get("endpoint") != "/invocations":
        warnings.append(f"Runtime endpoint '{runtime.get('endpoint')}' differs from default '/invocations'")

    if runtime.get("health_check") != "/ping":
        warnings.append(f"Health check '{runtime.get('health_check')}' differs from default '/ping'")

    # -- Model config validation --
    model = manifest.get("model", {})
    if model.get("provider") != "bedrock":
        warnings.append(f"Model provider '{model.get('provider')}' is not 'bedrock'")

    inf_config = model.get("inference_config", {})
    if inf_config.get("max_tokens", 0) > 8192:
        warnings.append(f"max_tokens={inf_config['max_tokens']} exceeds typical Bedrock limits")

    # -- Environment variable references --
    env_refs = _collect_env_refs(manifest)
    for path_key, refs in env_refs.items():
        for ref in refs:
            if ref not in os.environ:
                # Check if it has a default value (e.g., ${VAR:default})
                raw_value = _get_value_at_path(manifest, path_key)
                if ":}" in raw_value:
                    # Has default, skip warning
                    continue
                warnings.append(f"Path '{path_key}' references env var '{ref}' which is not set")

    # -- AWS IAM references --
    iam = manifest.get("aws", {}).get("iam", {})
    for iam_key in ("role_arn", "intermediary_role_arn", "sso_client_id"):
        val = iam.get(iam_key, "")
        if val and not val.startswith("${"):
            warnings.append(
                f"aws.iam.{iam_key} contains a literal value (should use \\${{}} env var reference)"
            )
        elif not val:
            warnings.append(f"aws.iam.{iam_key} is not configured")

    # -- Deployment checks --
    deploy = manifest.get("deployment", {})
    if not deploy:
        warnings.append("No deployment configuration found")
    else:
        if not deploy.get("container_image"):
            warnings.append("deployment.container_image not specified")
        port = deploy.get("port", 8080)
        if port != 8080:
            warnings.append(f"Deployment port {port} differs from default 8080")

    return _report(errors, warnings, tool_map)


def _get_value_at_path(obj: Any, path: str) -> str:
    """Walk a dotted path to retrieve the raw string value."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            key = part.strip("[]")
            current = current.get(key, current)
        elif isinstance(current, list):
            try:
                idx = int(part.strip("[]"))
                current = current[idx] if idx < len(current) else ""
            except ValueError:
                return ""
        else:
            return str(current)
    return str(current)


def _report(errors: list[str], warnings: list[str], tool_map: dict) -> dict:
    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "tool_map": tool_map,
        "error_count": len(errors),
        "warning_count": len(warnings),
    }


# ---------------------------------------------------------------------------
# Startup hook — call this from server.py on application startup
# ---------------------------------------------------------------------------
def validate_on_startup(path: str | Path | None = None) -> dict:
    """Validate agent.json and log results; raise on critical errors."""
    report = validate_agent_json(path)

    if report["errors"]:
        logger.error("agent.json validation failed with %d error(s):", report["error_count"])
        for err in report["errors"]:
            logger.error("  [ERROR] %s", err)
        raise AgentValidationError(
            f"agent.json has {report['error_count']} validation error(s); "
            "fix before starting server"
        )

    if report["warnings"]:
        logger.warning("agent.json has %d warning(s):", report["warning_count"])
        for warn in report["warnings"]:
            logger.warning("  [WARN] %s", warn)
    else:
        logger.info("agent.json validated successfully — %d tools registered", len(report["tool_map"]))

    for name, endpoint in report["tool_map"].items():
        logger.debug("  tool %s → %s", name, endpoint)

    return report
