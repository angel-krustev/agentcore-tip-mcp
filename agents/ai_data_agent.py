"""AI-powered data agent: LLM + Athena + S3 Access Grants with graceful access denial.

The agent accepts natural language queries, uses Bedrock (Claude) to generate
SQL, executes against Athena/Lake Formation, and optionally extracts data
files via S3 Access Grants. When the user lacks permissions, it silently
continues and returns a polite notification instead of raising errors.

Run locally:
    python -m uvicorn agents.ai_data_agent:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from agentcore_tip.server import app, register_runner
from agentcore_tip.integrations.s3_access_grants import S3AccessGrantsClientResolver

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_DATABASE = os.environ.get("ATHENA_DATABASE", "lfdb")
DEFAULT_TABLE = os.environ.get("ATHENA_TABLE", "clients")
DEFAULT_WORKGROUP = os.environ.get("ATHENA_WORKGROUP", "idc-wg")
DEFAULT_CATALOG = os.environ.get("ATHENA_CATALOG", "AwsDataCatalog")
DEFAULT_POLL_SECONDS = float(os.environ.get("ATHENA_POLL_SECONDS", "1"))
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("ATHENA_TIMEOUT_SECONDS", "120"))
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "anthropic.claude-3-haiku-20240307-v1:0")
MAX_SQL_TOKENS = int(os.environ.get("MAX_SQL_TOKENS", "1024"))
MAX_ANSWER_TOKENS = int(os.environ.get("MAX_ANSWER_TOKENS", "4096"))

# ---------------------------------------------------------------------------
# LLM helpers (Bedrock / Claude)
# ---------------------------------------------------------------------------

def _bedrock_client(session: boto3.Session) -> Any:
    return session.client("bedrock-runtime")


def _claude_request(br: Any, system_prompt: str, user_message: str, max_tokens: int) -> str:
    """Send a Claude prompt via Bedrock Converse API."""
    response = br.converse(
        modelId=BEDROCK_MODEL,
        messages=[
            {"role": "user", "content": [{"text": user_message}]},
        ],
        system=[{"text": system_prompt}],
        inferenceConfig={
            "maxTokens": max_tokens,
            "temperature": 0.1,
        },
    )
    text = response["output"]["message"]["content"][0]["text"]
    # Strip markdown code fences if present
    text = re.sub(r"^```(?:sql|python|json)?\n|```$", "", text.strip(), flags=re.MULTILINE)
    return text


# ---------------------------------------------------------------------------
# Athena helpers
# ---------------------------------------------------------------------------

def _build_sql_query(br: Any, question: str, schema_hint: str) -> str:
    """Ask LLM to generate Athena SQL from a natural language question."""
    system_prompt = (
        "You are an Athena SQL expert. Generate a SINGLE valid Athena SQL query. "
        "Return ONLY the SQL — no explanation, no markdown, no backticks.\n\n"
        "Rules:\n"
        '- Use double quotes for identifiers: "database"."table"\n'
        "- Use the AwsDataCatalog catalog\n"
        "- Default to LIMIT 20 unless the user asks for more\n"
        "- Handle NULLs gracefully\n\n"
        f"Available schema hint: {schema_hint}"
    )
    return _claude_request(br, system_prompt, question, MAX_SQL_TOKENS)


def _start_query(athena: Any, query: str, workgroup: str, catalog: str, database: str) -> str:
    request: dict[str, Any] = {
        "QueryString": query,
        "QueryExecutionContext": {"Catalog": catalog, "Database": database},
        "WorkGroup": workgroup,
    }
    output_location = os.environ.get("ATHENA_OUTPUT_LOCATION")
    if output_location:
        request["ResultConfiguration"] = {"OutputLocation": output_location}
    return athena.start_query_execution(**request)["QueryExecutionId"]


def _wait_for_query(athena: Any, query_execution_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + DEFAULT_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        resp = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return resp
        time.sleep(DEFAULT_POLL_SECONDS)
    raise TimeoutError(f"Athena query {query_execution_id} timed out after {DEFAULT_TIMEOUT_SECONDS}s")


def _get_query_results(athena: Any, query_execution_id: str) -> list[dict[str, str | None]]:
    resp = athena.get_query_results(QueryExecutionId=query_execution_id)
    rows = resp.get("ResultSet", {}).get("Rows", [])
    if len(rows) < 2:
        return []
    headers = [col.get("VarCharValue", f"col_{i}") for i, col in enumerate(rows[0].get("Data", []))]
    result = []
    for row in rows[1:]:
        data = row.get("Data", [])
        result.append({headers[i]: cell.get("VarCharValue") for i, cell in enumerate(data) if i < len(headers)})
    return result


# ---------------------------------------------------------------------------
# S3 Access Grants helpers
# ---------------------------------------------------------------------------

def _try_s3_download(context, s3_uri: str) -> str | None:
    """Attempt to download data from S3 using Access Grants. Returns content or None on denial."""
    try:
        resolver = S3AccessGrantsClientResolver(context)
        s3_client = resolver.resolve(s3_uri)
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(s3_uri)
        bucket = parsed.netloc
        key = parsed.path.lstrip("/")
        if key.endswith("/"):
            resp = s3_client.list_objects_v2(Bucket=bucket, Prefix=key, MaxKeys=5)
            keys = [o["Key"] for o in resp.get("Contents", [])]
            return json.dumps({"type": "directory_listing", "objects": keys}, indent=2)
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read().decode("utf-8", errors="replace")
        return body[:50_000]
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code in ("AccessDenied", "403", "UnauthorizedOperation", "InvalidToken"):
            logger.info("S3 Access Grant denied for %s: %s", s3_uri, error_code)
            return None
        logger.warning("S3 error for %s: %s", s3_uri, exc)
        return None
    except Exception as exc:
        logger.warning("S3 Access Grant resolution failed for %s: %s", s3_uri, exc)
        return None


# ---------------------------------------------------------------------------
# LLM answer generation
# ---------------------------------------------------------------------------

def _generate_answer(br: Any, question: str, rows: list[dict], access_denials: list[str]) -> str:
    """Ask LLM to format query results into a natural language answer."""
    rows_summary = json.dumps(rows[:50], indent=2)
    denial_note = ""
    if access_denials:
        denial_note = (
            "\n\nIMPORTANT — the user does NOT have access to these resources: "
            + ", ".join(access_denials)
            + "\nMention this politely in your answer."
        )
    system_prompt = (
        "You are a helpful data analyst assistant. Answer the user's question based on "
        "the Athena query results below. Be concise and actionable."
        f"{denial_note}"
    )
    user_message = f"Question: {question}\n\nQuery Results:\n{rows_summary}"
    return _claude_request(br, system_prompt, user_message, MAX_ANSWER_TOKENS)


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/ai-agent/health")
def ai_agent_health() -> dict[str, str]:
    return {
        "runner": "agents.ai_data_agent",
        "llm_model": BEDROCK_MODEL,
        "workgroup": DEFAULT_WORKGROUP,
        "database": DEFAULT_DATABASE,
    }


# ---------------------------------------------------------------------------
# Main registered runner
# ---------------------------------------------------------------------------

@register_runner
def run_ai_data_agent(context, payload: dict[str, Any]) -> dict[str, Any]:
    """AI-powered data agent: natural language -> SQL -> Athena -> LLM answer."""
    question = (
        payload.get("question")
        or payload.get("query")
        or payload.get("input")
        or payload.get("message", "")
    )
    if not question:
        return {"ok": False, "error": "No question or query provided. Send a natural language question or SQL query."}

    access_denials: list[str] = []
    s3_data: dict[str, str] = {}
    rows: list[dict] = []
    sql_used = ""

    # 1. Detect S3 URIs in the question and try to fetch data via Access Grants
    s3_pattern = re.compile(r"s3://[^\s'\"]+")
    for s3_uri in s3_pattern.findall(str(question)):
        content = _try_s3_download(context, s3_uri)
        if content is not None:
            s3_data[s3_uri] = content
        else:
            access_denials.append(s3_uri)

    # 2. Determine SQL — either direct SQL from user, or LLM-generated
    athena = context.lakeformation_session().client("athena")
    br = _bedrock_client(context.session())

    if question.strip().upper().startswith(("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "WITH ", "CREATE ")):
        sql_used = question.strip()
    else:
        schema_hint = os.environ.get(
            "SCHEMA_HINT",
            f"Tables: {DEFAULT_TABLE} in database {DEFAULT_DATABASE}. "
            f"Workgroup: {DEFAULT_WORKGROUP}"
        )
        try:
            sql_used = _build_sql_query(br, question, schema_hint)
        except Exception as exc:
            logger.error("LLM SQL generation failed: %s", exc)
            return {"ok": False, "error": "Failed to generate SQL. Please rephrase your question or provide SQL directly."}

    # 3. Execute Athena query (wrap in try/except for LF permission denials)
    try:
        database = payload.get("database") or DEFAULT_DATABASE
        workgroup = payload.get("workgroup") or DEFAULT_WORKGROUP
        query_id = _start_query(athena, sql_used, workgroup, DEFAULT_CATALOG, database)
        execution = _wait_for_query(athena, query_id)
        state = execution["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            rows = _get_query_results(athena, query_id)
        else:
            reason = execution["QueryExecution"]["Status"].get("StateChangeReason", "Unknown error")
            if "Glue Data Catalog" in reason or "Lake Formation" in reason or "ACCESS_DENIED" in reason.upper():
                access_denials.append(f"Athena table ({reason})")
                rows = []
            else:
                return {"ok": False, "query_execution_id": query_id, "state": state, "reason": reason, "sql": sql_used}
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code in ("AccessDeniedException", "InvalidRequestException", "UnauthorizedOperation"):
            access_denials.append(f"Athena ({error_code})")
        else:
            logger.error("Athena query failed: %s", exc)
            return {"ok": False, "error": f"Athena query failed: {exc}", "sql": sql_used}

    # 4. Generate LLM answer
    all_context = rows
    if s3_data:
        all_context.append({"s3_files": {k: v[:500] for k, v in s3_data.items()}})

    try:
        answer = _generate_answer(br, question, all_context, access_denials)
    except Exception as exc:
        logger.error("LLM answer generation failed: %s", exc)
        answer = f"Query returned {len(rows)} rows. LLM answer generation failed: {exc}"

    result: dict[str, Any] = {
        "ok": True,
        "question": question,
        "sql": sql_used,
        "answer": answer,
        "rows_returned": len(rows),
        "rows": rows[:100],
    }
    if access_denials:
        result["access_denials"] = access_denials
    if s3_data:
        result["s3_files_fetched"] = list(s3_data.keys())

    return result
