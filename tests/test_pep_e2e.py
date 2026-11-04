"""Offline functional tests for the dual-interface Secure Broker / PEP.

No live AWS credentials, Entra ID tokens or network access are needed: every
boto3 client is replaced by a botocore ``Stubber``-wrapped client.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
import jwt
import pytest
from botocore.stub import ANY, Stubber
from cryptography.fernet import Fernet
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient

from agentcore_tip.core import plane_a_ingest, plane_b_mcp, sql_guard
from agentcore_tip.core.config import pep_config
from agentcore_tip.core.pep_server import plane_a_app, plane_b_app
from agentcore_tip.core.middleware import limiter
from agentcore_tip.core.http_limits import BodySizeLimitMiddleware
from agentcore_tip.core.session_store import SessionStore, SessionStoreConfigError, build_cipher, session_store
from agentcore_tip.core.strategies.sso_oidc import SsoOidcExchangeStrategy

CARRIER_ROLE = "arn:aws:iam::123456789012:role/CarrierRole"
OIDC_ROLE = "arn:aws:iam::123456789012:role/OidcBootstrapRole"
AGENT_ROLE = "FinancialAnalystAgentRole"
CALLER = {"x-amzn-caller-arn": f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/session-1"}
IDC_ASSERTION_PROVIDER = "arn:aws:iam::aws:contextProvider/IdentityCenter"


def _idc_token(subject: str, context: str) -> str:
    return jwt.encode({"sub": subject, "sts:identity_context": context}, "test-secret", algorithm="HS256")


def _sts_credentials(tag: str = "A") -> dict:
    return {
        "AccessKeyId": f"ASIAFAKEKEY{tag}0000000",
        "SecretAccessKey": "fake-secret",
        "SessionToken": "fake-session-token",
        "Expiration": datetime(2099, 1, 1, tzinfo=timezone.utc),
    }


class FakeAws:
    """Routes every boto3 client creation to a pre-built, stubbed client."""

    SERVICES = ("sts", "sso-oidc", "athena", "glue")

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_client = boto3.session.Session.client
        self.clients: dict[str, object] = {}
        self.stubbers: dict[str, Stubber] = {}
        self.calls: list[tuple[str, object]] = []
        self.assume_role_params: list[dict] = []
        self.web_identity_params: list[dict] = []
        self.athena_start_params: list[dict] = []
        for service in self.SERVICES:
            client = real_client(
                boto3.session.Session(),
                service,
                region_name="us-east-1",
                aws_access_key_id="AKIAFAKEFAKEFAKE",
                aws_secret_access_key="fake",
            )
            if service == "sts":
                client.meta.events.register(
                    "before-parameter-build.sts.AssumeRole",
                    lambda params, **_: self.assume_role_params.append(dict(params)),
                )
                client.meta.events.register(
                    "before-parameter-build.sts.AssumeRoleWithWebIdentity",
                    lambda params, **_: self.web_identity_params.append(dict(params)),
                )
            if service == "athena":
                client.meta.events.register(
                    "before-parameter-build.athena.StartQueryExecution",
                    lambda params, **_: self.athena_start_params.append(dict(params)),
                )
            stubber = Stubber(client)
            stubber.activate()
            self.clients[service] = client
            self.stubbers[service] = stubber

        def fake_client(_session: object, service_name: str, *args: object, **kwargs: object) -> object:
            self.calls.append((service_name, kwargs.get("config")))
            if service_name not in self.clients:
                raise AssertionError(f"Unexpected AWS client requested: {service_name}")
            return self.clients[service_name]

        monkeypatch.setattr(boto3.session.Session, "client", fake_client)

    def stub(self, service: str) -> Stubber:
        return self.stubbers[service]

    def services_called(self) -> list[str]:
        return [name for name, _ in self.calls]

    def stub_ingest(self, subject: str = "user-123", context: str = "ctx-abc") -> None:
        self.stub("sts").add_response(
            "assume_role_with_web_identity",
            {"Credentials": _sts_credentials("B")},
        )
        self.stub("sso-oidc").add_response(
            "create_token_with_iam",
            {"idToken": _idc_token(subject, context), "tokenType": "Bearer"},
        )

    def stub_query(self, rows: list[list[str]], header: list[str]) -> None:
        self.stub("sts").add_response(
            "assume_role", {"Credentials": _sts_credentials("C")}
        )
        athena = self.stub("athena")
        athena.add_response("start_query_execution", {"QueryExecutionId": "q-1"})
        athena.add_response("get_query_execution", {"QueryExecution": {"Status": {"State": "RUNNING"}}})
        athena.add_response("get_query_execution", {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}})
        athena.add_response(
            "get_query_results",
            {
                "ResultSet": {
                    "Rows": [{"Data": [{"VarCharValue": h} for h in header]}]
                    + [{"Data": [{"VarCharValue": v} for v in row]} for row in rows],
                }
            },
        )


@pytest.fixture(autouse=True)
def _configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAFAKEFAKEFAKE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setattr(pep_config, "aws_region", "us-east-1")
    monkeypatch.setattr(pep_config, "sso_client_id", "arn:aws:sso::123456789012:application/ssoins-1/apl-1")
    monkeypatch.setattr(pep_config, "carrier_role_arn", CARRIER_ROLE)
    monkeypatch.setattr(pep_config, "oidc_role_arn", OIDC_ROLE)
    monkeypatch.setattr(pep_config, "redis_url", None)
    monkeypatch.setattr(pep_config, "athena_poll_seconds", 0.01)
    monkeypatch.setattr(pep_config, "athena_output_location", "s3://athena-results-bucket/pep/")
    monkeypatch.setattr(pep_config, "allowed_agent_roles", ())
    monkeypatch.setattr(pep_config, "trusted_proxy_roles", ())
    monkeypatch.setattr(pep_config, "agent_arn_header", "x-pep-agent-role-arn")
    monkeypatch.setattr(pep_config, "athena_workgroup", "idc-wg")
    session_store._mem_store.clear()
    limiter.reset()
    yield
    session_store._mem_store.clear()


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> FakeAws:
    return FakeAws(monkeypatch)


class DualClient:
    """Routes requests to the Plane A or Plane B app, mirroring the two listeners."""

    PLANE_A_PATHS = ("/sessions",)

    def __init__(self) -> None:
        self.plane_a = TestClient(plane_a_app)
        self.plane_b = TestClient(plane_b_app)

    def __enter__(self) -> "DualClient":
        self.plane_a.__enter__()
        self.plane_b.__enter__()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.plane_b.__exit__(*exc_info)
        self.plane_a.__exit__(*exc_info)

    def _target(self, url: str) -> tuple[TestClient, str]:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path or "/"
        is_plane_a = path.startswith(self.PLANE_A_PATHS) or (parsed.netloc.endswith("-a") and path == "/ping")
        return (self.plane_a if is_plane_a else self.plane_b), path

    def request(self, method: str, url: str, **kwargs: object):
        target, path = self._target(url)
        return target.request(method, path, **kwargs)

    def get(self, url: str, **kwargs: object):
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: object):
        return self.request("POST", url, **kwargs)


@pytest.fixture
def client():
    with DualClient() as test_client:
        yield test_client


def _init_session(client: TestClient, aws: FakeAws, subject: str = "user-123", context: str = "ctx-abc") -> str:
    aws.stub_ingest(subject, context)
    response = client.post("/sessions/init", json={"token": "idp.jwt.value", "refresh_token": "idp-refresh"})
    assert response.status_code == 200, response.text
    return response.json()["session_ref"]


def _call_query(client: TestClient, session_ref: str, sql: str, **extra: object):
    return client.post(
        "/mcp/tools/query_lake_formation/call",
        headers=CALLER,
        json={"session_ref": session_ref, "sql": sql, **extra},
    )


# ---------------------------------------------------------------------------
# End-to-end flow
# ---------------------------------------------------------------------------

def test_dual_interface_lifecycle(client: TestClient, aws: FakeAws):
    assert client.get("/ping").status_code == 200

    session_ref = _init_session(client, aws)
    assert re.fullmatch(r"sess_[0-9a-f]{32}", session_ref)

    tools = client.get("/mcp/tools").json()["tools"]
    names = [t["name"] for t in tools]
    assert "query_lake_formation" in names
    assert not {"generate_sql", "explain_query", "query_data"} & set(names)

    aws.stub_query(rows=[["42"]], header=["total"])
    response = _call_query(client, session_ref, "SELECT count(*) AS total FROM lfdb.clients")
    body = response.json()
    assert response.status_code == 200
    assert body["ok"] is True, body
    assert body["rows"] == [{"total": "42"}]
    assert body["target_tables"] == [{"database": "lfdb", "table": "clients"}]
    assert "Credentials" not in json.dumps(body)

    for stubber in aws.stubbers.values():
        stubber.assert_no_pending_responses()


def test_ingestion_never_returns_credentials_or_tokens(client: TestClient, aws: FakeAws):
    aws.stub_ingest()
    response = client.post("/sessions/init", json={"token": "idp.jwt.value", "refresh_token": "r"})
    assert set(response.json()) == {"ok", "session_ref", "expires_in"}
    assert "ctx-abc" not in response.text
    assert "AKIA" not in response.text and "ASIA" not in response.text


def test_ingestion_uses_unsigned_sts_and_vtcp_tag(client: TestClient, aws: FakeAws):
    from botocore import UNSIGNED

    _init_session(client, aws)
    unsigned_config = next(cfg for name, cfg in aws.calls if name == "sts")
    assert unsigned_config.signature_version is UNSIGNED
    assert unsigned_config.user_agent_extra == "AgentCoreTIP/ingest"
    sso_config = next(cfg for name, cfg in aws.calls if name == "sso-oidc")
    assert sso_config.user_agent_extra == "AgentCoreTIP/ingest"


def test_session_stores_only_context_and_user(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws, subject="user-123", context="ctx-abc")
    _, stored = session_store._mem_store[session_ref]
    assert set(stored) == {"ref", "idc_context", "user_id", "created_at", "expires_at"}
    assert stored["ref"] == session_ref
    assert stored["idc_context"] == "ctx-abc"
    assert stored["user_id"] == "user-123"


def test_jit_assume_role_is_downscoped_to_queried_tables(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients", workgroup="idc-wg").json()["ok"]

    params = aws.assume_role_params[-1]
    assert params["RoleArn"] == CARRIER_ROLE
    assert params["SourceIdentity"] == AGENT_ROLE
    assert params["DurationSeconds"] == 900
    assert params["ProvidedContexts"] == [
        {"ProviderArn": IDC_ASSERTION_PROVIDER, "ContextAssertion": "ctx-abc"}
    ]
    policy = json.loads(params["Policy"])
    glue = next(s for s in policy["Statement"] if "glue:GetTable" in s["Action"])
    assert "arn:aws:glue:us-east-1:123456789012:table/lfdb/clients" in glue["Resource"]
    assert all("*" not in arn for arn in glue["Resource"])
    athena = next(s for s in policy["Statement"] if "athena:StartQueryExecution" in s["Action"])
    assert athena["Resource"].endswith(":workgroup/idc-wg")
    assert len(params["Policy"]) <= sql_guard.MAX_POLICY_CHARS


def test_downstream_clients_carry_vtcp_mcp_tag(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    aws.stub_query(rows=[["1"]], header=["x"])
    _call_query(client, session_ref, "SELECT x FROM lfdb.clients")
    tagged = {name: cfg.user_agent_extra for name, cfg in aws.calls}
    assert tagged == {"sts": "AgentCoreTIP/mcp", "athena": "AgentCoreTIP/mcp"}


def test_sessions_are_isolated_per_user(client: TestClient, aws: FakeAws):
    ref_a = _init_session(client, aws, subject="alice", context="ctx-alice")
    ref_b = _init_session(client, aws, subject="bob", context="ctx-bob")
    assert ref_a != ref_b

    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, ref_b, "SELECT x FROM lfdb.clients").json()["ok"]
    assert aws.assume_role_params[-1]["ProvidedContexts"][0]["ContextAssertion"] == "ctx-bob"

    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, ref_a, "SELECT x FROM lfdb.clients").json()["ok"]
    assert aws.assume_role_params[-1]["ProvidedContexts"][0]["ContextAssertion"] == "ctx-alice"


def test_athena_runs_off_the_event_loop(client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch):
    session_ref = _init_session(client, aws)
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    observed: dict[str, bool] = {}

    def fake_athena(creds, sql, database, workgroup, max_rows):
        try:
            asyncio.get_running_loop()
            observed["on_loop"] = True
        except RuntimeError:
            observed["on_loop"] = False
        return [{"x": "1"}]

    monkeypatch.setattr(plane_b_mcp, "_execute_athena_sync", fake_athena)
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()["ok"]
    assert observed == {"on_loop": False}


# ---------------------------------------------------------------------------
# Caller identity, sessions, SQL rejection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "headers",
    [{}, {"x-amzn-caller-arn": "not-an-arn"}, {"x-amzn-caller-arn": "arn:aws:iam::123456789012:user/bob"}],
)
def test_missing_or_invalid_caller_identity_is_rejected(client: TestClient, aws: FakeAws, headers: dict):
    session_ref = _init_session(client, aws)
    response = client.post(
        "/mcp/tools/query_lake_formation/call",
        headers=headers,
        json={"session_ref": session_ref, "sql": "SELECT 1 FROM t"},
    )
    assert response.status_code == 401
    assert "sts" not in aws.services_called()[2:]  # only the ingestion STS call happened


AGENT_ROLE_ARN = f"arn:aws:iam::123456789012:role/{AGENT_ROLE}"


def _caller(arn: str) -> dict:
    return {"x-amzn-caller-arn": arn}


def _query_as(client, arn: str, session_ref: str, sql: str = "SELECT x FROM lfdb.clients"):
    return client.post(
        "/mcp/tools/query_lake_formation/call",
        headers=_caller(arn),
        json={"session_ref": session_ref, "sql": sql},
    )


def test_agent_allow_list_uses_full_arns(client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch):
    session_ref = _init_session(client, aws)
    monkeypatch.setattr(pep_config, "allowed_agent_roles", ("arn:aws:iam::123456789012:role/SomeOtherAgentRole",))
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").status_code == 403

    monkeypatch.setattr(pep_config, "allowed_agent_roles", (AGENT_ROLE_ARN,))
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()["ok"]


@pytest.mark.parametrize(
    "arn",
    [
        # same role name in another account
        f"arn:aws:sts::999999999999:assumed-role/{AGENT_ROLE}/s1",
        # role name only differs by a prefix (suffix match would accept it)
        f"arn:aws:sts::123456789012:assumed-role/Not{AGENT_ROLE}/s1",
        # attacker-controlled path in front of the allowed role name
        f"arn:aws:iam::123456789012:role/evil/{AGENT_ROLE}",
        # service / kind mismatches and malformed ARNs
        f"arn:aws:iam::123456789012:assumed-role/{AGENT_ROLE}/s1",
        f"arn:aws:sts::123456789012:role/{AGENT_ROLE}",
        f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}",
        f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/s1/extra",
        f"arn:bogus:sts::123456789012:assumed-role/{AGENT_ROLE}/s1",
        f"arn:aws:sts::12345:assumed-role/{AGENT_ROLE}/s1",
        f"xarn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/s1",
        f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/s1 ",
        AGENT_ROLE,
    ],
)
def test_caller_arn_must_match_the_full_arn(client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch, arn: str):
    monkeypatch.setattr(pep_config, "allowed_agent_roles", (AGENT_ROLE_ARN,))
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    response = _query_as(client, arn, session_ref)
    assert response.status_code in (401, 403), arn
    assert aws.calls == []


def test_default_boundary_is_the_carrier_account(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    other_account = f"arn:aws:sts::999999999999:assumed-role/{AGENT_ROLE}/s1"
    assert _query_as(client, other_account, session_ref).status_code == 403
    assert aws.calls == []


def test_allow_list_entries_must_be_full_role_arns(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pep_config, "allowed_agent_roles", (AGENT_ROLE_ARN,))
    plane_b_mcp.validate_agent_allow_list()
    for bad in (AGENT_ROLE, f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/s1", "arn:aws:iam::123:role/x"):
        monkeypatch.setattr(pep_config, "allowed_agent_roles", (bad,))
        with pytest.raises(ValueError):
            plane_b_mcp.validate_agent_allow_list()


def test_role_path_caller_arn_is_parsed(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    response = client.post(
        "/mcp/tools/query_lake_formation/call",
        headers={"x-amzn-caller-arn": f"arn:aws:iam::123456789012:role/agents/team/{AGENT_ROLE}"},
        json={"session_ref": session_ref, "sql": "SELECT x FROM lfdb.clients"},
    )
    assert response.json()["ok"]
    assert aws.assume_role_params[-1]["SourceIdentity"] == AGENT_ROLE


# ---------------------------------------------------------------------------
# Session binding (trust on first use)
# ---------------------------------------------------------------------------

OTHER_AGENT_ARN = "arn:aws:sts::123456789012:assumed-role/MarketingAgentRole/session-9"


def test_session_is_bound_to_the_first_agent(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)

    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()["ok"]

    aws.calls.clear()
    hijack = _query_as(client, OTHER_AGENT_ARN, session_ref).json()
    assert hijack == {"ok": False, "error": "Session is bound to a different agent identity."}
    assert aws.calls == [], "no credentials may be vended to a non-owner agent"

    # The owner keeps working, including from a new assumed-role session of the same role.
    aws.stub_query(rows=[["2"]], header=["x"])
    again = _query_as(client, f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/another-session", session_ref).json()
    assert again["ok"], again


def test_first_caller_wins_even_if_it_is_the_other_agent(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _query_as(client, OTHER_AGENT_ARN, session_ref).json()["ok"]
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()["ok"] is False


def test_binding_applies_to_every_tool_and_the_jsonrpc_path(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_tables", {"TableList": []})
    assert client.post("/mcp/tools/list_tables/call", headers=CALLER, json={"session_ref": session_ref}).json()["ok"]

    aws.calls.clear()
    other = _caller(OTHER_AGENT_ARN)
    assert client.post("/mcp/tools/list_tables/call", headers=other, json={"session_ref": session_ref}).json()["ok"] is False
    assert client.post(
        "/mcp/tools/describe_table/call", headers=other, json={"session_ref": session_ref, "table": "clients"},
    ).json()["ok"] is False
    rpc = client.post("/mcp", headers=other, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_tables", "arguments": {"session_ref": session_ref}},
    }).json()
    assert rpc["result"]["isError"] is True
    assert aws.calls == []


# ---------------------------------------------------------------------------
# Trusted proxy: the real agent role is forwarded in x-pep-agent-role-arn
# ---------------------------------------------------------------------------

PROXY_ROLE = "claims-copilot-PepProxyRole-SGoHtFSxKSWR"
PROXY_ROLE_ARN = f"arn:aws:iam::123456789012:role/{PROXY_ROLE}"
AGENT_HEADER = "x-pep-agent-role-arn"
AGENT_ASSUMED_ARN = f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/agentcore-session"


def _via_proxy(agent_arn: str | None = AGENT_ASSUMED_ARN, caller_arn: str | None = None) -> dict:
    headers = {"x-amzn-caller-arn": caller_arn or f"arn:aws:sts::123456789012:assumed-role/{PROXY_ROLE}/lambda-1"}
    if agent_arn is not None:
        headers[AGENT_HEADER] = agent_arn
    return headers


@pytest.fixture
def proxied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pep_config, "trusted_proxy_roles", (PROXY_ROLE_ARN,))


def _query_with(client, headers: dict | list, session_ref: str):
    return client.post(
        "/mcp/tools/query_lake_formation/call",
        headers=headers,
        json={"session_ref": session_ref, "sql": "SELECT x FROM lfdb.clients"},
    )


def test_proxy_forwarded_agent_becomes_the_source_identity_and_the_proxy_the_session_name(
    client: TestClient, aws: FakeAws, proxied: None, caplog: pytest.LogCaptureFixture,
):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    with caplog.at_level(logging.INFO, logger="agentcore_tip.core.plane_b_mcp"):
        response = _query_with(client, _via_proxy(), session_ref)
    assert response.json()["ok"], response.text

    params = aws.assume_role_params[-1]
    assert params["SourceIdentity"] == AGENT_ROLE
    assert params["RoleSessionName"].startswith("pep-claims-copilot-PepProxy")
    assert PROXY_ROLE not in params["SourceIdentity"]
    request_id = _session_uuid(params["RoleSessionName"])
    assert f"agent={AGENT_ROLE} proxy={PROXY_ROLE} " in caplog.text
    assert f"request_id={request_id}" in caplog.text
    # The carrier assumption still carries the user's Identity Center context.
    assert params["ProvidedContexts"][0]["ContextAssertion"] == "ctx-abc"


def test_proxy_forwarded_agent_accepts_a_role_arn_with_a_path(client: TestClient, aws: FakeAws, proxied: None):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    headers = _via_proxy(f"arn:aws:iam::123456789012:role/agents/team/{AGENT_ROLE}")
    assert _query_with(client, headers, session_ref).json()["ok"]
    assert aws.assume_role_params[-1]["SourceIdentity"] == AGENT_ROLE


@pytest.mark.parametrize(
    "agent_header",
    [
        None,
        "",
        "not-an-arn",
        AGENT_ROLE,
        "arn:aws:iam::123456789012:user/bob",
        f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/s1/extra",
    ],
)
def test_trusted_proxy_must_forward_a_valid_agent_role(
    client: TestClient, aws: FakeAws, proxied: None, agent_header: str | None,
):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    assert _query_with(client, _via_proxy(agent_header), session_ref).status_code == 401
    assert aws.calls == []


def test_trusted_proxy_must_forward_exactly_one_agent_header(client: TestClient, aws: FakeAws, proxied: None):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    headers = [
        ("x-amzn-caller-arn", f"arn:aws:sts::123456789012:assumed-role/{PROXY_ROLE}/lambda-1"),
        (AGENT_HEADER, AGENT_ASSUMED_ARN),
        (AGENT_HEADER, OTHER_AGENT_ARN),
    ]
    assert _query_with(client, headers, session_ref).status_code == 401
    assert aws.calls == []


def test_forwarded_agent_goes_through_the_allow_list(
    client: TestClient, aws: FakeAws, proxied: None, monkeypatch: pytest.MonkeyPatch,
):
    session_ref = _init_session(client, aws)
    monkeypatch.setattr(pep_config, "allowed_agent_roles", (AGENT_ROLE_ARN,))
    aws.calls.clear()
    assert _query_with(client, _via_proxy(OTHER_AGENT_ARN), session_ref).status_code == 403
    other_account = f"arn:aws:sts::999999999999:assumed-role/{AGENT_ROLE}/s1"
    assert _query_with(client, _via_proxy(other_account), session_ref).status_code == 403
    assert aws.calls == []

    aws.stub_query(rows=[["1"]], header=["x"])
    assert _query_with(client, _via_proxy(), session_ref).json()["ok"]


def test_the_proxy_itself_does_not_need_to_be_an_allowed_agent(
    client: TestClient, aws: FakeAws, proxied: None, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(pep_config, "allowed_agent_roles", (AGENT_ROLE_ARN,))
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _query_with(client, _via_proxy(), session_ref).json()["ok"]


def test_agent_header_is_ignored_unless_the_verified_caller_is_a_trusted_proxy(
    client: TestClient, aws: FakeAws, proxied: None,
):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    # A direct agent claiming to be another agent: its own verified identity is used.
    headers = {**CALLER, AGENT_HEADER: OTHER_AGENT_ARN}
    assert _query_with(client, headers, session_ref).json()["ok"]
    assert aws.assume_role_params[-1]["SourceIdentity"] == AGENT_ROLE
    assert not aws.assume_role_params[-1]["RoleSessionName"].startswith("pep-claims-copilot")


def test_agent_header_is_never_read_when_no_proxy_is_trusted(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    # Without PEP_TRUSTED_PROXY_ROLES the proxy is just another caller and the header is ignored.
    assert _query_with(client, _via_proxy(OTHER_AGENT_ARN), session_ref).json()["ok"]
    assert aws.assume_role_params[-1]["SourceIdentity"] == PROXY_ROLE


def test_session_is_bound_to_the_forwarded_agent_not_the_proxy(client: TestClient, aws: FakeAws, proxied: None):
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _query_with(client, _via_proxy(), session_ref).json()["ok"]

    aws.calls.clear()
    hijack = _query_with(client, _via_proxy(OTHER_AGENT_ARN), session_ref).json()
    assert hijack == {"ok": False, "error": "Session is bound to a different agent identity."}
    assert aws.calls == [], "no credentials may be vended to another agent behind the same proxy"

    aws.stub_query(rows=[["2"]], header=["x"])
    again = _query_with(client, _via_proxy(f"arn:aws:sts::123456789012:assumed-role/{AGENT_ROLE}/new"), session_ref)
    assert again.json()["ok"]


def test_proxy_forwarding_applies_to_the_jsonrpc_path(client: TestClient, aws: FakeAws, proxied: None):
    missing = client.post("/mcp", headers=_via_proxy(None), json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert missing.status_code == 401

    session_ref = _init_session(client, aws)
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_tables", {"TableList": []})
    rpc = client.post("/mcp", headers=_via_proxy(), json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "list_tables", "arguments": {"session_ref": session_ref}},
    }).json()
    assert rpc["result"]["isError"] is False
    assert aws.assume_role_params[-1]["SourceIdentity"] == AGENT_ROLE


def test_trusted_proxy_entries_must_be_full_role_arns(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pep_config, "trusted_proxy_roles", (PROXY_ROLE_ARN,))
    plane_b_mcp.validate_agent_allow_list()
    for bad in (PROXY_ROLE, f"arn:aws:sts::123456789012:assumed-role/{PROXY_ROLE}/s1"):
        monkeypatch.setattr(pep_config, "trusted_proxy_roles", (bad,))
        with pytest.raises(ValueError, match="PEP_TRUSTED_PROXY_ROLES"):
            plane_b_mcp.validate_agent_allow_list()


def test_proxy_settings_are_read_from_the_environment(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip.core.config import PEPConfig

    assert PEPConfig.from_env().trusted_proxy_roles == ()
    assert PEPConfig.from_env().agent_arn_header == "x-pep-agent-role-arn"
    monkeypatch.setenv("PEP_TRUSTED_PROXY_ROLES", f"{PROXY_ROLE_ARN}, arn:aws:iam::123456789012:role/Other")
    monkeypatch.setenv("PEP_AGENT_ARN_HEADER", "X-Custom-Agent")
    config = PEPConfig.from_env()
    assert config.trusted_proxy_roles == (PROXY_ROLE_ARN, "arn:aws:iam::123456789012:role/Other")
    assert config.agent_arn_header == "x-custom-agent"


def test_each_session_binds_independently(client: TestClient, aws: FakeAws):
    ref_one = _init_session(client, aws, subject="alice", context="ctx-alice")
    ref_two = _init_session(client, aws, subject="bob", context="ctx-bob")
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, ref_one, "SELECT x FROM lfdb.clients").json()["ok"]
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _query_as(client, OTHER_AGENT_ARN, ref_two).json()["ok"]


class FakeRedis:
    """Async stand-in for redis.asyncio with the SET NX / GET / DELETE semantics the store needs."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.data:
            return None
        self.data[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def get(self, key):
        return self.data.get(key)

    async def delete(self, *keys):
        return sum(1 for key in keys if self.data.pop(key, None) is not None)


def test_binding_is_stored_in_redis_and_shared_across_replicas():
    async def scenario() -> None:
        redis = FakeRedis()
        cipher = build_cipher(Fernet.generate_key().decode())
        replica_one, replica_two = SessionStore(), SessionStore()
        replica_one._redis = replica_two._redis = redis
        replica_one._cipher = replica_two._cipher = cipher  # replicas share PEP_ENCRYPTION_KEY

        ref = await replica_one.create_session("ctx", "user-1", ttl=600)
        session = await replica_two.get_session(ref)
        assert session["expires_at"] > session["created_at"]

        assert await replica_one.bind_agent(ref, AGENT_ROLE_ARN, session["expires_at"]) is True
        assert redis.data[f"vt:bind:{ref}"] == AGENT_ROLE_ARN
        assert 0 < redis.ttls[f"vt:bind:{ref}"] <= 600

        # A different replica sees the same owner.
        assert await replica_two.bind_agent(ref, AGENT_ROLE_ARN, session["expires_at"]) is True
        assert await replica_two.bind_agent(ref, "arn:aws:iam::123456789012:role/Other", session["expires_at"]) is False

        await replica_one.delete_session(ref)
        assert f"vt:bind:{ref}" not in redis.data and await replica_two.get_session(ref) is None

    asyncio.run(scenario())


def test_bind_agent_rejects_unknown_or_malformed_sessions():
    async def scenario() -> None:
        store = SessionStore()
        assert await store.bind_agent("sess_" + "0" * 32, AGENT_ROLE_ARN, 0) is False
        assert await store.bind_agent("not-a-ref", AGENT_ROLE_ARN, 0) is False
        ref = await store.create_session("ctx", "u", ttl=60)
        assert await store.bind_agent(ref, "", 0) is False

    asyncio.run(scenario())


def test_concurrent_first_callers_only_one_wins():
    async def scenario() -> list[bool]:
        store = SessionStore()
        store._redis = FakeRedis()
        store._cipher = build_cipher(Fernet.generate_key().decode())
        ref = await store.create_session("ctx", "u", ttl=60)
        expires = (await store.get_session(ref))["expires_at"]
        identities = [f"arn:aws:iam::123456789012:role/Agent{i}" for i in range(8)]
        return await asyncio.gather(*(store.bind_agent(ref, ident, expires) for ident in identities))

    results = asyncio.run(scenario())
    assert results.count(True) == 1


# ---------------------------------------------------------------------------
# Workgroup is server-side only
# ---------------------------------------------------------------------------

def test_workgroup_is_not_in_the_tool_schema(client: TestClient):
    for tool in client.get("/mcp/tools").json()["tools"]:
        assert "workgroup" not in tool["inputSchema"]["properties"]


def test_caller_cannot_choose_the_workgroup(client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pep_config, "athena_workgroup", "approved-wg")
    session_ref = _init_session(client, aws)
    aws.stub_query(rows=[["1"]], header=["x"])
    response = _call_query(client, session_ref, "SELECT x FROM lfdb.clients", workgroup="attacker-wg")
    assert response.json()["ok"]
    assert aws.athena_start_params[-1]["WorkGroup"] == "approved-wg"
    policy = json.loads(aws.assume_role_params[-1]["Policy"])
    athena = next(s for s in policy["Statement"] if "athena:StartQueryExecution" in s["Action"])
    assert athena["Resource"].endswith(":workgroup/approved-wg")
    assert "attacker-wg" not in aws.assume_role_params[-1]["Policy"]


# ---------------------------------------------------------------------------
# Phase 3 (#9): SQL guard bypasses -- trailing newline, information_schema, pinned parser
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ident", ["lfdb\n", "lfdb\r\n", "lfdb\n\n", "\nlfdb", "lf\ndb"])
def test_identifier_validation_rejects_newlines(ident: str):
    # "$" would have accepted a single trailing "\n"; the pattern must anchor with \Z.
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.validate_identifier(ident, "database")
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.validate_database(ident)


def test_newline_identifiers_cannot_reach_the_iam_policy():
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.generate_downscoped_policy([{"database": "lfdb", "table": "clients\n"}])
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.generate_downscoped_policy([{"database": "lfdb\n", "table": "clients"}])
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.generate_downscoped_policy([{"database": "lfdb", "table": "clients"}], workgroup="idc-wg\n")
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.generate_metadata_policy("lfdb", "clients\n")


def test_tool_arguments_with_trailing_newlines_are_rejected_before_aws(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    assert _call_query(client, session_ref, "SELECT x FROM clients", database="lfdb\n").json()["ok"] is False
    assert client.post(
        "/mcp/tools/list_tables/call", headers=CALLER, json={"session_ref": session_ref, "database": "lfdb\n"},
    ).json()["ok"] is False
    assert client.post(
        "/mcp/tools/describe_table/call", headers=CALLER, json={"session_ref": session_ref, "table": "clients\n"},
    ).json()["ok"] is False
    assert aws.calls == [], "no credentials may be vended for malformed identifiers"


INFORMATION_SCHEMA_QUERIES = [
    "SELECT * FROM information_schema.tables",
    "SELECT table_name FROM INFORMATION_SCHEMA.COLUMNS",
    'SELECT * FROM "information_schema"."tables"',
    'SELECT * FROM "Information_Schema".columns',
    "SELECT * FROM awsdatacatalog.information_schema.tables",
    "SELECT c.x FROM lfdb.clients c JOIN information_schema.columns i ON 1 = 1",
    "WITH t AS (SELECT * FROM information_schema.tables) SELECT * FROM t",
    "SELECT * FROM lfdb.clients WHERE id IN (SELECT table_name FROM information_schema.tables)",
    "SELECT * FROM lfdb.clients UNION ALL SELECT * FROM information_schema.schemata",
]


@pytest.mark.parametrize("sql", INFORMATION_SCHEMA_QUERIES)
def test_sql_guard_blocks_information_schema(sql: str):
    with pytest.raises(sql_guard.SQLGuardError, match="system schemas"):
        sql_guard.validate_and_extract_tables(sql, "lfdb")


def test_sql_guard_blocks_information_schema_as_the_default_database():
    with pytest.raises(sql_guard.SQLGuardError, match="system schemas"):
        sql_guard.validate_and_extract_tables("SELECT * FROM columns", "information_schema")
    with pytest.raises(sql_guard.SQLGuardError, match="system schemas"):
        sql_guard.generate_metadata_policy("INFORMATION_SCHEMA", None)
    with pytest.raises(sql_guard.SQLGuardError, match="system schemas"):
        sql_guard.generate_downscoped_policy([{"database": "information_schema", "table": "tables"}])


@pytest.mark.parametrize("sql", INFORMATION_SCHEMA_QUERIES[:3])
def test_information_schema_is_blocked_through_every_tool(client: TestClient, aws: FakeAws, sql: str):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    assert _call_query(client, session_ref, sql).json()["ok"] is False
    assert _call_query(client, session_ref, "SELECT * FROM columns", database="information_schema").json()["ok"] is False
    for database in ("information_schema", "INFORMATION_SCHEMA"):
        assert client.post(
            "/mcp/tools/list_tables/call", headers=CALLER, json={"session_ref": session_ref, "database": database},
        ).json()["ok"] is False
        assert client.post(
            "/mcp/tools/describe_table/call", headers=CALLER,
            json={"session_ref": session_ref, "database": database, "table": "tables"},
        ).json()["ok"] is False
    assert aws.calls == [], "no credentials may be vended for system-schema requests"


def test_sqlglot_is_pinned_to_one_exact_version_everywhere():
    import sqlglot

    root = Path(__file__).resolve().parent.parent
    pins: dict[str, list[str]] = {}
    for name in ("requirements.txt", "pyproject.toml"):
        text = (root / name).read_text(encoding="utf-8")
        pins[name] = re.findall(r"sqlglot\s*([<>=!~]+[\w.]+)", text)
        assert pins[name], f"{name} must declare sqlglot"
    flattened = {spec for specs in pins.values() for spec in specs}
    assert len(flattened) == 1 and next(iter(flattened)).startswith("=="), pins
    # The corpus above was validated against exactly this parser release.
    assert sqlglot.__version__ == next(iter(flattened))[2:]


# ---------------------------------------------------------------------------
# Phase 3 (#10): engine / catalog errors never reach the caller
# ---------------------------------------------------------------------------

LEAKY_ATHENA_FAILURES = {
    "start": ("start_query_execution", "InvalidRequestException", "Table lfdb.payroll_secret does not exist"),
    "status": ("get_query_execution", "AccessDeniedException", "Lake Formation denied lfdb.payroll_secret"),
    "results": ("get_query_results", "AccessDeniedException", "s3://hidden-bucket/payroll_secret denied"),
}


@pytest.mark.parametrize("stage", ["start", "status", "results", "failed-state", "cancelled-state"])
def test_athena_errors_return_one_generic_message(
    client: TestClient, aws: FakeAws, caplog: pytest.LogCaptureFixture, stage: str,
):
    session_ref = _init_session(client, aws)
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    athena = aws.stub("athena")
    if stage == "start":
        athena.add_client_error(*LEAKY_ATHENA_FAILURES["start"][:1], *LEAKY_ATHENA_FAILURES["start"][1:], 400)
    else:
        athena.add_response("start_query_execution", {"QueryExecutionId": "q-leak"})
        if stage == "status":
            athena.add_client_error(*LEAKY_ATHENA_FAILURES["status"], 400)
        elif stage == "results":
            athena.add_response("get_query_execution", {"QueryExecution": {"Status": {"State": "SUCCEEDED"}}})
            athena.add_client_error(*LEAKY_ATHENA_FAILURES["results"], 400)
        else:
            state = "FAILED" if stage == "failed-state" else "CANCELLED"
            athena.add_response("get_query_execution", {"QueryExecution": {"Status": {
                "State": state,
                "StateChangeReason": "COLUMN_NOT_FOUND: line 1:8: Column 'payroll_secret' cannot be resolved",
            }}})

    with caplog.at_level(logging.WARNING, logger="agentcore_tip.core.plane_b_mcp"):
        response = _call_query(client, session_ref, "SELECT payroll_secret FROM lfdb.clients")

    assert response.status_code == 200
    assert response.json() == {"ok": False, "error": "Query execution failed due to invalid syntax or permissions"}
    assert "payroll_secret" not in response.text and "hidden-bucket" not in response.text
    athena.assert_no_pending_responses()
    # Operators still get the real reason, with the query id, in the server log.
    assert "payroll_secret" in caplog.text
    if stage.endswith("state"):
        assert "query_id=q-leak" in caplog.text


def test_all_athena_failures_are_indistinguishable_to_the_caller(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    bodies = []
    for reason in ("TABLE_NOT_FOUND: lfdb.nothere", "PERMISSION_DENIED: no access to lfdb.clients", "SYNTAX_ERROR"):
        aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
        aws.stub("athena").add_response("start_query_execution", {"QueryExecutionId": "q-x"})
        aws.stub("athena").add_response("get_query_execution", {"QueryExecution": {"Status": {
            "State": "FAILED", "StateChangeReason": reason}}})
        bodies.append(_call_query(client, session_ref, "SELECT x FROM lfdb.clients").json())
    assert bodies[0] == bodies[1] == bodies[2]


def test_glue_errors_do_not_reveal_whether_a_table_exists(client: TestClient, aws: FakeAws, caplog: pytest.LogCaptureFixture):
    session_ref = _init_session(client, aws)
    bodies = []
    for code, message in (
        ("EntityNotFoundException", "Table hr_secret not found"),
        ("AccessDeniedException", "Insufficient Lake Formation permission on hr_secret"),
    ):
        aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
        aws.stub("glue").add_client_error("get_table", code, message, 400)
        with caplog.at_level(logging.WARNING, logger="agentcore_tip.core.plane_b_mcp"):
            bodies.append(client.post(
                "/mcp/tools/describe_table/call", headers=CALLER,
                json={"session_ref": session_ref, "table": "hr_secret"},
            ).json())
    assert bodies[0] == bodies[1] == {"ok": False, "error": plane_b_mcp.CATALOG_FAILED_MESSAGE}
    assert "hr_secret" not in json.dumps(bodies) and "EntityNotFound" not in json.dumps(bodies)
    assert "EntityNotFoundException" in caplog.text and "AccessDeniedException" in caplog.text

    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_client_error("get_tables", "AccessDeniedException", "no access to database lfdb", 400)
    listed = client.post("/mcp/tools/list_tables/call", headers=CALLER, json={"session_ref": session_ref}).json()
    assert listed == {"ok": False, "error": plane_b_mcp.CATALOG_FAILED_MESSAGE}


def test_aws_error_text_cannot_forge_log_lines(client: TestClient, aws: FakeAws, caplog: pytest.LogCaptureFixture):
    session_ref = _init_session(client, aws)
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("athena").add_client_error(
        "start_query_execution", "InvalidRequestException", "boom\nWARNING forged line user=admin", 400,
    )
    with caplog.at_level(logging.WARNING, logger="agentcore_tip.core.plane_b_mcp"):
        _call_query(client, session_ref, "SELECT x FROM lfdb.clients")
    assert not any(line.startswith("WARNING forged") for line in caplog.text.splitlines())


# ---------------------------------------------------------------------------
# Phase 3 (#14): unique STS RoleSessionName per assumption
# ---------------------------------------------------------------------------

_UUID_TAIL_RE = re.compile(r"-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_VALID_SESSION_NAME_RE = re.compile(r"[\w+=,.@-]{2,64}")


def _session_uuid(name: str) -> str:
    match = _UUID_TAIL_RE.search(name)
    assert match, f"{name!r} does not end with a UUID"
    assert str(uuid.UUID(match.group(1))) == match.group(1)
    return match.group(1)


@pytest.mark.parametrize("base", ["pep-agent", "x", "", "a" * 200, "user@example.com", "bad name/with*chars", "ünïcode-role"])
def test_unique_session_name_is_valid_and_ends_with_a_uuid(base: str):
    from agentcore_tip.core.strategies.sso_oidc import unique_session_name

    name = unique_session_name(base)
    assert _VALID_SESSION_NAME_RE.fullmatch(name), name
    assert len(name) <= 64
    _session_uuid(name)  # the UUID is never truncated, even for a 200-character base


def test_unique_session_name_differs_per_call_and_honours_request_id():
    from agentcore_tip.core.strategies.sso_oidc import unique_session_name

    names = {unique_session_name("pep-agent") for _ in range(200)}
    assert len(names) == 200
    fixed = str(uuid.uuid4())
    assert unique_session_name("pep-agent", fixed) == f"pep-agent-{fixed}"
    for bad in ("not-a-uuid", "1234", "../../x"):
        with pytest.raises(ValueError):
            unique_session_name("pep-agent", bad)


def test_every_plane_b_assumption_has_a_unique_session_name_matching_the_log(
    client: TestClient, aws: FakeAws, caplog: pytest.LogCaptureFixture,
):
    session_ref = _init_session(client, aws)
    with caplog.at_level(logging.INFO, logger="agentcore_tip.core.plane_b_mcp"):
        for _ in range(3):
            aws.stub_query(rows=[["1"]], header=["x"])
            assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()["ok"]

    names = [params["RoleSessionName"] for params in aws.assume_role_params[-3:]]
    assert len(set(names)) == 3
    ids = [_session_uuid(name) for name in names]
    assert all(_VALID_SESSION_NAME_RE.fullmatch(name) for name in names)
    assert all(name.startswith("pep-FinancialAnalyst") for name in names), names
    for request_id in ids:
        assert f"request_id={request_id}" in caplog.text, "CloudTrail session must be traceable to a log line"
    # SourceIdentity stays the plain agent role name: the session name is only the correlation handle.
    assert {params["SourceIdentity"] for params in aws.assume_role_params[-3:]} == {AGENT_ROLE}


def test_plane_a_intermediary_session_names_are_unique(client: TestClient, aws: FakeAws):
    _init_session(client, aws)
    _init_session(client, aws)
    names = [params["RoleSessionName"] for params in aws.web_identity_params[-2:]]
    assert len(set(names)) == 2
    for name in names:
        assert name.startswith("agentcore_tip-oidc-exchange-")
        _session_uuid(name)
        assert _VALID_SESSION_NAME_RE.fullmatch(name)


def test_legacy_exchange_session_names_are_unique(aws: FakeAws):
    strategy = SsoOidcExchangeStrategy(
        client_id="client", role_arn=CARRIER_ROLE, region="us-east-1", intermediary_role_arn=OIDC_ROLE,
    )
    for _ in range(2):
        aws.stub_ingest(subject="u1", context="ctx-1")
        aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
        strategy.exchange("idp.jwt")
    names = [params["RoleSessionName"] for params in aws.assume_role_params[-2:]]
    assert names[0] != names[1] and all(name.startswith("u1-") for name in names)
    for name in names:
        _session_uuid(name)


# ---------------------------------------------------------------------------
# Phase 4 (#6): session records are Fernet-encrypted in Redis
# ---------------------------------------------------------------------------

@pytest.fixture
def redis_store(monkeypatch: pytest.MonkeyPatch):
    """The global session store backed by an in-process fake Redis, with real Fernet encryption."""
    redis, key = FakeRedis(), Fernet.generate_key().decode()
    monkeypatch.setattr(session_store, "_redis", redis)
    monkeypatch.setattr(session_store, "_cipher", build_cipher(key))
    return redis, key


def test_redis_sessions_are_encrypted_and_the_full_flow_still_works(client: TestClient, aws: FakeAws, redis_store):
    redis, key = redis_store
    session_ref = _init_session(client, aws, subject="user-123", context="ctx-secret-assertion")

    stored = redis.data[f"vt:session:{session_ref}"]
    assert stored.startswith("gAAAA"), "the value must be a Fernet token"
    for plaintext in ("ctx-secret-assertion", "user-123", "idc_context", "user_id", session_ref):
        assert plaintext not in stored
    record = json.loads(Fernet(key.encode()).decrypt(stored.encode()))
    assert (record["idc_context"], record["user_id"], record["ref"]) == ("ctx-secret-assertion", "user-123", session_ref)

    # Decryption on the read path: the original assertion is what reaches STS.
    aws.stub_query(rows=[["1"]], header=["x"])
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()["ok"]
    assert aws.assume_role_params[-1]["ProvidedContexts"][0]["ContextAssertion"] == "ctx-secret-assertion"

    # TOFU binding works through Redis, and nothing secret sits in any Redis key or value.
    assert redis.data[f"vt:bind:{session_ref}"] == AGENT_ROLE_ARN
    assert _query_as(client, OTHER_AGENT_ARN, session_ref).json()["error"].startswith("Session is bound")
    assert "ctx-secret-assertion" not in json.dumps(redis.data)


def test_tampered_swapped_foreign_and_plaintext_records_are_rejected(redis_store):
    redis, key = redis_store

    async def scenario() -> None:
        ref_a = await session_store.create_session("ctx-a", "user-a", ttl=600)
        ref_b = await session_store.create_session("ctx-b", "user-b", ttl=600)
        assert (await session_store.get_session(ref_a))["idc_context"] == "ctx-a"
        slot = f"vt:session:{ref_a}"
        good = redis.data[slot]

        redis.data[slot] = good[:-4] + ("AAAA" if good[-4:] != "AAAA" else "BBBB")  # bit-flipped
        assert await session_store.get_session(ref_a) is None

        redis.data[slot] = redis.data[f"vt:session:{ref_b}"]  # valid record copied under another ref
        assert await session_store.get_session(ref_a) is None

        redis.data[slot] = json.dumps({"ref": ref_a, "idc_context": "x", "user_id": "u"})  # legacy plaintext
        assert await session_store.get_session(ref_a) is None

        foreign = Fernet(Fernet.generate_key()).encrypt(json.dumps({"ref": ref_a, "idc_context": "x"}).encode())
        redis.data[slot] = foreign.decode()  # encrypted under a different key
        assert await session_store.get_session(ref_a) is None

        redis.data[slot] = good
        assert (await session_store.get_session(ref_a))["idc_context"] == "ctx-a"  # untouched original still fine

    asyncio.run(scenario())


def test_a_corrupted_record_looks_like_an_expired_session_to_the_caller(client: TestClient, aws: FakeAws, redis_store):
    redis, _ = redis_store
    session_ref = _init_session(client, aws)
    redis.data[f"vt:session:{session_ref}"] = "gAAAA-not-a-real-token"
    aws.calls.clear()
    assert _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json() == {
        "ok": False, "error": "Invalid or expired session_ref",
    }
    assert aws.calls == []


def test_key_rotation_keeps_existing_sessions_readable():
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()

    async def scenario() -> None:
        redis = FakeRedis()
        before, after, old_only = SessionStore(), SessionStore(), SessionStore()
        for store, keys in ((before, old), (after, f"{new},{old}"), (old_only, old)):
            store._redis, store._cipher = redis, build_cipher(keys)

        ref = await before.create_session("ctx", "u", ttl=60)
        assert (await after.get_session(ref))["idc_context"] == "ctx"  # old record, new key in front
        fresh = await after.create_session("ctx2", "u", ttl=60)  # encrypted with the new (first) key
        assert await old_only.get_session(fresh) is None

    asyncio.run(scenario())


@pytest.mark.parametrize("key", [None, "", "   ", ",", "not-a-fernet-key", "short", "é" * 44])
def test_redis_refuses_to_start_without_a_valid_encryption_key(monkeypatch: pytest.MonkeyPatch, key):
    monkeypatch.setattr(pep_config, "redis_url", "rediss://localhost:6379/0")
    monkeypatch.setattr(pep_config, "encryption_key", key)
    store = SessionStore()
    with pytest.raises(SessionStoreConfigError) as excinfo:
        asyncio.run(store.init())
    assert store._redis is None and store._cipher is None, "must fail before connecting, never fall back to plaintext"
    if key and key.strip(" ,"):
        assert key not in str(excinfo.value), "error text must not echo key material"


def test_pep_startup_fails_closed_when_redis_has_no_key(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip.core import pep_server

    monkeypatch.setattr(pep_config, "redis_url", "rediss://localhost:6379/0")
    monkeypatch.setattr(pep_config, "encryption_key", None)
    monkeypatch.setattr(session_store, "_redis", None)
    with pytest.raises(SessionStoreConfigError, match="PEP_ENCRYPTION_KEY"):
        asyncio.run(pep_server.serve([]))


REDIS_URL_PASSWORD = "s3cr3t-redis-pw"


@pytest.mark.parametrize(
    "url",
    [
        f"redis://:{REDIS_URL_PASSWORD}@cache.internal:6379/0",   # plaintext, with a password that must not leak
        "redis://cache.internal:6379/0",
        "REDIS://cache.internal:6379/0",
        "unix:///var/run/redis.sock",
        "tcp://cache.internal:6379",
        "http://cache.internal:6379",
        "cache.internal:6379",
        "localhost",
        " rediss://cache.internal:6379/0",                         # leading whitespace is not a rediss:// URL
        "xrediss://cache.internal:6379/0",
        "rediss://",                                               # no host
        "rediss:///0",
        f"rediss://:{REDIS_URL_PASSWORD}@/0",
        "rediss://cache.internal:6379/0?ssl_cert_reqs=none",       # TLS on paper, verification off
        "rediss://cache.internal:6379/0?ssl_cert_reqs=NONE",
        "rediss://cache.internal:6379/0?ssl_cert_reqs=optional",
        "rediss://cache.internal:6379/0?ssl_cert_reqs=CERT_NONE",
        "rediss://cache.internal:6379/0?ssl_cert_reqs=CERT_OPTIONAL",
        "rediss://cache.internal:6379/0?ssl_ca_certs=/ca.pem&ssl_cert_reqs=none",
        "rediss://cache.internal:6379/0?ssl_check_hostname=false",
        "rediss://cache.internal:6379/0?ssl_check_hostname=0",
        "rediss://cache.internal:6379/0?ssl_check_hostname=OFF",
        "rediss://[::1/0",                                         # malformed
    ],
)
def test_redis_url_must_be_rediss_with_verification_on(monkeypatch: pytest.MonkeyPatch, url: str):
    monkeypatch.setattr(pep_config, "redis_url", url)
    monkeypatch.setattr(pep_config, "encryption_key", Fernet.generate_key().decode())  # a valid key must not rescue it
    store = SessionStore()
    with pytest.raises(SessionStoreConfigError) as excinfo:
        asyncio.run(store.init())
    assert store._redis is None and store._cipher is None, "must refuse before building a client"
    assert REDIS_URL_PASSWORD not in str(excinfo.value) and "cache.internal" not in str(excinfo.value)


@pytest.mark.parametrize(
    "url",
    [
        "rediss://cache.internal:6379/0",
        "REDISS://cache.internal:6379/0",
        f"rediss://:{REDIS_URL_PASSWORD}@cache.internal:6380/1",
        "rediss://user:pw@cache.internal",
        "rediss://[::1]:6379/0",
        "rediss://cache.internal:6379/0?ssl_cert_reqs=required&ssl_ca_certs=/etc/ssl/redis-ca.pem",
        "rediss://cache.internal:6379/0?ssl_check_hostname=true",
    ],
)
def test_verified_tls_redis_urls_are_accepted(monkeypatch: pytest.MonkeyPatch, url: str):
    monkeypatch.setattr(pep_config, "redis_url", url)
    monkeypatch.setattr(pep_config, "encryption_key", Fernet.generate_key().decode())

    async def scenario() -> None:
        store = SessionStore()
        await store.init()  # the client is lazy: nothing connects here
        assert store._redis is not None and store._cipher is not None
        await store.close()

    asyncio.run(scenario())


def test_the_transport_is_checked_before_the_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pep_config, "redis_url", "redis://cache.internal:6379/0")
    monkeypatch.setattr(pep_config, "encryption_key", None)
    with pytest.raises(SessionStoreConfigError, match="rediss://"):
        asyncio.run(SessionStore().init())


def test_pep_main_refuses_plaintext_redis_with_a_clean_message(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip.core import pep_server

    monkeypatch.setattr(pep_config, "redis_url", f"redis://:{REDIS_URL_PASSWORD}@cache.internal:6379/0")
    monkeypatch.setattr(pep_config, "encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(session_store, "_redis", None)
    monkeypatch.setattr(pep_server, "build_servers", lambda *a, **k: [])  # a regression must fail, not start listeners
    monkeypatch.setattr("sys.argv", ["pep"])
    with pytest.raises(SystemExit) as excinfo:
        pep_server.main()
    assert str(excinfo.value).startswith("Configuration error: REDIS_URL must start with rediss://")
    assert REDIS_URL_PASSWORD not in str(excinfo.value)


def test_redis_url_is_read_from_the_environment_and_in_memory_mode_needs_none(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip.core.config import PEPConfig

    monkeypatch.setenv("REDIS_URL", "rediss://cache.internal:6379/0")
    assert PEPConfig.from_env().redis_url == "rediss://cache.internal:6379/0"
    monkeypatch.delenv("REDIS_URL")
    assert PEPConfig.from_env().redis_url is None
    monkeypatch.setattr(pep_config, "redis_url", None)  # no Redis => in-memory dev mode: no URL/key requirements
    asyncio.run(SessionStore().init())


def test_pep_main_exits_with_a_clean_message_when_redis_has_no_key(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip.core import pep_server

    monkeypatch.setattr(pep_config, "redis_url", "rediss://localhost:6379/0")
    monkeypatch.setattr(pep_config, "encryption_key", None)
    monkeypatch.setattr(session_store, "_redis", None)
    monkeypatch.setattr(pep_server, "build_servers", lambda *a, **k: [])  # a regression must fail, not start listeners
    monkeypatch.setattr("sys.argv", ["pep"])
    with pytest.raises(SystemExit) as excinfo:  # SystemExit(str), not a traceback
        pep_server.main()
    assert str(excinfo.value).startswith("Configuration error: PEP_ENCRYPTION_KEY is required")


def test_redis_init_builds_the_cipher_from_pep_encryption_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pep_config, "redis_url", "rediss://localhost:6379/0")
    monkeypatch.setattr(pep_config, "encryption_key", Fernet.generate_key().decode())

    async def scenario() -> SessionStore:
        store = SessionStore()
        await store.init()  # redis.from_url is lazy: no connection is made
        assert store._cipher is not None and store._redis is not None
        await store.close()
        return store

    asyncio.run(scenario())


def test_redis_store_without_a_cipher_refuses_to_write_plaintext():
    store = SessionStore()
    store._redis = FakeRedis()
    with pytest.raises(SessionStoreConfigError):
        asyncio.run(store.create_session("ctx", "u"))
    assert store._redis.data == {}


def test_encryption_key_is_not_in_the_config_repr(monkeypatch: pytest.MonkeyPatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(pep_config, "encryption_key", key)
    assert key not in repr(pep_config) and key not in str(pep_config)


def test_encryption_key_is_read_from_pep_encryption_key(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip.core.config import PEPConfig

    key = Fernet.generate_key().decode()
    monkeypatch.setenv("PEP_ENCRYPTION_KEY", key)
    assert PEPConfig.from_env().encryption_key == key
    monkeypatch.delenv("PEP_ENCRYPTION_KEY")
    assert PEPConfig.from_env().encryption_key is None


# ---------------------------------------------------------------------------
# Phase 4 (#8): 422 responses never echo submitted values
# ---------------------------------------------------------------------------

CANARY = "eyJCANARYtoken.payload.SECRETsignature"


@pytest.mark.parametrize(
    "body",
    [
        {"token": CANARY * 800},                              # over the length limit
        {"refresh_token": CANARY},                            # token missing
        {"token": "", "refresh_token": CANARY},               # token too short
        {"token": {"nested": CANARY}},                        # wrong type
        {"token": [CANARY, 1]},
    ],
)
def test_validation_errors_never_echo_the_submitted_values(
    client: TestClient, aws: FakeAws, caplog: pytest.LogCaptureFixture, body: dict,
):
    with caplog.at_level(logging.DEBUG):
        response = client.post("/sessions/init", json=body)
    assert response.status_code == 422
    assert "CANARY" not in response.text and "SECRET" not in response.text
    payload = response.json()
    assert payload["ok"] is False and payload["error"] == "Invalid request."
    assert payload["details"] and all(set(detail) == {"loc", "msg"} for detail in payload["details"])
    assert "CANARY" not in caplog.text
    assert aws.calls == [], "an invalid request must not reach AWS"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"content": '{"token": "eyJCANARYtoken.payload.SECRET', "headers": {"content-type": "application/json"}},  # truncated JSON
        {"content": "token=eyJCANARYtoken.SECRET", "headers": {"content-type": "text/plain"}},                      # wrong content type
        {"content": '"eyJCANARYtoken.SECRET"', "headers": {"content-type": "application/json"}},                    # not an object
    ],
)
def test_malformed_bodies_never_echo_the_submitted_text(client: TestClient, aws: FakeAws, kwargs: dict):
    response = client.post("/sessions/init", **kwargs)
    assert response.status_code == 422
    assert "CANARY" not in response.text and "SECRET" not in response.text
    assert aws.calls == []


def test_refresh_token_is_ignored_never_stored_or_echoed(client: TestClient, aws: FakeAws):
    aws.stub_ingest()
    response = client.post("/sessions/init", json={"token": "idp.jwt.value", "refresh_token": "REFRESH-CANARY"})
    assert response.status_code == 200 and "REFRESH-CANARY" not in response.text
    assert "REFRESH-CANARY" not in json.dumps(session_store._mem_store, default=str)
    assert "refresh_token" not in plane_a_ingest.SessionInitRequest.model_fields


def test_both_planes_override_the_default_422_handler():
    for app in (plane_a_app, plane_b_app):
        assert app.exception_handlers[RequestValidationError] is plane_a_ingest.validation_error_handler


# ---------------------------------------------------------------------------
# Phase 4 (#11): body size is enforced on the streamed bytes, not on Content-Length
# ---------------------------------------------------------------------------

def _run_through_middleware(limit: int, chunks: list[bytes], headers=(), scope_type: str = "http"):
    """Drive BodySizeLimitMiddleware directly with a hand-built ASGI stream (no HTTP client
    in between, so no Content-Length is added behind our back). ``events`` records the order of
    reads from the client and the response messages the middleware sent."""
    seen_bodies: list[bytes] = []
    events: list[str] = []
    sent: list[dict] = []
    queue = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ]

    async def downstream(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        seen_bodies.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        events.append("read")
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        events.append("start" if message["type"] == "http.response.start" else "body")
        sent.append(message)

    middleware = BodySizeLimitMiddleware(downstream, get_max_bytes=lambda: limit)
    scope = {"type": scope_type, "method": "POST", "path": "/x", "headers": list(headers)}
    asyncio.run(middleware(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    return types.SimpleNamespace(status=status, seen=seen_bodies, events=events, reads=events.count("read"), sent=sent)


def test_chunked_body_without_content_length_is_refused_the_moment_it_passes_the_limit():
    result = _run_through_middleware(5000, [b"x" * 1000] * 10)
    assert result.status == 413 and result.seen == [], "the application must never run"
    # 413 headers go out right after the 6th chunk (6000 > 5000); only then is the rest drained.
    assert result.events[:7] == ["read"] * 6 + ["start"]
    assert result.reads == 10 and result.events[-1] == "body", "leftover upload is consumed, then the response finishes"
    head = next(m for m in result.sent if m["type"] == "http.response.start")
    assert (b"connection", b"close") in head["headers"] and (b"content-type", b"application/json") in head["headers"]
    assert b"too large" in next(m for m in result.sent if m["type"] == "http.response.body")["body"]


def test_an_understated_content_length_is_not_trusted():
    result = _run_through_middleware(5000, [b"x" * 2000] * 5, headers=[(b"content-length", b"10")])
    assert result.status == 413 and result.seen == []


@pytest.mark.parametrize("value", [b"abc", b"", b"-5", b"1e9"])
def test_a_malformed_content_length_does_not_disable_the_limit(value: bytes):
    result = _run_through_middleware(5000, [b"x" * 2000] * 5, headers=[(b"content-length", value)])
    assert result.status == 413 and result.seen == []


def test_an_honest_oversize_content_length_is_refused_before_anything_is_buffered():
    result = _run_through_middleware(5000, [b"x" * 9000], headers=[(b"content-length", b"9000")])
    assert result.status == 413 and result.seen == []
    assert result.events[0] == "start", "refused before reading a single byte"


def test_an_oversize_final_chunk_is_not_drained():
    # A finished stream has nothing left to read; under a real server receive() would block here.
    result = _run_through_middleware(5000, [b"x" * 6000])
    assert result.status == 413 and result.reads == 1


def test_draining_is_bounded_so_an_endless_upload_cannot_pin_the_worker():
    result = _run_through_middleware(5000, [b"x" * 1024] * 5000)  # ~5 MiB offered
    assert result.status == 413 and result.seen == []
    assert result.reads < 2000, "drain stops at its cap (1 MiB) instead of consuming the whole stream"
    assert result.events[-1] == "body"


def test_bodies_within_the_limit_are_replayed_unchanged():
    chunks = [b"a" * 1000, b"b" * 1000, b"c" * 500]
    result = _run_through_middleware(5000, chunks)
    assert result.status == 200 and result.seen == [b"".join(chunks)]
    result = _run_through_middleware(5000, [b""])  # bodyless request
    assert result.status == 200 and result.seen == [b""]


def test_the_limit_is_inclusive_at_exactly_the_maximum():
    assert _run_through_middleware(3000, [b"x" * 1500, b"x" * 1500]).status == 200
    assert _run_through_middleware(3000, [b"x" * 1500, b"x" * 1501]).status == 413


def test_non_http_scopes_pass_through():
    result = _run_through_middleware(10, [b"x" * 1000], scope_type="lifespan")
    assert result.status == 200 and result.seen == [b"x" * 1000]


def test_oversize_requests_get_413_on_every_plane_and_the_llm_host(
    client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(pep_config, "max_request_body_bytes", 2048)
    big = json.dumps({"token": "x" * 5000}).encode()
    for path, headers in (("/sessions/init", {}), ("/mcp/tools/list_tables/call", CALLER)):
        response = client.post(path, content=big, headers={**headers, "content-type": "application/json"})
        assert response.status_code == 413, path
        assert response.json() == {"ok": False, "error": "Request body too large (max 2048 bytes)."}
    assert aws.calls == []

    from agentcore_tip import server

    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "2048")
    monkeypatch.setattr(server, "validate_on_startup", lambda: None)
    with TestClient(server.app) as llm_host:
        assert llm_host.post("/invocations", content=big, headers={"content-type": "application/json"}).status_code == 413


def test_plane_b_no_longer_trusts_the_content_length_header():
    source = (Path(__file__).resolve().parent.parent / "agentcore_tip" / "core" / "plane_b_mcp.py").read_text(encoding="utf-8")
    assert 'headers.get("content-length"' not in source and "_check_body_size" not in source


def test_real_listeners_refuse_chunked_oversize_bodies_on_both_ports(monkeypatch: pytest.MonkeyPatch):
    import socket

    import httpx

    from agentcore_tip.core import pep_server

    monkeypatch.setattr(pep_config, "max_request_body_bytes", 4096)

    def free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    port_a, port_b = free_port(), free_port()

    async def chunks(total: int, size: int = 1024):
        sent = 0
        while sent < total:
            yield b"x" * size
            sent += size

    async def scenario() -> dict[str, int]:
        servers = pep_server.build_servers(port_a, port_b)
        for server in servers:
            server.config.host = "127.0.0.1"
        task = asyncio.create_task(pep_server.serve(servers))
        try:
            for _ in range(100):
                if all(s.started for s in servers):
                    break
                await asyncio.sleep(0.1)
            assert all(s.started for s in servers)
            results: dict[str, int] = {}
            headers = {"content-type": "application/json"}
            async with httpx.AsyncClient() as http:
                for label, url in (
                    ("A", f"http://127.0.0.1:{port_a}/sessions/init"),
                    ("B", f"http://127.0.0.1:{port_b}/mcp/tools/list_tables/call"),
                ):
                    big = await http.post(url, content=chunks(64 * 1024), headers=headers)
                    # httpx streams a generator body as chunked transfer encoding: no Content-Length.
                    assert "content-length" not in big.request.headers
                    assert big.request.headers["transfer-encoding"] == "chunked"
                    results[f"{label}-oversize"] = big.status_code
                    small = await http.post(url, content=b"{}", headers=headers)
                    results[f"{label}-small"] = small.status_code
            return results
        finally:
            servers[0].should_exit = True
            await asyncio.wait_for(task, timeout=15)

    results = asyncio.run(scenario())
    assert results["A-oversize"] == 413 and results["B-oversize"] == 413
    # An in-limit request is not refused by the size guard: it reaches the application.
    assert results["A-small"] == 422 and results["B-small"] == 401


def test_invalid_session_ref(client: TestClient, aws: FakeAws):
    for ref in ("sess_" + "0" * 32, "../../etc/passwd", ""):
        body = _call_query(client, ref, "SELECT x FROM lfdb.clients").json()
        assert body == {"ok": False, "error": "Invalid or expired session_ref"}
    assert "sts" not in aws.services_called()


@pytest.mark.parametrize(
    "sql",
    [
        "DROP TABLE lfdb.clients",
        "SELECT * FROM lfdb.clients; DELETE FROM lfdb.clients",
        "INSERT INTO lfdb.clients SELECT * FROM lfdb.other",
        "CREATE TABLE x AS SELECT * FROM lfdb.clients",
        "SELECT 1",
    ],
)
def test_unsafe_sql_is_rejected_before_any_credentials_are_vended(client: TestClient, aws: FakeAws, sql: str):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    body = _call_query(client, session_ref, sql).json()
    assert body["ok"] is False
    assert aws.calls == []


def test_sts_denial_is_reported_without_leaking_details(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub("sts").add_client_error("assume_role", "AccessDenied", "secret internal detail", 403)
    body = _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()
    assert body == {"ok": False, "error": "STS Authorization Denied (AccessDenied)"}


def test_athena_failure_is_reported(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    athena = aws.stub("athena")
    athena.add_response("start_query_execution", {"QueryExecutionId": "q-2"})
    athena.add_response(
        "get_query_execution",
        {"QueryExecution": {"Status": {"State": "FAILED", "StateChangeReason": "SYNTAX_ERROR"}}},
    )
    body = _call_query(client, session_ref, "SELECT x FROM lfdb.clients").json()
    assert body == {"ok": False, "error": plane_b_mcp.QUERY_FAILED_MESSAGE}


def test_list_and_describe_tables(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)

    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_tables", {"TableList": [{"Name": "clients", "TableType": "EXTERNAL_TABLE"}]})
    listed = client.post("/mcp/tools/list_tables/call", headers=CALLER, json={"session_ref": session_ref}).json()
    assert listed["ok"] and listed["tables"] == [{"name": "clients", "table_type": "EXTERNAL_TABLE"}]

    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response(
        "get_table",
        {"Table": {"Name": "clients", "StorageDescriptor": {"Columns": [{"Name": "id", "Type": "bigint"}]}}},
    )
    described = client.post(
        "/mcp/tools/describe_table/call", headers=CALLER, json={"session_ref": session_ref, "table": "Clients"},
    ).json()
    assert described["ok"] and described["columns"] == [{"name": "id", "type": "bigint"}]
    policy = json.loads(aws.assume_role_params[-1]["Policy"])
    assert policy["Statement"][0]["Resource"][-1].endswith(":table/lfdb/clients")


def test_describe_table_rejects_wildcards(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)
    aws.calls.clear()
    body = client.post(
        "/mcp/tools/describe_table/call", headers=CALLER, json={"session_ref": session_ref, "table": "*"},
    ).json()
    assert body["ok"] is False
    assert aws.calls == []


def test_jsonrpc_endpoint(client: TestClient, aws: FakeAws):
    session_ref = _init_session(client, aws)

    listed = client.post("/mcp", headers=CALLER, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()
    assert {t["name"] for t in listed["result"]["tools"]} == {"query_lake_formation", "list_tables", "describe_table"}

    aws.stub_query(rows=[["7"]], header=["n"])
    called = client.post(
        "/mcp",
        headers=CALLER,
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "query_lake_formation", "arguments": {"session_ref": session_ref, "sql": "SELECT n FROM lfdb.t"}},
        },
    ).json()
    assert called["result"]["isError"] is False
    assert json.loads(called["result"]["content"][0]["text"])["rows"] == [{"n": "7"}]

    unknown = client.post("/mcp", headers=CALLER, json={"jsonrpc": "2.0", "id": 3, "method": "nope"}).json()
    assert unknown["error"]["code"] == -32601
    assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"}).status_code == 401


# ---------------------------------------------------------------------------
# Plane A failures
# ---------------------------------------------------------------------------

def test_ingest_rejected_token(client: TestClient, aws: FakeAws):
    aws.stub("sts").add_client_error("assume_role_with_web_identity", "InvalidIdentityToken", "bad token", 400)
    response = client.post("/sessions/init", json={"token": "bad-token-value"})
    assert response.status_code == 401
    assert "InvalidIdentityToken" in response.json()["detail"]
    assert "bad token" not in response.text


def test_ingest_unconfigured(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(pep_config, "sso_client_id", "")
    assert client.post("/sessions/init", json={"token": "x"}).status_code == 503


def test_ingest_requires_token(client: TestClient):
    assert client.post("/sessions/init", json={"token": ""}).status_code == 422


# ---------------------------------------------------------------------------
# Strategy split
# ---------------------------------------------------------------------------

def test_strategy_split_and_legacy_exchange(aws: FakeAws):
    strategy = SsoOidcExchangeStrategy(
        client_id="client", role_arn=CARRIER_ROLE, region="us-east-1", intermediary_role_arn=OIDC_ROLE,
    )
    aws.stub_ingest(subject="u1", context="ctx-1")
    identity = strategy.get_identity_context("idp.jwt")
    assert identity == {"identity_context": "ctx-1", "user_id": "u1"}

    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    creds = strategy.assume_downscoped_role("ctx-1", AGENT_ROLE, '{"Version":"2012-10-17","Statement":[]}')
    assert set(creds) == {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
    assert aws.assume_role_params[-1]["Policy"] == '{"Version":"2012-10-17","Statement":[]}'
    assert aws.assume_role_params[-1]["SourceIdentity"] == AGENT_ROLE

    aws.stub_ingest(subject="u1", context="ctx-2")
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    legacy_creds, expires_at = strategy.exchange("idp.jwt")
    assert legacy_creds["AccessKeyId"].startswith("ASIAFAKEKEY") and expires_at > 0
    assert "Policy" not in aws.assume_role_params[-1]
    assert "SourceIdentity" not in aws.assume_role_params[-1]


@pytest.mark.parametrize("bad", ["", "x", "has space", "a" * 65])
def test_assume_downscoped_role_validates_source_identity(bad: str):
    strategy = SsoOidcExchangeStrategy(client_id="c", role_arn=CARRIER_ROLE)
    with pytest.raises(ValueError):
        strategy.assume_downscoped_role("ctx", bad, "{}")


# ---------------------------------------------------------------------------
# SQL guard
# ---------------------------------------------------------------------------

def test_sql_guard_extracts_tables_and_ignores_ctes():
    sql = "WITH recent AS (SELECT * FROM Sales.Orders) SELECT * FROM recent r JOIN lfdb.clients c ON r.id = c.id"
    cleaned, tables = sql_guard.validate_and_extract_tables(sql, "lfdb")
    assert sorted(tables, key=lambda t: t["table"]) == [
        {"database": "lfdb", "table": "clients"},
        {"database": "sales", "table": "orders"},
    ]
    assert cleaned.upper().startswith("WITH")


def test_sql_guard_strips_catalog_and_trailing_semicolon():
    _, tables = sql_guard.validate_and_extract_tables("SELECT * FROM AwsDataCatalog.lfdb.clients;", "other")
    assert tables == [{"database": "lfdb", "table": "clients"}]


@pytest.mark.parametrize(
    "sql",
    [
        "",
        "SELECT * FROM other_catalog.db.t",
        'SELECT * FROM "a*b"',
        "SELECT * FROM UNNEST(ARRAY[1, 2])",
        "SELECT * INTO new_t FROM t",
        "UPDATE t SET a = 1",
        "SHOW TABLES",
        "SELECT * FROM a; SELECT * FROM b",
        "SELECT FROM WHERE",
    ],
)
def test_sql_guard_rejects(sql: str):
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.validate_and_extract_tables(sql, "lfdb")


def test_sql_guard_policy_size_limit():
    tables = [{"database": "lfdb", "table": f"t{i}_" + "x" * 120} for i in range(10)]
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.generate_downscoped_policy(tables, region="us-east-1", account_id="123456789012", workgroup="w")


def test_sql_guard_policy_rejects_injected_identifiers():
    with pytest.raises(sql_guard.SQLGuardError):
        sql_guard.generate_downscoped_policy([{"database": "lfdb", "table": "t*"}])


# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------

def test_session_store_ttl_and_malformed_refs(monkeypatch: pytest.MonkeyPatch):
    store = SessionStore()

    async def scenario() -> None:
        ref = await store.create_session("ctx", "user-1", ttl=60)
        assert (await store.get_session(ref))["user_id"] == "user-1"
        assert await store.get_session("sess_nothex") is None
        assert await store.get_session("") is None

        import time as time_module

        real_time = time_module.time
        monkeypatch.setattr(time_module, "time", lambda: real_time() + 3600)
        assert await store.get_session(ref) is None

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Architectural guardrails
# ---------------------------------------------------------------------------

def test_route_modules_are_plain_python_with_inspectable_signatures():
    from agentcore_tip.core import pep_server

    for module in (plane_a_ingest, plane_b_mcp, pep_server):
        assert module.__file__.endswith(".py")
    for module in (plane_a_ingest, plane_b_mcp):
        for route in (r for r in module.router.routes if hasattr(r, "endpoint")):
            inspect.signature(route.endpoint)


def test_default_build_is_pure_python():
    root = Path(__file__).resolve().parent.parent
    active_build_files = (
        "pyproject.toml",
        "setup.py",
        "Dockerfile.ecr-test",
        "build.sh",
        "build.ps1",
    )
    for name in active_build_files:
        text = (root / name).read_text(encoding="utf-8")
        assert "Cython" not in text and "cythonize" not in text.lower(), name
    assert not (root / "pyproject.cython.toml").exists()


def test_invocations_runner_executes_off_the_event_loop(monkeypatch: pytest.MonkeyPatch):
    from agentcore_tip import server

    observed: dict[str, bool] = {}

    def runner(context, payload):
        try:
            asyncio.get_running_loop()
            observed["on_loop"] = True
        except RuntimeError:
            observed["on_loop"] = False
        return {"ok": True}

    monkeypatch.setattr(server, "_registered_runner", runner)
    monkeypatch.setattr(server, "validate_on_startup", lambda: None)
    with TestClient(server.app) as test_client:
        response = test_client.post("/invocations", json={"question": "hi"})
    assert response.status_code == 200 and response.json() == {"ok": True}
    assert observed == {"on_loop": False}


def test_no_llm_or_bedrock_in_pep_modules():
    root = Path(__file__).resolve().parent.parent / "agentcore_tip" / "core"
    for name in ("pep_server.py", "plane_a_ingest.py", "plane_b_mcp.py", "sql_guard.py", "session_store.py"):
        source = (root / name).read_text(encoding="utf-8").lower()
        assert "converse" not in source and "bedrock-runtime" not in source, name


# ---------------------------------------------------------------------------
# Network isolation: port separation and no monolith remnants in the PEP
# ---------------------------------------------------------------------------

def _paths(app) -> set[str]:
    return set(app.openapi()["paths"])


def test_each_plane_serves_only_its_own_routes():
    plane_a_paths, plane_b_paths = _paths(plane_a_app), _paths(plane_b_app)
    assert "/sessions/init" in plane_a_paths
    assert not any(p.startswith("/mcp") for p in plane_a_paths)
    assert "/mcp/tools/{tool_name}/call" in plane_b_paths and "/mcp" in plane_b_paths
    assert not any(p.startswith("/sessions") for p in plane_b_paths)

    with DualClient() as dual:
        assert dual.plane_a.get("/mcp/tools").status_code == 404
        assert dual.plane_a.post("/mcp/tools/list_tables/call", headers=CALLER, json={}).status_code == 404
        assert dual.plane_b.post("/sessions/init", json={"token": "idp.jwt.value"}).status_code == 404


def test_plane_ports_default_to_8080_and_8081():
    from agentcore_tip.core.config import PEPConfig

    config = PEPConfig.from_env()
    assert (config.plane_a_port, config.plane_b_port) == (8080, 8081)


def test_llm_host_does_not_mount_pep_planes():
    from agentcore_tip import server

    paths = _paths(server.app)
    assert not any(p.startswith(("/sessions", "/mcp")) for p in paths)
    source = (Path(__file__).resolve().parent.parent / "agentcore_tip" / "server.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(from|import)\s+[\w.]*(plane_a_ingest|plane_b_mcp|session_store|pep_server)", source, re.MULTILINE)


def test_pep_process_does_not_import_context_or_agent_modules():
    import subprocess
    import sys

    root = Path(__file__).resolve().parent.parent
    code = (
        "import tests.conftest, sys; import agentcore_tip.core.pep_server; "
        "banned = [m for m in ('agentcore_tip.core.context', 'agentcore_tip.core.agentcore_provider', "
        "'agentcore_tip.server', 'agentcore_tip.core.decorators', 'agentcore_tip.core.credentials') if m in sys.modules]; "
        "print('BANNED=' + ','.join(banned))"
    )
    result = subprocess.run([sys.executable, "-W", "ignore", "-c", code], cwd=root, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert "BANNED=" in result.stdout and result.stdout.strip().endswith("BANNED="), result.stdout


def test_build_servers_requires_distinct_ports():
    from agentcore_tip.core import pep_server

    with pytest.raises(ValueError):
        pep_server.build_servers(9000, 9000)


def test_serve_runs_two_listeners_on_separate_ports():
    import socket

    import httpx

    from agentcore_tip.core import pep_server

    def free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    port_a, port_b = free_port(), free_port()

    async def scenario() -> tuple[dict, dict, int, int]:
        servers = pep_server.build_servers(port_a, port_b)
        for server in servers:
            server.config.host = "127.0.0.1"
        task = asyncio.create_task(pep_server.serve(servers))
        try:
            for _ in range(100):
                if all(s.started for s in servers):
                    break
                await asyncio.sleep(0.1)
            assert all(s.started for s in servers), "both planes must start"
            async with httpx.AsyncClient() as http:
                a_ping = (await http.get(f"http://127.0.0.1:{port_a}/ping")).json()
                b_ping = (await http.get(f"http://127.0.0.1:{port_b}/ping")).json()
                a_mcp = (await http.get(f"http://127.0.0.1:{port_a}/mcp/tools")).status_code
                b_sessions = (await http.post(f"http://127.0.0.1:{port_b}/sessions/init", json={"token": "x" * 8})).status_code
            return a_ping, b_ping, a_mcp, b_sessions
        finally:
            servers[0].should_exit = True  # one plane stopping must stop the other
            await asyncio.wait_for(task, timeout=15)
            assert not any(s.started for s in servers[1:]) or all(s.should_exit for s in servers)

    a_ping, b_ping, a_mcp, b_sessions = asyncio.run(scenario())
    assert a_ping["service"] == "pep-plane-a" and b_ping["service"] == "pep-plane-b"
    assert a_mcp == 404 and b_sessions == 404


# ---------------------------------------------------------------------------
# MFA test client (examples/mfa_pep_client.py) driven against the in-process PEP
# ---------------------------------------------------------------------------

def _run_mfa_client(monkeypatch: pytest.MonkeyPatch, test_client: TestClient, token: str, *extra: str) -> int:
    from examples import mfa_pep_client

    monkeypatch.setattr(mfa_pep_client.httpx, "Client", lambda **_: test_client)
    monkeypatch.setattr(
        "sys.argv",
        ["mfa_pep_client", "--token", token, "--plane-a-url", "http://pep-a", "--plane-b-url", "http://pep-b", *extra],
    )
    return mfa_pep_client.main()


def test_mfa_client_full_flow(client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch, capsys):
    token = jwt.encode({"sub": "user-123", "amr": ["pwd", "mfa"]}, "k", algorithm="HS256")
    aws.stub_ingest()
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_tables", {"TableList": [{"Name": "clients"}]})
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_table", {"Table": {"Name": "clients", "StorageDescriptor": {"Columns": []}}})
    aws.stub_query(rows=[["1"]], header=["id"])
    aws.stub_query(rows=[["1"]], header=["id"])  # the workgroup-spoofing negative check runs a real query
    for reason in ("TABLE_NOT_FOUND: lfdb.zz_no_such_table_qa7", "COLUMN_NOT_FOUND: zz_no_such_col_qa7"):
        aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
        aws.stub("athena").add_response("start_query_execution", {"QueryExecutionId": "q-miss"})
        aws.stub("athena").add_response("get_query_execution", {"QueryExecution": {"Status": {
            "State": "FAILED", "StateChangeReason": reason}}})
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_client_error("get_table", "EntityNotFoundException", "Table zz_no_such_table_qa7 not found", 400)

    assert _run_mfa_client(monkeypatch, client, token, "--require-mfa", "--negative-checks") == 0
    output = capsys.readouterr().out
    assert "RESULT: PASS" in output
    assert token not in output
    assert "FAIL" not in output


def test_mfa_client_refuses_token_without_mfa(client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch):
    token = jwt.encode({"sub": "user-123", "amr": ["pwd"]}, "k", algorithm="HS256")
    with pytest.raises(SystemExit):
        _run_mfa_client(monkeypatch, client, token, "--require-mfa")
    assert aws.calls == []


@pytest.mark.parametrize("claims", [{"sub": "user-123"}, {"sub": "user-123", "amr": []}])
def test_mfa_client_allows_missing_or_empty_amr(
    client: TestClient, aws: FakeAws, monkeypatch: pytest.MonkeyPatch, capsys, claims: dict,
):
    token = jwt.encode(claims, "k", algorithm="HS256")
    aws.stub_ingest()
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_tables", {"TableList": []})
    aws.stub("sts").add_response("assume_role", {"Credentials": _sts_credentials()})
    aws.stub("glue").add_response("get_table", {"Table": {"Name": "clients", "StorageDescriptor": {"Columns": []}}})
    aws.stub_query(rows=[["1"]], header=["id"])

    assert _run_mfa_client(monkeypatch, client, token, "--require-mfa") == 0
    output = capsys.readouterr().out
    assert "no 'amr' claim" in output and "RESULT: PASS" in output
