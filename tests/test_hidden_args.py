"""MissionSquad hidden secret injection (src/hidden_args.py).

mcp-api merges each user's declared secrets into every tools/call as top-level
arguments. These tests drive the real server through an in-memory FastMCP
client, the HTTP app and the stdio entry point, so they pin the whole path: the
middleware removes the hidden key before argument validation, the resolver
applies it ahead of every fallback, and the key reaches SerpApi only as
`api_key`, never in a tool result or a log record.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

import mcp.types as mt
import pytest
import requests
import serpapi
from fastmcp import Client, FastMCP
from fastmcp.client.transports import PythonStdioTransport
from fastmcp.server.middleware import MiddlewareContext
from serpapi.models import SerpResults
from starlette.testclient import TestClient
from urllib3 import HTTPSConnectionPool
from urllib3.exceptions import MaxRetryError, NewConnectionError

import src.mcp_components.tools as mcp_tools
import src.server as server
from src.hidden_args import (
    HIDDEN_ARG_NAMES,
    HiddenArgsLogFilter,
    HiddenArgsMiddleware,
    get_hidden_args,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRATION = json.loads(
    (ROOT / "missionsquad" / "registration.json").read_text(encoding="utf-8")
)
SECRET = "hidden-user-key-0123456789abcdef"
TOOLS = ("search", "search_table", "search_dashboard")
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


@pytest.fixture
def searches(monkeypatch):
    """Record every SerpApi request instead of sending it."""
    captured = []

    def fake_search(params):
        captured.append(dict(params))
        return SerpResults({"organic_results": []}, client=None)

    monkeypatch.setattr(mcp_tools.serpapi, "search", fake_search)
    return captured


@pytest.fixture
def no_env_key(monkeypatch):
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.setFormatter(logging.Formatter())
        self.messages = []

    def emit(self, record):
        self.messages.append(self.format(record))


@pytest.fixture
def log_messages():
    """Every log record at any level, formatted with its traceback.

    FastMCP's logger does not propagate to the root logger, so pytest's caplog
    would miss its records; attach to it directly.
    """
    handler = _Records()
    loggers = [
        logging.getLogger(),
        logging.getLogger("fastmcp"),
        logging.getLogger("mcp"),
    ]
    levels = [logger.level for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
    yield handler.messages
    for logger, level in zip(loggers, levels):
        logger.removeHandler(handler)
        logger.setLevel(level)


async def call(name, arguments):
    async with Client(server.mcp) as client:
        return await client.call_tool_mcp(name, arguments)


def result_text(result):
    return json.dumps(result.model_dump(mode="json"))


def transport_error(api_key):
    """A connection failure as requests and serpapi raise it before any response."""
    pool = HTTPSConnectionPool("serpapi.com", 443)
    url = f"/search?engine=google_light&q=x&api_key={api_key}"
    reason = NewConnectionError(pool, "Failed to resolve 'serpapi.com'")
    return serpapi.exceptions.HTTPConnectionError(
        requests.exceptions.ConnectionError(MaxRetryError(pool, url, reason))
    )


# --- Tool surface and MissionSquad registration ------------------------------


async def test_no_tool_schema_declares_a_hidden_name():
    # A hidden name declared as a public field would be taken from the model's
    # arguments by the middleware, and would put the secret in the schema.
    async with Client(server.mcp) as client:
        tools = await client.list_tools()
    assert {tool.name for tool in tools} >= set(TOOLS)
    for tool in tools:
        assert not HIDDEN_ARG_NAMES & set(tool.input_schema.get("properties", {}))
        for name in HIDDEN_ARG_NAMES:
            assert name not in (tool.description or "")


def test_registration_declares_exactly_the_hidden_names():
    secret_names = REGISTRATION["secretNames"]
    assert sorted(secret_names) == sorted(HIDDEN_ARG_NAMES)
    assert len(secret_names) == len(set(secret_names))
    assert [field["name"] for field in REGISTRATION["secretFields"]] == secret_names
    assert "secretName" not in REGISTRATION  # legacy single-secret field


def test_registration_secret_fields_are_complete_password_inputs():
    for field in REGISTRATION["secretFields"]:
        assert field["inputType"] == "password"
        assert field["label"].strip()
        assert field["description"].strip()
        assert isinstance(field["required"], bool)
    required = {f["name"]: f["required"] for f in REGISTRATION["secretFields"]}
    assert required == {"apiKey": True}


def test_registration_launches_the_stdio_entry_point_without_a_server_key():
    assert REGISTRATION["transportType"] == "stdio"
    assert REGISTRATION["command"] == "uv"
    assert (ROOT / REGISTRATION["args"][-1]).is_file()
    assert REGISTRATION["args"][-1] == "src/stdio.py"
    # A process-wide key would be spent on every user who has not set their own.
    assert "SERPAPI_API_KEY" not in json.dumps(REGISTRATION)


# --- Resolution and precedence -----------------------------------------------


@pytest.mark.parametrize("name", TOOLS)
async def test_hidden_key_reaches_serpapi_only_as_api_key(name, searches, no_env_key):
    result = await call(name, {"params": {"q": "x"}, "apiKey": SECRET})

    assert not result.is_error
    assert len(searches) == 1
    sent = searches[0]
    assert sent["api_key"] == SECRET
    assert [key for key, value in sent.items() if value == SECRET] == ["api_key"]
    assert not HIDDEN_ARG_NAMES & set(sent)


@pytest.mark.parametrize("name", TOOLS)
async def test_hidden_key_overrides_env_fallback(name, searches, monkeypatch):
    monkeypatch.setenv("SERPAPI_API_KEY", "ENVKEY")
    await call(name, {"params": {"q": "x"}, "apiKey": SECRET})
    assert searches[0]["api_key"] == SECRET


async def test_env_fallback_applies_without_hidden_key(searches, monkeypatch):
    monkeypatch.setenv("SERPAPI_API_KEY", "ENVKEY")
    result = await call("search", {"params": {"q": "x"}})
    assert not result.is_error
    assert searches[0]["api_key"] == "ENVKEY"


async def test_null_hidden_key_is_treated_as_absent(searches, monkeypatch):
    monkeypatch.setenv("SERPAPI_API_KEY", "ENVKEY")
    await call("search", {"params": {"q": "x"}, "apiKey": None})
    assert searches[0]["api_key"] == "ENVKEY"


async def test_hidden_key_is_trimmed(searches, no_env_key):
    await call("search", {"params": {"q": "x"}, "apiKey": f"  {SECRET}\n"})
    assert searches[0]["api_key"] == SECRET


async def test_hidden_key_wins_over_caller_supplied_api_key_param(searches, no_env_key):
    await call("search", {"params": {"q": "x", "api_key": "MODEL"}, "apiKey": SECRET})
    assert searches[0]["api_key"] == SECRET


@pytest.mark.parametrize("name", TOOLS)
async def test_missing_key_names_the_missionsquad_secret(name, searches, no_env_key):
    result = await call(name, {"params": {"q": "x"}})

    text = result_text(result)
    assert "Missing API key" in text
    assert "secret name: apiKey" in text
    assert "SERPAPI_API_KEY" in text
    assert searches == []


@pytest.mark.parametrize(
    "value, message",
    [
        (123, 'Hidden argument \\"apiKey\\" must be a string.'),
        (["k"], 'Hidden argument \\"apiKey\\" must be a string.'),
        ({"k": "v"}, 'Hidden argument \\"apiKey\\" must be a string.'),
        (True, 'Hidden argument \\"apiKey\\" must be a string.'),
        ("", 'Hidden argument \\"apiKey\\" must not be empty.'),
        ("   ", 'Hidden argument \\"apiKey\\" must not be empty.'),
    ],
    ids=["int", "list", "object", "bool", "empty", "whitespace"],
)
@pytest.mark.parametrize("name", TOOLS)
async def test_invalid_hidden_key_is_a_user_facing_error(
    name, value, message, searches, monkeypatch
):
    # A malformed hidden value is a configuration error: it must not quietly
    # fall back to a key from the environment.
    monkeypatch.setenv("SERPAPI_API_KEY", "ENVKEY")
    result = await call(name, {"params": {"q": "x"}, "apiKey": value})

    assert message in result_text(result)
    assert searches == []
    if name == "search":
        assert result.is_error


# --- HTTP transport ----------------------------------------------------------


@pytest.fixture
def http():
    with TestClient(server.starlette_app) as client:
        yield client


def http_search(http, path="/mcp", headers=None, arguments=None):
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "search", "arguments": arguments},
    }
    response = http.post(path, json=body, headers={**MCP_HEADERS, **(headers or {})})
    assert response.status_code == 200
    return response.json()["result"]


def test_http_hidden_key_overrides_the_request_key(http, searches):
    http_search(
        http,
        headers={"Authorization": "Bearer HEADERKEY"},
        arguments={"params": {"q": "x"}, "apiKey": SECRET},
    )
    assert searches[0]["api_key"] == SECRET


def test_http_hidden_key_works_without_a_request_key(http, searches, monkeypatch):
    monkeypatch.setenv("SERPAPI_API_KEY", "ENVKEY")  # never used over HTTP
    result = http_search(http, arguments={"params": {"q": "x"}, "apiKey": SECRET})
    assert not result["isError"]
    assert searches[0]["api_key"] == SECRET


def test_http_request_key_still_applies_without_a_hidden_key(http, searches):
    http_search(
        http,
        headers={"Authorization": "Bearer HEADERKEY"},
        arguments={"params": {"q": "x"}},
    )
    assert searches[0]["api_key"] == "HEADERKEY"


# --- Isolation between users -------------------------------------------------


async def test_concurrent_calls_each_see_only_their_own_hidden_key():
    # Both calls must be inside the tool at once before either reads its key a
    # second time, so a value shared across calls would be observed.
    probe = FastMCP("probe", middleware=[HiddenArgsMiddleware()])
    arrived = 0
    both_inside = asyncio.Event()

    @probe.tool
    async def whoami(label: str) -> dict:
        nonlocal arrived
        before = get_hidden_args().get("apiKey")
        arrived += 1
        if arrived == 2:
            both_inside.set()
        await asyncio.wait_for(both_inside.wait(), timeout=5)
        return {
            "label": label,
            "before": before,
            "after": get_hidden_args().get("apiKey"),
        }

    async with Client(probe) as client:
        results = await asyncio.gather(
            client.call_tool("whoami", {"label": "alice", "apiKey": "ALICE"}),
            client.call_tool("whoami", {"label": "bob", "apiKey": "BOB"}),
        )

    seen = {r.structured_content["label"]: r.structured_content for r in results}
    assert seen["alice"]["before"] == seen["alice"]["after"] == "ALICE"
    assert seen["bob"]["before"] == seen["bob"]["after"] == "BOB"


async def test_many_users_on_one_server_each_search_with_their_own_key(
    searches, no_env_key
):
    async with Client(server.mcp) as client:
        await asyncio.gather(
            *(
                client.call_tool_mcp(
                    "search", {"params": {"q": f"user{n}"}, "apiKey": f"KEY{n}"}
                )
                for n in range(20)
            )
        )

    assert len(searches) == 20
    assert {sent["q"]: sent["api_key"] for sent in searches} == {
        f"user{n}": f"KEY{n}" for n in range(20)
    }


async def test_a_call_without_a_hidden_key_does_not_inherit_one(searches, no_env_key):
    async with Client(server.mcp) as client:
        await client.call_tool_mcp("search", {"params": {"q": "a"}, "apiKey": SECRET})
        result = await client.call_tool_mcp("search", {"params": {"q": "b"}})

    assert result.is_error
    assert "Missing API key" in result_text(result)
    assert [sent["q"] for sent in searches] == ["a"]


async def test_middleware_scopes_hidden_values_to_the_call():
    seen = {}

    async def call_next(context):
        seen["hidden"] = dict(get_hidden_args())
        seen["arguments"] = context.message.arguments
        raise RuntimeError("tool failed")

    context = MiddlewareContext(
        message=mt.CallToolRequestParams(
            name="search", arguments={"params": {"q": "x"}, "apiKey": SECRET}
        ),
        method="tools/call",
    )
    with pytest.raises(RuntimeError, match="tool failed"):
        await HiddenArgsMiddleware().on_call_tool(context, call_next)

    assert seen == {"hidden": {"apiKey": SECRET}, "arguments": {"params": {"q": "x"}}}
    assert dict(get_hidden_args()) == {}  # reset even though the tool raised


# --- The key never leaks into results or logs --------------------------------


async def test_unknown_argument_is_still_rejected_without_echoing_the_key(
    searches, no_env_key, log_messages
):
    result = await call("search", {"params": {"q": "x"}, "bogus": 1, "apiKey": SECRET})

    assert result.is_error
    assert "bogus" in result_text(result)
    assert SECRET not in result_text(result)
    # Positive control: FastMCP did log the rejected call, without the key.
    assert any("Invalid arguments for tool 'search'" in m for m in log_messages)
    assert not any(SECRET in m for m in log_messages)
    assert searches == []


@pytest.mark.parametrize("name", TOOLS)
async def test_successful_calls_never_log_the_key(
    name, searches, no_env_key, log_messages
):
    await call(name, {"params": {"q": "x"}, "apiKey": SECRET})
    # Positive control: the DEBUG record carrying the call's arguments was emitted.
    assert any(f"call_tool {name} with" in m for m in log_messages)
    assert not any(SECRET in m for m in log_messages)
    # Redacting the log record must not change the arguments the call used.
    assert searches[0]["api_key"] == SECRET


def test_log_filter_redacts_copies_and_leaves_other_records_alone():
    arguments = {"params": {"q": "x"}, "apiKey": SECRET}
    record = logging.LogRecord(
        "fastmcp",
        logging.DEBUG,
        __file__,
        1,
        "call %s with %s",
        ("search", arguments),
        None,
    )
    other = logging.LogRecord("x", logging.INFO, __file__, 1, "n=%s", (1,), None)

    assert HiddenArgsLogFilter().filter(record)
    assert HiddenArgsLogFilter().filter(other)
    assert record.getMessage() == (
        "call search with {'params': {'q': 'x'}, 'apiKey': '[REDACTED]'}"
    )
    assert arguments["apiKey"] == SECRET
    assert other.args == (1,)


def test_transport_error_fixture_quotes_the_key_like_the_real_client():
    # Guards the redaction tests below: the unredacted message must contain the key.
    assert f"api_key={SECRET}" in str(transport_error(SECRET))


def test_map_search_error_redacts_the_key_from_transport_errors():
    out = mcp_tools.map_search_error(transport_error(SECRET))
    assert SECRET not in out
    assert "api_key=[REDACTED]" in out
    assert "Max retries exceeded" in out


@pytest.mark.parametrize("name", TOOLS)
async def test_transport_error_result_does_not_echo_the_key(
    name, monkeypatch, no_env_key, log_messages
):
    def failing_search(params):
        raise transport_error(params["api_key"])

    monkeypatch.setattr(mcp_tools.serpapi, "search", failing_search)
    result = await call(name, {"params": {"q": "x"}, "apiKey": SECRET})

    assert "api_key=[REDACTED]" in result_text(result)
    assert SECRET not in result_text(result)
    assert not any(SECRET in m for m in log_messages)


# --- Production entry point --------------------------------------------------


async def test_stdio_entry_point_starts_without_a_key_and_reads_the_hidden_one(
    tmp_path,
):
    env = {k: v for k, v in os.environ.items() if k != "SERPAPI_API_KEY"}
    transport = PythonStdioTransport(
        ROOT / "src" / "stdio.py", env=env, cwd=str(tmp_path), keep_alive=False
    )
    async with Client(transport) as client:
        tools = await client.list_tools()
        missing = await client.call_tool_mcp("search", {"params": {"q": "x"}})
        # A non-string key fails in the resolver, before any network call, which
        # proves the hidden argument crossed the real stdio transport and passed
        # argument validation.
        invalid = await client.call_tool_mcp(
            "search", {"params": {"q": "x"}, "apiKey": 123}
        )

    for tool in tools:
        assert not HIDDEN_ARG_NAMES & set(tool.input_schema.get("properties", {}))
    assert missing.is_error
    assert "secret name: apiKey" in missing.content[0].text
    assert invalid.is_error
    assert (
        invalid.content[0].text == 'Error: Hidden argument "apiKey" must be a string.'
    )
