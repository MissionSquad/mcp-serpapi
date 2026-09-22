"""MissionSquad hidden secret injection.

MissionSquad's mcp-api stores each user's secrets for this server and merges
them into every ``tools/call`` as top-level arguments named by the server's
declared ``secretNames`` (see ``missionsquad/registration.json``). They are not
in any tool's input schema, so the model never sees or supplies them.

Python FastMCP has no equivalent of ``context.extraArgs``: it validates tool
arguments against the function signature and rejects undeclared keys with an
error that echoes the value back to the caller and into the server log.
``HiddenArgsMiddleware`` removes the declared hidden names before validation
and exposes them to the current tool call only, through ``get_hidden_args()``.
FastMCP also logs the raw arguments of every call at DEBUG before middleware
runs; ``install_log_redaction()`` masks the hidden values in that record.
"""

import logging
from collections.abc import Mapping
from contextvars import ContextVar
from types import MappingProxyType
from typing import Any

import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult

# The user's SerpApi API key.
API_KEY_ARG = "apiKey"

# Must match `secretNames` in missionsquad/registration.json.
HIDDEN_ARG_NAMES = frozenset({API_KEY_ARG})

_NO_HIDDEN_ARGS: Mapping[str, Any] = MappingProxyType({})

# FastMCP logs "Handler called: call_tool <name> with <arguments>" here at DEBUG.
_TOOL_CALL_LOGGER = "fastmcp.server.mixins.mcp_operations"

# A ContextVar rather than ctx.set_state(): FastMCP state is session-scoped by
# default, and mcp-api sends every user's calls over one stdio session. Each
# request runs in its own task, so a value set here is visible to this call only.
_hidden_args: ContextVar[Mapping[str, Any]] = ContextVar(
    "hidden_args", default=_NO_HIDDEN_ARGS
)


def get_hidden_args() -> Mapping[str, Any]:
    """Hidden values injected into the current tool call; empty outside one."""
    return _hidden_args.get()


def read_hidden_string(name: str) -> str | None:
    """Return the trimmed hidden value ``name``, or None when it was not injected.

    Raises RuntimeError with a user-facing message when the value is present but
    is not a non-empty string. The message never includes the value.
    """
    value = get_hidden_args().get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RuntimeError(f'Error: Hidden argument "{name}" must be a string.')
    value = value.strip()
    if not value:
        raise RuntimeError(f'Error: Hidden argument "{name}" must not be empty.')
    return value


class HiddenArgsMiddleware(Middleware):
    """Move declared hidden arguments out of a tool call before validation."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        arguments = context.message.arguments or {}
        hidden = {
            name: value for name, value in arguments.items() if name in HIDDEN_ARG_NAMES
        }
        visible = {
            name: value
            for name, value in arguments.items()
            if name not in HIDDEN_ARG_NAMES
        }
        message = context.message.model_copy(update={"arguments": visible})
        token = _hidden_args.set(MappingProxyType(hidden))
        try:
            return await call_next(context.copy(message=message))
        finally:
            _hidden_args.reset(token)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping) and HIDDEN_ARG_NAMES & value.keys():
        return {
            name: "[REDACTED]" if name in HIDDEN_ARG_NAMES else item
            for name, item in value.items()
        }
    return value


class HiddenArgsLogFilter(logging.Filter):
    """Mask hidden values in log records that carry tool-call arguments.

    Replaces the record's arguments with redacted copies, so the dict the tool
    call itself uses is never modified.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(_redact(arg) for arg in record.args)
        elif isinstance(record.args, Mapping):
            record.args = _redact(record.args)
        return True


def install_log_redaction() -> None:
    """Attach ``HiddenArgsLogFilter`` to FastMCP's tool-call logger once.

    A logger filter runs before any handler formats the record, whatever the
    configured level or handlers.
    """
    logger = logging.getLogger(_TOOL_CALL_LOGGER)
    if not any(isinstance(f, HiddenArgsLogFilter) for f in logger.filters):
        logger.addFilter(HiddenArgsLogFilter())
