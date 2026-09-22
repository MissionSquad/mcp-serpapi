# MissionSquad Hidden Secret Refactor: mcp-serpapi

Package-specific refactor guide for moving this server's SerpApi API key into
MissionSquad hidden secret injection. Written against the reviewed code on
`main` at `cdbc1fd` (FastMCP 4.0.3, mcp 2.2.0, pydantic 2.12.4, serpapi 1.1.1).

## 1. Current state

### Runtime

- Python server on Python FastMCP (`fastmcp[apps]`), not `@missionsquad/fastmcp`.
- Two entry points share one `FastMCP` instance (`src/server.py`):
  - `src/stdio.py`: stdio transport, used by local hosts (Claude Desktop bundle)
    and by MissionSquad `mcp-api`.
  - `src/server.py` `starlette_app`: streamable HTTP, SerpApi's hosted
    deployment (`mcp.serpapi.com`).
- Tools: `search` (`src/mcp_components/tools.py`), `search_table` and
  `search_dashboard` (`src/mcp_components/apps.py`). All three reach SerpApi
  through `fetch_search_response()`, which calls `resolve_api_key()`.
- Resources: `serpapi://engines` and `serpapi://engines/{engine_name}`; no auth.

### Auth and hidden-input inventory

| Input | Source today | Used by | Classification |
|---|---|---|---|
| SerpApi API key (stdio) | `SERPAPI_API_KEY` env, read per call in `resolve_api_key()` | all three tools | **hidden, injected per user** (`apiKey`); env kept as local fallback |
| SerpApi API key (HTTP) | `Authorization: Bearer` header or `/{key}/mcp` path, set on `request.state` by `ApiKeyMiddleware` | all three tools | per-request transport auth; unchanged, lower precedence than hidden `apiKey` |
| `params.api_key` | visible tool arg | ignored: `fetch_search_response()` sets `api_key` last | visible business input that is already neutralized; unchanged |
| `MCP_HOST`, `MCP_PORT` | env | HTTP entry point only | deployment config, not user-specific; unchanged |
| SerpApi base URL | constant in the `serpapi` library | n/a | not configurable; no hidden field |

### Verified defects against the hidden-secret contract

1. **No hidden-argument path.** Python FastMCP has no `context.extraArgs`.
   Tool arguments are validated with a pydantic `TypeAdapter` built from the
   function signature, which rejects undeclared keys. A MissionSquad call with
   an injected top-level `apiKey` fails every tool with
   `unexpected_keyword_argument`.
2. **The rejected secret is echoed.** That validation error includes
   `input_value='<the key>'` in the tool result returned to the model, and
   FastMCP logs `Invalid arguments for tool ...` with `'input': '<the key>'`
   at WARNING.
3. **Connection errors echo the key.** When the request to SerpApi fails
   before a response (DNS failure, refused connection, connect timeout),
   `map_search_error()` falls back to `str(exception)`, which contains the
   full request URL including `api_key=<the key>`. The tool result carries it
   to the model.
4. **Env-only stdio auth.** Over stdio the key comes only from the process
   environment, so a shared MissionSquad process can serve one key at most.
5. **Raw arguments in the DEBUG log.** FastMCP's wire handler
   (`fastmcp/server/mixins/mcp_operations.py`) logs
   `Handler called: call_tool <name> with <arguments>` at DEBUG before any
   middleware runs. With hidden injection, that record would carry every
   user's key whenever DEBUG logging is enabled. (Found by the log-capture
   tests written for this refactor.)

## 2. Target contract

### Hidden inputs

| Name | Required | Kind | Env fallback | Normalization |
|---|---|---|---|---|
| `apiKey` | yes | true secret | `SERPAPI_API_KEY` (stdio only) | must be a string; trimmed; empty after trimming is an error |

One execution target per call. No base URL, account, or multi-key topology is
modelled. No cross-field rules.

### Precedence (every tool call)

1. Hidden `apiKey` injected into the call.
2. Transport fallback:
   - HTTP: the key `ApiKeyMiddleware` attached to the request. The hosted
     server never reads the environment (existing guarantee, kept).
   - stdio: `SERPAPI_API_KEY`, for local standalone use.
3. User-facing error naming the exact fix.

### MissionSquad registration

`missionsquad/registration.json` is the registration payload for `mcp-api`.
`secretNames` must equal `HIDDEN_ARG_NAMES` in `src/hidden_args.py`; a test
enforces this so the two cannot drift.

## 3. Design

### Runtime mechanism (Python equivalent of `context.extraArgs`)

`src/hidden_args.py` adds `HiddenArgsMiddleware`, registered on the `FastMCP`
instance. FastMCP runs server middleware on `tools/call` before tool lookup
and argument validation, and the core call path reads the arguments from the
middleware's (possibly replaced) `context.message`. The middleware:

1. Takes the declared hidden names (`HIDDEN_ARG_NAMES`) out of the call's
   arguments before validation, so pydantic never sees or echoes them.
2. Stores them in a `ContextVar` for the duration of that one call and resets
   it in `finally`.
3. Leaves every other argument alone, so unknown visible arguments are still
   rejected exactly as before.

Why a `ContextVar` and not `ctx.set_state()`: FastMCP 4 state is
session-scoped by default, and `mcp-api` multiplexes every user's calls over
one stdio session. A `ContextVar` set inside the call's own task is
per-call. The MCP server handles each request in its own task, so concurrent
calls cannot see each other's values.

Why an explicit name list instead of "all undeclared keys": it keeps the
hidden contract explicit (handbook Rule 10) and preserves the existing error
for mistyped visible arguments.

### Resolver

`read_hidden_string(name)` in `src/hidden_args.py` validates type and
emptiness and trims. `resolve_api_key()` in `src/mcp_components/tools.py`
applies the precedence above. Tool handlers never touch hidden values
directly; they keep calling `fetch_search_response()` / `fetch_search_data()`.

### Client factory

`serpapi.search` is a module-level, unauthenticated client; the key travels
per call as the `api_key` query parameter, set last in
`fetch_search_response()` so `params` cannot override it. No per-user client
or cache is introduced. The client's shared `requests.Session` carries no
SerpApi auth (auth is the query parameter). **No caches or background timers
exist or are added.**

### Error redaction

`map_search_error()` redacts `api_key=<value>` from any fallback error text
before it becomes a tool result.

### Log redaction

`install_log_redaction()` attaches `HiddenArgsLogFilter` to FastMCP's
tool-call logger (`fastmcp.server.mixins.mcp_operations`). A logger filter
runs before any handler formats the record, whatever the configured level or
handlers, and it swaps in a redacted copy of the arguments so the dict the
call uses is untouched. The MCP SDK's stdio and streamable HTTP transports do
not log request bodies. If a FastMCP upgrade moves that log line to another
logger, the log-capture tests fail.

## 4. File-by-file changes

| File | Change |
|---|---|
| `src/hidden_args.py` (new) | `API_KEY_ARG`, `HIDDEN_ARG_NAMES`, `HiddenArgsMiddleware`, `get_hidden_args()`, `read_hidden_string()`, `HiddenArgsLogFilter`, `install_log_redaction()` |
| `src/server.py` | register `HiddenArgsMiddleware` on the `FastMCP` instance; call `install_log_redaction()` |
| `src/mcp_components/tools.py` | `resolve_api_key()` reads hidden `apiKey` first; stdio missing-key and 401 messages name the MissionSquad secret; `map_search_error()` redacts `api_key=` values |
| `missionsquad/registration.json` (new) | `mcp-api` payload with `secretNames` / `secretFields` |
| `tests/test_hidden_args.py` (new) | coverage listed in section 6 |
| `tests/test_server.py` | update the exact stdio missing-key message |
| `tests/test_mcpb.py` | `missionsquad/` is excluded from the bundle |
| `.mcpbignore` | exclude `missionsquad/` from the Claude Desktop bundle |
| `.env.example` | document `SERPAPI_API_KEY` as the local stdio fallback |
| `README.md` | MissionSquad section: hidden key, fallback, precedence, local use, registration |

## 5. Anti-patterns removed or guarded

- Auth read only from `process` env in a shared server: replaced by per-call
  hidden `apiKey` with env as fallback.
- Hidden key reaching argument validation (and being echoed): stripped first.
- Hidden/public key collision: a test asserts no tool declares `apiKey`.
- Top-level pass-through: tools have fixed signatures; `params` is a nested
  free-form object and hidden keys arrive at the top level, so they never
  enter `params`. A test asserts nothing but `api_key` (the SerpApi auth
  parameter) carries the key to SerpApi.
- Secret in error text: redacted.
- Secret in logs: no tool handler logs arguments, and FastMCP's DEBUG record
  of raw arguments is redacted. Tests capture every record at DEBUG, including
  FastMCP's non-propagating logger, and assert the key never appears.

## 6. Test plan

- hidden `apiKey` overrides `SERPAPI_API_KEY` (stdio) and the header key (HTTP)
- env fallback works with no hidden value
- missing key, wrong type, empty string, whitespace-only: user-facing errors
- one-of / paired validation: not applicable (single field)
- no tool schema declares a hidden name
- the key reaches SerpApi only as `api_key`; `apiKey` is not forwarded
- two users with different keys, called concurrently on one server, each get
  their own key; hidden values are cleared after each call
- unknown visible arguments are still rejected, without echoing the key
- the key never appears in log records or tool results, including
  validation-error and connection-error paths
- `registration.json` `secretNames` equals `HIDDEN_ARG_NAMES`; every field is
  `inputType: "password"`
- the real `src/stdio.py` process starts with no `SERPAPI_API_KEY`, lists
  tools, and resolves a hidden `apiKey` over the real stdio transport

## 7. Validation criteria

- `uv run pytest -q` passes.
- `uv format --check` passes.
- The stdio entry point starts with no key configured.

## 8. Out of scope

- SerpApi's hosted HTTP deployment (`copilot/`, `release.yml`, `server.json`
  registry entry) is left unchanged.
- npm packaging requirements in the handbook do not apply: this is a Python
  package.
- The MCP SDK's legacy SSE transport (`mcp/server/sse.py`) logs raw request
  bodies at DEBUG. This server does not use SSE.
