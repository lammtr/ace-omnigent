# Omnigent — SigV4 MCP Client Auth Build Specification

> **Build contract.** Standalone build specification for a single change to a
> forked `omnigent` repository. Give an implementation agent the whole
> document — this is a single-component change, not a multi-agent split. It
> adds AWS SigV4 request signing to omnigent's *outbound* MCP client
> connections, so the omnigent server can call MCP tool servers hosted on
> AWS Innovation Labs (Bedrock AgentCore Runtimes) using credentials obtained
> via `aws-azure-login` + `boto3`.

| Field | Value |
|---|---|
| Spec ID | `omnigent-sigv4-mcp-auth-build-spec` |
| Spec version | `0.1.0` |
| Date | 2026-07-23 |
| Status | Draft — ready for implementation agent |
| Origin | `ace-design/outputs/specs/omnigent/omnigent-sigv4-mcp-auth-build-spec.md` |
| Target repository | A fork of `omnigent-ai/omnigent` (clone-and-fork target; not this repo) |
| Upstream base commit | `c9201a3650e8ecb35a120db7403ad4d46287c246` (2026-07-23), `https://github.com/omnigent-ai/omnigent.git` — re-verified against this commit (fast-forwarded from the `6e3c778` / 2026-07-10 commit this spec was first drafted against, 382 commits later). All file/line references below are current as of this commit; re-check if the fork starts from something newer still. |
| Target files | `omnigent/spec/types.py`, `omnigent/spec/parser.py`, `omnigent/tools/mcp.py`, `pyproject.toml`, `uv.lock`, `docs/AGENT_YAML_SPEC.md`, `tests/spec/`, `tests/tools/test_mcp.py` |
| Reference implementation | `ace-runtime-test/ace_explore.py` (this org's existing SigV4-over-MCP client, hitting the same class of Bedrock AgentCore endpoints) |
| Related design doc | `wiki/design/ace-omnigent-review.md` (unrelated in content — that doc tracks control-plane/policy learnings from omnigent; this spec is a standalone engineering change) |

---

## §1 Purpose and Outcome

Omnigent's MCP tool-client layer supports exactly one non-static outbound
auth scheme today: a Databricks OAuth bearer token resolved fresh at
connection time (`databricks_profile` on `MCPServerConfig`). This spec adds a
second scheme, AWS SigV4, so an `omnigent` agent can declare an MCP server
that lives behind AWS IAM auth — e.g. a Bedrock AgentCore Runtime endpoint in
an AWS Innovation Labs account — and have every request to it signed with
credentials sourced from a named `aws-azure-login`-refreshed AWS CLI profile.

The outcome: a `tools/mcp/<name>.yaml` entry like

```yaml
name: ace-peg
transport: http
url: "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/<url-encoded-runtime-arn>/invocations?qualifier=DEFAULT"
auth:
  type: sigv4
  profile: default          # AWS CLI profile kept fresh by aws-azure-login
  service: bedrock-agentcore
  region: ap-southeast-2     # optional — falls back to the profile's region
```

connects successfully, discovers tools, and calls them, end to end, against
a real Bedrock AgentCore Runtime — the same one `ace_explore.py` already
proves reachable — for as long as a human (or a scheduled job) reruns
`aws-azure-login --mode cli --profile default` every few hours to keep the
profile's temporary credentials from expiring.

## §2 Scope Boundary

### 2.1 Included

- A new `auth: {type: sigv4, ...}` YAML block for HTTP-transport MCP server
  entries, parsed into new `MCPServerConfig` fields.
- A per-request AWS SigV4 signer (`httpx.Auth`) wired into both HTTP MCP
  transports (`streamablehttp_client` and the legacy `sse_client` fallback).
- Promoting `boto3`/`botocore` from optional extras to a hard dependency.
- Unit tests for the new parser branch, the signer, and the transport wiring.
- A doc update to `docs/AGENT_YAML_SPEC.md` describing the new `auth` type.

### 2.2 Explicitly Later / Out of Scope

- Any change to *inbound* auth on the omnigent server (`omnigent/server/auth.py`
  and friends) — this spec is exclusively about omnigent-as-MCP-client calling
  *out*. Do not touch `AuthProvider`, `UnifiedAuthProvider`, or the web UI's
  cookie-session login flow.
- Resolving a friendly ACE name → SSM runtime ARN → invocation URL the way
  `ace_explore.py`'s `resolve_ace_id`/`fetch_runtime_arn`/`build_mcp_url` do.
  This spec assumes the operator pastes the fully-built AgentCore invocation
  URL into `url:` by hand, same as any other HTTP MCP server entry today. If
  that manual step turns out to be painful in practice, an SSM-resolution
  helper is a natural follow-on — port the three functions above almost
  verbatim — but it is not part of this change.
- Any automation of the `aws-azure-login` refresh itself (cron job, launchd
  agent, container sidecar). The user has confirmed they'll run it by hand /
  script it themselves every few hours; this spec only makes omnigent
  tolerate that cadence correctly (see §5.2's re-resolve-per-request
  requirement — this is *why* that requirement exists).
- LLM-provider-side Bedrock auth (`omnigent/llms/adapters/bedrock.py`). That
  path already goes through boto3's own bedrock-runtime client, which handles
  its own SigV4 signing internally and is unaffected by this change.
- Any AWS deploy target under `deploy/` (still none exists; not needed here —
  this change runs wherever the omnigent server already runs today).

## §3 Background

### 3.1 Current architecture (confirmed by reading the code, not inferred)

- **MCP client core**: `omnigent/tools/mcp.py`'s `McpServerConnection` wraps
  one MCP server (stdio or HTTP) end to end — connect, discover tools, call
  tools, reconnect-with-backoff, circuit breaker.
- **The one existing non-static outbound auth scheme**: Databricks OAuth.
  `_resolve_databricks_token()` (`omnigent/tools/mcp.py:86-123`) uses the
  Databricks SDK's `WorkspaceClient(profile=...)` to mint a bearer token,
  called fresh on every `connect()`/`_reconnect()` from
  `_resolve_http_headers()` (`omnigent/tools/mcp.py:924-941`), which merges it
  into a static headers dict handed to the transport.
- **Where that headers dict is consumed**: `_open_streamable_http_transport`
  (`:943-972`) and `_open_sse_transport` (`:974-1004`) each call the MCP SDK's
  `streamablehttp_client(...)` / `sse_client(...)` with `headers=headers`
  only. **Both of those SDK functions already accept an `auth: httpx.Auth |
  None` parameter that omnigent never passes** — confirmed directly against
  the installed `mcp` package
  (`mcp/client/streamable_http.py:686-693`, `mcp/client/sse.py:30-38`). That
  unused parameter is exactly the seam SigV4 needs.
- **Config schema**: `MCPServerConfig` (`omnigent/spec/types.py:930-954`) has
  a `databricks_profile: str | None` field alongside `url`/`headers`.
  `omnigent/spec/parser.py:2326-2366` parses a YAML `auth: {type: databricks,
  profile: ...}` block into it, inline in the same loop that builds each
  `MCPServerConfig`.
- **`boto3`/`botocore` are already in the dependency graph**, just as optional
  extras (`bedrock`, `s3` — `pyproject.toml:125,129`) used by
  `omnigent/llms/adapters/bedrock.py` and `omnigent/stores/artifact_store/s3.py`
  for unrelated outbound calls.

### 3.2 The reference pattern this org already runs in production-adjacent tooling

`ace-runtime-test/ace_explore.py` is a working MCP client against exactly this
class of target (a Bedrock AgentCore Runtime `bedrock-agentcore:InvokeAgentRuntime`
endpoint), authenticated with `aws-azure-login`-refreshed credentials:

1. `aws-azure-login --mode cli --profile default` — SAML federation via Azure
   AD, writes short-lived static credentials into the named AWS CLI profile.
2. `boto3.Session(profile_name=profile, region_name=region).get_credentials()`
   reads those credentials from disk.
3. A small `httpx.Auth` subclass, `SigV4HTTPXAuth` (`ace_explore.py:25-50`),
   wraps `botocore.auth.SigV4Auth(credentials, service, region)` and signs
   each outgoing `httpx.Request` in `auth_flow()`.
4. That `auth=` object is passed straight into `streamablehttp_client(url,
   headers=headers, auth=auth, ...)` (`ace_explore.py:228-230`).

This spec ports that pattern into omnigent's `McpServerConnection`, with one
correctness fix required by omnigent's long-lived connections (§5.2).

## §4 Design

### 4.1 Config schema — `omnigent/spec/types.py`

Add to `MCPServerConfig` (near `databricks_profile`, `:939`):

```python
# AWS SigV4 auth — signs every HTTP request to the MCP server with
# credentials from a named AWS CLI profile (e.g. one kept fresh by
# aws-azure-login). Mutually exclusive with databricks_profile in
# practice, but not enforced as such: both merge into the same
# transport call, and MCPServerConfig doesn't otherwise police which
# auth fields co-occur.
aws_profile: str | None = None
aws_service: str | None = None   # e.g. "bedrock-agentcore"; no default — require explicit
aws_region: str | None = None    # optional; falls back to the profile's configured region
```

Update the docstring (`:892-928`) with the same style of `:param` entries
used for `databricks_profile`. Update `__repr__` (`:956-975`) — these three
fields are not secrets (profile/service/region names), so, like
`databricks_profile`, they are safe to include un-redacted.

### 4.2 YAML parsing — `omnigent/spec/parser.py:2326-2366`

Add a sibling branch to the existing `raw_auth.get("type") == "databricks"`
check:

```python
aws_profile: str | None = None
aws_service: str | None = None
aws_region: str | None = None
if isinstance(raw_auth, dict) and str(raw_auth.get("type", "")) == "sigv4":
    raw_profile = raw_auth.get("profile")
    raw_service = raw_auth.get("service")
    if raw_profile is None or raw_service is None:
        raise OmnigentError(
            f"Inline MCP server {name!r} auth type 'sigv4' requires "
            f"'profile' and 'service' fields",
            code=ErrorCode.INVALID_INPUT,
        )
    aws_profile = str(raw_profile)
    aws_service = str(raw_service)
    if (raw_region := raw_auth.get("region")) is not None:
        aws_region = str(raw_region)
```

Pass the three new fields into the `MCPServerConfig(...)` construction at
`:2350-2366`, same as `databricks_profile=databricks_profile` there today.

**Verify during implementation**: confirm whether any separate cross-field
validator elsewhere rejects `databricks_profile` (or would reject the new
`aws_*` fields) when `transport == "stdio"`. The class docstring
(`types.py:888-890`) claims a validator enforces HTTP-only vs. stdio-only
fields, but it names only `url`/`headers` (HTTP) and `command`/`args`/`env`
(stdio) — not the auth-profile fields. If no such check currently exists for
`databricks_profile` either, this is pre-existing behavior, not a regression
to fix here; just don't assume one exists without checking.

### 4.3 Credential resolution and signing — `omnigent/tools/mcp.py`

New function, same shape as `_resolve_databricks_token` (`:86-123`):

```python
def _resolve_sigv4_auth(profile: str, service: str, region: str | None) -> "SigV4SessionAuth":
    return SigV4SessionAuth(profile=profile, service=service, region=region)
```

New class (new module `omnigent/tools/aws_auth.py`, or inline in `mcp.py` —
implementer's call; a separate module keeps `mcp.py`'s size down and makes it
importable without pulling in `httpx`/`botocore` for stdio-only callers):

```python
class SigV4SessionAuth(httpx.Auth):
    """Signs every request with AWS SigV4, re-resolving credentials from
    the named profile on each request (not cached at construction) so a
    long-lived MCP connection picks up credentials refreshed by an
    out-of-band `aws-azure-login` rerun without needing a reconnect."""

    requires_request_body = True

    def __init__(self, profile: str, service: str, region: str | None):
        self._profile = profile
        self._service = service
        self._region = region

    def auth_flow(self, request: httpx.Request):
        session = boto3.Session(profile_name=self._profile, region_name=self._region)
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError(
                f"No AWS credentials found for profile {self._profile!r}. "
                f"Run `aws-azure-login --mode cli --profile {self._profile}` "
                f"and retry."
            )
        region = self._region or session.region_name
        signer = SigV4Auth(credentials.get_frozen_credentials(), self._service, region)
        aws_request = AWSRequest(
            method=request.method,
            url=str(request.url),
            data=request.content,
            headers={"content-type": request.headers.get("content-type", "application/json")},
        )
        signer.add_auth(aws_request)
        for key, value in aws_request.headers.items():
            request.headers[key] = value
        yield request
```

Add a resolver method to `McpServerConnection`, parallel to
`_resolve_http_headers` (`:924-941`):

```python
def _resolve_http_auth(self) -> httpx.Auth | None:
    if self.config.aws_profile is None:
        return None
    assert self.config.aws_service is not None  # enforced at parse time
    return _resolve_sigv4_auth(
        self.config.aws_profile, self.config.aws_service, self.config.aws_region
    )
```

Wire it through `_open_http_transport` (`:869-922`) →
`_open_streamable_http_transport` (`:943-972`) / `_open_sse_transport`
(`:974-1004`), adding an `auth: httpx.Auth | None` parameter to both and
passing it to the SDK call's existing `auth=` parameter.

### 4.4 Why per-request re-resolution is not optional

This is the one place a naive port of the Databricks pattern breaks. The
Databricks bearer token is resolved once per `connect()`/`_reconnect()` and
reused as a *static* header for the life of that connection — fine, because
OAuth bearer tokens are used verbatim across many requests. **A SigV4
signature is not reusable across requests**: it's computed over the specific
method, path, and request-body hash, with a timestamp valid for a short
window. Precomputing it once at connect time (mirroring
`_resolve_http_headers()`'s model) would produce a header that's already
wrong for the second request in the session.

Separately, `McpServerConnection`'s lifecycle task
(`_run_lifecycle`, `:671-757`) holds one transport + session open
indefinitely — it does not naturally cycle through `connect()` again just
because time has passed. Given the user's confirmed operating cadence
(`aws-azure-login` rerun every few hours, not automatically), an MCP
connection that outlives one such window will still be sending requests long
after the profile's credentials from the *previous* login have expired. The
`SigV4SessionAuth.auth_flow()` design above re-reads the profile via a fresh
`boto3.Session(...).get_credentials()` on *every single request*, so it picks
up whatever the most recent `aws-azure-login` run wrote to
`~/.aws/credentials` without needing a reconnect. This is a deliberate
trade-off — a small per-call credential-file read — in exchange for
correctness; if profiling shows it's hot, a short TTL cache (e.g. re-resolve
only if the last resolution is >60s old) is a reasonable follow-on
optimization, not a prerequisite.

### 4.5 Dependency change — `pyproject.toml`, `uv.lock`

Move `boto3`/`botocore` from the `bedrock`/`s3` optional extras
(`:125`, `:129`) into the core `dependencies` list (`:24-112` — this list has
grown from unrelated upstream additions since this spec's line numbers were
last verified; locate it by the `dependencies = [` opener, don't trust the
range boundary literally), keeping the same version constraint
(`boto3>=1.30,<2`, `botocore>=1.30,<2`) already used elsewhere in the file so
it doesn't conflict with the pinned dev-dependency copy at `:296-302`. The
`bedrock`/`s3` extras' own boto3/botocore entries
become redundant once it's a core dependency — either drop them from those
extras or leave them as harmless duplicates; implementer's call. Regenerate
`uv.lock` (`uv lock`) after the `pyproject.toml` edit — do not hand-edit the
lock file.

## §5 Error Handling and Operational Behavior

- **Missing/expired credentials** surface as the `RuntimeError` raised inside
  `SigV4SessionAuth.auth_flow()` (§4.3), with the same actionable remediation
  message `ace_explore.py`'s README already gives operators: rerun
  `aws-azure-login --mode cls --profile <name>`.
- **AWS-side auth rejection** (expired token, wrong permissions) surfaces as
  an HTTP 4xx from the AgentCore endpoint. This is *not* one of
  `McpServerConnection`'s recognized connection-error types
  (`_CONNECTION_ERROR_TYPES`, `omnigent/tools/mcp.py:1216-1221`), so
  `_call_tool_with_reconnect` (`:1272-1324`) will not treat it as
  retryable-via-reconnect — correct, since reconnecting doesn't fix expired
  AWS credentials. It still counts toward the per-server circuit breaker
  (`call_tool`'s blanket `except Exception: record_failure()`,
  `:513-532`), which is also correct: it stops hammering a target with
  doomed calls during an expiry window and self-heals via the half-open
  probe (`:241-266`) once a human reruns `aws-azure-login`. No code change
  needed here beyond what §4.3–4.4 already produce — just document the
  expected operator experience (a burst of clear auth errors, then automatic
  recovery on the next probe after re-login) so it isn't mistaken for a bug.

## §6 Testing and Evidence Standard

1. **Parser unit test** (`tests/spec/` — mirror whatever file currently tests
   the `auth: {type: databricks, ...}` branch): a YAML fixture with
   `auth: {type: sigv4, profile: p, service: bedrock-agentcore, region: r}`
   parses into the expected `MCPServerConfig.aws_profile/aws_service/aws_region`;
   a fixture missing `profile` or `service` raises `OmnigentError` with
   `ErrorCode.INVALID_INPUT`.
2. **Signer unit test** (`tests/tools/test_mcp.py` or a new
   `tests/tools/test_aws_auth.py`) — directly portable from
   `ace-runtime-test/tests/test_ace_explore.py:81-97`
   (`test_sigv4_auth_adds_authorization_header`): construct
   `botocore.credentials.Credentials(access_key=..., secret_key=..., token=...)`,
   monkeypatch `boto3.Session` to return them, build an `httpx.Request`, run
   `SigV4SessionAuth.auth_flow()`, and assert `authorization` starts with
   `AWS4-HMAC-SHA256`, `x-amz-date` is present, and `x-amz-security-token`
   propagates the session token.
3. **Re-resolution test**: call `auth_flow()` twice with the mocked
   `boto3.Session` returning *different* credentials each time (simulating a
   post-`aws-azure-login` rotation) and assert the second signature reflects
   the second credential set — this is the regression test for §4.4's
   correctness requirement.
4. **Transport wiring test**: assert `_open_streamable_http_transport` and
   `_open_sse_transport` pass a non-`None` `auth=` through to the SDK client
   call when `config.aws_profile` is set, and `None` when it isn't (existing
   Databricks/no-auth paths unaffected).
5. **Missing-credentials test**: `boto3.Session(...).get_credentials()`
   returning `None` raises the actionable `RuntimeError` from `auth_flow()`.
6. **Manual/e2e acceptance** (cannot be scripted in CI without live AWS
   access): point a real `tools/mcp/<name>.yaml` at the same Bedrock
   AgentCore Runtime URL `ace_explore.py` already reaches, with `aws_profile`
   set to a profile freshly authenticated via `aws-azure-login`, and confirm
   the omnigent server connects, discovers tools, and completes a `tools/call`
   round trip. Repeat after deliberately waiting past the profile's
   credential expiry without re-running `aws-azure-login`, and confirm the
   failure mode matches §5 (clear error, not a hang or a misleading
   "connection lost" reconnect loop).
7. Standard repo hygiene: `ruff check`, `ruff format --check`, the repo's
   type checker, and `pre-commit run --all-files` per this repo's
   `CLAUDE.md` (already present in the omnigent clone at
   `.tmp/omnigent/CLAUDE.md` and presumably carried into the fork).

## §7 Documentation Updates

- `docs/AGENT_YAML_SPEC.md`: document the new `auth: {type: sigv4, profile,
  service, region}` block next to wherever `type: databricks` is documented,
  including the operational note that the referenced AWS profile must be
  kept alive by an out-of-band `aws-azure-login` (or equivalent) refresh.
- `MCPServerConfig`'s docstring (`omnigent/spec/types.py`) — covered in §4.1.

## §8 Final Acceptance / Definition of Done

1. A `tools/mcp/<name>.yaml` entry with `auth: {type: sigv4, ...}` parses
   without error and produces an `MCPServerConfig` with the three new fields
   set.
2. Every HTTP request omnigent sends to that MCP server — `initialize`,
   `tools/list`, and each `tools/call` — carries a valid, freshly-computed
   `Authorization: AWS4-HMAC-SHA256 ...` header; two requests in the same
   long-lived connection have *different* signatures.
3. A real Bedrock AgentCore Runtime endpoint (the same class of target
   `ace_explore.py` already reaches) accepts the connection, and tool
   discovery + a tool call succeed end to end.
4. After the referenced profile's credentials expire without a fresh
   `aws-azure-login` run, the next call fails with a clear, actionable error
   (not a silent hang, not a misclassified "connection lost" reconnect
   storm) — and succeeds again on the first call after the profile is
   refreshed, without needing the omnigent process restarted.
5. `boto3`/`botocore` are core dependencies; `uv.lock` is regenerated and
   consistent.
6. All §6 tests pass; lint/format/type-check pass; `pre-commit run
   --all-files` is clean.
7. Existing Databricks-profile and no-auth MCP server configs are unaffected
   (regression check — run the existing MCP test suite, not just the new
   tests).

## §9 Agent Assignment

> Implement this spec in full against the forked `omnigent` repository. Add
> `aws_profile`/`aws_service`/`aws_region` to `MCPServerConfig`
> (`omnigent/spec/types.py`), parse a new `auth: {type: sigv4, profile,
> service, region}` YAML block for it (`omnigent/spec/parser.py`, mirroring
> the existing `type: databricks` branch), and add a `SigV4SessionAuth`
> `httpx.Auth` class that **re-resolves AWS credentials from the named
> profile on every request** (not once at connect time — see §4.4 for why
> that distinction is load-bearing) and signs with `botocore.auth.SigV4Auth`,
> following `ace-runtime-test/ace_explore.py`'s `SigV4HTTPXAuth` as the
> reference implementation. Wire the resulting `httpx.Auth` object through
> `McpServerConnection._open_http_transport` into both
> `streamablehttp_client(..., auth=...)` and `sse_client(..., auth=...)` —
> both already accept it; only the `headers=`-only call sites need to change.
> Promote `boto3`/`botocore` to a hard dependency. Do not touch the omnigent
> server's inbound auth (`omnigent/server/auth.py`), the web UI's session
> login, or any Bedrock LLM-adapter code — none of that is in scope. Return
> the §6 test evidence and a manual end-to-end run against a real Bedrock
> AgentCore Runtime endpoint.

## §10 Handoff Checklist

- [ ] I read the full spec, not just §9.
- [ ] I changed only the files listed in the header's "Target files" plus
      tests and docs — no inbound-auth, web UI, or LLM-adapter changes.
- [ ] The signer re-resolves credentials per request, not per connection
      (§4.4) — verified by the re-resolution test in §6.3.
- [ ] `boto3`/`botocore` are core dependencies; `uv.lock` regenerated.
- [ ] All §6 tests pass, including the existing MCP test suite (regression
      check for Databricks-profile and no-auth configs).
- [ ] Lint, format, type-check, and `pre-commit run --all-files` are clean.
- [ ] A real Bedrock AgentCore Runtime endpoint was reached end to end
      (§6.6) — evidence attached (redacted of any credential material).
- [ ] The credential-expiry failure mode was manually verified (§6.6,
      second half) — clear error, self-heals on next successful login.
- [ ] `docs/AGENT_YAML_SPEC.md` documents the new `auth` type.
- [ ] No AWS credential, profile content, or signed request appears in logs,
      test fixtures, or the PR description beyond what §6's mocked tests need.

## §11 Change Log

- 2026-07-23 — Created version `0.1.0`. Derived from a read-only review of
  `.tmp/omnigent` (base commit `6e3c77855b08c9b612bf20763fe14f57a7ff9ad4`) and
  `ace-runtime-test/ace_explore.py`, confirming: (a) omnigent's only
  extension point for non-static outbound MCP auth is the
  `databricks_profile`/`_resolve_http_headers()` pattern in
  `omnigent/tools/mcp.py`; (b) the underlying `mcp` SDK transports already
  accept an unused `auth: httpx.Auth` parameter, which is the correct seam
  for SigV4 (a static-header port of the Databricks pattern would be
  incorrect, since SigV4 signatures are per-request and time-boxed); and
  (c) `ace_explore.py`'s `SigV4HTTPXAuth` + its test
  (`test_sigv4_auth_adds_authorization_header`) is a directly portable
  reference implementation and test pattern. User confirmed: continual
  manual `aws-azure-login` refresh every few hours is acceptable, and
  `boto3` may become a hard dependency.
- 2026-07-23 — Re-verified against upstream before handoff, per user request
  ("don't want another round of analysis"). The `.tmp/omnigent` clone was
  382 commits stale (`6e3c778`, 2026-07-10); fetched and fast-forwarded to
  `c9201a3` (2026-07-23, clean tree, no local commits lost). Diffed the
  exact files this spec touches between the two commits:
  `omnigent/tools/mcp.py` — **byte-identical, zero changes** (every design
  decision in §4.3–§4.5 and §5 stands as originally written, no line shift).
  `omnigent/spec/types.py` and `omnigent/spec/parser.py` — the
  `MCPServerConfig`/`databricks_profile`/inline-auth-parsing logic this spec
  extends is **byte-identical**, just shifted down by unrelated upstream
  insertions earlier in each file (+16 lines in `types.py` from an unrelated
  `LLMConfig.fallback_models` addition; +32 lines in `parser.py` from
  unrelated YAML-loader and `_parse_llm`/`_parse_os_env_sandbox` changes) —
  all line-number citations in §3.1, §4.1, and §4.2 updated accordingly, no
  design change needed. `pyproject.toml` — the `bedrock`/`s3` boto3 extras
  and the dev-dependency boto3 pin are unchanged in content, shifted by +9
  lines; the core `dependencies` list grew substantially from unrelated
  additions (protobuf, python-dateutil, version bumps, new optional extras
  for slack/islo/dictation/etc.) — §4.5 updated to locate it by its opening
  bracket rather than a literal range. `docs/AGENT_YAML_SPEC.md` changed
  only unrelated prose (system-prompt terminology), no conflict with §7.
  Net result: no substantive design revision, only citation corrections —
  the spec as originally reasoned through is confirmed still accurate.
