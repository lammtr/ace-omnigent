# MCP Server URL Resolution via AWS SSM — Design

## Context

Follow-on to the AWS SigV4 MCP client auth feature (`docs/ace/omnigent-sigv4-mcp-auth-build-spec.md`,
merged in PR #1). That spec explicitly deferred "resolving a friendly ACE
name → SSM runtime ARN → invocation URL" as "a natural follow-on... not part
of this change" (§2.2). This design is that follow-on, scoped down from a
full friendly-name resolver to what's actually needed: fetch a Bedrock
AgentCore runtime's invocation URL from a stable AWS SSM Parameter Store
path, so the operator doesn't have to hand-paste (and re-paste, on every
redeploy) the full invocation URL into YAML.

Reference implementation: `ace-runtime-test/ace_explore.py`'s
`fetch_runtime_arn`/`build_mcp_url`/`ssm_runtime_arn_path` functions —
ported here, minus the hardcoded friendly-name-to-ace-id mapping
(`ACE_ID_BY_NAME`), which is this org's naming convention, not something the
general-purpose omnigent framework should bake in.

Also discovered and fixed as part of this work: the standalone
`tools/mcp/<name>.yaml` file format (parsed by `_parse_http_mcp_server`) does
not read the `auth:` block at all today — not for the pre-existing
`databricks` type, not for `sigv4`. A server declared this way currently
connects with **no auth whatsoever**, silently. This is the operator's
actual use case (`tools/mcp/ace-marshall.yaml`), so it must be fixed as part
of this change, not left as a separate gap.

## Goal

```yaml
# tools/mcp/ace-marshall.yaml
name: ace-marshall
transport: http
ssm_parameter: /ace/poc/ace-os/marshall/runtime/url   # holds a runtime ARN, despite the name
auth:
  type: sigv4
  profile: default
  service: bedrock-agentcore
  region: ap-southeast-2
```

connects successfully, re-resolving the invocation URL from that SSM
parameter fresh on every connect/reconnect (so a redeploy — which changes
the runtime ARN — is picked up on the next reconnect without a YAML edit),
and signs every request with SigV4 as already built.

## Scope

### Included

- `ssm_parameter` YAML field (sibling to `url`, HTTP-transport only,
  mutually exclusive with `url`) on both the inline `tools:` block format
  and the standalone `tools/mcp/<name>.yaml` file format.
- A shared auth-block parser (`databricks`/`sigv4`) extracted out of
  `_parse_inline_mcp_servers` and reused by `_parse_http_mcp_server` — fixes
  the silent-no-auth bug in the standalone-file path for *all* auth types,
  not just this new feature.
- SSM-based URL resolution (`omnigent/tools/aws_auth.py`), reusing the
  existing `aws_profile`/`aws_region` fields (no new profile/region
  concept) — resolved once per `connect()`/`_reconnect()`, mirroring the
  existing Databricks-token resolution cadence.
- `__repr__` and `mcp_manager.py` config-change-hash coverage for the new
  field, mirroring the existing `aws_*` fields.
- Unit tests for the resolver, both parsers, and transport wiring.

### Explicitly out of scope

- Friendly-name → ace-id → SSM-path resolution (`ACE_ID_BY_NAME`,
  `ssm_runtime_arn_path`'s convention-based path building). The operator
  supplies the exact SSM parameter path directly; omnigent does not guess
  or template it from a name. (This deployment's actual path,
  `/ace/poc/ace-os/marshall/runtime/url`, doesn't even match
  `ace_explore.py`'s hardcoded convention for marshall
  — concrete evidence this shouldn't be baked into the framework.)
- A configurable `qualifier` (AgentCore invocation qualifier). Hardcoded to
  `"DEFAULT"`, matching `ace_explore.py`'s default and every known caller.
  Add a YAML knob later if a real need shows up.
- Any change to the SigV4 signer itself (`SigV4SessionAuth`) — untouched.
- Any change to inbound auth, the web UI, or LLM-adapter code (same
  boundary as the parent SigV4 spec).

## Design

### 1. `MCPServerConfig` — new field

`aws_ssm_parameter: str | None = None` (near the existing `aws_profile`
etc.). Docstring: *"AWS SSM Parameter Store path holding the runtime ARN to
connect to (e.g. a Bedrock AgentCore runtime). Mutually exclusive with
`url`. Requires `aws_profile` to be set (the same profile used for SigV4
signing) — there's no separate credential concept just for the SSM
lookup."* Included un-redacted in `__repr__` (a parameter *path*, not a
secret — same treatment as `aws_profile`).

### 2. Shared auth-block parser

Extract `_parse_mcp_auth_block(raw_auth, name, source) -> tuple[str | None,
str | None, str | None, str | None]` (returns `databricks_profile,
aws_profile, aws_service, aws_region`) out of the databricks/sigv4-handling
code currently inline in `_parse_inline_mcp_servers`. Both
`_parse_inline_mcp_servers` and `_parse_http_mcp_server` call it. Error
messages keep their current wording (parameterized by `name`/`source` for
the two different error-message styles the two parsers already use —
`_parse_inline_mcp_servers` says `f"Inline MCP server {name!r}..."`,
`_parse_http_mcp_server` says `f"MCP server {name!r}... {yaml_file}"` — the
helper takes a pre-formatted message-prefix or the two identifying pieces
needed to reproduce both stylings; implementer's call on the exact
signature, as long as neither parser's existing error wording changes for
databricks).

### 3. `ssm_parameter` parsing (both parsers)

- `ssm_parameter` and `url` both set → `OmnigentError` /
  `ErrorCode.INVALID_INPUT`: "specify exactly one of `url` or
  `ssm_parameter`".
- Neither set (HTTP transport) → existing "missing required field `url`"
  error, reworded to mention both: "missing required field `url` or
  `ssm_parameter`".
- `ssm_parameter` set but `aws_profile` is `None` (no `auth: {type: sigv4,
  profile: ...}` block) → `OmnigentError`: "`ssm_parameter` requires `auth:
  {type: sigv4, profile: ...}` to resolve via AWS SSM".

### 4. Resolver — `omnigent/tools/aws_auth.py`

```python
def resolve_ssm_runtime_url(
    ssm_parameter: str, profile: str, region: str | None, qualifier: str = "DEFAULT"
) -> str:
    """Fetch a runtime ARN from SSM and build its AgentCore invocation URL."""
```

Ported from `ace_explore.py`'s `fetch_runtime_arn`/`build_mcp_url`:
`boto3.Session(profile_name=profile, region_name=region).client("ssm").get_parameter(Name=ssm_parameter)`,
`ParameterNotFound` → actionable `RuntimeError` naming the parameter path
(mirrors the existing `SigV4SessionAuth` credential-error message style —
clear, names the exact remediation). Region-fallback (`region or
session.region_name`) same as `SigV4SessionAuth`. Percent-encode the ARN
(`urllib.parse.quote(arn, safe="")`) and build
`https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{encoded_arn}/invocations?qualifier={qualifier}`.

### 5. Wiring — `omnigent/tools/mcp.py`

New `McpServerConnection._resolve_http_url() -> str` (parallel to
`_resolve_http_headers`/`_resolve_http_auth`):

```python
def _resolve_http_url(self) -> str:
    if self.config.url is not None:
        return self.config.url
    assert self.config.aws_ssm_parameter is not None  # enforced at parse time
    assert self.config.aws_profile is not None          # enforced at parse time
    return resolve_ssm_runtime_url(
        self.config.aws_ssm_parameter, self.config.aws_profile, self.config.aws_region
    )
```

`_open_http_transport` calls this once (same place it currently reads
`self.config.url`/calls `_resolve_http_headers()`/`_resolve_http_auth()`)
and threads the resolved `url` as an explicit parameter through to
`_open_streamable_http_transport`/`_open_sse_transport` — those two methods
stop reading `self.config.url` directly and take `url: str` as a parameter
instead, matching how `headers`/`auth`/`timeout` are already threaded. The
existing `if self.config.url is None: raise RuntimeError(...)` guard in
`_open_http_transport` is replaced by `_resolve_http_url()`'s own
assertions (parse-time validation already guarantees one of `url`/
`ssm_parameter` is set).

### 6. `mcp_manager.py` hash coverage

Add `aws_ssm_parameter` to both `compute_spec_hash`/`compute_server_hash`
payloads, same treatment as the other `aws_*` fields (a changed SSM
parameter path must trigger a reconnect).

## Error Handling

- SSM `ParameterNotFound` → `RuntimeError` naming the exact parameter path
  and the profile, so the operator knows immediately whether the path is
  wrong or the deployment doesn't exist in this env.
- Missing `aws_profile` alongside `ssm_parameter`, or both `url` and
  `ssm_parameter` set → parse-time `OmnigentError` (fails loud before any
  connection attempt, same posture as the SigV4 auth-block validation).
- A redeploy mid-connection (ARN changes) is picked up on the *next*
  reconnect, not the current connection — consistent with "resolve once per
  connect" from the design discussion; not treated as an error case, just a
  latency characteristic worth documenting in the field's docstring.

## Testing

1. Resolver unit tests (`tests/tools/test_aws_auth.py`): happy path (mocked
   SSM client → ARN → URL, percent-encoding correctness), `ParameterNotFound`
   → actionable `RuntimeError`, region-fallback to profile's configured
   region.
2. Parser tests for **both** YAML shapes (`tests/spec/test_parser.py` for
   inline, a `tests/spec/` test — or wherever `_parse_http_mcp_server`/
   `_discover_mcp_servers` is currently tested — for the standalone-file
   path): happy path with `ssm_parameter`, both-set error, neither-set
   error, `ssm_parameter`-without-`aws_profile` error. Also: a regression
   test proving the standalone-file path (`_parse_http_mcp_server`) now
   parses `auth: {type: databricks, profile}` and `auth: {type: sigv4, ...}`
   correctly — the bug this design fixes.
3. Transport-wiring test (`tests/tools/test_mcp.py`): `connect()` with
   `aws_ssm_parameter` set reaches the transport with the *resolved* URL
   (mock `resolve_ssm_runtime_url`), and is called again (re-resolved, not
   cached) on a reconnect.
4. `mcp_manager.py` hash test mirroring the existing `aws_profile` hash
   test, for `aws_ssm_parameter`.
5. Manual/e2e (same posture as the parent spec — cannot be scripted without
   live AWS access): point `tools/mcp/ace-marshall.yaml` at the real
   `/ace/poc/ace-os/marshall/runtime/url` parameter and confirm connect +
   tool discovery succeed end to end.

## Non-Goals / Deferred

- Friendly-name resolution (`ace_name: ace-marshall` → SSM path) — punted,
  see Scope. If this turns out to be worth it later, it layers on top of
  `ssm_parameter` (a name→path lookup that produces the same field) without
  changing anything built here.
- Configurable `qualifier`.
