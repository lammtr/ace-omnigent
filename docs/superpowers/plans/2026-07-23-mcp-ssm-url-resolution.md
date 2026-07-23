# MCP Server URL Resolution via AWS SSM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `ssm_parameter` YAML field (alternative to `url`) on HTTP
MCP servers, so omnigent resolves the Bedrock AgentCore invocation URL from
an AWS SSM Parameter Store path fresh on every connect/reconnect, instead
of the operator hand-pasting (and re-pasting on every redeploy) the full
URL. Also fixes a discovered bug: the standalone `tools/mcp/<name>.yaml`
file format never parsed `auth:` at all — not `databricks`, not `sigv4` —
so a server declared that way connects with no auth, silently.

**Architecture:** A shared `_parse_mcp_auth_block` helper (extracted from
the existing inline-`tools:`-block parser) is reused by both YAML shapes so
`databricks`/`sigv4` auth and the new `ssm_parameter` field work
identically regardless of which format declares the server. A new
`resolve_ssm_runtime_url()` in `omnigent/tools/aws_auth.py` (ported from
`ace-runtime-test/ace_explore.py`'s `fetch_runtime_arn`/`build_mcp_url`)
does the actual SSM lookup + ARN-to-URL build. `McpServerConnection` gains
a `_resolve_http_url()` method (parallel to the existing
`_resolve_http_headers`/`_resolve_http_auth`) called once per
connect/reconnect, and the resolved URL is threaded as an explicit
parameter through the transport methods (matching how `headers`/`auth`
already are).

**Tech Stack:** Python 3.12, `boto3`/`botocore` (already core deps per the
parent SigV4 spec), `httpx`, pytest.

## Global Constraints

- Design doc: `docs/superpowers/specs/2026-07-23-mcp-ssm-url-resolution-design.md`.
- Builds on the merged SigV4 MCP auth feature (`aws_profile`/`aws_service`/
  `aws_region` on `MCPServerConfig`, `SigV4SessionAuth` in
  `omnigent/tools/aws_auth.py`, `_resolve_http_auth`/`_resolve_http_headers`
  in `omnigent/tools/mcp.py`). Do not change any of that existing behavior
  except where a task explicitly threads a new parameter through it.
- Friendly-name → SSM-path resolution (`ace_name: ace-marshall` style) is
  explicitly OUT of scope — the operator supplies the exact SSM parameter
  path. Do not add any name-to-path convention/mapping.
- `qualifier` stays hardcoded `"DEFAULT"` — not a YAML-configurable field.
- URL resolution happens once per `connect()`/`_reconnect()` — NOT per
  request (that cadence is specific to `SigV4SessionAuth`'s credential
  re-resolution and does not apply here; a runtime ARN doesn't rotate on a
  timer).
- Error messages for the new validation must follow each parser's existing
  wording style exactly (see Task 2/3 for the two distinct styles) —
  reviewers will check this precisely, since it's the whole point of the
  shared-helper refactor.
- No AWS credential material in test fixtures beyond fake values (mirror
  the existing `tests/tools/test_aws_auth.py` fixtures' style, e.g.
  `AKIDEXAMPLE`).
- Run `uv run pytest <touched files>` after each task, and the touched
  file's full suite before committing — this plan touches shared parsing/
  connection code exercised by hundreds of existing tests; regressions are
  cheap to catch immediately and expensive to find later.

---

### Task 1: `MCPServerConfig` — new `aws_ssm_parameter` field

**Files:**
- Modify: `omnigent/spec/types.py:936-994` (`MCPServerConfig` fields,
  docstring, `__repr__`)
- Test: `tests/tools/test_mcp.py`

**Interfaces:**
- Produces: `MCPServerConfig.aws_ssm_parameter: str | None` — consumed by
  Task 2/3 (parsers) and Task 5 (`_resolve_http_url`).

- [ ] **Step 1: Add the field**

In `omnigent/spec/types.py`, immediately after the `aws_region` field
(currently line 956):

```python
    aws_region: str | None = None  # optional; falls back to the profile's configured region
    # AWS SSM Parameter Store path holding the runtime ARN to connect to
    # (e.g. a Bedrock AgentCore runtime). Mutually exclusive with url.
    # Requires aws_profile to be set (the same profile used for SigV4
    # signing) — there's no separate credential concept just for the SSM
    # lookup. Resolved fresh on every connect/reconnect, not per request:
    # unlike SigV4 credentials, a runtime ARN doesn't rotate on a timer,
    # only on redeploy.
    aws_ssm_parameter: str | None = None
```

- [ ] **Step 2: Add a docstring `:param:` entry**

In the same file, after the existing `:param aws_region:` entry (search for
it — it's in the class docstring near the other `:param aws_*:` lines),
add:

```python
    :param aws_ssm_parameter: AWS SSM Parameter Store path holding a
        runtime ARN, e.g. ``"/ace/poc/ace-os/marshall/runtime/url"``.
        When set, the connection URL is resolved from this parameter
        instead of ``url`` — mutually exclusive with it. Requires
        ``aws_profile`` to be set.
```

- [ ] **Step 3: Update `__repr__`**

In `omnigent/spec/types.py`, `__repr__` currently ends with (verify exact
current text first — it was edited by the prior SigV4 plan):

```python
        return (
            f"MCPServerConfig(name={self.name!r}, transport={self.transport!r}, "
            f"url={self.url!r}, headers={redacted_headers!r}, "
            f"databricks_profile={self.databricks_profile!r}, "
            f"aws_profile={self.aws_profile!r}, aws_service={self.aws_service!r}, "
            f"aws_region={self.aws_region!r}, "
            f"command={self.command!r}, args={self.args!r}, "
            f"env={redacted_env!r}, "
            f"timeout={self.timeout!r}, retry={self.retry!r})"
        )
```

Add `aws_ssm_parameter` (a path, not a secret — same treatment as the other
`aws_*` fields) right after `aws_region`:

```python
        return (
            f"MCPServerConfig(name={self.name!r}, transport={self.transport!r}, "
            f"url={self.url!r}, headers={redacted_headers!r}, "
            f"databricks_profile={self.databricks_profile!r}, "
            f"aws_profile={self.aws_profile!r}, aws_service={self.aws_service!r}, "
            f"aws_region={self.aws_region!r}, aws_ssm_parameter={self.aws_ssm_parameter!r}, "
            f"command={self.command!r}, args={self.args!r}, "
            f"env={redacted_env!r}, "
            f"timeout={self.timeout!r}, retry={self.retry!r})"
        )
```

- [ ] **Step 4: Write the repr test**

Add to `tests/tools/test_mcp.py`, near `test_mcp_server_config_repr_includes_sigv4_fields`:

```python
def test_mcp_server_config_repr_includes_ssm_parameter() -> None:
    """
    MCPServerConfig.__repr__ includes aws_ssm_parameter un-redacted — it's
    a parameter path, not a secret, same treatment as aws_profile.
    """
    config = MCPServerConfig(
        name="ssm-svc",
        aws_ssm_parameter="/ace/poc/ace-os/marshall/runtime/url",
    )
    r = repr(config)

    assert "aws_ssm_parameter='/ace/poc/ace-os/marshall/runtime/url'" in r
```

- [ ] **Step 5: Run the test**

Run: `uv run pytest tests/tools/test_mcp.py -k repr -v`
Expected: PASS (4 repr tests, including the new one)

- [ ] **Step 6: Commit**

```bash
git add omnigent/spec/types.py tests/tools/test_mcp.py
git commit -m "feat(mcp): add aws_ssm_parameter field to MCPServerConfig"
```

---

### Task 2: Shared auth-block parser + `ssm_parameter` for the inline `tools:` format

**Files:**
- Modify: `omnigent/spec/parser.py:2245-2390` (`_parse_inline_mcp_servers`)
  — add a new `_parse_mcp_auth_block` helper immediately above it
- Test: `tests/spec/test_parser.py`

**Interfaces:**
- Consumes: `MCPServerConfig.aws_ssm_parameter` (Task 1).
- Produces: `_parse_mcp_auth_block(raw_auth: object, describe: str,
  location_suffix: str = "") -> tuple[str | None, str | None, str | None,
  str | None]` (returns `databricks_profile, aws_profile, aws_service,
  aws_region`) — consumed by Task 3's `_parse_http_mcp_server`.

This task is a **refactor + bug-relevant extraction with no behavior change
to the inline format's existing databricks/sigv4 handling** — verify this
with the existing test suite — plus **one new feature**: `ssm_parameter`
support for the inline format.

- [ ] **Step 1: Write the failing tests for the new `ssm_parameter` behavior**

Add to `tests/spec/test_parser.py`, near the existing
`test_parse_inline_mcp_sigv4_auth*` tests:

```python
def test_parse_inline_mcp_ssm_parameter(tmp_path: Path) -> None:
    """
    An inline MCP entry with ``ssm_parameter`` (no ``url``) parses into
    MCPServerConfig.aws_ssm_parameter, with transport inferred as http.

    Failure means either the field is dropped, or (more subtly) transport
    inference — which currently only checks command/url — silently skips
    the whole entry because neither command nor url is present.
    """
    config = {
        "spec_version": 1,
        "name": "ssm-agent",
        "tools": {
            "marshall": {
                "type": "mcp",
                "ssm_parameter": "/ace/poc/ace-os/marshall/runtime/url",
                "auth": {
                    "type": "sigv4",
                    "profile": "default",
                    "service": "bedrock-agentcore",
                    "region": "ap-southeast-2",
                },
            }
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(config))
    spec = parse(tmp_path)

    assert len(spec.mcp_servers) == 1
    server = spec.mcp_servers[0]
    assert server.transport == "http"
    assert server.url is None
    assert server.aws_ssm_parameter == "/ace/poc/ace-os/marshall/runtime/url"
    assert server.aws_profile == "default"


def test_parse_inline_mcp_ssm_parameter_and_url_both_set_raises(tmp_path: Path) -> None:
    """Specifying both url and ssm_parameter is a usage error, not a silent pick."""
    config = {
        "spec_version": 1,
        "name": "ssm-agent-bad",
        "tools": {
            "marshall": {
                "type": "mcp",
                "url": "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
                "ssm_parameter": "/ace/poc/ace-os/marshall/runtime/url",
                "auth": {"type": "sigv4", "profile": "default", "service": "bedrock-agentcore"},
            }
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(config))

    with pytest.raises(OmnigentError, match=r"exactly one of 'url' or 'ssm_parameter'"):
        parse(tmp_path)


def test_parse_inline_mcp_ssm_parameter_without_aws_profile_raises(tmp_path: Path) -> None:
    """ssm_parameter without an auth: {type: sigv4, ...} block is a usage error.

    There's no separate credential concept for the SSM lookup itself — it
    reuses aws_profile from the sigv4 auth block. Without it, the lookup
    has no AWS profile to use.
    """
    config = {
        "spec_version": 1,
        "name": "ssm-agent-noauth",
        "tools": {
            "marshall": {
                "type": "mcp",
                "ssm_parameter": "/ace/poc/ace-os/marshall/runtime/url",
            }
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(config))

    with pytest.raises(OmnigentError, match=r"'ssm_parameter' requires auth"):
        parse(tmp_path)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/spec/test_parser.py -k ssm_parameter -v`
Expected: FAIL — the first test fails because the inline entry is silently
skipped (transport inference doesn't recognize `ssm_parameter`, so
`spec.mcp_servers` is empty); the other two fail because no validation
exists yet (no error raised).

- [ ] **Step 3: Extract the shared `_parse_mcp_auth_block` helper**

In `omnigent/spec/parser.py`, immediately above `_parse_inline_mcp_servers`
(currently line 2245), add:

```python
def _parse_mcp_auth_block(
    raw_auth: object,
    describe: str,
    location_suffix: str = "",
) -> tuple[str | None, str | None, str | None, str | None]:
    """
    Parse an MCP server's ``auth:`` block (``databricks`` or ``sigv4``).

    Shared by the inline ``tools:`` block parser and the standalone
    ``tools/mcp/<name>.yaml`` file parser so both auth types behave
    identically regardless of which YAML shape declares the server.

    :param raw_auth: The raw ``auth`` value from the YAML mapping.
    :param describe: Error-message prefix identifying the server, e.g.
        ``f"Inline MCP server {name!r}"`` or ``f"MCP server {name!r}"``.
    :param location_suffix: Error-message suffix, e.g. ``f": {yaml_file}"``
        for file-based parsing, or ``""`` for inline parsing.
    :returns: ``(databricks_profile, aws_profile, aws_service, aws_region)``,
        each ``None`` unless *raw_auth* declares the matching type.
    :raises OmnigentError: If a ``databricks`` block is missing ``profile``,
        or a ``sigv4`` block is missing ``profile``/``service``.
    """
    databricks_profile: str | None = None
    aws_profile: str | None = None
    aws_service: str | None = None
    aws_region: str | None = None
    if isinstance(raw_auth, dict) and str(raw_auth.get("type", "")) == "databricks":
        raw_profile = raw_auth.get("profile")
        if raw_profile is None:
            raise OmnigentError(
                f"{describe} auth type 'databricks' requires a 'profile' field{location_suffix}",
                code=ErrorCode.INVALID_INPUT,
            )
        databricks_profile = str(raw_profile)
    if isinstance(raw_auth, dict) and str(raw_auth.get("type", "")) == "sigv4":
        raw_profile = raw_auth.get("profile")
        raw_service = raw_auth.get("service")
        if raw_profile is None or raw_service is None:
            raise OmnigentError(
                f"{describe} auth type 'sigv4' requires 'profile' and 'service' fields"
                f"{location_suffix}",
                code=ErrorCode.INVALID_INPUT,
            )
        aws_profile = str(raw_profile)
        aws_service = str(raw_service)
        if (raw_region := raw_auth.get("region")) is not None:
            aws_region = str(raw_region)
    return databricks_profile, aws_profile, aws_service, aws_region
```

Verify the two error messages this produces are byte-for-byte identical to
the strings currently hardcoded in `_parse_inline_mcp_servers` (lines
2333-2337 and 2350-2354) when called with `describe=f"Inline MCP server
{name!r}"` and `location_suffix=""` — the existing tests
(`test_parse_inline_mcp_sigv4_auth_missing_profile_raises`, etc.) assert on
these exact strings via `pytest.raises(..., match=...)` and must keep
passing unchanged.

- [ ] **Step 4: Replace the inline auth-parsing block with a call to the helper**

In `omnigent/spec/parser.py`, `_parse_inline_mcp_servers` currently has
(lines 2326-2358):

```python
        # Optional Databricks auth — resolves a bearer token at
        # connection time from ~/.databrickscfg.
        raw_auth = val.get("auth")
        databricks_profile: str | None = None
        if isinstance(raw_auth, dict) and str(raw_auth.get("type", "")) == "databricks":
            raw_profile = raw_auth.get("profile")
            if raw_profile is None:
                raise OmnigentError(
                    f"Inline MCP server {name!r} auth type 'databricks' "
                    f"requires a 'profile' field",
                    code=ErrorCode.INVALID_INPUT,
                )
            databricks_profile = str(raw_profile)
        # Optional AWS SigV4 auth — signs every request with credentials
        # from a named AWS CLI profile (e.g. one kept fresh by
        # aws-azure-login). Re-resolved fresh per request by
        # SigV4SessionAuth, not cached here.
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

Replace with:

```python
        # Optional Databricks/SigV4 auth block — see _parse_mcp_auth_block.
        raw_auth = val.get("auth")
        databricks_profile, aws_profile, aws_service, aws_region = _parse_mcp_auth_block(
            raw_auth, f"Inline MCP server {name!r}"
        )
```

- [ ] **Step 5: Run the existing databricks/sigv4 inline tests to confirm the refactor is behavior-preserving**

Run: `uv run pytest tests/spec/test_parser.py -k "databricks or sigv4" -v`
Expected: PASS, unchanged (this proves the extraction didn't alter
behavior before moving on to the new feature).

- [ ] **Step 6: Fix transport inference to recognize `ssm_parameter`**

In the same function, currently (lines 2300-2309):

```python
        command = val.get("command")
        url = val.get("url")
        if command is not None:
            transport: str = "stdio"
        elif url is not None:
            transport = "http"
        else:
            # Databricks-managed server or unknown shape — no local
            # endpoint to display; skip.
            continue
```

Change to:

```python
        command = val.get("command")
        url = val.get("url")
        ssm_parameter = val.get("ssm_parameter")
        if command is not None:
            transport: str = "stdio"
        elif url is not None or ssm_parameter is not None:
            transport = "http"
        else:
            # Databricks-managed server or unknown shape — no local
            # endpoint to display; skip.
            continue
```

- [ ] **Step 7: Add `ssm_parameter` validation and pass it into `MCPServerConfig`**

In the same function, immediately after Step 4's `_parse_mcp_auth_block`
call (so `aws_profile` is known) and before the existing `tools:` allowlist
parsing block, add:

```python
        ssm_parameter_str: str | None = None
        if ssm_parameter is not None:
            if url is not None:
                raise OmnigentError(
                    f"Inline MCP server {name!r} must specify exactly one of "
                    f"'url' or 'ssm_parameter', not both",
                    code=ErrorCode.INVALID_INPUT,
                )
            if aws_profile is None:
                raise OmnigentError(
                    f"Inline MCP server {name!r} 'ssm_parameter' requires "
                    f"auth: {{type: sigv4, profile: ...}} to resolve via AWS SSM",
                    code=ErrorCode.INVALID_INPUT,
                )
            ssm_parameter_str = str(ssm_parameter)
```

Then add `aws_ssm_parameter=ssm_parameter_str,` to the `MCPServerConfig(...)`
construction (currently lines 2370-2389), alongside the existing
`aws_profile=aws_profile,` line.

- [ ] **Step 8: Run the new tests to verify they pass**

Run: `uv run pytest tests/spec/test_parser.py -k ssm_parameter -v`
Expected: PASS (3 tests)

- [ ] **Step 9: Run the full parser test file for regressions**

Run: `uv run pytest tests/spec/test_parser.py -v`
Expected: PASS, no regressions (in particular every existing
`test_parse_inline_mcp_*` test).

- [ ] **Step 10: Commit**

```bash
git add omnigent/spec/parser.py tests/spec/test_parser.py
git commit -m "feat(mcp): extract shared auth-block parser; add ssm_parameter to inline MCP format"
```

---

### Task 3: Fix `auth:` handling and add `ssm_parameter` to the standalone `tools/mcp/<name>.yaml` format

**Files:**
- Modify: `omnigent/spec/parser.py:2451-2506` (`_parse_http_mcp_server`)
- Test: `tests/spec/test_parser.py`

**Interfaces:**
- Consumes: `_parse_mcp_auth_block` (Task 2), `MCPServerConfig.aws_ssm_parameter`
  (Task 1).

This is the task that fixes the actual bug (silently-dropped `auth:` on
standalone bundle files) and delivers the operator's real use case
(`tools/mcp/ace-marshall.yaml`).

- [ ] **Step 1: Write the failing tests**

Add to `tests/spec/test_parser.py`, near `test_parse_inline_and_bundle_mcp_combined`
(currently around line 1542) — this test already shows the exact fixture
pattern for `tools/mcp/*.yaml` bundle files (`tmp_path / "tools" / "mcp"`,
one `.yaml` file per server, `parse(tmp_path)`):

```python
def _write_bundle_mcp_yaml(tmp_path: Path, filename: str, content: dict) -> None:
    """Write one tools/mcp/<filename> bundle-file MCP server config."""
    mcp_dir = tmp_path / "tools" / "mcp"
    mcp_dir.mkdir(parents=True, exist_ok=True)
    (mcp_dir / filename).write_text(yaml.dump(content))
    (tmp_path / "config.yaml").write_text(yaml.dump({"spec_version": 1, "name": "bundle-test"}))


def test_discover_mcp_bundle_file_parses_databricks_auth(tmp_path: Path) -> None:
    """
    ``tools/mcp/<name>.yaml`` with ``auth: {type: databricks, profile}``
    parses into MCPServerConfig.databricks_profile.

    Regression test for the bug this task fixes: _parse_http_mcp_server
    never read `auth:` at all before this change, so a bundle-file server
    with this exact YAML would silently connect with NO auth — the token
    header would simply never be added, and the failure mode would be an
    opaque 401 from the remote server, not a parse-time error.
    """
    _write_bundle_mcp_yaml(
        tmp_path,
        "docs.yaml",
        {
            "name": "docs",
            "transport": "http",
            "url": "https://my-workspace.databricks.com/api/2.0/mcp",
            "auth": {"type": "databricks", "profile": "oss"},
        },
    )
    spec = parse(tmp_path)

    server = next(s for s in spec.mcp_servers if s.name == "docs")
    assert server.databricks_profile == "oss"


def test_discover_mcp_bundle_file_parses_sigv4_auth(tmp_path: Path) -> None:
    """``tools/mcp/<name>.yaml`` with ``auth: {type: sigv4, ...}`` parses correctly.

    Same regression class as the databricks test above — sigv4 auth was
    equally silently dropped by _parse_http_mcp_server before this fix.
    """
    _write_bundle_mcp_yaml(
        tmp_path,
        "ace-peg.yaml",
        {
            "name": "ace-peg",
            "transport": "http",
            "url": "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
            "auth": {
                "type": "sigv4",
                "profile": "default",
                "service": "bedrock-agentcore",
                "region": "ap-southeast-2",
            },
        },
    )
    spec = parse(tmp_path)

    server = next(s for s in spec.mcp_servers if s.name == "ace-peg")
    assert server.aws_profile == "default"
    assert server.aws_service == "bedrock-agentcore"
    assert server.aws_region == "ap-southeast-2"


def test_discover_mcp_bundle_file_ssm_parameter(tmp_path: Path) -> None:
    """``ssm_parameter`` (no ``url``) parses into aws_ssm_parameter — the operator's actual use case."""
    _write_bundle_mcp_yaml(
        tmp_path,
        "ace-marshall.yaml",
        {
            "name": "ace-marshall",
            "transport": "http",
            "ssm_parameter": "/ace/poc/ace-os/marshall/runtime/url",
            "auth": {
                "type": "sigv4",
                "profile": "default",
                "service": "bedrock-agentcore",
                "region": "ap-southeast-2",
            },
        },
    )
    spec = parse(tmp_path)

    server = next(s for s in spec.mcp_servers if s.name == "ace-marshall")
    assert server.url is None
    assert server.aws_ssm_parameter == "/ace/poc/ace-os/marshall/runtime/url"


def test_discover_mcp_bundle_file_ssm_parameter_and_url_both_set_raises(tmp_path: Path) -> None:
    """Specifying both url and ssm_parameter in a bundle file is a usage error."""
    _write_bundle_mcp_yaml(
        tmp_path,
        "bad.yaml",
        {
            "name": "bad",
            "transport": "http",
            "url": "https://example.com/mcp",
            "ssm_parameter": "/ace/poc/ace-os/marshall/runtime/url",
            "auth": {"type": "sigv4", "profile": "default", "service": "bedrock-agentcore"},
        },
    )

    with pytest.raises(OmnigentError, match=r"exactly one of 'url' or 'ssm_parameter'"):
        parse(tmp_path)


def test_discover_mcp_bundle_file_ssm_parameter_without_aws_profile_raises(tmp_path: Path) -> None:
    """ssm_parameter without a sigv4 auth block is a usage error in bundle files too."""
    _write_bundle_mcp_yaml(
        tmp_path,
        "bad.yaml",
        {
            "name": "bad",
            "transport": "http",
            "ssm_parameter": "/ace/poc/ace-os/marshall/runtime/url",
        },
    )

    with pytest.raises(OmnigentError, match=r"'ssm_parameter' requires auth"):
        parse(tmp_path)


def test_discover_mcp_bundle_file_missing_url_and_ssm_parameter_raises(tmp_path: Path) -> None:
    """Missing both url and ssm_parameter still fails loud, with the reworded message."""
    _write_bundle_mcp_yaml(tmp_path, "bad.yaml", {"name": "bad", "transport": "http"})

    with pytest.raises(OmnigentError, match=r"missing required field 'url' or 'ssm_parameter'"):
        parse(tmp_path)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/spec/test_parser.py -k "discover_mcp_bundle" -v`
Expected: FAIL — the databricks/sigv4 tests fail because `server.databricks_profile`/
`server.aws_profile` are `None` (silently dropped); the `ssm_parameter`
tests fail because the field doesn't exist / no validation runs; the
missing-both test fails because the current message says only `"missing
required field 'url'"`, not the reworded version.

- [ ] **Step 3: Update `_parse_http_mcp_server`**

In `omnigent/spec/parser.py`, `_parse_http_mcp_server` currently has (lines
2486-2506):

```python
    url = raw.get("url")
    if url is None:
        raise OmnigentError(
            f"MCP server {name!r} missing required field 'url': {yaml_file}",
            code=ErrorCode.INVALID_INPUT,
        )
    return MCPServerConfig(
        name=str(name),
        transport="http",
        url=str(url),
        headers=(
            expand_env_vars(raw.get("headers", {})) if expand_env else raw.get("headers", {})
        ),
        description=raw.get("description"),
        timeout=(
            _parse_int_field(raw["timeout"], f"MCP server {name!r}.timeout")
            if "timeout" in raw
            else None
        ),
        retry=_parse_retry(raw["retry"]) if "retry" in raw else None,
    )
```

Replace with:

```python
    url = raw.get("url")
    ssm_parameter = raw.get("ssm_parameter")
    if url is not None and ssm_parameter is not None:
        raise OmnigentError(
            f"MCP server {name!r} must specify exactly one of 'url' or "
            f"'ssm_parameter', not both: {yaml_file}",
            code=ErrorCode.INVALID_INPUT,
        )
    if url is None and ssm_parameter is None:
        raise OmnigentError(
            f"MCP server {name!r} missing required field 'url' or 'ssm_parameter': {yaml_file}",
            code=ErrorCode.INVALID_INPUT,
        )
    raw_auth = raw.get("auth")
    databricks_profile, aws_profile, aws_service, aws_region = _parse_mcp_auth_block(
        raw_auth, f"MCP server {name!r}", f": {yaml_file}"
    )
    if ssm_parameter is not None and aws_profile is None:
        raise OmnigentError(
            f"MCP server {name!r} 'ssm_parameter' requires auth: {{type: sigv4, "
            f"profile: ...}} to resolve via AWS SSM: {yaml_file}",
            code=ErrorCode.INVALID_INPUT,
        )
    return MCPServerConfig(
        name=str(name),
        transport="http",
        url=str(url) if url is not None else None,
        aws_ssm_parameter=str(ssm_parameter) if ssm_parameter is not None else None,
        headers=(
            expand_env_vars(raw.get("headers", {})) if expand_env else raw.get("headers", {})
        ),
        description=raw.get("description"),
        databricks_profile=databricks_profile,
        aws_profile=aws_profile,
        aws_service=aws_service,
        aws_region=aws_region,
        timeout=(
            _parse_int_field(raw["timeout"], f"MCP server {name!r}.timeout")
            if "timeout" in raw
            else None
        ),
        retry=_parse_retry(raw["retry"]) if "retry" in raw else None,
    )
```

Note `url` changed from `str(url)` (unconditional) to `str(url) if url is
not None else None` — it's no longer guaranteed non-`None` at this point
since `ssm_parameter` can satisfy the "one of the two" requirement instead.

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `uv run pytest tests/spec/test_parser.py -k "discover_mcp_bundle" -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Run the full parser test file for regressions**

Run: `uv run pytest tests/spec/test_parser.py -v`
Expected: PASS, no regressions — in particular
`test_parse_inline_and_bundle_mcp_combined` and any other existing
bundle-file test.

- [ ] **Step 6: Commit**

```bash
git add omnigent/spec/parser.py tests/spec/test_parser.py
git commit -m "fix(mcp): parse auth: and ssm_parameter in tools/mcp/<name>.yaml bundle files"
```

---

### Task 4: `resolve_ssm_runtime_url` resolver

**Files:**
- Modify: `omnigent/tools/aws_auth.py` (add the function + `urllib.parse`
  import)
- Test: `tests/tools/test_aws_auth.py`

**Interfaces:**
- Produces: `resolve_ssm_runtime_url(ssm_parameter: str, profile: str,
  region: str | None, qualifier: str = "DEFAULT") -> str` — consumed by
  Task 5's `_resolve_http_url`.
- Reference implementation: `ace-runtime-test/ace_explore.py:77-115`
  (`build_mcp_url`/`fetch_runtime_arn`) — port the ARN-encoding and
  URL-building logic verbatim; the SSM/profile error handling follows the
  same proactive-`ProfileNotFound`-handling pattern already established in
  `SigV4SessionAuth.auth_flow` (found and fixed as a real bug during the
  parent SigV4 feature's review — apply the same fix here from the start
  rather than waiting to rediscover it).

- [ ] **Step 1: Write the failing tests**

Add to `tests/tools/test_aws_auth.py`:

```python
def test_resolve_ssm_runtime_url_happy_path() -> None:
    """
    Fetches the ARN from the given SSM parameter and builds the AgentCore
    invocation URL, percent-encoding the ARN so its ':' and '/' survive
    as a single path segment (ported from ace_explore.py's build_mcp_url).
    """
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = {
        "Parameter": {
            "Value": "arn:aws:bedrock-agentcore:ap-southeast-2:300428143068:runtime/marshall-abc123"
        }
    }
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ssm
    mock_session.region_name = "ap-southeast-2"

    with patch("omnigent.tools.aws_auth.boto3.Session", return_value=mock_session):
        url = resolve_ssm_runtime_url(
            "/ace/poc/ace-os/marshall/runtime/url", "default", "ap-southeast-2"
        )

    assert url == (
        "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/"
        "arn%3Aaws%3Abedrock-agentcore%3Aap-southeast-2%3A300428143068%3Aruntime%2Fmarshall-abc123"
        "/invocations?qualifier=DEFAULT"
    )
    mock_session.client.assert_called_once_with("ssm")
    mock_ssm.get_parameter.assert_called_once_with(Name="/ace/poc/ace-os/marshall/runtime/url")


def test_resolve_ssm_runtime_url_falls_back_to_session_region() -> None:
    """When region=None, the resolver uses the profile's configured region."""
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = {
        "Parameter": {"Value": "arn:aws:bedrock-agentcore:us-west-2:1:runtime/x"}
    }
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ssm
    mock_session.region_name = "us-west-2"

    with patch("omnigent.tools.aws_auth.boto3.Session", return_value=mock_session):
        url = resolve_ssm_runtime_url("/some/param", "default", None)

    assert url.startswith("https://bedrock-agentcore.us-west-2.amazonaws.com/")


def test_resolve_ssm_runtime_url_parameter_not_found_raises() -> None:
    """A missing SSM parameter raises an actionable RuntimeError, not a bare botocore exception."""
    mock_ssm = MagicMock()

    class _ParameterNotFound(Exception):
        pass

    mock_ssm.exceptions.ParameterNotFound = _ParameterNotFound
    mock_ssm.get_parameter.side_effect = _ParameterNotFound()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ssm
    mock_session.region_name = "ap-southeast-2"

    with patch("omnigent.tools.aws_auth.boto3.Session", return_value=mock_session):
        with pytest.raises(RuntimeError) as exc:
            resolve_ssm_runtime_url("/ace/poc/ace-os/marshall/runtime/url", "default", None)

    assert "/ace/poc/ace-os/marshall/runtime/url" in str(exc.value)


def test_resolve_ssm_runtime_url_profile_not_found_raises() -> None:
    """A bad/stale profile name raises the same actionable RuntimeError pattern as SigV4SessionAuth."""
    with patch("omnigent.tools.aws_auth.boto3.Session", side_effect=ProfileNotFound(profile="stale")):
        with pytest.raises(RuntimeError) as exc:
            resolve_ssm_runtime_url("/some/param", "stale", "ap-southeast-2")

    assert "stale" in str(exc.value)
    assert "aws-azure-login" in str(exc.value)
```

This requires `MagicMock`, `patch` (already imported in the file per Task
3 of the parent plan), and `ProfileNotFound`/`resolve_ssm_runtime_url`
imported at the top — check the file's current imports and add whichever
of `from botocore.exceptions import ProfileNotFound` and `from
omnigent.tools.aws_auth import resolve_ssm_runtime_url, SigV4SessionAuth`
(extending the existing import line) are missing.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/tools/test_aws_auth.py -k ssm -v`
Expected: FAIL — `ImportError: cannot import name 'resolve_ssm_runtime_url'`

- [ ] **Step 3: Add `urllib.parse` import and the function**

In `omnigent/tools/aws_auth.py`, add to the imports (after `from __future__
import annotations`):

```python
import urllib.parse
```

Then add, after the `SigV4SessionAuth` class:

```python
def resolve_ssm_runtime_url(
    ssm_parameter: str,
    profile: str,
    region: str | None,
    qualifier: str = "DEFAULT",
) -> str:
    """
    Fetch a Bedrock AgentCore runtime ARN from AWS SSM Parameter Store
    and build its invocation URL.

    Ported from ``ace-runtime-test/ace_explore.py``'s
    ``fetch_runtime_arn``/``build_mcp_url``. Unlike credential
    resolution, a runtime ARN doesn't rotate on a timer — only on
    redeploy — so this is resolved once per connect/reconnect, not per
    request (see ``McpServerConnection._resolve_http_url``).

    :param ssm_parameter: SSM Parameter Store path holding the runtime
        ARN, e.g. ``"/ace/poc/ace-os/marshall/runtime/url"``.
    :param profile: AWS CLI profile name, used for both the SSM lookup
        and (separately) SigV4 signing.
    :param region: AWS region, or ``None`` to fall back to the profile's
        configured region.
    :param qualifier: AgentCore invocation qualifier.
    :returns: The full AgentCore data-plane invocations URL.
    :raises RuntimeError: If the profile has no credentials, or the SSM
        parameter does not exist.
    """
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        ssm = session.client("ssm")
    except ProfileNotFound:
        raise RuntimeError(
            f"No AWS credentials found for profile {profile!r}. "
            f"Run `aws-azure-login --mode cli --profile {profile}` and retry."
        ) from None
    resolved_region = region or session.region_name
    try:
        response = ssm.get_parameter(Name=ssm_parameter)
    except ssm.exceptions.ParameterNotFound:
        raise RuntimeError(
            f"SSM parameter {ssm_parameter!r} not found (profile {profile!r}, "
            f"region {resolved_region!r}). Check the parameter path and that "
            f"the runtime is deployed."
        ) from None
    runtime_arn = response["Parameter"]["Value"]
    encoded_arn = urllib.parse.quote(runtime_arn, safe="")
    return (
        f"https://bedrock-agentcore.{resolved_region}.amazonaws.com"
        f"/runtimes/{encoded_arn}/invocations?qualifier={qualifier}"
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/tools/test_aws_auth.py -v`
Expected: PASS (all tests, including the 4 new ones — 9 total)

- [ ] **Step 5: Commit**

```bash
git add omnigent/tools/aws_auth.py tests/tools/test_aws_auth.py
git commit -m "feat(mcp): add resolve_ssm_runtime_url for Bedrock AgentCore URL resolution"
```

---

### Task 5: Wire URL resolution into `McpServerConnection`

**Files:**
- Modify: `omnigent/tools/mcp.py:890-1040ish` (`_open_http_transport`, new
  `_resolve_http_url`, `_open_streamable_http_transport`,
  `_open_sse_transport`, import line)
- Test: `tests/tools/test_mcp.py`

**Interfaces:**
- Consumes: `resolve_ssm_runtime_url` (Task 4),
  `MCPServerConfig.aws_ssm_parameter` (Task 1).

- [ ] **Step 1: Write the failing tests**

Add to `tests/tools/test_mcp.py`, near the existing sigv4 transport tests
(`test_http_connect_passes_sigv4_auth_to_transport`, currently around line
1420):

```python
@pytest.mark.asyncio()
async def test_http_connect_resolves_url_from_ssm_parameter() -> None:
    """
    connect() resolves the URL via resolve_ssm_runtime_url when
    aws_ssm_parameter is set (no static url configured), and passes the
    RESOLVED url to the transport — not the raw ssm_parameter path.
    """
    config = MCPServerConfig(
        name="test-ssm",
        aws_ssm_parameter="/ace/poc/ace-os/marshall/runtime/url",
        aws_profile="default",
        aws_service="bedrock-agentcore",
        aws_region="ap-southeast-2",
    )
    resolved_url = "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations"

    with patch(
        "omnigent.tools.mcp.resolve_ssm_runtime_url", return_value=resolved_url
    ) as mock_resolve:
        with _mock_http_transport() as captured:
            conn = McpServerConnection(config=config)
            await conn.connect()

    mock_resolve.assert_called_once_with(
        "/ace/poc/ace-os/marshall/runtime/url", "default", "ap-southeast-2"
    )
    assert captured.transport_kwargs["url"] == resolved_url

    await conn.close()


@pytest.mark.asyncio()
async def test_http_connect_uses_static_url_without_calling_ssm_resolver() -> None:
    """
    When config.url is set, connect() must NOT call the SSM resolver at
    all — url always takes priority, and an unnecessary AWS API call on
    every connect for a server that doesn't use ssm_parameter would be a
    regression.
    """
    config = MCPServerConfig(name="test-static-url", url="http://localhost:9000/mcp")

    with patch("omnigent.tools.mcp.resolve_ssm_runtime_url") as mock_resolve:
        with _mock_http_transport() as captured:
            conn = McpServerConnection(config=config)
            await conn.connect()

    mock_resolve.assert_not_called()
    assert captured.transport_kwargs["url"] == "http://localhost:9000/mcp"

    await conn.close()


def test_resolve_http_url_reresolves_on_each_call() -> None:
    """
    _resolve_http_url() re-resolves via SSM on every call, not cached —
    same cadence requirement as the Databricks token and SigV4 auth
    resolvers. A stale cached URL would survive a redeploy indefinitely.
    """
    config = MCPServerConfig(
        name="test-ssm-fresh",
        aws_ssm_parameter="/some/param",
        aws_profile="default",
        aws_service="bedrock-agentcore",
    )
    conn = McpServerConnection(config=config)

    with patch(
        "omnigent.tools.mcp.resolve_ssm_runtime_url",
        side_effect=["https://first.example.com/invocations", "https://second.example.com/invocations"],
    ) as mock_resolve:
        first = conn._resolve_http_url()
        second = conn._resolve_http_url()

    assert first == "https://first.example.com/invocations"
    assert second == "https://second.example.com/invocations"
    assert mock_resolve.call_count == 2
```

Also add `resolve_ssm_runtime_url` to the existing `from
omnigent.tools.aws_auth import SigV4SessionAuth` import line if this test
file references it directly anywhere (it doesn't need to — the patches
above target `omnigent.tools.mcp.resolve_ssm_runtime_url`, i.e. the name as
imported into `mcp.py`, not the original module).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/tools/test_mcp.py -k ssm -v`
Expected: FAIL — `AttributeError`/`ModuleNotFoundError` on
`omnigent.tools.mcp.resolve_ssm_runtime_url` (not imported yet), and
`_resolve_http_url` doesn't exist yet.

- [ ] **Step 3: Update the import**

In `omnigent/tools/mcp.py`, currently:

```python
from omnigent.tools.aws_auth import SigV4SessionAuth
```

Change to:

```python
from omnigent.tools.aws_auth import SigV4SessionAuth, resolve_ssm_runtime_url
```

- [ ] **Step 4: Add `_resolve_http_url`**

In `omnigent/tools/mcp.py`, immediately after `_resolve_http_auth` (currently
ending around line 978):

```python
    def _resolve_http_url(self) -> str:
        """
        Resolve the effective HTTP URL for the MCP connection.

        Returns ``config.url`` verbatim when set. Otherwise resolves it
        fresh from AWS SSM (``config.aws_ssm_parameter``) on every call —
        same per-connect cadence as ``_resolve_http_headers``, not
        per-request: a runtime ARN doesn't rotate the way credentials do,
        it only changes on redeploy.

        :returns: The URL to connect to.
        """
        if self.config.url is not None:
            return self.config.url
        assert self.config.aws_ssm_parameter is not None  # enforced at parse time
        assert self.config.aws_profile is not None  # enforced at parse time
        return resolve_ssm_runtime_url(
            self.config.aws_ssm_parameter, self.config.aws_profile, self.config.aws_region
        )
```

- [ ] **Step 5: Update `_open_http_transport` to resolve and thread the URL**

In `omnigent/tools/mcp.py`, `_open_http_transport` currently does (lines
910-944):

```python
        if self.config.url is None:
            # Validator prevents this at spec-load time; the assert
            # is a belt-and-suspenders check for programmatic
            # MCPServerConfig construction paths that skip the
            # validator.
            raise RuntimeError(
                f"MCP server {self.config.name!r} transport='http' but url is None — "
                "validator should have caught this"
            )
        timeout = self.config.timeout
        headers = self._resolve_http_headers()
        auth = self._resolve_http_auth()
        if _is_sse_endpoint(self.config.url):
            ...
            return await self._open_sse_transport(stack, timeout, headers, auth)
        try:
            return await self._open_streamable_http_transport(stack, timeout, headers, auth)
        except Exception as exc:
            ...
            return await self._open_sse_transport(stack, timeout, headers, auth)
```

Change to:

```python
        url = self._resolve_http_url()
        timeout = self.config.timeout
        headers = self._resolve_http_headers()
        auth = self._resolve_http_auth()
        if _is_sse_endpoint(url):
            ...
            return await self._open_sse_transport(stack, url, timeout, headers, auth)
        try:
            return await self._open_streamable_http_transport(stack, url, timeout, headers, auth)
        except Exception as exc:
            ...
            return await self._open_sse_transport(stack, url, timeout, headers, auth)
```

(Keep the `...` docstring/comments and the `_logger.debug(...)` call in the
`except` block exactly as they are today — only the guard clause at the top
is removed, replaced by `url = self._resolve_http_url()`, and the three
call sites gain the `url` argument. `_resolve_http_url()`'s own asserts
replace the removed `RuntimeError` guard's belt-and-suspenders role.)

- [ ] **Step 6: Thread `url` through both transport methods**

In `omnigent/tools/mcp.py`, `_open_streamable_http_transport` currently:

```python
    async def _open_streamable_http_transport(
        self,
        stack: AsyncExitStack,
        timeout: int | None,
        headers: dict[str, str] | None,
        auth: httpx.Auth | None,
    ) -> tuple[_ReadStream, _WriteStream]:
        ...
        assert self.config.url is not None
        read_stream, write_stream, _get_session_id = await stack.enter_async_context(
            streamablehttp_client(
                url=self.config.url,
                headers=headers,
                timeout=float(timeout) if timeout is not None else 30,
                sse_read_timeout=float(timeout) if timeout is not None else 300,
                auth=auth,
            )
        )
        return read_stream, write_stream
```

Change to:

```python
    async def _open_streamable_http_transport(
        self,
        stack: AsyncExitStack,
        url: str,
        timeout: int | None,
        headers: dict[str, str] | None,
        auth: httpx.Auth | None,
    ) -> tuple[_ReadStream, _WriteStream]:
        ...
        read_stream, write_stream, _get_session_id = await stack.enter_async_context(
            streamablehttp_client(
                url=url,
                headers=headers,
                timeout=float(timeout) if timeout is not None else 30,
                sse_read_timeout=float(timeout) if timeout is not None else 300,
                auth=auth,
            )
        )
        return read_stream, write_stream
```

Add a `:param url:` docstring line ("Resolved connection URL — either the
config's static `url` or one resolved via AWS SSM.") matching the existing
`:param headers:`/`:param auth:` style, and remove the now-redundant
`assert self.config.url is not None` line.

Apply the identical change to `_open_sse_transport` (same signature change:
add `url: str` as the second parameter after `stack`, use `url=url` in the
`sse_client(...)` call, remove its `assert self.config.url is not None`,
add the same `:param url:` docstring line).

- [ ] **Step 7: Find and fix any other callers of the two transport methods**

Run: `grep -n "_open_streamable_http_transport\|_open_sse_transport" omnigent/tools/mcp.py tests/tools/test_mcp.py`

The parent SigV4 plan's implementer found and fixed two test-only fakes
that monkeypatch these methods directly with a fixed-arity signature
(`test_open_http_transport_routes_sse_url_straight_to_sse`,
`test_open_http_transport_uses_streamable_for_non_sse_url` — both added a
4th `auth` param last time). This task adds a 5th parameter (`url`,
inserted as the *second* positional param, right after `stack`) — update
both fakes' signatures again to match the new parameter order. Do not
change either test's assertions, only the fake functions' parameter lists.

- [ ] **Step 8: Run the new tests to verify they pass**

Run: `uv run pytest tests/tools/test_mcp.py -k ssm -v`
Expected: PASS (3 tests)

- [ ] **Step 9: Run the full MCP test suite for regressions**

Run: `uv run pytest tests/tools/test_mcp.py -v`
Expected: PASS, no regressions — in particular every existing
`test_http_*`/`test_sse_*`/`test_open_http_transport_*` test.

- [ ] **Step 10: Commit**

```bash
git add omnigent/tools/mcp.py tests/tools/test_mcp.py
git commit -m "feat(mcp): resolve HTTP MCP server URL from AWS SSM when configured"
```

---

### Task 6: Config-change hash coverage — `omnigent/runner/mcp_manager.py`

**Files:**
- Modify: `omnigent/runner/mcp_manager.py:87-148ish` (`compute_spec_hash`,
  `compute_server_hash`)
- Test: `tests/runner/test_mcp_manager.py`

**Interfaces:**
- Consumes: `MCPServerConfig.aws_ssm_parameter` (Task 1).

- [ ] **Step 1: Write the failing test**

Add to `tests/runner/test_mcp_manager.py`, near
`test_compute_server_hash_changes_with_aws_profile`:

```python
def test_compute_server_hash_changes_with_aws_ssm_parameter() -> None:
    """
    compute_server_hash must reflect aws_ssm_parameter — otherwise
    pointing a running server at a different SSM parameter wouldn't
    trigger a reconnect, mirroring the aws_profile hash-coverage fix.
    """
    base = MCPServerConfig(
        name="ssm-svc",
        aws_ssm_parameter="/ace/poc/ace-os/marshall/runtime/url",
        aws_profile="default",
        aws_service="bedrock-agentcore",
    )
    different_param = MCPServerConfig(
        name="ssm-svc",
        aws_ssm_parameter="/ace/poc/modules/other/runtime/url",
        aws_profile="default",
        aws_service="bedrock-agentcore",
    )

    assert compute_server_hash(base) != compute_server_hash(different_param)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/runner/test_mcp_manager.py -k aws_ssm_parameter -v`
Expected: FAIL — both configs hash identically since `aws_ssm_parameter`
isn't in the payload yet.

- [ ] **Step 3: Add the field to both hash payloads**

In `omnigent/runner/mcp_manager.py`, `compute_spec_hash`'s per-server
payload dict — add immediately after the `"aws_region": c.aws_region,`
line:

```python
                    "aws_region": c.aws_region,
                    "aws_ssm_parameter": c.aws_ssm_parameter,
```

And `compute_server_hash`'s payload dict — same addition after its
`"aws_region": config.aws_region,` line:

```python
            "aws_region": config.aws_region,
            "aws_ssm_parameter": config.aws_ssm_parameter,
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/runner/test_mcp_manager.py -k aws_ssm_parameter -v`
Expected: PASS

- [ ] **Step 5: Run the full mcp_manager test suite for regressions**

Run: `uv run pytest tests/runner/test_mcp_manager.py -v`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add omnigent/runner/mcp_manager.py tests/runner/test_mcp_manager.py
git commit -m "fix(mcp): include aws_ssm_parameter in server config-change hash"
```

---

### Task 7: Documentation and full verification pass

**Files:**
- Modify: `docs/AGENT_YAML_SPEC.md` (MCP server section)

**Interfaces:** None — documentation and verification only.

- [ ] **Step 1: Document `ssm_parameter` in `docs/AGENT_YAML_SPEC.md`**

In `docs/AGENT_YAML_SPEC.md`'s MCP server section, immediately after the
existing sigv4 example block (added by the parent SigV4 spec — search for
`type: sigv4` in that file), add:

```markdown
Instead of a static `url`, an `ssm_parameter` can be given to resolve the
connection URL from AWS SSM Parameter Store at connect time (requires
`auth: {type: sigv4, ...}`, since the same profile is used for both the
lookup and request signing):

```yaml
tools:
  ace-marshall:
    type: mcp
    ssm_parameter: /ace/poc/ace-os/marshall/runtime/url   # holds a runtime ARN
    auth:
      type: sigv4
      profile: default
      service: bedrock-agentcore
      region: ap-southeast-2
```

`ssm_parameter` and `url` are mutually exclusive. The parameter's value is
treated as the runtime ARN and re-resolved into the invocation URL fresh
on every connect/reconnect — so a redeploy (which changes the ARN) is
picked up on the next reconnect without a YAML edit. This works identically
in a standalone `tools/mcp/<name>.yaml` bundle file.
```

- [ ] **Step 2: Run the full test suite for the touched areas**

Run: `uv run pytest tests/spec/test_parser.py tests/tools/test_mcp.py tests/tools/test_aws_auth.py tests/runner/test_mcp_manager.py -v`
Expected: PASS, no regressions across all four files.

- [ ] **Step 3: Lint and format**

Run: `uv run ruff check . && uv run ruff format --check omnigent/spec/parser.py omnigent/spec/types.py omnigent/tools/mcp.py omnigent/tools/aws_auth.py omnigent/runner/mcp_manager.py tests/spec/test_parser.py tests/tools/test_mcp.py tests/tools/test_aws_auth.py tests/runner/test_mcp_manager.py docs/AGENT_YAML_SPEC.md`
Expected: clean. Fix any reported issues and re-run.

- [ ] **Step 4: Type-check**

Run: `uv run --with pyrefly pyrefly check omnigent/spec/parser.py omnigent/spec/types.py omnigent/tools/mcp.py omnigent/tools/aws_auth.py omnigent/runner/mcp_manager.py`
Expected: no new errors attributable to these files (4 pre-existing errors
elsewhere in `parser.py`/`mcp_manager.py` are known-unrelated — see the
parent SigV4 plan's verification notes; do not attempt to fix them here).

- [ ] **Step 5: Pre-commit on touched files**

Run: `uv run pre-commit run --files omnigent/spec/parser.py omnigent/spec/types.py omnigent/tools/mcp.py omnigent/tools/aws_auth.py omnigent/runner/mcp_manager.py tests/spec/test_parser.py tests/tools/test_mcp.py tests/tools/test_aws_auth.py tests/runner/test_mcp_manager.py docs/AGENT_YAML_SPEC.md`
Expected: clean.

- [ ] **Step 6: Manual/e2e acceptance (cannot be scripted without live AWS access)**

Point `tools/mcp/ace-marshall.yaml` (already created in this repo, see
`tools/mcp/ace-marshall.yaml`) at a real deployment after refreshing
credentials (`aws-azure-login --mode cli --profile default`), and confirm
`omni run --config <an-agent-that-uses-it>.yaml` connects, discovers
tools, and completes a tool call. Confirm a bad `ssm_parameter` path fails
with the actionable `RuntimeError` from Task 4, not an opaque botocore
traceback.

- [ ] **Step 7: Commit**

```bash
git add docs/AGENT_YAML_SPEC.md
git commit -m "docs: document ssm_parameter MCP server URL resolution"
```
