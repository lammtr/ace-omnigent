# SigV4 MCP Client Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AWS SigV4 request signing as a second outbound MCP-client auth
scheme (alongside the existing Databricks OAuth scheme), so omnigent can call
MCP tool servers hosted behind AWS IAM auth (e.g. Bedrock AgentCore Runtimes)
using credentials from a named, `aws-azure-login`-refreshed AWS CLI profile.

**Architecture:** A new `auth: {type: sigv4, profile, service, region}` YAML
block parses into three new `MCPServerConfig` fields
(`aws_profile`/`aws_service`/`aws_region`). A new `httpx.Auth` subclass,
`SigV4SessionAuth` (new module `omnigent/tools/aws_auth.py`), re-resolves AWS
credentials from the named profile **on every request** (not once at connect
time — SigV4 signatures are per-request and time-boxed) and signs with
`botocore.auth.SigV4Auth`. It's wired into `McpServerConnection`'s two HTTP
transport methods via the MCP SDK's already-existing `auth=` parameter.
`boto3`/`botocore` move from optional extras to core dependencies.

**Tech Stack:** Python 3.12, `httpx`, `boto3`/`botocore`, `mcp` SDK
(`streamablehttp_client`/`sse_client`), pytest + `pytest-asyncio`, `ruff`.

## Global Constraints

- Spec: `docs/ace/omnigent-sigv4-mcp-auth-build-spec.md` (v0.1.0, base commit
  `c9201a3650e8ecb35a120db7403ad4d46287c246` — this repo's current `HEAD`,
  confirmed identical during planning; no rebase needed).
- Do NOT touch inbound auth (`omnigent/server/auth.py`, `AuthProvider`,
  `UnifiedAuthProvider`), the web UI login flow, or
  `omnigent/llms/adapters/bedrock.py`.
- `boto3>=1.30,<2` / `botocore>=1.30,<2` — same version constraint already
  used in the `bedrock`/`s3` extras and the dev-dependency pin
  (`pyproject.toml:296-302`); do not introduce a conflicting pin.
- The signer MUST re-resolve credentials from `boto3.Session(...)` on every
  `auth_flow()` call, not cache them at construction — this is the one
  correctness-critical deviation from a naive port of the Databricks
  static-header pattern (spec §4.4).
- No AWS credential material, profile content, or signed request may appear
  in logs, test fixtures, or commit messages beyond what mocked tests need
  (fake key material only, e.g. `AKIDEXAMPLE`).
- Regenerate `uv.lock` via `uv lock` after any `pyproject.toml` dependency
  edit — never hand-edit the lock file.
- Verified during planning, one addition beyond the spec's literal file list:
  `omnigent/runner/mcp_manager.py`'s `compute_spec_hash`/`compute_server_hash`
  already fold `databricks_profile` into the config-change-detection hash
  (`:98`, `:138`). The three new `aws_*` fields must be added there too,
  mirroring `databricks_profile` exactly — otherwise editing a running
  server's AWS profile/service/region in YAML would silently fail to trigger
  a reconnect. Task 5 below.

---

### Task 1: Config schema — `MCPServerConfig`

**Files:**
- Modify: `omnigent/spec/types.py:892-975` (`MCPServerConfig` docstring,
  fields, `__repr__`)
- Test: `tests/tools/test_mcp.py` (repr tests already exist for
  `databricks_profile`-adjacent fields at `:365-408`; add sigv4 equivalents)

**Interfaces:**
- Produces: `MCPServerConfig.aws_profile: str | None`,
  `MCPServerConfig.aws_service: str | None`,
  `MCPServerConfig.aws_region: str | None` — consumed by Task 2 (parser) and
  Task 4 (`_resolve_http_auth`).

- [ ] **Step 1: Add the three new fields to `MCPServerConfig`**

In `omnigent/spec/types.py`, immediately after the `databricks_profile` field
(currently line 939):

```python
    databricks_profile: str | None = None
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

- [ ] **Step 2: Document the new fields in the class docstring**

In the same file, after the `:param databricks_profile:` entry (currently
ending at line 908), add:

```python
    :param aws_profile: AWS CLI profile name (e.g. one kept fresh by
        ``aws-azure-login``). When set, every HTTP request is signed
        with AWS SigV4 using credentials resolved fresh from this
        profile on each request. Valid only on ``"http"``.
    :param aws_service: AWS service name to sign for, e.g.
        ``"bedrock-agentcore"``. Required when ``aws_profile`` is set.
    :param aws_region: AWS region for signing. Optional — falls back to
        the profile's configured region when unset.
```

- [ ] **Step 3: Update `__repr__` to include the new fields un-redacted**

In `omnigent/spec/types.py`, `__repr__` (currently lines 956-975) currently
ends:

```python
        return (
            f"MCPServerConfig(name={self.name!r}, transport={self.transport!r}, "
            f"url={self.url!r}, headers={redacted_headers!r}, "
            f"databricks_profile={self.databricks_profile!r}, "
            f"command={self.command!r}, args={self.args!r}, "
            f"env={redacted_env!r}, "
            f"timeout={self.timeout!r}, retry={self.retry!r})"
        )
```

Change to:

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

These are names, not secrets — same treatment as `databricks_profile`.

- [ ] **Step 4: Write the repr test**

Add to `tests/tools/test_mcp.py`, near `test_mcp_server_config_repr_empty_headers`
(currently line 398):

```python
def test_mcp_server_config_repr_includes_sigv4_fields() -> None:
    """
    MCPServerConfig.__repr__ includes aws_profile/aws_service/aws_region
    un-redacted (they're names, not secrets — same treatment as
    databricks_profile).
    """
    config = MCPServerConfig(
        name="sigv4-svc",
        url="https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
        aws_profile="default",
        aws_service="bedrock-agentcore",
        aws_region="ap-southeast-2",
    )
    r = repr(config)

    assert "aws_profile='default'" in r
    assert "aws_service='bedrock-agentcore'" in r
    assert "aws_region='ap-southeast-2'" in r
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/tools/test_mcp.py -k repr -v`
Expected: PASS (3 repr tests, including the new one)

- [ ] **Step 6: Commit**

```bash
git add omnigent/spec/types.py tests/tools/test_mcp.py
git commit -m "feat(mcp): add aws_profile/aws_service/aws_region to MCPServerConfig"
```

---

### Task 2: YAML parsing — inline `auth: {type: sigv4, ...}`

**Files:**
- Modify: `omnigent/spec/parser.py:2326-2366`
- Test: `tests/spec/test_parser.py` (mirrors the existing
  `test_parse_inline_mcp_databricks_only_skipped` pattern at `:1327-1352`)

**Interfaces:**
- Consumes: `MCPServerConfig.aws_profile/aws_service/aws_region` (Task 1).
- Produces: `_parse_inline_mcp_servers(...)` returns `MCPServerConfig`
  instances with the three new fields populated from YAML.

- [ ] **Step 1: Write the failing parser tests**

Verified against the actual file: `tests/spec/test_parser.py` has no
YAML-writing helper — every inline-MCP test builds a plain `dict`, writes it
with `(tmp_path / "config.yaml").write_text(yaml.dump(config))`, then calls
`parse(tmp_path)` (imported at the top from `omnigent.spec.parser`) and reads
`spec.mcp_servers`. Existing `OmnigentError` assertions use
`pytest.raises(OmnigentError, match=r"...")` against the message, not a
`.code` check — `ErrorCode` isn't imported in this file today. Follow that
exact convention. Add near `test_parse_inline_mcp_databricks_only_skipped`
(currently `:1327-1352`):

```python
def test_parse_inline_mcp_sigv4_auth(tmp_path: Path) -> None:
    """
    ``auth: {type: sigv4, profile, service, region}`` on an inline MCP
    server parses into MCPServerConfig.aws_profile/aws_service/aws_region.

    Failure means the sigv4 auth block is silently dropped and the
    connection would go out unsigned, which AWS IAM will reject as an
    opaque 4xx with no indication the YAML was misread.
    """
    config = {
        "spec_version": 1,
        "name": "sigv4-agent",
        "tools": {
            "ace-peg": {
                "type": "mcp",
                "url": "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
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
    assert server.name == "ace-peg"
    assert server.aws_profile == "default"
    assert server.aws_service == "bedrock-agentcore"
    assert server.aws_region == "ap-southeast-2"


def test_parse_inline_mcp_sigv4_auth_region_optional(tmp_path: Path) -> None:
    """``region`` is optional on the sigv4 auth block; aws_region stays None."""
    config = {
        "spec_version": 1,
        "name": "sigv4-agent-no-region",
        "tools": {
            "ace-peg": {
                "type": "mcp",
                "url": "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
                "auth": {
                    "type": "sigv4",
                    "profile": "default",
                    "service": "bedrock-agentcore",
                },
            }
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(config))
    spec = parse(tmp_path)

    server = spec.mcp_servers[0]
    assert server.aws_profile == "default"
    assert server.aws_service == "bedrock-agentcore"
    assert server.aws_region is None


def test_parse_inline_mcp_sigv4_auth_missing_profile_raises(tmp_path: Path) -> None:
    """Missing ``profile`` on a sigv4 auth block raises OmnigentError."""
    config = {
        "spec_version": 1,
        "name": "sigv4-agent-bad",
        "tools": {
            "ace-peg": {
                "type": "mcp",
                "url": "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
                "auth": {"type": "sigv4", "service": "bedrock-agentcore"},
            }
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(config))

    with pytest.raises(OmnigentError, match=r"sigv4.*requires.*profile.*service"):
        parse(tmp_path)


def test_parse_inline_mcp_sigv4_auth_missing_service_raises(tmp_path: Path) -> None:
    """Missing ``service`` on a sigv4 auth block raises OmnigentError."""
    config = {
        "spec_version": 1,
        "name": "sigv4-agent-bad",
        "tools": {
            "ace-peg": {
                "type": "mcp",
                "url": "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
                "auth": {"type": "sigv4", "profile": "default"},
            }
        },
    }
    (tmp_path / "config.yaml").write_text(yaml.dump(config))

    with pytest.raises(OmnigentError, match=r"sigv4.*requires.*profile.*service"):
        parse(tmp_path)
```

The `match=` regex above relies on the exact wording in Step 3's
`OmnigentError(...)` message ("requires 'profile' and 'service' fields") —
keep the message and the regex in sync if either changes.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/spec/test_parser.py -k sigv4 -v`
Expected: FAIL — `AttributeError: 'MCPServerConfig' object has no attribute 'aws_profile'`

- [ ] **Step 3: Add the sigv4 parsing branch**

In `omnigent/spec/parser.py`, immediately after the existing databricks
branch (currently ending at line 2338, before the `tools:` allowlist parsing
that starts at line 2339):

```python
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

- [ ] **Step 4: Pass the new fields into the `MCPServerConfig(...)` construction**

In the same file, the `MCPServerConfig(...)` call (currently lines 2350-2366)
currently includes `databricks_profile=databricks_profile,`. Add immediately
after it:

```python
                databricks_profile=databricks_profile,
                aws_profile=aws_profile,
                aws_service=aws_service,
                aws_region=aws_region,
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/spec/test_parser.py -k sigv4 -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Run the full parser test file to check for regressions**

Run: `uv run pytest tests/spec/test_parser.py -v`
Expected: PASS, no regressions in the ~150+ existing tests (in particular
`test_parse_inline_mcp_databricks_only_skipped` and the other
`databricks`-auth-adjacent tests must still pass unchanged).

- [ ] **Step 7: Verify the stdio cross-field-validation question from spec §4.2**

Search for any validator that currently rejects `databricks_profile` when
`transport == "stdio"`:

Run: `grep -n "databricks_profile" omnigent/spec/types.py omnigent/spec/parser.py`

If no such validator exists today (the class docstring at `types.py:888-890`
names only `url`/`headers`/`command`/`args`/`env`, not the profile fields),
this is confirmed pre-existing behavior — do not add new validation for
`aws_profile`/`aws_service`/`aws_region` either; that would be scope creep
beyond what this spec asks for. Just note the finding in the PR description.

- [ ] **Step 8: Commit**

```bash
git add omnigent/spec/parser.py tests/spec/test_parser.py
git commit -m "feat(mcp): parse auth: {type: sigv4, profile, service, region} YAML block"
```

---

### Task 3: `SigV4SessionAuth` signer

**Files:**
- Create: `omnigent/tools/aws_auth.py`
- Test: Create `tests/tools/test_aws_auth.py`

**Interfaces:**
- Produces: `omnigent.tools.aws_auth.SigV4SessionAuth(profile: str, service:
  str, region: str | None)` — an `httpx.Auth` subclass with `auth_flow(self,
  request: httpx.Request)`. Consumed by Task 4's `_resolve_sigv4_auth`.
- Reference implementation: `ace-runtime-test/ace_explore.py:25-50`
  (`SigV4HTTPXAuth`) and its test
  `ace-runtime-test/tests/test_ace_explore.py:81-97`
  (`test_sigv4_auth_adds_authorization_header`) — port both directly, adapted
  to re-resolve credentials from a profile name per-request instead of
  taking pre-resolved `Credentials` in `__init__`.

- [ ] **Step 1: Write the failing signer tests**

Create `tests/tools/test_aws_auth.py`:

```python
"""Tests for AWS SigV4 request signing (omnigent/tools/aws_auth.py)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from botocore.credentials import Credentials

from omnigent.tools.aws_auth import SigV4SessionAuth


def _mock_boto3_session(creds: Credentials, region: str | None = "ap-southeast-2"):
    """Patch boto3.Session so .get_credentials()/.region_name return fixed values."""
    mock_session = MagicMock()
    mock_session.get_credentials.return_value = creds
    mock_session.region_name = region
    return patch("omnigent.tools.aws_auth.boto3.Session", return_value=mock_session)


def _make_request() -> httpx.Request:
    return httpx.Request(
        "POST",
        "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations?qualifier=DEFAULT",
        headers={"content-type": "application/json"},
        content=b'{"jsonrpc":"2.0"}',
    )


def test_sigv4_auth_adds_authorization_header() -> None:
    """
    Directly ported from ace_explore.py's
    test_sigv4_auth_adds_authorization_header. If this regresses, every
    request to a sigv4-authed MCP server is sent unsigned and AWS rejects
    it with an opaque 4xx.
    """
    creds = Credentials(access_key="AKIDEXAMPLE", secret_key="secret", token="tok")
    with _mock_boto3_session(creds):
        auth = SigV4SessionAuth(profile="default", service="bedrock-agentcore", region="ap-southeast-2")
        flow = auth.auth_flow(_make_request())
        signed = next(flow)

    assert "authorization" in signed.headers
    assert signed.headers["authorization"].startswith("AWS4-HMAC-SHA256")
    assert "x-amz-date" in signed.headers
    assert signed.headers.get("x-amz-security-token") == "tok"


def test_sigv4_auth_reresolves_credentials_per_request() -> None:
    """
    Regression test for spec §4.4: a SigV4 signature is not reusable
    across requests. Two auth_flow() calls with different mocked
    credentials (simulating a post-aws-azure-login rotation) must
    produce different Authorization headers.

    If credentials were cached at construction (the naive Databricks-style
    port), both signatures would be identical and a long-lived MCP
    connection would silently keep signing with stale, expired
    credentials after an out-of-band aws-azure-login rerun.
    """
    auth = SigV4SessionAuth(profile="default", service="bedrock-agentcore", region="ap-southeast-2")

    creds_1 = Credentials(access_key="AKIDFIRST00000000000", secret_key="secret1", token="tok1")
    with _mock_boto3_session(creds_1):
        signed_1 = next(auth.auth_flow(_make_request()))

    creds_2 = Credentials(access_key="AKIDSECOND0000000000", secret_key="secret2", token="tok2")
    with _mock_boto3_session(creds_2):
        signed_2 = next(auth.auth_flow(_make_request()))

    assert signed_1.headers["authorization"] != signed_2.headers["authorization"]
    assert signed_1.headers["x-amz-security-token"] == "tok1"
    assert signed_2.headers["x-amz-security-token"] == "tok2"


def test_sigv4_auth_missing_credentials_raises_actionable_error() -> None:
    """
    boto3.Session(...).get_credentials() returning None (e.g. the named
    profile doesn't exist, or aws-azure-login was never run) must raise a
    RuntimeError that tells the operator exactly what to run — not a bare
    AttributeError from calling .get_frozen_credentials() on None.
    """
    with _mock_boto3_session(None):  # type: ignore[arg-type]
        auth = SigV4SessionAuth(profile="stale-profile", service="bedrock-agentcore", region="ap-southeast-2")
        with pytest.raises(RuntimeError) as exc:
            next(auth.auth_flow(_make_request()))

    assert "stale-profile" in str(exc.value)
    assert "aws-azure-login" in str(exc.value)


def test_sigv4_auth_falls_back_to_session_region_when_unset() -> None:
    """
    When aws_region is None, the signer must use the profile's configured
    region (session.region_name) rather than signing with region=None,
    which botocore would reject or sign incorrectly.
    """
    creds = Credentials(access_key="AKIDEXAMPLE", secret_key="secret", token=None)
    with _mock_boto3_session(creds, region="us-west-2") as _:
        auth = SigV4SessionAuth(profile="default", service="bedrock-agentcore", region=None)
        signed = next(auth.auth_flow(_make_request()))

    assert "authorization" in signed.headers
    assert "us-west-2" in signed.headers["authorization"]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/tools/test_aws_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'omnigent.tools.aws_auth'`

- [ ] **Step 3: Write `omnigent/tools/aws_auth.py`**

```python
"""AWS SigV4 request signing for outbound HTTP MCP client connections.

Kept as its own module (not inlined in ``omnigent/tools/mcp.py``) so
stdio-only MCP callers don't pull in ``httpx``/``botocore`` just to import
the MCP client core.
"""

from __future__ import annotations

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest


class SigV4SessionAuth(httpx.Auth):
    """
    Signs every HTTP request with AWS SigV4, re-resolving credentials
    from the named profile on each request.

    A SigV4 signature is computed over the specific method, path, and
    request-body hash, with a short validity window — it is not reusable
    across requests. Re-reading credentials from ``boto3.Session(...)``
    fresh on every ``auth_flow()`` call (rather than caching them at
    construction) lets a long-lived MCP connection pick up credentials
    refreshed by an out-of-band ``aws-azure-login`` rerun without
    needing a reconnect.
    """

    requires_request_body = True

    def __init__(self, profile: str, service: str, region: str | None) -> None:
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/tools/test_aws_auth.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add omnigent/tools/aws_auth.py tests/tools/test_aws_auth.py
git commit -m "feat(mcp): add SigV4SessionAuth httpx.Auth signer with per-request credential re-resolution"
```

---

### Task 4: Wire the signer into `McpServerConnection`

**Files:**
- Modify: `omnigent/tools/mcp.py:86-123` (add `_resolve_sigv4_auth`, sibling
  to `_resolve_databricks_token`), `:924-1004`
  (`_resolve_http_auth`/`_open_streamable_http_transport`/`_open_sse_transport`),
  and the module's `import` block (`:14-56`) for `httpx` and the new
  `SigV4SessionAuth` import.
- Test: `tests/tools/test_mcp.py`

**Interfaces:**
- Consumes: `omnigent.tools.aws_auth.SigV4SessionAuth` (Task 3),
  `MCPServerConfig.aws_profile/aws_service/aws_region` (Task 1).
- Produces: `McpServerConnection._resolve_http_auth() -> httpx.Auth | None`,
  consumed only within this class. `_open_streamable_http_transport` and
  `_open_sse_transport` gain a required `auth: httpx.Auth | None` parameter.

- [ ] **Step 1: Write the failing transport-wiring tests**

Add to `tests/tools/test_mcp.py`, near `test_http_connect_passes_headers_to_transport`
(currently `:1350-1373`) — reuse the existing `_mock_http_transport` helper
(`:1261-1327`), which already captures every kwarg passed to
`streamablehttp_client` via `captured.transport_kwargs.update(kwargs)`, so no
helper changes are needed for the Streamable HTTP case:

```python
@pytest.mark.asyncio()
async def test_http_connect_passes_sigv4_auth_to_transport() -> None:
    """
    HTTP connect() builds a SigV4SessionAuth and passes it as `auth=` to
    streamablehttp_client when aws_profile is set.

    If this is missed, requests to a sigv4-configured MCP server go out
    unsigned via the headers-only code path and AWS rejects every call.
    """
    config = MCPServerConfig(
        name="test-sigv4",
        url="https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
        aws_profile="default",
        aws_service="bedrock-agentcore",
        aws_region="ap-southeast-2",
    )

    with _mock_http_transport() as captured:
        conn = McpServerConnection(config=config)
        await conn.connect()

    auth = captured.transport_kwargs.get("auth")
    assert isinstance(auth, SigV4SessionAuth)
    assert auth._profile == "default"
    assert auth._service == "bedrock-agentcore"
    assert auth._region == "ap-southeast-2"

    await conn.close()


@pytest.mark.asyncio()
async def test_http_connect_passes_none_auth_when_no_aws_profile() -> None:
    """
    Existing Databricks-profile and no-auth configs must keep passing
    auth=None to the transport — a regression here would attach signing
    to every MCP connection, not just sigv4-configured ones.
    """
    config = MCPServerConfig(
        name="test-no-sigv4",
        url="http://localhost:9000/mcp",
        headers={"Authorization": "Bearer tok_xyz"},
    )

    with _mock_http_transport() as captured:
        conn = McpServerConnection(config=config)
        await conn.connect()

    assert captured.transport_kwargs.get("auth") is None

    await conn.close()
```

Also add `SigV4SessionAuth` to the `from omnigent.tools.mcp import (...)`
block's neighboring import — add a new
`from omnigent.tools.aws_auth import SigV4SessionAuth` line near the top of
`tests/tools/test_mcp.py` (alongside the existing `from omnigent.spec.types
import MCPServerConfig, RetryPolicy` at line 21).

For the SSE path, add one more test that exercises `_open_sse_transport`
directly (mirroring the existing `test_http_falls_back_to_sse_when_streamable_fails`
pattern at `:1399-1470`, but routed straight to SSE via a `/sse`-suffixed
URL so `_is_sse_endpoint` sends it there without needing a Streamable HTTP
failure first):

```python
@pytest.mark.asyncio()
async def test_sse_connect_passes_sigv4_auth_to_transport() -> None:
    """
    The legacy SSE transport path must also receive the SigV4 auth
    object — it's a separate SDK call site
    (_open_sse_transport/sse_client) from the Streamable HTTP one, so
    wiring one without the other would leave /sse-routed sigv4 servers
    sending unsigned requests.
    """
    config = MCPServerConfig(
        name="test-sigv4-sse",
        url="https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/sse",
        aws_profile="default",
        aws_service="bedrock-agentcore",
        aws_region="ap-southeast-2",
    )

    captured_sse_kwargs: dict[str, Any] = {}
    mock_sse_ctx = AsyncMock()
    mock_sse_ctx.__aenter__ = AsyncMock(return_value=(MagicMock(), MagicMock()))
    mock_sse_ctx.__aexit__ = AsyncMock(return_value=False)

    def _capturing_sse(**kwargs: Any) -> AsyncMock:
        captured_sse_kwargs.update(kwargs)
        return mock_sse_ctx

    mock_session = AsyncMock()
    mock_session.initialize = AsyncMock()
    mock_tools_result = MagicMock()
    mock_tools_result.tools = []
    mock_session.list_tools.return_value = mock_tools_result
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    with patch("omnigent.tools.mcp.sse_client", side_effect=_capturing_sse):
        with patch("omnigent.tools.mcp.ClientSession", return_value=mock_session):
            conn = McpServerConnection(config=config)
            await conn.connect()

    auth = captured_sse_kwargs.get("auth")
    assert isinstance(auth, SigV4SessionAuth)

    await conn.close()
```

Check `_is_sse_endpoint` (`omnigent/tools/mcp.py:345`) before finalizing this
test to confirm a `.../sse` (no trailing slash requirement) URL routes
straight to `_open_sse_transport` as expected — read the function, don't
assume its exact matching rule.

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `uv run pytest tests/tools/test_mcp.py -k sigv4 -v`
Expected: FAIL — `_mock_http_transport`/the real `_open_http_transport` path
doesn't pass `auth=` yet, so `captured.transport_kwargs.get("auth")` is
either absent or `None` for the sigv4 config, and
`test_http_connect_passes_none_auth_when_no_aws_profile` may pass vacuously
already (that one is a regression guard, added now so it fails later if
the wiring is done wrong — verify with step 3's diff review, not by
expecting a specific failure here).

- [ ] **Step 3: Add the `_resolve_sigv4_auth` helper next to `_resolve_databricks_token`**

In `omnigent/tools/mcp.py`, add the import near the top (`:14-56` region,
alongside the other `from omnigent...` imports):

```python
from omnigent.tools.aws_auth import SigV4SessionAuth
```

And `httpx` needs to be importable for the type annotation — check whether
`omnigent/tools/mcp.py` already imports `httpx` anywhere (it currently does
not, per the module's import block); add `import httpx` alongside the
existing `import asyncio` / `import json` block if missing.

Then, immediately after `_resolve_databricks_token` (ending at line 123),
add:

```python
def _resolve_sigv4_auth(profile: str, service: str, region: str | None) -> SigV4SessionAuth:
    """
    Build the AWS SigV4 ``httpx.Auth`` object for a sigv4-configured MCP
    server.

    Unlike :func:`_resolve_databricks_token`, this does not resolve
    credentials itself — :class:`SigV4SessionAuth` re-resolves them fresh
    on every request (see its docstring for why that distinction matters
    for long-lived MCP connections).

    :param profile: AWS CLI profile name.
    :param service: AWS service name to sign for, e.g. ``"bedrock-agentcore"``.
    :param region: AWS region, or ``None`` to fall back to the profile's
        configured region.
    :returns: A ``SigV4SessionAuth`` instance.
    """
    return SigV4SessionAuth(profile=profile, service=service, region=region)
```

- [ ] **Step 4: Add `_resolve_http_auth` to `McpServerConnection`**

In `omnigent/tools/mcp.py`, immediately after `_resolve_http_headers`
(currently ending at line 941):

```python
    def _resolve_http_auth(self) -> httpx.Auth | None:
        """
        Build the ``httpx.Auth`` object for the MCP connection, or
        ``None`` if no non-header auth scheme is configured.

        :returns: A :class:`SigV4SessionAuth` when ``aws_profile`` is
            set, else ``None``.
        """
        if self.config.aws_profile is None:
            return None
        assert self.config.aws_service is not None  # enforced at parse time
        return _resolve_sigv4_auth(
            self.config.aws_profile, self.config.aws_service, self.config.aws_region
        )
```

- [ ] **Step 5: Wire `auth` through `_open_http_transport` and both transport methods**

In `omnigent/tools/mcp.py`, `_open_http_transport` (currently `:869-922`)
currently does:

```python
        timeout = self.config.timeout
        headers = self._resolve_http_headers()
        if _is_sse_endpoint(self.config.url):
            ...
            return await self._open_sse_transport(stack, timeout, headers)
        try:
            return await self._open_streamable_http_transport(stack, timeout, headers)
        except Exception as exc:
            ...
            return await self._open_sse_transport(stack, timeout, headers)
```

Change to resolve and thread `auth` through:

```python
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

(Keep the existing docstrings/comments in that method verbatim — only the
three call sites and the new `auth = self._resolve_http_auth()` line change.)

Then update both transport methods' signatures and SDK calls. Current
`_open_streamable_http_transport` (`:943-972`):

```python
    async def _open_streamable_http_transport(
        self,
        stack: AsyncExitStack,
        timeout: int | None,
        headers: dict[str, str] | None,
    ) -> tuple[_ReadStream, _WriteStream]:
        ...
        assert self.config.url is not None
        read_stream, write_stream, _get_session_id = await stack.enter_async_context(
            streamablehttp_client(
                url=self.config.url,
                headers=headers,
                timeout=float(timeout) if timeout is not None else 30,
                sse_read_timeout=float(timeout) if timeout is not None else 300,
            )
        )
        return read_stream, write_stream
```

becomes:

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

Add a `:param auth:` line to its docstring (`"Resolved AWS SigV4 signer, or
None."`), matching the existing `:param headers:` line's style.

Current `_open_sse_transport` (`:974-1004`):

```python
    async def _open_sse_transport(
        self,
        stack: AsyncExitStack,
        timeout: int | None,
        headers: dict[str, str] | None,
    ) -> tuple[_ReadStream, _WriteStream]:
        ...
        assert self.config.url is not None
        read_stream, write_stream = await stack.enter_async_context(
            sse_client(
                url=self.config.url,
                headers=headers,
                timeout=float(timeout) if timeout is not None else 5,
                sse_read_timeout=float(timeout) if timeout is not None else 300,
            )
        )
        return read_stream, write_stream
```

becomes:

```python
    async def _open_sse_transport(
        self,
        stack: AsyncExitStack,
        timeout: int | None,
        headers: dict[str, str] | None,
        auth: httpx.Auth | None,
    ) -> tuple[_ReadStream, _WriteStream]:
        ...
        assert self.config.url is not None
        read_stream, write_stream = await stack.enter_async_context(
            sse_client(
                url=self.config.url,
                headers=headers,
                timeout=float(timeout) if timeout is not None else 5,
                sse_read_timeout=float(timeout) if timeout is not None else 300,
                auth=auth,
            )
        )
        return read_stream, write_stream
```

Same docstring addition as above. Check for any other call sites of
`_open_streamable_http_transport`/`_open_sse_transport` in `mcp.py` besides
`_open_http_transport` (`grep -n "_open_streamable_http_transport\|_open_sse_transport" omnigent/tools/mcp.py`)
before finalizing — the spec's read of the code found only the three call
sites shown above, but confirm no test-only or reconnect-path caller was
missed.

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `uv run pytest tests/tools/test_mcp.py -k sigv4 -v`
Expected: PASS (3 tests)

- [ ] **Step 7: Run the full MCP test suite for regressions**

Run: `uv run pytest tests/tools/test_mcp.py -v`
Expected: PASS, no regressions — in particular
`test_http_connect_passes_headers_to_transport`,
`test_http_connect_passes_none_headers_when_empty`, and
`test_http_falls_back_to_sse_when_streamable_fails` must all still pass
unchanged (Databricks-profile and no-auth paths unaffected, per spec §6.4 /
§8.7).

- [ ] **Step 8: Commit**

```bash
git add omnigent/tools/mcp.py tests/tools/test_mcp.py
git commit -m "feat(mcp): wire SigV4 auth through streamable-HTTP and SSE MCP transports"
```

---

### Task 5: Config-change hash coverage — `omnigent/runner/mcp_manager.py`

**Files:**
- Modify: `omnigent/runner/mcp_manager.py:87-148`
  (`compute_spec_hash`, `compute_server_hash`)
- Test: `tests/runner/test_mcp_manager.py`

**Interfaces:**
- Consumes: `MCPServerConfig.aws_profile/aws_service/aws_region` (Task 1).
- No new interface produced — this task only extends the existing hash
  payloads so `RunnerMcpManager` correctly detects when a running server's
  AWS auth config changes and needs a reconnect.

This task is not in the spec's literal "Target files" list, but is a direct,
low-risk consequence of Task 1: both hash functions already fold
`databricks_profile` into their JSON payload (`:98`, `:138`) specifically so
editing a server's auth profile in YAML triggers a reconnect instead of
silently continuing to use stale config. Skipping this would leave the new
`aws_*` fields invisible to that change-detection mechanism.

- [ ] **Step 1: Write the failing hash test**

Add to `tests/runner/test_mcp_manager.py`, near the existing hash-comparison
assertions (e.g. around `:273-274`, `test_shared_server_reused_across_different_specs`):

```python
def test_compute_server_hash_changes_with_aws_profile() -> None:
    """
    compute_server_hash must reflect aws_profile/aws_service/aws_region —
    otherwise switching a running server's AWS auth profile in YAML would
    silently fail to trigger a reconnect (the pool would keep reusing the
    old connection, which is either still signed with the old profile's
    identity or, if that profile's credentials expired, stuck failing).
    """
    base = MCPServerConfig(
        name="sigv4-svc",
        url="https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
        aws_profile="default",
        aws_service="bedrock-agentcore",
        aws_region="ap-southeast-2",
    )
    different_profile = MCPServerConfig(
        name="sigv4-svc",
        url="https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/x/invocations",
        aws_profile="other-profile",
        aws_service="bedrock-agentcore",
        aws_region="ap-southeast-2",
    )

    assert compute_server_hash(base) != compute_server_hash(different_profile)
```

Confirm `MCPServerConfig` and `compute_server_hash` are already imported at
the top of `tests/runner/test_mcp_manager.py` (they are, per the existing
`compute_server_hash`/`compute_spec_hash` import at `:37-38`).

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/runner/test_mcp_manager.py -k aws_profile -v`
Expected: FAIL — both configs currently hash identically since `aws_profile`
isn't in the payload yet.

- [ ] **Step 3: Add the three fields to both hash payloads**

In `omnigent/runner/mcp_manager.py`, `compute_spec_hash`'s per-server payload
dict (currently `:93-105`) — add immediately after the
`"databricks_profile": c.databricks_profile,` line:

```python
                    "databricks_profile": c.databricks_profile,
                    "aws_profile": c.aws_profile,
                    "aws_service": c.aws_service,
                    "aws_region": c.aws_region,
```

And `compute_server_hash`'s payload dict (currently `:132-144`) — same
addition after its `"databricks_profile": config.databricks_profile,` line:

```python
            "databricks_profile": config.databricks_profile,
            "aws_profile": config.aws_profile,
            "aws_service": config.aws_service,
            "aws_region": config.aws_region,
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/runner/test_mcp_manager.py -k aws_profile -v`
Expected: PASS

- [ ] **Step 5: Run the full mcp_manager test suite for regressions**

Run: `uv run pytest tests/runner/test_mcp_manager.py -v`
Expected: PASS, no regressions (hash values change, but no test asserts a
specific hash literal — only equality/inequality between configs, per the
existing pattern at `:237`, `:273-274`).

- [ ] **Step 6: Commit**

```bash
git add omnigent/runner/mcp_manager.py tests/runner/test_mcp_manager.py
git commit -m "fix(mcp): include aws_profile/aws_service/aws_region in server config-change hash"
```

---

### Task 6: Promote `boto3`/`botocore` to core dependencies

**Files:**
- Modify: `pyproject.toml` (`dependencies` list, `bedrock`/`s3` extras)
- Modify: `uv.lock` (regenerated, not hand-edited)

**Interfaces:**
- None — this task only changes dependency resolution. Tasks 3-5's code
  already imports `boto3`/`botocore` as if they were core deps; this task
  makes that installation guarantee real (`uv sync` without `--extra
  bedrock`/`--extra s3` must still provide them).

- [ ] **Step 1: Add `boto3`/`botocore` to the core `dependencies` list**

In `pyproject.toml`, locate the `dependencies = [` opener (currently line
24) and add, near the other AWS-adjacent or general HTTP-client entries
(e.g. right after the `"httpx>=0.27,<1",` line):

```toml
    "httpx>=0.27,<1",
    # AWS SigV4 request signing for outbound MCP client connections
    # (omnigent/tools/aws_auth.py) and the bedrock/s3 optional-extra
    # call sites that previously pulled these in separately.
    "boto3>=1.30,<2",
    "botocore>=1.30,<2",
```

- [ ] **Step 2: Remove the now-redundant entries from the `bedrock`/`s3` extras**

In `pyproject.toml`, change:

```toml
bedrock = ["boto3>=1.30,<2", "botocore>=1.30,<2"]
```

to:

```toml
# boto3/botocore are core dependencies now (see `dependencies` above); this
# extra is kept as a no-op alias so existing `--extra bedrock` invocations
# keep working.
bedrock = []
```

and:

```toml
s3 = ["boto3>=1.30,<2", "botocore>=1.30,<2"]
```

to:

```toml
# boto3/botocore are core dependencies now (see `dependencies` above); this
# extra is kept as a no-op alias so existing `--extra s3` invocations keep
# working.
s3 = []
```

(Match the existing no-op-alias comment style already used for
`claude-sdk = []` / `openai-agents = []` at `:117-118`.)

- [ ] **Step 3: Regenerate the lock file**

Run: `uv lock`
Expected: `uv.lock` updates to reflect `boto3`/`botocore` as core deps; no
version conflicts (the constraint matches the existing dev-dependency pin at
`:296-302`).

- [ ] **Step 4: Normalize the lock file registry**

The repo's pre-commit hook `normalize-uv-lock-registry` rewrites any
non-public registry URL `uv lock` may have written back to `pypi.org`. Run
it directly so the diff is clean before committing:

Run: `.venv/bin/python scripts/normalize_uv_lock_registry.py uv.lock`
Expected: no-op or a clean rewrite to `pypi.org` URLs.

- [ ] **Step 5: Verify the environment installs cleanly without extras**

Run: `uv sync` (no `--extra` flags)
Expected: succeeds; `uv run python -c "import boto3, botocore; print('ok')"`
prints `ok`.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "build: promote boto3/botocore to core dependencies for SigV4 MCP auth"
```

---

### Task 7: Documentation — `docs/AGENT_YAML_SPEC.md`

**Files:**
- Modify: `docs/AGENT_YAML_SPEC.md:210-237` (MCP server section)

**Interfaces:** None — documentation only.

Note found during planning: the existing "MCP server" section (`:210-237`)
does not currently document the pre-existing inline `auth: {type:
databricks, profile}` MCP-server block either (the `type: databricks`
mentions elsewhere in this file, e.g. `:24-26`, `:60-62`, `:359-361`, are all
`executor.auth`/LLM-routing auth, a different feature). Adding sigv4
documentation here without also retroactively documenting databricks would
leave the section inconsistent, so this task documents both, using the
databricks branch's actual parser behavior (`omnigent/spec/parser.py:2330-2338`)
as the source of truth for what to write.

- [ ] **Step 1: Add both auth blocks to the MCP server doc section**

In `docs/AGENT_YAML_SPEC.md`, after the existing "MCP tools can also point
at a remote URL" example (currently ending at line 236, before the `###
Python function tool` heading at line 238), insert:

```markdown
MCP servers behind non-static auth can declare an `auth` block instead of
(or alongside) static `headers`:

```yaml
tools:
  docs:
    type: mcp
    url: https://my-workspace.databricks.com/api/2.0/mcp
    auth:
      type: databricks
      profile: oss           # ~/.databrickscfg profile
```

```yaml
tools:
  ace-peg:
    type: mcp
    url: "https://bedrock-agentcore.ap-southeast-2.amazonaws.com/runtimes/<url-encoded-runtime-arn>/invocations?qualifier=DEFAULT"
    auth:
      type: sigv4
      profile: default        # AWS CLI profile, e.g. kept fresh by aws-azure-login
      service: bedrock-agentcore
      region: ap-southeast-2  # optional — falls back to the profile's configured region
```

`type: databricks` resolves a bearer token at connection time from
`~/.databrickscfg`. `type: sigv4` signs every request with AWS SigV4,
re-resolving credentials from the named AWS CLI profile on each request —
so a connection stays valid across an out-of-band credential refresh (e.g.
`aws-azure-login --mode cli --profile default` rerun every few hours)
without needing the agent restarted. Both require the referenced profile to
be kept alive by the operator; omnigent does not run the refresh itself.
```

- [ ] **Step 2: Proofread the rendered markdown**

Run: `uv run python -c "import markdown" 2>/dev/null; grep -n '```' docs/AGENT_YAML_SPEC.md | sed -n '1,40p'`
Expected: fenced code blocks are still balanced (even count) after the edit
— a stray/missing triple-backtick would break every code block after it in
the file.

- [ ] **Step 3: Commit**

```bash
git add docs/AGENT_YAML_SPEC.md
git commit -m "docs: document auth: {type: sigv4} and auth: {type: databricks} MCP server blocks"
```

---

### Task 8: Full verification pass

**Files:** None modified — verification only.

**Interfaces:** None.

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest`
Expected: PASS (e2e/live tests skipped by default per `CONTRIBUTING.md`).
Pay particular attention to `tests/tools/test_mcp.py`,
`tests/tools/test_aws_auth.py`, `tests/spec/test_parser.py`,
`tests/runner/test_mcp_manager.py`, and anywhere else `MCPServerConfig` is
constructed with positional-adjacent keyword args (a new field inserted in
the middle of the dataclass could reorder keyword-argument-order-sensitive
call sites, though `@dataclass` keyword construction should be unaffected —
confirm no test constructs `MCPServerConfig` positionally).

- [ ] **Step 2: Lint and format**

Run: `uv run ruff check . && uv run ruff format --check .`
Expected: clean. Fix any reported issues (in particular, the multi-line
f-string in the new `RuntimeError` message and the `SigV4SessionAuth`
docstring line lengths) and re-run.

- [ ] **Step 3: Type-check (if `pyrefly` is set up for this repo — confirm via `pyrefly.toml`)**

Run: `uv run pyrefly check` (if this fails with "command not found", check
`pyproject.toml`'s `dev` extra for the type-checker package name and install
it via `uv sync --extra dev` first)
Expected: no new errors attributable to `omnigent/tools/aws_auth.py`,
`omnigent/tools/mcp.py`, `omnigent/spec/types.py`, `omnigent/spec/parser.py`,
or `omnigent/runner/mcp_manager.py`.

- [ ] **Step 4: Run pre-commit on all files**

Run: `uv run pre-commit run --all-files`
Expected: clean (this also re-runs `normalize-uv-lock-registry` and
`sync-version-py`, confirming Task 6's lock-file edit is stable).

- [ ] **Step 5: Manual/e2e acceptance against a real Bedrock AgentCore Runtime (spec §6.6)**

This step cannot be scripted in CI without live AWS access. With a real
`tools/mcp/<name>.yaml` (or inline `tools:` block) pointed at the same
Bedrock AgentCore Runtime URL `ace-runtime-test/ace_explore.py` already
reaches, and `aws_profile` set to a profile freshly authenticated via
`aws-azure-login --mode cli --profile <name>`:

1. Start the omnigent server/host and run an agent that uses the MCP
   server. Confirm it connects, discovers tools, and completes a
   `tools/call` round trip.
2. Wait past the profile's credential expiry without re-running
   `aws-azure-login`, then trigger another tool call. Confirm the failure
   is a clear, actionable error (matching `SigV4SessionAuth.auth_flow()`'s
   `RuntimeError` message, or an AWS 4xx surfaced through the circuit
   breaker per spec §5) — not a hang or a misleading "connection lost"
   reconnect loop.
3. Rerun `aws-azure-login --mode cli --profile <name>`, then call the tool
   again without restarting the omnigent process. Confirm it succeeds.

Record redacted evidence (no credential material) of steps 1-3 for the PR
description, per the spec's §10 handoff checklist.

- [ ] **Step 6: Fill in the PR template and open the PR**

Per this repo's `CLAUDE.md`, fill in every section of
`.github/pull_request_template.md` (Summary, Test Plan, Demo — `N/A` is fine
here, this is a non-visual backend change unless a UI surfaces MCP auth type
— check `web/` for any MCP-server-config UI before assuming `N/A`; Type of
change; Test coverage; Coverage notes). Reference the §10 handoff checklist
items from the spec directly in the Test Plan section.
