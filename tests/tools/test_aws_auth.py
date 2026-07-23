"""Tests for AWS SigV4 request signing (omnigent/tools/aws_auth.py)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest
from botocore.credentials import Credentials
from botocore.exceptions import ProfileNotFound

from omnigent.tools.aws_auth import SigV4SessionAuth, resolve_ssm_runtime_url


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
        auth = SigV4SessionAuth(
            profile="default", service="bedrock-agentcore", region="ap-southeast-2"
        )
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
    auth = SigV4SessionAuth(
        profile="default", service="bedrock-agentcore", region="ap-southeast-2"
    )

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
        auth = SigV4SessionAuth(
            profile="stale-profile", service="bedrock-agentcore", region="ap-southeast-2"
        )
        with pytest.raises(RuntimeError) as exc:
            next(auth.auth_flow(_make_request()))

    assert "stale-profile" in str(exc.value)
    assert "aws-azure-login" in str(exc.value)


def test_sigv4_auth_profile_not_found_raises_actionable_error() -> None:
    """
    boto3.Session(profile_name=...) raises ProfileNotFound immediately at
    construction — before get_credentials() is ever reached — when the
    named profile doesn't exist (e.g. a typo'd or stale profile name).
    This must surface as the same actionable RuntimeError as the
    credentials-is-None case, not an unhandled ProfileNotFound.
    """
    with patch(
        "omnigent.tools.aws_auth.boto3.Session",
        side_effect=ProfileNotFound(profile="stale-profile"),
    ):
        auth = SigV4SessionAuth(
            profile="stale-profile", service="bedrock-agentcore", region="ap-southeast-2"
        )
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


def test_resolve_ssm_runtime_url_happy_path() -> None:
    """
    Fetches the ARN from the given SSM parameter and builds the AgentCore
    invocation URL, percent-encoding the ARN so its ':' and '/' survive
    as a single path segment (ported from ace_explore.py's build_mcp_url).
    """
    mock_ssm = MagicMock()
    mock_ssm.get_parameter.return_value = {
        "Parameter": {
            "Value": (
                "arn:aws:bedrock-agentcore:ap-southeast-2:300428143068:runtime/marshall-abc123"
            )
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
    """A bad/stale profile name raises the same actionable RuntimeError as SigV4SessionAuth."""
    with patch(
        "omnigent.tools.aws_auth.boto3.Session",
        side_effect=ProfileNotFound(profile="stale"),
    ):
        with pytest.raises(RuntimeError) as exc:
            resolve_ssm_runtime_url("/some/param", "stale", "ap-southeast-2")

    assert "stale" in str(exc.value)
    assert "aws-azure-login" in str(exc.value)
