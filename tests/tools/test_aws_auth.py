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
