"""AWS SigV4 request signing for outbound HTTP MCP client connections.

Kept as its own module (not inlined in ``omnigent/tools/mcp.py``) so
stdio-only MCP callers don't pull in ``httpx``/``botocore`` just to import
the MCP client core.
"""

from __future__ import annotations

import urllib.parse

import boto3
import httpx
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ProfileNotFound


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
        try:
            session = boto3.Session(profile_name=self._profile, region_name=self._region)
            credentials = session.get_credentials()
        except ProfileNotFound:
            session = None
            credentials = None
        if session is None or credentials is None:
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
