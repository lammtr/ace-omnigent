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
