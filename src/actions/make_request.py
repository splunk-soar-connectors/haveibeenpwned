# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
from urllib.parse import unquote, urlsplit

from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams as SDKMakeRequestParams, Param

from ..app import Asset, app
from ..helper import request


DEFAULT_REQUEST_TIMEOUT_SECONDS = 30
INVALID_ENDPOINT_MESSAGE = (
    "Endpoint must be a relative path within the HIBP API v3 base URL; do not include the base URL, query string, or fragment."
)


class MakeRequestParams(SDKMakeRequestParams):
    """Request parameters specialized for the HIBP API v3 base URL."""

    query_parameters: str | None = Param(
        description=("Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2"),
        required=False,
    )
    http_method: str = Param(
        description="HTTP method to use for the HIBP API request.",
        required=False,
        default="GET",
        value_list=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
    )
    endpoint: str = Param(
        description=(
            "Relative endpoint within the HIBP API v3 base URL. For example, "
            "'pasteaccount/user%40example.com' or 'subscription/status'. "
            "Do not include the base URL."
        ),
        required=True,
    )

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Endpoint must not be empty or whitespace-only")
        return value


def _get_endpoint(endpoint: str) -> str:
    """Validate a relative HIBP path while preserving encoded path data."""
    endpoint = endpoint.strip()
    if not endpoint:
        raise ActionFailure("Endpoint must not be empty")
    if endpoint.startswith("//") or endpoint.startswith(("http://", "https://")):
        raise ActionFailure(INVALID_ENDPOINT_MESSAGE)

    endpoint = endpoint.lstrip("/")
    parsed = urlsplit(endpoint)
    if not endpoint or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or "?" in endpoint or "#" in endpoint:
        raise ActionFailure(INVALID_ENDPOINT_MESSAGE)

    decoded = endpoint
    for _ in range(len(endpoint)):
        value = unquote(decoded)
        if value == decoded:
            break
        decoded = value

    if (
        decoded.startswith(("/", "\\"))
        or "\\" in decoded
        or any(part in {".", ".."} for part in decoded.split("/"))
        or any(ord(char) < 32 or ord(char) == 127 for char in decoded)
    ):
        raise ActionFailure(INVALID_ENDPOINT_MESSAGE)
    return endpoint


def _get_headers(headers_json: str | None) -> dict[str, str]:
    if not headers_json:
        return {}
    try:
        headers = json.loads(headers_json)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ActionFailure("Headers must be a JSON object") from exc
    if not isinstance(headers, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in headers.items()):
        raise ActionFailure("Headers must be a JSON object with string keys and values")

    # Authentication is always supplied by the configured asset. The caller
    # may override the default User-Agent when the HIBP API requires a more
    # specific client identifier.
    return headers


def _get_query_params(query_parameters: str | None) -> dict | str | None:
    if not query_parameters:
        return None
    try:
        parsed = json.loads(query_parameters)
    except (json.JSONDecodeError, TypeError):
        return query_parameters.lstrip("?")
    if not isinstance(parsed, dict):
        raise ActionFailure("Query parameters must be a JSON object or query string")
    return parsed or None


def _get_body(body: str | None, headers: dict[str, str]):
    if not body:
        return None, None
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    ).lower()
    if "json" not in content_type:
        return None, body
    try:
        return json.loads(body), None
    except (json.JSONDecodeError, TypeError) as exc:
        raise ActionFailure("Body must contain valid JSON when Content-Type is JSON") from exc


@app.make_request()
def make_request(params: MakeRequestParams, asset: Asset, soar: SOARClient) -> MakeRequestOutput:
    """Make an HTTP request to any HIBP API v3 endpoint using this asset's API key.

    Endpoint availability and required HTTP methods depend on the HIBP API and
    the subscription associated with the configured key.
    """
    endpoint = _get_endpoint(params.endpoint)
    headers = _get_headers(params.headers)
    query_params = _get_query_params(params.query_parameters)
    json_body, content = _get_body(params.body, headers)
    timeout = params.timeout if params.timeout is not None else DEFAULT_REQUEST_TIMEOUT_SECONDS

    response = request(
        asset,
        endpoint,
        query_params,
        method=params.http_method,
        headers=headers,
        json_body=json_body,
        content=content,
        timeout=timeout,
        verify=params.verify_ssl,
    )

    # A generic request returns the vendor's status and body for both success
    # and HTTP error responses, matching the SDK's standard MakeRequestOutput.
    return MakeRequestOutput(
        status_code=response.status_code,
        response_body=response.text,
    )
