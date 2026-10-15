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
import re
from html import escape
from urllib.parse import quote, urlparse

from soar_sdk.auth import StaticTokenAuth
from soar_sdk.exceptions import ActionFailure
from soar_sdk.shims.phantom.utils import is_url

from .consts import API_BASE_URL, BAD_RESPONSE_CODES


def request(
    asset,
    endpoint,
    params=None,
    *,
    method="GET",
    headers=None,
    json_body=None,
    content=None,
    timeout=30,
    verify=True,
):
    # Manifest generation imports this module in the CLI environment, which may
    # lack app runtime dependencies. Import the HTTP client only when executing.
    import httpx

    auth = StaticTokenAuth(asset.api_key, header_name="hibp-api-key", token_type="")
    try:
        with httpx.Client(
            auth=auth,
            timeout=timeout,
            verify=verify,
            follow_redirects=False,
            headers={"User-Agent": "Splunk SOAR Have I Been Pwned"},
        ) as client:
            return client.request(
                method,
                API_BASE_URL + endpoint.lstrip("/"),
                params=params,
                headers=headers,
                json=json_body,
                content=content,
            )
    except httpx.HTTPError as exc:
        raise ActionFailure("REST call failed") from exc


def require_nonblank(value: str, name: str) -> str:
    if not value.strip():
        raise ValueError(f"{name} must not be empty or whitespace-only")
    return value


def _safe_error_detail(value, api_key: str, limit: int) -> str:
    text = str(value)
    # Error bodies can reflect credentials. Redact before truncation so a key
    # crossing the length boundary cannot leak a partial value.
    if api_key:
        for secret in {api_key, quote(api_key, safe="")}:
            text = re.sub(re.escape(secret), "[redacted]", text, flags=re.IGNORECASE)
    text = " ".join("".join(char if char.isprintable() else " " for char in text).split())
    text = escape(text)
    return text if len(text) <= limit else text[:limit] + "..."


def raise_for_http_error(response, asset, *, legacy_messages=False):
    if 200 <= response.status_code < 300:
        return
    message = f"HIBP API returned HTTP {response.status_code}"
    if legacy_messages:
        message = BAD_RESPONSE_CODES.get(response.status_code, message)
    detail = response.text
    try:
        payload = response.json()
        if isinstance(payload, dict):
            detail = payload.get("message") or payload.get("error") or detail
            if isinstance(detail, dict):
                detail = detail.get("message") or detail
    except ValueError:
        pass
    detail = _safe_error_detail(detail, asset.api_key, 500)
    if detail:
        message += f". Vendor detail: {detail}"
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        message += f". Retry-After: {_safe_error_detail(retry_after, asset.api_key, 100)}"
    raise ActionFailure(message)


def make_rest_call(asset, endpoint, params=None, *, truncate=False):
    query = dict(params or {})
    if not truncate:
        query["truncateResponse"] = "false"
    response = request(asset, endpoint, query)
    if response.status_code == 404:
        # The legacy connector explicitly inserts this sentinel for 404s.
        return [{"not_found": BAD_RESPONSE_CODES[404]}]
    raise_for_http_error(response, asset, legacy_messages=True)
    try:
        payload = response.json()
    except ValueError as exc:
        raise ActionFailure("Conversion of Response to JSON failed") from exc
    if not isinstance(payload, list) or any(not isinstance(item, dict) for item in payload):
        raise ActionFailure("Unexpected HIBP response: expected a list of breach objects")
    return payload


def normalize_domain(domain):
    if is_url(domain):
        domain = urlparse(domain).hostname or ""
    # Preserve the legacy replacement (including occurrences away from the prefix).
    return domain.replace("www.", "")
