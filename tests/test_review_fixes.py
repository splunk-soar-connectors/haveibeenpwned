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
from unittest.mock import Mock

import httpx
import pytest
from pydantic import ValidationError
from soar_sdk.exceptions import ActionFailure

from src import helper
from src.actions import lookup_domain, lookup_email, make_request
from src.app import Asset, test_connectivity as connectivity_action
from src.consts import BAD_RESPONSE_CODES


@pytest.fixture
def asset():
    return Asset(api_key="unit-test-placeholder")  # pragma: allowlist secret


@pytest.fixture
def vendor(monkeypatch):
    client_type = httpx.Client
    captured = []

    def install(handler):
        def handle(request):
            captured.append(request)
            return handler(request)

        def create_client(**kwargs):
            return client_type(transport=httpx.MockTransport(handle), **kwargs)

        monkeypatch.setattr(httpx, "Client", create_client)
        return captured

    return install


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "destination", ["https://redirect.example/result", "http://haveibeenpwned.com/result", "https://haveibeenpwned.com/result"]
)
def test_lookup_never_follows_credential_bearing_redirect(asset, vendor, status, destination):
    requests = vendor(lambda request: httpx.Response(status, headers={"Location": destination}))
    with pytest.raises(ActionFailure, match=f"HTTP {status}"):
        helper.make_rest_call(asset, "breaches")
    assert len(requests) == 1
    assert requests[0].url.host == "haveibeenpwned.com"
    assert requests[0].url.scheme == "https"
    assert requests[0].headers["hibp-api-key"] == asset.api_key


@pytest.mark.parametrize("status", [300, 302, 400, 401, 403, 429, 500, 502, 503, 504])
def test_connectivity_rejects_http_error_with_valid_json(asset, vendor, status, capsys):
    requests = vendor(lambda request: httpx.Response(status, json={"message": "upstream failure"}))
    with pytest.raises(ActionFailure, match="upstream failure"):
        connectivity_action.__wrapped__(Mock(), asset)
    assert len(requests) == 1
    assert "Test Connectivity passed" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "module,params",
    [
        (lookup_domain, lookup_domain.LookupDomainParams(domain="example.com")),
        (lookup_email, lookup_email.LookupEmailParams(email="test@example.com")),
    ],
)
def test_lookup_rejects_error_status_even_with_breach_shaped_payload(module, params, asset, vendor):
    vendor(lambda request: httpx.Response(500, json=[{"Name": "Example"}]))
    soar = Mock()
    action = getattr(module, module.__name__.split(".")[-1])
    with pytest.raises(ActionFailure, match="HTTP 500"):
        action.__wrapped__(params, soar, asset)
    soar.set_message.assert_not_called()
    soar.set_summary.assert_not_called()


@pytest.mark.parametrize("payload", [{"message": "unexpected"}, None, True, "string", [None], [1], ["string"], [{"Name": "good"}, None]])
@pytest.mark.parametrize("action_id", ["lookup_domain", "lookup_email", "test_connectivity"])
def test_lookup_response_shape_is_checked_before_success(payload, action_id, asset, vendor):
    vendor(lambda request: httpx.Response(200, content=json.dumps(payload), headers={"Content-Type": "application/json"}))
    soar = Mock()
    with pytest.raises(ActionFailure, match="expected a list of breach objects"):
        if action_id == "test_connectivity":
            connectivity_action.__wrapped__(soar, asset)
        elif action_id == "lookup_domain":
            lookup_domain.lookup_domain.__wrapped__(lookup_domain.LookupDomainParams(domain="example.com"), soar, asset)
        else:
            lookup_email.lookup_email.__wrapped__(lookup_email.LookupEmailParams(email="test@example.com"), soar, asset)
    soar.set_message.assert_not_called()
    soar.set_summary.assert_not_called()


@pytest.mark.parametrize("action_id,count", [("lookup_domain", 1), ("lookup_email", 0)])
def test_http_404_still_inserts_legacy_sentinel_and_summary(action_id, count, asset, vendor):
    vendor(lambda request: httpx.Response(404, text="Not found"))
    soar = Mock()
    if action_id == "lookup_domain":
        result = lookup_domain.lookup_domain.__wrapped__(lookup_domain.LookupDomainParams(domain="example.com"), soar, asset)
    else:
        result = lookup_email.lookup_email.__wrapped__(lookup_email.LookupEmailParams(email="test@example.com"), soar, asset)
    assert [item.model_dump(by_alias=True) for item in result] == [{"not_found": BAD_RESPONSE_CODES[404]}]
    assert soar.set_summary.call_args.args[0].model_dump() == {"total_breaches": count}


@pytest.mark.parametrize(
    "params_class,key,label",
    [
        (lookup_domain.LookupDomainParams, "domain", "Domain"),
        (lookup_email.LookupEmailParams, "email", "Email"),
        (make_request.MakeRequestParams, "endpoint", "Endpoint"),
    ],
)
@pytest.mark.parametrize("value", ["", " ", "\t\n", "\u2003"])
def test_required_input_rejects_blank_value(params_class, key, label, value):
    with pytest.raises(ValidationError, match=f"{label} must not be empty"):
        params_class(**{key: value})


@pytest.mark.parametrize("domain", ["http://", "https:///path", "www.", "http://www."])
def test_normalized_empty_domain_is_rejected_before_request(domain, asset, monkeypatch):
    call = Mock()
    monkeypatch.setattr(lookup_domain, "make_rest_call", call)
    with pytest.raises(ValueError, match="Domain must not be empty"):
        lookup_domain.lookup_domain.__wrapped__(lookup_domain.LookupDomainParams(domain=domain), Mock(), asset)
    call.assert_not_called()


@pytest.mark.parametrize(
    "endpoint",
    [
        "pasteaccount/a%23b%40example.com",
        "pasteaccount/a%3Fb%40example.com",
        "pasteaccount/a%2Fb%40example.com",
        "pasteaccount/a%2Bb%40example.com",
        "pasteaccount/a%2523b%40example.com",
        "breach/Example%23Name",
    ],
)
def test_encoded_path_data_reaches_vendor_unchanged(endpoint, asset, vendor):
    requests = vendor(lambda request: httpx.Response(200, json={"future": [None, True]}))
    soar = Mock()
    result = make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint=endpoint), asset, soar)
    assert requests[0].url.raw_path == b"/api/v3/" + endpoint.encode()
    assert requests[0].url.host == "haveibeenpwned.com"
    assert requests[0].headers["hibp-api-key"] == asset.api_key
    assert json.loads(result.model_dump()["response_body"]) == {"future": [None, True]}
    soar.set_message.assert_not_called()
    soar.set_summary.assert_not_called()


@pytest.mark.parametrize(
    "endpoint",
    [
        "%2F%2Fevil.example",
        "safe/%2e%2e/path",
        "safe/%252e%252e/path",
        "safe%2F..%2Fpath",
        "%5c%5cevil.example",
        "a%00b",
        "a%7Fb",
        "a%250ab",
        "breaches?",
        "breaches#",
    ],
)
def test_encoded_traversal_controls_and_literal_delimiters_are_rejected(endpoint, asset, monkeypatch):
    call = Mock()
    monkeypatch.setattr(make_request, "request", call)
    with pytest.raises(ActionFailure, match="relative path"):
        make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint=endpoint), asset, Mock())
    call.assert_not_called()


@pytest.mark.parametrize("query", [{}, {"query_parameters": None}, {"query_parameters": ""}, {"query_parameters": "{}"}])
def test_optional_query_has_no_manifest_filler_default(query, asset, monkeypatch):
    params = make_request.MakeRequestParams(endpoint="breaches", **query)
    if not query:
        assert params.query_parameters is None
    metadata = make_request.make_request.meta.model_dump()
    assert "default" not in metadata["parameters"]["query_parameters"]
    call = Mock(return_value=httpx.Response(200, json=[]))
    monkeypatch.setattr(make_request, "request", call)
    make_request.make_request.__wrapped__(params, asset, Mock())
    assert call.call_args.args == (asset, "breaches", None)


@pytest.mark.parametrize("status", [403, 429, 500, 503])
def test_generic_request_returns_vendor_error_response(status, asset, vendor):
    vendor(lambda request: httpx.Response(status, headers={"Retry-After": "7"}, json={"message": "Resource access denied"}))
    result = make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint="subscription/status"), asset, Mock())
    assert result.status_code == status
    assert json.loads(result.response_body) == {"message": "Resource access denied"}


@pytest.mark.parametrize("body", ["Service temporarily unavailable", '{"error":{"message":"Unverified domain"}}'])
def test_nonstandard_error_body_still_provides_diagnostics(body, asset, vendor):
    vendor(lambda request: httpx.Response(503, text=body))
    result = make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint="breaches"), asset, Mock())
    assert result.status_code == 503
    assert result.response_body == body


def test_generic_error_body_is_preserved_for_caller(asset, vendor):
    detail = f"<script>{asset.api_key.upper()}</script>\nretry\x1b now"
    vendor(lambda request: httpx.Response(429, headers={"Retry-After": "7"}, json={"message": detail}))
    result = make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint="breaches"), asset, Mock())
    assert result.status_code == 429
    assert json.loads(result.response_body)["message"] == detail


def test_generic_error_body_is_not_truncated(asset, vendor):
    detail = "x" * 490 + asset.api_key + "z" * 1000
    vendor(lambda request: httpx.Response(429, headers={"Retry-After": "7" * 1000}, json={"message": detail}))
    result = make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint="breaches"), asset, Mock())
    assert result.status_code == 429
    assert json.loads(result.response_body)["message"] == detail


def test_generic_manifest_declares_standard_make_request_outputs():
    output = make_request.make_request.meta.model_dump()["output"]
    assert any(field["data_path"] == "action_result.data.*.status_code" and field["data_type"] == "numeric" for field in output)
    assert any(field["data_path"] == "action_result.data.*.response_body" and field["data_type"] == "string" for field in output)
