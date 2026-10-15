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
import ast
import json
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import quote, urlparse

import httpx
import pytest
from pydantic import ValidationError
from soar_sdk.actions_manager import ActionsManager
from soar_sdk.exceptions import ActionFailure
from soar_sdk.shims.phantom.action_result import ActionResult
from soar_sdk.shims.phantom.base_connector import BaseConnector
from soar_sdk.shims.phantom.utils import is_url

from src import helper
from src.actions import lookup_domain, lookup_email, make_request
from src.app import Asset, app, test_connectivity as connectivity_action
from src.consts import BAD_RESPONSE_CODES


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def asset():
    return Asset(api_key="unit-test-placeholder")  # pragma: allowlist secret


@pytest.fixture
def legacy():
    # Execute the unchanged legacy handlers with SDK platform shims. Only imports
    # are replaced; request/handler bodies stay byte-for-byte in the fixture.
    source = (FIXTURES / "haveibeenpwned_connector.txt").read_text()
    tree = ast.parse(source)
    tree.body = [node for node in tree.body if not isinstance(node, ast.Import | ast.ImportFrom)]
    scope = {
        "__name__": "legacy_fixture",
        "sys": sys,
        "quote": quote,
        "BaseConnector": BaseConnector,
        "ActionResult": ActionResult,
        "phantom": SimpleNamespace(
            APP_SUCCESS=True,
            APP_ERROR=False,
            is_fail=lambda value: not value,
            is_url=is_url,
            get_host_from_url=lambda value: urlparse(value).hostname,
        ),
        "requests": Mock(),
    }
    exec((FIXTURES / "haveibeenpwned_consts.txt").read_text(), scope)
    exec(compile(tree, "legacy_fixture", "exec"), scope)
    return scope["HaveIBeenPwnedConnector"]()


def serialize(result):
    return json.loads(
        json.dumps(
            {
                "status": result.get_status(),
                "message": result.get_message(),
                "parameter": result.get_param(),
                "data": result.get_data(),
                "summary": result.get_summary(),
            }
        )
    )


def run_sdk(module, params, asset):
    soar = Mock()
    outputs = getattr(module, module.__name__.split(".")[-1]).__wrapped__(params, soar, asset)
    manager = ActionsManager()
    app._adapt_action_result(outputs, manager, params, message=soar.set_message.call_args.args[0], summary=soar.set_summary.call_args.args[0])
    return serialize(manager.get_results()[0])


@pytest.mark.parametrize(
    "payload",
    [
        [
            {
                "Name": "Example",
                "Domain": "example.com",
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
                "IsMalware": False,
                "PwnCount": 12,
                "Extra": {"nested": [1, None, {"new": True}]},
            }
        ],
        [{"Name": "Example"}],
        [{"Name": None, "Domain": None, "DataClasses": None, "PwnCount": None, "Extra": None}],
        [{"Name": "One"}, {"Name": "Two", "Unexpected": [1, "two", None]}],
        [{"not_found": BAD_RESPONSE_CODES[404]}],
    ],
)
@pytest.mark.parametrize("action", ["lookup_email", "lookup_domain"])
def test_complete_serialized_result_matches_legacy(payload, action, legacy, asset, monkeypatch):
    params = {"email": "test@example.com", "truncate": "False"} if action == "lookup_email" else {"domain": "https://www.example.com/path"}
    legacy.action_identifier = action
    legacy._make_rest_call = Mock(return_value=(True, deepcopy(payload)))
    getattr(legacy, "_" + action)(params)
    module = lookup_email if action == "lookup_email" else lookup_domain
    monkeypatch.setattr(module, "make_rest_call", Mock(return_value=deepcopy(payload)))
    param_class = lookup_email.LookupEmailParams if action == "lookup_email" else lookup_domain.LookupDomainParams
    assert run_sdk(module, param_class(**params), asset) == serialize(legacy.get_action_results()[0])


@pytest.mark.parametrize("truncate", ["True", "False", "true", "anything", None])
def test_email_encoding_and_string_truncate_semantics(truncate, legacy, asset, monkeypatch):
    params = {"email": "a+b@example.com/name", "truncate": truncate}
    legacy.action_identifier = "lookup_email"
    legacy._make_rest_call = Mock(return_value=(True, [{"Name": "One"}]))
    legacy._lookup_email(params)
    call = Mock(return_value=[{"Name": "One"}])
    monkeypatch.setattr(lookup_email, "make_rest_call", call)
    lookup_email.lookup_email.__wrapped__(lookup_email.LookupEmailParams(**params), Mock(), asset)
    assert call.call_args.args[1] == legacy._make_rest_call.call_args.args[0]
    assert call.call_args.kwargs == legacy._make_rest_call.call_args.kwargs


@pytest.mark.parametrize(
    "domain", ["www.example.com", "https://www.example.com/path?q=one", "http://www.example.com:8080/path", "sub.www.example.com"]
)
def test_domain_normalization_matches_legacy(domain, legacy, asset, monkeypatch):
    legacy.action_identifier = "lookup_domain"
    legacy._make_rest_call = Mock(return_value=(True, []))
    legacy._lookup_domain({"domain": domain})
    call = Mock(return_value=[])
    monkeypatch.setattr(lookup_domain, "make_rest_call", call)
    lookup_domain.lookup_domain.__wrapped__(lookup_domain.LookupDomainParams(domain=domain), Mock(), asset)
    assert call.call_args.kwargs["params"] == legacy._make_rest_call.call_args.kwargs["params"]


def test_missing_truncate_keeps_false_default(asset, monkeypatch):
    params = lookup_email.LookupEmailParams(email="test@example.com")
    assert params.truncate == "False"
    call = Mock(return_value=[{"Name": "One"}])
    monkeypatch.setattr(lookup_email, "make_rest_call", call)
    lookup_email.lookup_email.__wrapped__(params, Mock(), asset)
    assert call.call_args.kwargs["truncate"] is False


@pytest.mark.parametrize(
    "module,params",
    [
        (lookup_email, {"email": "test@example.com"}),
        (lookup_domain, {"domain": "example.com"}),
    ],
)
def test_empty_response_is_success(module, params, asset, monkeypatch):
    monkeypatch.setattr(module, "make_rest_call", Mock(return_value=[]))
    cls = lookup_email.LookupEmailParams if module is lookup_email else lookup_domain.LookupDomainParams
    result = run_sdk(module, cls(**params), asset)
    assert result["status"] is True
    assert result["data"] == []
    assert result["summary"] == {"total_breaches": 0}


@pytest.mark.parametrize("params_class", [lookup_email.LookupEmailParams, lookup_domain.LookupDomainParams])
def test_required_lookup_parameter(params_class):
    with pytest.raises(ValidationError):
        params_class()


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429])
def test_http_status_mapping_matches_legacy(status, legacy, asset, monkeypatch):
    response = httpx.Response(status)
    legacy._api_key = asset.api_key
    legacy._make_rest_call.__func__.__globals__["requests"].get.return_value = response
    ok, old_response = legacy._make_rest_call("breaches")
    monkeypatch.setattr(helper, "request", Mock(return_value=response))
    if ok:
        assert helper.make_rest_call(asset, "breaches") == old_response
    else:
        with pytest.raises(ActionFailure) as error:
            helper.make_rest_call(asset, "breaches")
        assert error.value.message == old_response


def test_json_failure(asset, monkeypatch):
    response = Mock(status_code=200)
    response.json.side_effect = ValueError("bad json")
    monkeypatch.setattr(helper, "request", Mock(return_value=response))
    with pytest.raises(ActionFailure, match="Conversion of Response to JSON failed"):
        helper.make_rest_call(asset, "breaches")


@pytest.mark.parametrize("truncate", [False, True])
def test_request_preserves_auth_query_and_url(asset, monkeypatch, truncate):
    captured = []

    def handler(request):
        captured.append(request)
        return httpx.Response(200, json=[{"Name": "Example"}])

    client_type = httpx.Client
    options = []

    def create_client(**kwargs):
        options.append(kwargs)
        return client_type(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", create_client)
    assert helper.make_rest_call(asset, "breaches", {"domain": "example.com"}, truncate=truncate) == [{"Name": "Example"}]
    request = captured[0]
    assert request.headers["hibp-api-key"] == asset.api_key
    assert request.headers["user-agent"] == "Splunk SOAR Have I Been Pwned"
    assert request.url.params["domain"] == "example.com"
    assert ("truncateResponse" in request.url.params) is (not truncate)
    assert options[0]["timeout"] == 30


def test_network_failure(asset, monkeypatch):
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=False)
    client.request.side_effect = httpx.ConnectError("offline")
    monkeypatch.setattr(httpx, "Client", Mock(return_value=client))
    with pytest.raises(ActionFailure, match="REST call failed"):
        helper.request(asset, "breaches")


@pytest.mark.parametrize("response", [[{"Name": "Example"}], [{"not_found": BAD_RESPONSE_CODES[404]}]])
def test_connectivity_success_and_not_found(asset, monkeypatch, response):
    call = Mock(return_value=response)
    monkeypatch.setattr("src.app.make_rest_call", call)
    connectivity_action.__wrapped__(Mock(), asset)
    assert call.call_args.args[1] == "breachedaccount/account-exists%40hibp-integration-tests.com"
    assert call.call_args.kwargs == {"truncate": True}


def test_connectivity_propagates_failure(asset, monkeypatch):
    monkeypatch.setattr("src.app.make_rest_call", Mock(side_effect=ActionFailure("Unauthorized")))
    with pytest.raises(ActionFailure, match="Unauthorized"):
        connectivity_action.__wrapped__(Mock(), asset)


@pytest.mark.parametrize(
    "endpoint",
    ["https://evil.example/path", "//evil.example", "../path", "%252e%252e/path", "breaches?x=1", "breaches#frag", "a\\b", "a%0ab"],
)
def test_make_request_rejects_invalid_endpoint(endpoint, asset):
    with pytest.raises(ActionFailure, match="relative path"):
        make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint=endpoint), asset, Mock())


@pytest.mark.parametrize("query", ["[]", "null"])
def test_make_request_rejects_invalid_query(query, asset):
    with pytest.raises(ActionFailure, match="JSON object"):
        make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint="breaches", query_parameters=query), asset, Mock())


def test_make_request_raw_response(asset, monkeypatch):
    response = httpx.Response(200, json={"Example": ["alias"], "future": None})
    call = Mock(return_value=response)
    monkeypatch.setattr(make_request, "request", call)
    result = make_request.make_request.__wrapped__(
        make_request.MakeRequestParams(endpoint="subscribeddomains", query_parameters='{"key": "value"}'), asset, Mock()
    )
    assert result.model_dump(by_alias=True) == {"status_code": 200, "response_body": response.text}
    assert call.call_args.args == (asset, "subscribeddomains", {"key": "value"})
    assert call.call_args.kwargs == {
        "method": "GET",
        "headers": {},
        "json_body": None,
        "content": None,
        "timeout": 30,
        "verify": True,
    }


@pytest.mark.parametrize("status", [302, 401, 404, 429, 500])
def test_make_request_returns_http_error_responses(status, asset, monkeypatch):
    response = httpx.Response(status, text="HIBP error")
    monkeypatch.setattr(make_request, "request", Mock(return_value=response))
    result = make_request.make_request.__wrapped__(make_request.MakeRequestParams(endpoint="subscription/status"), asset, Mock())
    assert result.model_dump(by_alias=True) == {"status_code": status, "response_body": "HIBP error"}


def test_manifest_existing_actions_params_outputs_and_columns():
    original = json.loads((FIXTURES / "haveibeenpwned.txt").read_text())
    current = {meta.identifier: meta.model_dump() for meta in app.actions_manager.get_actions_meta_list()}
    assert set(current) == {"test_connectivity", "lookup_email", "lookup_domain", "make_request"}
    for old in original["actions"]:
        new = current[old["identifier"]]
        for key in ("action", "identifier", "type", "read_only", "versions"):
            assert new[key] == old[key]
        for key, param in old["parameters"].items():
            for field in ("description", "data_type", "order", "contains", "required", "primary", "default", "value_list"):
                if field in param:
                    assert new["parameters"][key][field] == param[field]
        new_outputs = {output["data_path"]: output for output in new["output"]}
        for output in old["output"]:
            assert output["data_path"] in new_outputs
            for key in ("data_type", "contains", "column_name", "column_order"):
                if key in output:
                    assert new_outputs[output["data_path"]][key] == output[key]
    config = Asset.to_json_schema()["api_key"]
    assert config["data_type"] == "password"
    assert config["required"] is True


@pytest.mark.parametrize(
    "module,params",
    [
        (lookup_email, {"email": "test@example.com", "truncate": "False"}),
        (lookup_domain, {"domain": "example.com"}),
    ],
)
def test_decorated_action_flattens_full_results(module, params, asset, legacy, monkeypatch):
    payload = [{"Name": "One", "Future": {"items": [None, True]}}, {"Name": None}]
    action_id = module.__name__.split(".")[-1]
    legacy.action_identifier = action_id
    legacy._make_rest_call = Mock(return_value=(True, deepcopy(payload)))
    getattr(legacy, "_" + action_id)(params)
    monkeypatch.setattr(module, "make_rest_call", Mock(return_value=deepcopy(payload)))
    manager = ActionsManager()
    monkeypatch.setattr(app, "actions_manager", manager)
    soar = Mock()
    soar.set_summary.side_effect = lambda value: setattr(soar, "summary", value)
    soar.set_message.side_effect = lambda value: setattr(soar, "message", value)
    soar.get_summary.side_effect = lambda: soar.summary
    soar.get_message.side_effect = lambda: soar.message
    param_class = lookup_email.LookupEmailParams if module is lookup_email else lookup_domain.LookupDomainParams
    assert getattr(module, action_id)(param_class(**params), soar=soar, asset=asset) is True
    assert len(manager.get_results()) == 1
    assert serialize(manager.get_results()[0]) == serialize(legacy.get_action_results()[0])


@pytest.mark.parametrize(
    "module,params",
    [
        (lookup_email, {"email": "test@example.com"}),
        (lookup_domain, {"domain": "example.com"}),
    ],
)
def test_lookup_action_reports_expected_vendor_failure(module, params, asset, monkeypatch):
    monkeypatch.setattr(module, "make_rest_call", Mock(side_effect=ActionFailure(BAD_RESPONSE_CODES[429])))
    param_class = lookup_email.LookupEmailParams if module is lookup_email else lookup_domain.LookupDomainParams
    function = getattr(module, module.__name__.split(".")[-1])
    with pytest.raises(ActionFailure) as error:
        function.__wrapped__(param_class(**params), Mock(), asset)
    assert error.value.message == "Error during REST call occurred. " + BAD_RESPONSE_CODES[429]


def test_explicit_null_truncate_serialized_result_matches_legacy(legacy, asset, monkeypatch):
    params = {"email": "test@example.com", "truncate": None}
    payload = [{"Name": "Example", "Extra": None}]
    legacy.action_identifier = "lookup_email"
    legacy._make_rest_call = Mock(return_value=(True, deepcopy(payload)))
    legacy._lookup_email(params)
    monkeypatch.setattr(lookup_email, "make_rest_call", Mock(return_value=deepcopy(payload)))
    assert run_sdk(lookup_email, lookup_email.LookupEmailParams(**params), asset) == serialize(legacy.get_action_results()[0])
