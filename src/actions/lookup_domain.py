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
from pydantic import field_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import make_rest_call, normalize_domain, require_nonblank
from ..models import BreachOutput, BreachSummary


class LookupDomainParams(Params):
    domain: str = Param(description="URL or domain to query", required=True, primary=True, cef_types=["url", "domain"])

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        return require_nonblank(value, "Domain")


@app.action(
    name="lookup domain",
    identifier="lookup_domain",
    description="Searches for breaches associated with a domain",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=BreachSummary,
)
def lookup_domain(params: LookupDomainParams, soar: SOARClient, asset: Asset) -> list[BreachOutput]:
    domain = require_nonblank(normalize_domain(params.domain), "Domain")
    try:
        response = make_rest_call(asset, "breaches", params={"domain": domain})
    except ActionFailure as exc:
        raise ActionFailure(f"Error during REST call occurred. {exc.message}") from exc
    soar.set_summary(BreachSummary(total_breaches=len(response)))
    soar.set_message("Lookup Domain succeeded")
    return [BreachOutput(**item) for item in response]
