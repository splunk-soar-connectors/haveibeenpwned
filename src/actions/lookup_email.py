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
from urllib.parse import quote

from pydantic import field_validator, model_validator
from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..helper import make_rest_call, require_nonblank
from ..models import BreachSummary, EmailBreachOutput


class LookupEmailParams(Params):
    email: str = Param(description="Email address", required=True, primary=True, cef_types=["email"], column_name="Email")
    truncate: str | None = Param(
        description="Truncate results to just domains (Default: False)", required=False, default="False", value_list=["True", "False"]
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return require_nonblank(value, "Email")

    @model_validator(mode="before")
    @classmethod
    def preserve_truncate_default(cls, values):
        # SDK optional-field handling inserts None for missing fields. Preserve
        # the legacy string default while still accepting an explicit null.
        return {"truncate": "False", **values}


@app.action(
    name="lookup email",
    identifier="lookup_email",
    description="Searches for breaches associated with an email",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=BreachSummary,
)
def lookup_email(params: LookupEmailParams, soar: SOARClient, asset: Asset) -> list[EmailBreachOutput]:
    try:
        response = make_rest_call(asset, "breachedaccount/" + quote(params.email, safe=""), truncate=params.truncate == "True")
    except ActionFailure as exc:
        raise ActionFailure(f"Error during REST call occurred. {exc.message}") from exc
    total = 0 if response and "not_found" in response[0] else len(response)
    soar.set_summary(BreachSummary(total_breaches=total))
    soar.set_message("Lookup Email succeeded")
    return [EmailBreachOutput(**item) for item in response]
