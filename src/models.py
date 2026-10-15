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
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput


class BreachOutput(PermissiveActionOutput):
    # Non-optional declarations retain metadata without inserting absent keys.
    # DataClasses remains a string datapath in SOAR, while permissive serialization
    # preserves the vendor's original array and any undeclared response fields.
    Name: str = OutputField(column_name="Company")
    Domain: str = OutputField(cef_types=["url", "domain"], column_name="Domain")
    BreachDate: str = OutputField(column_name="Date Of Breach")
    IsVerified: bool = OutputField(column_name="Verified")
    DataClasses: str = OutputField(column_name="Data Compromised")
    AddedDate: str = OutputField()
    Description: str = OutputField()
    IsActive: bool = OutputField()
    IsFabricated: bool = OutputField()
    IsRetired: bool = OutputField()
    IsSensitive: bool = OutputField()
    IsSpamList: bool = OutputField()
    LogoPath: str = OutputField()
    LogoType: str = OutputField()
    ModifiedDate: str = OutputField()
    PwnCount: float = OutputField()
    Title: str = OutputField()


class EmailBreachOutput(BreachOutput):
    Domain: str = OutputField(cef_types=["domain"], column_name="Domain")
    not_found: str = OutputField()


class BreachSummary(ActionOutput):
    total_breaches: int = OutputField(example_values=[1])

    @classmethod
    def _to_json_schema(cls, parent_datapath="action_result.data.*", column_order_counter=None):
        # Preserve the legacy summary-root datapath as well as its numeric child.
        yield {"data_path": parent_datapath, "data_type": "string"}
        yield from super()._to_json_schema(parent_datapath, column_order_counter)
