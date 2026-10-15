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

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

from .consts import TEST_CONNECTIVITY_EMAIL
from .helper import make_rest_call


class Asset(BaseAsset):
    api_key: str = AssetField(description="API key", required=True, sensitive=True, category=FieldCategory.CONNECTIVITY)


app = App(
    name="Have I Been Pwned",
    app_type="investigative",
    logo="logo_haveibeenpwned.svg",
    logo_dark="logo_haveibeenpwned_dark.svg",
    product_vendor="Troy Hunt",
    product_name="Have I Been Pwned",
    publisher="Splunk",
    appid="6a474f60-5355-4ac1-8654-37a2d4a2143b",
    fips_compliant=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate the asset configuration for connectivity using supplied configuration."""
    logger = getLogger()
    logger.info("Connecting to the Have I Been Pwned server")
    make_rest_call(asset, f"breachedaccount/{quote(TEST_CONNECTIVITY_EMAIL, safe='')}", truncate=True)
    logger.info("Login to Have I Been Pwned server is successful")
    logger.info("Test Connectivity passed")


# Imports register the actions through decorator side effects.
from .actions import lookup_domain, lookup_email, make_request  # noqa: F401


if __name__ == "__main__":
    app.cli()
