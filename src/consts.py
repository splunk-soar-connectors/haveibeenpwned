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
API_BASE_URL = "https://haveibeenpwned.com/api/v3/"
TEST_CONNECTIVITY_EMAIL = "account-exists@hibp-integration-tests.com"
BAD_RESPONSE_CODES = {
    400: "Bad Request - the account does not comply with an acceptable format",
    403: "Forbidden - no user agent has been specified in the request",
    404: "Not found - The account could not be found and has likely not been pwned",
    429: "Too many requests - the rate limit has been exceeded",
    401: "Unauthorized - Access denied due to improperly formed hibp-api-key",
}
