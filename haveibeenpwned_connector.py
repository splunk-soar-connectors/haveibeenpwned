# File: haveibeenpwned_connector.py
#
# Copyright (c) 2016-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Phantom imports
import sys

import phantom.app as phantom
import requests
import simplejson as json
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# THIS Connector imports
from haveibeenpwned_consts import *


class HaveIBeenPwnedConnector(BaseConnector):
    def __init__(self):
        super().__init__()

    def initialize(self):
        config = self.get_config()
        self._python_version = int(sys.version_info[0])

        self._api_key = config[HAVEIBEENPWNED_CONFIG_API_KEY]

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, params=None, truncate=False):
        full_url = HAVEIBEENPWNED_API_BASE_URL + endpoint
        headers = {"hibp-api-key": self._api_key}

        if not truncate:
            full_url = full_url + "?truncateResponse=false"

        try:
            response = requests.get(
                full_url,
                params=params,  # nosemgrep: python.requests.best-practice.use-timeout.use-timeout
                headers=headers,
            )
        except:
            return phantom.APP_ERROR, HAVEIBEENPWNED_REST_CALL_FAILURE

        if response.status_code in HAVEIBEENPWNED_BAD_RESPONSE_CODES:
            if response.status_code == HAVEIBEENPWNED_STATUS_CODE_NO_DATA:
                return phantom.APP_SUCCESS, [{"not_found": HAVEIBEENPWNED_BAD_RESPONSE_CODES[response.status_code]}]
            return phantom.APP_ERROR, HAVEIBEENPWNED_BAD_RESPONSE_CODES[response.status_code]

        try:
            resp_json = response.json()
        except:
            return phantom.APP_ERROR, HAVEIBEENPWNED_REST_CALL_JSON_FAILURE

        return phantom.APP_SUCCESS, resp_json

    def _handle_test_connectivity(self, params):
        action_result = self.add_action_result(ActionResult(dict(params)))

        self.save_progress("Connecting to the Have I Been Pwned server")

        endpoint = HAVEIBEENPWNED_API_ENDPOINT_LOOKUP_EMAIL.format(email=TEST_CONNECTIVITY_EMAIL)

        ret_val, response = self._make_rest_call(endpoint, truncate=True)

        if phantom.is_fail(ret_val):
            self.save_progress(f"Test Connectivity Failed. Error: {response}")
            return action_result.get_status()

        self.save_progress("Login to Have I Been Pwned server is successful")
        self.save_progress("Test Connectivity passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _lookup_domain(self, params):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(params)))
        domain = params[HAVEIBEENPWNED_ACTION_PARAM_DOMAIN]
        if phantom.is_url(domain):
            domain = phantom.get_host_from_url(domain).replace("www.", "")

        if "www." in domain:
            domain = domain.replace("www.", "")

        endpoint = HAVEIBEENPWNED_API_ENDPOINT_LOOKUP_DOMAIN
        kwargs = {HAVEIBEENPWEND_PARAM_DOMAIN_KEY: domain}
        self.debug_print("Make REST Call")
        ret_val, response = self._make_rest_call(endpoint, params=kwargs)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, HAVEIBEENPWNED_REST_CALL_ERR, response)

        for item in response:
            action_result.add_data(item)

        action_result.set_summary({HAVEIBEENPWNED_TOTAL_BREACHES: len(response)})

        return action_result.set_status(phantom.APP_SUCCESS, HAVEIBEENPWNED_LOOKUP_DOMAIN_SUCCESS)

    def _lookup_email(self, params):
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(ActionResult(dict(params)))

        email = params[HAVEIBEENPWNED_ACTION_PARAM_EMAIL]
        truncate = params.get(HAVEIBEENPWNED_ACTION_PARAM_TRUNCATE, "False") == "True"
        endpoint = HAVEIBEENPWNED_API_ENDPOINT_LOOKUP_EMAIL.format(email=email)

        self.debug_print("Make REST Call")
        ret_val, response = self._make_rest_call(endpoint, truncate=truncate)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, HAVEIBEENPWNED_REST_CALL_ERR, response)

        for item in response:  # Response ends up being a list
            action_result.add_data(item)

        if "not_found" in response[0]:
            action_result.set_summary({HAVEIBEENPWNED_TOTAL_BREACHES: 0})
        else:
            action_result.set_summary({HAVEIBEENPWNED_TOTAL_BREACHES: len(response)})

        return action_result.set_status(phantom.APP_SUCCESS, HAVEIBEENPWNED_LOOKUP_EMAIL_SUCCESS)

    def handle_action(self, params):
        action = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS
        if action == ACTION_ID_LOOKUP_DOMAIN:
            ret_val = self._lookup_domain(params)
        elif action == ACTION_ID_LOOKUP_EMAIL:
            ret_val = self._lookup_email(params)
        elif action == ACTION_ID_TEST_CONNECTIVITY:
            ret_val = self._handle_test_connectivity(params)

        return ret_val


if __name__ == "__main__":
    """ Code that is executed when run in standalone debug mode
    for .e.g:
    python2.7 ./zendesk_connector.py /tmp/zendesk_test_create_ticket.json
        """

    # Imports
    import pudb

    # Breakpoint at runtime
    pudb.set_trace()

    # The first param is the input json file
    with open(sys.argv[1]) as f:
        # Load the input json file
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=" " * 4))

        # Create the connector class object
        connector = HaveIBeenPwnedConnector()

        # Se the member vars
        connector.print_progress_message = True

        # Call BaseConnector::_handle_action(...) to kickoff action handling.
        ret_val = connector._handle_action(json.dumps(in_json), None)

        # Dump the return value
        print(ret_val)

    sys.exit(0)
