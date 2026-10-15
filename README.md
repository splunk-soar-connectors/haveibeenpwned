# Have I Been Pwned

Publisher: Splunk <br>
Connector Version: 2.1.6 <br>
Product Vendor: Troy Hunt <br>
Product Name: Have I Been Pwned <br>
Minimum Product Version: 7.0.0

Queries Have I Been Pwned for data breach information with investigative actions

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Have I Been Pwned server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http | tcp | 80 |
|         https | tcp | 443 |

### Configuration variables

This table lists the configuration variables required to operate Have I Been Pwned. These variables are specified when configuring a Have I Been Pwned asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** | required | password | API key |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration. <br>
[lookup domain](#action-lookup-domain) - Searches for breaches associated with a domain <br>
[lookup email](#action-lookup-email) - Searches for breaches associated with an email <br>
[make request](#action-make-request) - Make an HTTP request to any HIBP API v3 endpoint using this asset's API key.

Endpoint availability and required HTTP methods depend on the HIBP API and
the subscription associated with the configured key.

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration.

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup domain'

Searches for breaches associated with a domain

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | URL or domain to query | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.domain | string | `url` `domain` | |
action_result.data.\*.Name | string | | |
action_result.data.\*.Domain | string | `url` `domain` | |
action_result.data.\*.BreachDate | string | | |
action_result.data.\*.IsVerified | boolean | | True False |
action_result.data.\*.DataClasses | string | | |
action_result.data.\*.AddedDate | string | | |
action_result.data.\*.Description | string | | |
action_result.data.\*.IsActive | boolean | | True False |
action_result.data.\*.IsFabricated | boolean | | True False |
action_result.data.\*.IsRetired | boolean | | True False |
action_result.data.\*.IsSensitive | boolean | | True False |
action_result.data.\*.IsSpamList | boolean | | True False |
action_result.data.\*.LogoPath | string | | |
action_result.data.\*.LogoType | string | | |
action_result.data.\*.ModifiedDate | string | | |
action_result.data.\*.PwnCount | numeric | | |
action_result.data.\*.Title | string | | |
action_result.summary | string | | |
action_result.summary.total_breaches | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup email'

Searches for breaches associated with an email

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | required | Email address | string | `email` |
**truncate** | optional | Truncate results to just domains (Default: False) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.email | string | `email` | |
action_result.parameter.truncate | string | | |
action_result.data.\*.Name | string | | |
action_result.data.\*.Domain | string | `domain` | |
action_result.data.\*.BreachDate | string | | |
action_result.data.\*.IsVerified | boolean | | True False |
action_result.data.\*.DataClasses | string | | |
action_result.data.\*.AddedDate | string | | |
action_result.data.\*.Description | string | | |
action_result.data.\*.IsActive | boolean | | True False |
action_result.data.\*.IsFabricated | boolean | | True False |
action_result.data.\*.IsRetired | boolean | | True False |
action_result.data.\*.IsSensitive | boolean | | True False |
action_result.data.\*.IsSpamList | boolean | | True False |
action_result.data.\*.LogoPath | string | | |
action_result.data.\*.LogoType | string | | |
action_result.data.\*.ModifiedDate | string | | |
action_result.data.\*.PwnCount | numeric | | |
action_result.data.\*.Title | string | | |
action_result.data.\*.not_found | string | | |
action_result.summary | string | | |
action_result.summary.total_breaches | numeric | | 1 |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

Make an HTTP request to any HIBP API v3 endpoint using this asset's API key.

Endpoint availability and required HTTP methods depend on the HIBP API and
the subscription associated with the configured key.

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | optional | HTTP method to use for the HIBP API request. | string | |
**endpoint** | required | Relative endpoint within the HIBP API v3 base URL. For example, 'pasteaccount/user%40example.com' or 'subscription/status'. Do not include the base URL. | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Default is True. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 404 500 |
action_result.data.\*.response_body | string | | {"key": "value"} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
