# Have I Been Pwned

Publisher: Splunk \
Connector Version: 2.1.4 \
Product Vendor: Troy Hunt \
Product Name: Have I Been Pwned \
Minimum Product Version: 5.1.0

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

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[lookup email](#action-lookup-email) - Searches for breaches associated with an email \
[lookup domain](#action-lookup-domain) - Searches for breaches associated with a domain

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'lookup email'

Searches for breaches associated with an email

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** | required | Email address | string | `email` |
**truncate** | optional | Truncate results to just domains (Default: False) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.email | string | `email` | test@gmail.com |
action_result.parameter.truncate | string | | False |
action_result.data.\*.AddedDate | string | | |
action_result.data.\*.BreachDate | string | | |
action_result.data.\*.DataClasses | string | | |
action_result.data.\*.Description | string | | |
action_result.data.\*.Domain | string | `domain` | |
action_result.data.\*.IsActive | boolean | | |
action_result.data.\*.IsFabricated | boolean | | |
action_result.data.\*.IsRetired | boolean | | |
action_result.data.\*.IsSensitive | boolean | | |
action_result.data.\*.IsSpamList | boolean | | |
action_result.data.\*.IsVerified | boolean | | |
action_result.data.\*.LogoPath | string | | |
action_result.data.\*.LogoType | string | | |
action_result.data.\*.ModifiedDate | string | | |
action_result.data.\*.Name | string | | |
action_result.data.\*.PwnCount | numeric | | |
action_result.data.\*.Title | string | | |
action_result.data.\*.not_found | string | | |
action_result.summary | string | | |
action_result.summary.total_breaches | numeric | | 1 |
action_result.message | string | | Lookup Email succeeded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'lookup domain'

Searches for breaches associated with a domain

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** | required | URL or domain to query | string | `url` `domain` |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.domain | string | `url` `domain` | google.com |
action_result.data.\*.AddedDate | string | | |
action_result.data.\*.BreachDate | string | | |
action_result.data.\*.DataClasses | string | | |
action_result.data.\*.Description | string | | |
action_result.data.\*.Domain | string | `url` `domain` | |
action_result.data.\*.IsActive | boolean | | |
action_result.data.\*.IsFabricated | boolean | | |
action_result.data.\*.IsRetired | boolean | | |
action_result.data.\*.IsSensitive | boolean | | |
action_result.data.\*.IsSpamList | boolean | | |
action_result.data.\*.IsVerified | boolean | | |
action_result.data.\*.LogoPath | string | | |
action_result.data.\*.LogoType | string | | |
action_result.data.\*.ModifiedDate | string | | |
action_result.data.\*.Name | string | | |
action_result.data.\*.PwnCount | numeric | | |
action_result.data.\*.Title | string | | |
action_result.summary | string | | |
action_result.summary.total_breaches | numeric | | 1 |
action_result.message | string | | Lookup Domain succeeded |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
