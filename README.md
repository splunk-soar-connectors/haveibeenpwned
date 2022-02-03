[comment]: # "Auto-generated SOAR connector documentation"
# Have I Been Pwned

Publisher: Splunk  
Connector Version: 2\.1\.3  
Product Vendor: Troy Hunt  
Product Name: Have I Been Pwned  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.1\.0  

Queries Have I Been Pwned for data breach information with investigative actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Have I Been Pwned server. Below are the
default ports used by Splunk SOAR.

|         Service Name | Transport Protocol | Port |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Have I Been Pwned asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_key** |  required  | password | API key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup email](#action-lookup-email) - Searches for breaches associated with an email  
[lookup domain](#action-lookup-domain) - Searches for breaches associated with a domain  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup email'
Searches for breaches associated with an email

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email address | string |  `email` 
**truncate** |  optional  | Truncate results to just domains \(Default\: False\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.parameter\.truncate | string | 
action\_result\.data\.\*\.AddedDate | string | 
action\_result\.data\.\*\.BreachDate | string | 
action\_result\.data\.\*\.DataClasses | string | 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.Domain | string |  `domain` 
action\_result\.data\.\*\.IsActive | boolean | 
action\_result\.data\.\*\.IsFabricated | boolean | 
action\_result\.data\.\*\.IsRetired | boolean | 
action\_result\.data\.\*\.IsSensitive | boolean | 
action\_result\.data\.\*\.IsSpamList | boolean | 
action\_result\.data\.\*\.IsVerified | boolean | 
action\_result\.data\.\*\.LogoPath | string | 
action\_result\.data\.\*\.LogoType | string | 
action\_result\.data\.\*\.ModifiedDate | string | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.PwnCount | numeric | 
action\_result\.data\.\*\.Title | string | 
action\_result\.data\.\*\.not\_found | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_breaches | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'lookup domain'
Searches for breaches associated with a domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | URL or domain to query | string |  `url`  `domain` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `url`  `domain` 
action\_result\.data\.\*\.AddedDate | string | 
action\_result\.data\.\*\.BreachDate | string | 
action\_result\.data\.\*\.DataClasses | string | 
action\_result\.data\.\*\.Description | string | 
action\_result\.data\.\*\.Domain | string |  `url`  `domain` 
action\_result\.data\.\*\.IsActive | boolean | 
action\_result\.data\.\*\.IsFabricated | boolean | 
action\_result\.data\.\*\.IsRetired | boolean | 
action\_result\.data\.\*\.IsSensitive | boolean | 
action\_result\.data\.\*\.IsSpamList | boolean | 
action\_result\.data\.\*\.IsVerified | boolean | 
action\_result\.data\.\*\.LogoPath | string | 
action\_result\.data\.\*\.LogoType | string | 
action\_result\.data\.\*\.ModifiedDate | string | 
action\_result\.data\.\*\.Name | string | 
action\_result\.data\.\*\.PwnCount | numeric | 
action\_result\.data\.\*\.Title | string | 
action\_result\.summary | string | 
action\_result\.summary\.total\_breaches | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 