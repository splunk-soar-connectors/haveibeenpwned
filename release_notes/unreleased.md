**Unreleased**

* Converted the app from BaseConnector to Splunk SOAR SDK 6.1.2; app version remains 2.1.6.
* Minimum SOAR version increases from 5.1.0 to 7.0.0. Python 3.9 support is removed; SDK runtimes are Python 3.13 and 3.14.
* Preserved app ID 6a474f60-5355-4ac1-8654-37a2d4a2143b, package name phantom_haveibeenpwned, and action identifiers test_connectivity, lookup_email, and lookup_domain.
* Preserved raw API results (including undeclared fields, arrays, explicit nulls, and absent fields), legacy 404 sentinel, total_breaches summaries, and table columns.
* Added a generic make request action for arbitrary HTTP methods within the API v3 base URL, including paste, breach catalogue, subscription, subscribed-domain, stealer-log, and domain-verification endpoints when allowed by the API key and subscription. It returns the HTTP status and raw response body, including non-2xx responses. It does not cover the separate Pwned Passwords service.
* Requests use SDK static-token authentication with the same hibp-api-key header, a descriptive User-Agent, and a 30-second default timeout. Generic requests can override timeout and TLS verification; connectivity failures now produce an explicit SDK action error, and an empty email-result array now succeeds with zero breaches.
* SDK packaging generates the manifest and bundled dependencies. Table title/size use platform defaults; table column names and order are preserved. The SDK supplies the connectivity success message and status example metadata.
* Disabled redirects for all actions to prevent API-key forwarding. Fixed lookup and connectivity actions fail on non-2xx responses except the preserved lookup 404 sentinel; generic requests return non-2xx status and body as data. Lookup and connectivity success responses must contain a list of objects.
* Reject empty required inputs and domains that normalize to an empty value. Generic requests preserve encoded path data while rejecting traversal, external URLs, and control characters.
* HTTP failures for fixed lookup and connectivity actions include bounded, sanitized vendor details and Retry-After timing with API-key redaction. Generic requests return vendor error responses as output data; the optional query parameter no longer has an empty-string manifest default.
