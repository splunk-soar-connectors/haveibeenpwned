# SDK conversion review

The app is converted on `haveibeenpwned-sdkify` for local review and is ready for
instance testing. Version remains **2.1.6**. No deployment, commit, push, or PR has
been performed. The installable artifact is `haveibeenpwned.tgz` in the repository
root and is ignored by Git.

## Compatibility and manifest fidelity

The generated package manifest was compared with the unchanged legacy manifest in
`tests/fixtures/haveibeenpwned.txt`. All original action names, identifiers, action
types, read-only flags, parameters, CEF types, summary datapaths, and output
datapaths survive. The app UUID and `phantom_haveibeenpwned` package name survive.
All six email-table columns and five domain-table columns retain their names,
order, and bindings. Legacy source snapshots live only in regression fixtures;
they are not included in the installable package.

The SDK requires SOAR **7.0.0** rather than **5.1.0**. Python **3.9** is removed;
SDK **6.1.2** supports **3.13 and 3.14**. The main module becomes `src.app:app`.
The package contains the SDK and its transitive runtime wheels for both Python
versions and Linux x86_64/aarch64. All manifest wheel paths were checked against
the archive; the source, documentation, and logos match the checkout. No tests,
credentials, bytecode, caches, or build directories are bundled.

### Explicit defaults and documentation differences

The SDK adds parameter `name`, `allow_list=false`, and explicit optional/primary
flags. These express legacy defaults. It adds connectivity status/message/object
count datapaths, boolean examples, packaging metadata, `contributors=[]`, and
`supports_es_polling=false`. These do not add ingestion or change lookup results.
Status examples use the SDK's `failure` spelling instead of legacy `failed`.
The SDK omits parameter/message example values and the stale
`latest_tested_versions` claim. Table titles, width, and height use platform
settings; column names and order remain explicit.

`PermissiveActionOutput` preserves entire API objects, including extra properties,
arrays, explicit nulls, and missing keys. Declared fields retain SOAR metadata.
The connector does not invent null/default response fields. The legacy 404
`not_found` sentinel is explicitly inserted. Its email summary is zero; its domain
summary remains one, preserving the original behavior. Missing `truncate` retains
the string `False`; an explicitly null value is accepted and preserved.

### Actual behavior changes

Requests use SDK `StaticTokenAuth` with the same raw `hibp-api-key` header. They
have a descriptive User-Agent and a 30-second timeout. Redirects are disabled for
every action so the API key cannot be forwarded to another origin or over HTTP.
All non-2xx responses fail, except the preserved lookup 404 sentinel. The SDK
formats failures and supplies its connectivity success message. Connectivity
errors now fail explicitly, and an empty email-result array
succeeds with a zero count instead of raising an index error. Successful legacy
lookup messages and complete serialized results are retained.

The generic `make request` action supports the SDK's standard HTTP methods,
headers, query parameters, body, timeout, and TLS verification controls within
the fixed HIBP API v3 base URL. It returns the status and raw body for both
successful and non-2xx responses. Relative endpoints are validated against
external URLs, traversal, and control characters; redirects are disabled so the
API key is not forwarded. This covers less common operations such as pastes,
breach catalogue metadata, subscription status, subscribed domains, eligible
stealer-log queries, and domain-verification operations when the API key and
subscription permit them. It does not cover the separate Pwned Passwords
service. See [the vendor API documentation](https://haveibeenpwned.com/API/v3).

### Review fixes (F1–F8)

- F1: Disable redirects centrally, including same-origin redirects. A redirect is
  an actionable HTTP failure; no second request can forward authentication.
- F5: Reject every non-2xx status before parsing success data. Preserve the legacy
  lookup 404 sentinel and mapped error prefixes.
- F8: Check URL structure before decoding; use repeated decoding only for
  traversal and control-character checks. Encoded email characters such as
  `%23`, `%3F`, `%2F`, and `%2B` remain path data and are sent unchanged.
- F4: Require lookup/connectivity results to be a list of objects before counts
  or results are published. Preserve arbitrary fields, missing fields, explicit
  nulls inside objects, and empty lists.
- F2: Reject empty and whitespace-only required inputs and domains that become
  empty after normalization, before making a request. Valid inputs retain their
  original parameter values.
- F6: Include bounded vendor error details and Retry-After headers. Redact the
  configured key before truncating, escape HTML, and remove control characters.
- F7: Publish a generic GET success message and numeric HTTP status summary.
  Its existing status_code and raw response_body output fields remain unchanged.
- F3: Remove the generic query parameter's empty-string manifest default. Omitted,
  null, empty-string, and empty-object query values all produce no query fields.

The only added output metadata from these fixes is the new generic action's
`action_result.summary.status_code` datapath. The generic query default is removed;
all legacy action parameters, defaults, output metadata, and table bindings remain
unchanged by these fixes. Redirect rejection, blank-input rejection, malformed
response rejection, and comprehensive HTTP status handling are intentional
behavior changes, with regression coverage.

The HTTP client import is inside the request helper because manifest generation
imports app modules in the CLI environment, which may lack app-only dependencies.

## Validation

- 158 unit tests pass on Python 3.13 and 3.14, including complete serialized legacy
  comparisons, extra/missing/null API fields, explicit null parameters, SDK
  decorator adaptation, URL encoding, normalization, status mappings,
  authentication headers, query merging, and generic-request validation. Review
  regressions cover redirects, non-2xx connectivity/lookup failures, malformed
  response shapes, blank inputs, encoded endpoint characters, unsafe paths,
  bounded/redacted error details, retry timing, and generic success metadata.
- `uv run soarapps test unit --no-parallel` passes in the app environment. Dev
  dependencies include pytest-cov and pytest-xdist for the SDK test runner.
- `/Users/atkm/.local/bin/pre-commit run --all-files` passes with intended files
  staged, including new runtime and test files.
- Package build and manifest/archive audits pass. Release workflows,
  CONTRIBUTING.md, LICENSE, manual_readme_content.md, logos, and historical release
  notes are preserved. README is regenerated with the manual content; NOTICE
  retains the original attribution and adds runtime dependency licenses.

Instance and live-vendor testing remain pending. Unit tests execute legacy
handlers using SDK platform shims and mock HTTP; they cannot establish live API
access, platform table rendering, or installation success. No instance credentials
or vendor asset secrets were written into the repository.
