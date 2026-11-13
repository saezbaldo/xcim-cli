# XCIM CLI

`xcim doctor` reports the configuration that an agent can actually observe. It never provisions an application, writes to an attester, reads SQL, or performs consent. The distribution is **xcim-cli** on both registries; the executable is **xcim**. The npm and Python editions have no runtime dependencies beyond their own runtime.

```sh
# Run this version once it is published:
npm exec --package=xcim-cli@0.2.0 -- xcim doctor --attester emabled --json
pipx run --spec xcim-cli==0.2.0 xcim doctor --attester emabled --json
```

Node 22+ or Python 3.9+ is required, respectively. Run from source with `node xcim.mjs doctor --attester emabled --json` or `python xcim_doctor.py doctor --attester emabled --json`.

**Development version:** The `--oidc-mode` option documented below is planned for 0.3.0 or later and is not available in 0.2.0. The installation commands above install 0.2.0. Check the npm and PyPI registry listings to see whether 0.3.0 is published before installing it.

## Choose an attester and profile

- `--attester emabled` (default) reads `https://api.emabled.com/v1/capabilities`. An explicit HTTPS origin, without a path, credentials, query, fragment or non-default port, can be used for another attester that implements the same capability contract. That contract is a compatibility requirement for this release, not an XCIM-mandated endpoint.
- `--workflow company|esp` (default `company`) selects the workflow. For company setup, `--profile evp|oidc|both` (default `both`) selects the identity checks. `--evp-mode vendor|hosted` (default `vendor`) distinguishes a vendor-origin form from a hosted one. Advertised experimental EVP support is not proof that the origin or browser is eligible.
- For a company OIDC profile, `--oidc-mode hosted|site-managed` (default `hosted`) identifies who manages the sign-in flow. Use `site-managed` only if your site's backend handles the provider callback and submits identity evidence to Emabled. Doctor does not infer the mode from the snapshot.
- `--intent operate|test` (default `operate`) distinguishes operating an existing connection from preparing a new OIDC sign-in test. `test` requires the company workflow and an OIDC profile. It checks prerequisites; it does not start a test.
- `--offline` makes no HTTP requests. Without it, the company workflow makes one unauthenticated HTTPS GET with a five-second deadline and rejects redirects. The ESP workflow is always offline: the public capability response does not describe ESP workspace setup. No workflow reads browser sessions or uses vendor, ESP, database, or publishing credentials.

## Diagnose company setup

The public capability endpoint does not expose workspace settings. Use the diagnostics export in the Emabled console's application setup view when available. This version accepts that `xcim-doctor/company-snapshot/v1` export and older, unversioned setup JSON. An authorized operator on an older console can save **only the JSON response body** of the existing read-only `GET /v1/control/provisioning/{requestId}/setup` request as `setup.json`. Do not export a HAR, request headers, session cookies, or tokens. Keep the JSON local; it may contain workspace metadata. The CLI does not log into the console or fetch the private endpoint.

```sh
xcim doctor --attester emabled --snapshot setup.json --source src_example --profile oidc --json
xcim doctor --attester emabled --snapshot setup.json --source src_example --profile oidc --intent test --json
# If your own backend manages the OIDC callback:
xcim doctor --attester emabled --snapshot setup.json --source src_example --profile oidc --oidc-mode site-managed --json
```

Snapshots are operator-supplied observations, not signed evidence. They are supported only by the Emabled adapter and expire after 24 hours. The versioned export records the selected site when available. `--source` overrides that selection and the file must contain that source. A versioned export without a selected site is not an inventory: choose a site and export again or pass the ID of a site in the file. With legacy JSON, always pass `--source` for a paginated or site-scoped response; the legacy fields cannot distinguish the final page from a complete result.

The report separates public capabilities from recorded workspace configuration: application registration, signed manifest publication, pairwise key configuration, source binding, recorded website DNS verification, exact return URI, exchange endpoint, provider binding/review and browser bootstrap. It does not independently verify any of those proofs. Live DNS, sender-domain authority, access to signing keys, Origin Trial token validity, end-to-end consent and receipts, and current permission are not checked.

The recorded exchange, provider-binding, review, and bootstrap fields describe Emabled's hosted OIDC relay setup. They are not universal prerequisites for a site-managed OIDC flow. The snapshot does not identify which OIDC integration mode a site uses. Reports with OIDC selected include this limitation in `notes` and list `site_managed_oidc_setup` under `not_checked`.

With `--oidc-mode site-managed`, Doctor does not evaluate those hosted-relay fields. Instead it reports `oidc.site_managed_setup` as `unknown`, with `evidence: not_checked` and a blocking `verify_site_managed_oidc_setup` action. This cannot become `configured` in this version: inspect the site backend and independently test identity, consent and return. If no other checks block, this still exits 2, not 0. The mode applies to both `--intent operate` and `--intent test`; it does not run a sign-in test. Omitting the flag retains the existing hosted-relay behavior.

In versioned exports, `oidc.exchange_endpoint` uses the selected site's `exchangeEndpointVerified` flag. If that flag is absent or `null`, the check is unknown. An older unversioned response only records application-wide endpoint activity; it does not show the endpoint is verified for the selected site.

An active OIDC binding with confirmed bootstrap can continue operating after its administrative review ceases to be current. Doctor preserves `oidc.provider_review` as `missing` in that case, but marks it `advisory`, not blocking. `--intent test` treats the same review as a blocker for a new sign-in test.

## Diagnose ESP list-validation setup

Export an ESP diagnostics snapshot from the Emabled console when available. This command reads the local export; it does not accept a list, submit a job, reveal recipient data, or confirm anybody's consent.

```sh
xcim doctor --attester emabled --workflow esp --snapshot esp-diagnostics.json --json
```

The `xcim-doctor/esp-snapshot/v1` export contains exactly `schema`, `observedAt` (an ISO 8601 timestamp), and six nullable booleans: `credentialsEnabled`, `listValidationEnabled`, `eligibleRole`, `mfaRequired`, `partnerIdentityActive`, and `delegationAvailable`. `null` means the console did not establish the fact. In particular, a partial or unavailable authorization listing cannot show that no delegation exists. The export does not include tenant, partner, or delegation IDs, domains, recipients, keys, or files.

The report distinguishes an operator-controlled feature from missing role, MFA, ESP identity, or company delegation. A company admin still grants the ESP an explicit, scoped authorization. A configured delegation check is only a recorded observation, not authorization to upload a list or proof of current permission. Identity profiles and `--source` apply only to the company workflow.

## Agent output

With `--json`, stdout contains one JSON object (`schema: xcim-doctor/v1`). Each check has:

- `status`: `configured` (observed), `missing` (explicitly absent), or `unknown` (insufficient evidence).
- `evidence`: `attester_capabilities`, `console_snapshot`, or `not_checked` for the site-managed setup Doctor cannot assess. Consult the top-level evidence statuses to distinguish an observed response from an unavailable or stale one.
- `human_required`: a blocking next step requires a human. Missing evidence does not turn every dependent check into a separate human task.
- `next_action`: stable machine-readable instruction code, or `null` for a configured check.
- `actor`: who can handle that action (`agent`, `workspace_admin`, `company_admin`, `attester_operator`, or `browser_user`), or `null` when no action is needed. An actor is guidance, not permission to take the action.
- `severity`: `ok`, `blocker`, or `advisory`. Use `blocking` to distinguish a prerequisite from a nonblocking observation. `summary.blocking` and `summary.advisory` count these independently of the original status counts.

The report does not echo response bodies, raw snapshot values such as keys or URLs, or server error text. It includes the selected application/source IDs for correlation. It has no global “integration ready” verdict.

| Exit | Meaning |
| --- | --- |
| 0 | No blocking checks. A missing, nonblocking advisory may still be present. This is not a readiness verdict. |
| 2 | At least one blocking check is missing or unknown. This includes a run with no snapshot. |
| 3 | A requested input could not be read/validated, or the attester request failed. The JSON report still describes what was observed. |
| 64 | Invalid command or flags. |

## Local verification

```sh
npm test
python -m unittest discover -s tests
```

The suites use synthetic configuration, assert the read-only network contract, and check parity across the two editions. Do not share private setup snapshots or credentials in issues, pull requests, or test fixtures.

## License

This standalone CLI is licensed under [Apache-2.0](https://github.com/saezbaldo/xcim-cli/blob/main/LICENSE).
