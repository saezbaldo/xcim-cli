# XCIM CLI

`xcim doctor` reports the configuration that an agent can actually observe. It never provisions an application, writes to an attester, reads SQL, or performs consent. The distribution is **xcim-cli** on both registries; the executable is **xcim**. The npm and Python editions have no runtime dependencies beyond their own runtime.

```sh
# Once the packages have been published:
npm exec --package=xcim-cli -- xcim doctor --attester emabled --json
pipx run --spec xcim-cli xcim doctor --attester emabled --json
```

Node 22+ or Python 3.9+ is required, respectively. Run from source with `node xcim.mjs doctor --attester emabled --json` or `python xcim_doctor.py doctor --attester emabled --json`.

## Choose an attester and profile

- `--attester emabled` (default) reads `https://api.emabled.com/v1/capabilities`. An explicit HTTPS origin, without a path, credentials, query, fragment or non-default port, can be used for another attester that implements the same capability contract. That contract is a compatibility requirement for this release, not an XCIM-mandated endpoint.
- `--profile evp|oidc|both` (default `both`) selects the checks. For EVP, `--evp-mode vendor|hosted` (default `vendor`) distinguishes a vendor-origin form from a hosted one.
- `--offline` makes no HTTP requests. Otherwise the command makes one unauthenticated HTTPS GET with a five-second deadline and rejects redirects. It does not read browser sessions or use vendor, ESP, database or publishing credentials.

## Diagnose workspace configuration

The public capability endpoint does not expose workspace settings. An authorized operator can open the application setup view in the Emabled console and save **only the JSON response body** of its existing read-only `GET /v1/control/provisioning/{requestId}/setup` request as `setup.json`. Do not export a HAR, request headers, session cookies or tokens. Keep the JSON local; it may contain workspace metadata. This edition does not log into the console or fetch this private endpoint itself.

```sh
xcim doctor --attester emabled --snapshot setup.json --source src_example --profile both --json
```

The snapshot is an operator-supplied observation, not signed evidence. It is supported only by the Emabled adapter and expires after 24 hours. Pass the source ID when multiple sources are linked or the response is paginated; the file must contain that source. Without a source ID the CLI selects a unique linked source only on an unpaginated response. It never infers that a source on another page is missing.

The report separates public capabilities from recorded workspace configuration: application registration, signed manifest publication, pairwise key configuration, source binding, recorded website DNS verification, exact return URI, exchange endpoint, provider binding/review and browser bootstrap. It does not independently verify any of those proofs. Live DNS, sender-domain authority, access to signing keys, Origin Trial token validity, end-to-end consent and receipts, and current permission are not checked.

## Agent output

With `--json`, stdout contains one JSON object (`schema: xcim-doctor/v1`). Each check has:

- `status`: `configured` (observed), `missing` (explicitly absent), or `unknown` (insufficient evidence).
- `evidence`: `attester_capabilities` or `console_snapshot`. Consult the top-level evidence statuses to distinguish an observed response from an unavailable or stale one.
- `human_required`: the unresolved next step requires a console operator, application owner, provider review or browser action. Missing evidence does not turn every dependent check into a separate human task.
- `next_action`: stable machine-readable instruction code, or `null` for a configured check.

The report does not echo response bodies, raw snapshot values such as keys or URLs, or server error text. It includes the selected application/source IDs for correlation. It has no global “integration ready” verdict.

| Exit | Meaning |
| --- | --- |
| 0 | All selected, in-scope configuration checks were observed. |
| 2 | At least one check is missing or unknown. This includes a public-only run with no snapshot. |
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
