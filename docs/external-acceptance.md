# External acceptance runbook

`scripts/external-acceptance.rb` is the single evidence collector for gates that
cannot be proven by an isolated unit test. It runs the complete repository-local
`make contract` target plus migration, secret, license, build and local
performance checks, then runs fixed-version FRPS/FRPC checks when their
artifacts and isolated configuration are supplied. The local performance
profile is evidence for the development host only; it never replaces the
documented 2 vCPU/2 GiB target or production capacity run.

The collector never creates a Cloudflare record, requests an ACME certificate,
changes a production DNS zone, or treats missing credentials as success. It
writes a redacted, mode `0600` report to
`output/external-acceptance.json` (or `EXTERNAL_ACCEPTANCE_REPORT`) and prints
the same JSON to stdout.

Before the external steps, the collector also runs `make acceptance-evidence`.
That command writes `output/acceptance-evidence.json` plus one mode `0600`
traceability log per standard item. The index contains all 141 standard
acceptance IDs and the derived `DOD-001` row, with the required environment,
steps, expected, actual, artifacts, operator, and execution-time fields. Its
overall status remains `blocked` whenever the matrix contains `部分通过` or
`待外部`; it is a traceability record only and never replaces the underlying
test logs, external request IDs, screenshots, or release-owner review.
The contract job validates the index schema, and CI uploads the generated
index as a 14-day artifact for the exact checkout revision.

Every collector step also records the acceptance evidence fields required by
the standard: `environment`, `steps`, `expected`, `actual`, `artifacts`,
`operator`, and `executed_at`. Redacted command output is written as a separate
mode `0600` log under `output/external-acceptance/` and referenced from the
step's `artifacts.logs`; set `EXTERNAL_ACCEPTANCE_ARTIFACT_DIR` to place those
logs in another protected directory. A blocked step records the missing
requirements and its blocked-state log, but never turns that state into a
passing gate.

Exit codes are intentionally strict:

- `0`: every scheduled step passed;
- `1`: a scheduled step failed;
- `2`: at least one required external dependency or evidence bundle is blocked.

`blocked` is never a release pass.

## Local and FRP gates

Run the collector from the repository root:

```bash
make external-acceptance
```

The fixed FRP network checks become executable only after all of these are set:

```bash
export FRP_E2E_FRPS_BINARY=/opt/frp/frps
export FRP_E2E_FRPS_CONFIG=/var/tmp/frps-e2e.toml
export FRP_E2E_FRPC_BINARY=/opt/frp/frpc
export FRP_E2E_FRPC_CONFIG=/var/tmp/frpc-e2e.toml
export FRP_E2E_URL=http://127.0.0.1:18080/
export FRP_E2E_FRPS_READY_PORT=7000
export FRP_E2E_FRPS_SHA256='<release-manifest-sha256>'
export FRP_E2E_FRPC_SHA256='<release-manifest-sha256>'
export FRP_E2E_FIXTURE_DIR="$PWD/tests/fixtures/frp/network"
export FRP_E2E_FIXTURE_HOST=127.0.0.1
export FRP_E2E_FIXTURE_PORT=17081
export FRPC_VERIFY_BINARY=/opt/frp/frpc
export FRPC_VERIFY_VERSION=0.68.0
make external-acceptance
```

The FRP configs must use a disposable Linux test host, a loopback-only Panel
Plugin endpoint, a test transport-secret file, and a test mapping/session. When
`FRP_E2E_FIXTURE_DIR` is set, the network runner starts and cleans up the
isolated `python3` HTTP fixture for the configured port, so the upstream service
cannot be accidentally omitted from the real proxy test.
Never copy a production token or database into the report directory.

For repeatable Linux fault-boundary checks, run this on an Ubuntu 24.04 runner:

```bash
make fault-injection
```

The command mounts a disposable 32MiB tmpfs, fills it until the kernel returns
`ENOSPC`, and verifies that a failed Router snapshot write leaves the previous
`last-good` file unchanged. It also performs an encrypted backup decode/restore
rehearsal in a fresh temporary data directory and runs the Provider/ACME HTTP
`Date` skew checks. This is recorded as implementation evidence only; it does
not replace the release environment's full clean-host restore, system-clock, or
target-disk exercise.

The manual performance workflow now also includes a resource-constrained Linux
profile with exactly 2 vCPU and 2 GiB RAM, SQLite WAL, an explicit warm-up, and the complete
PERF-001/002/003/005/006/007 test suite; it uploads the fixed-profile log
separately from the unconstrained hosted comparison. The release workflow
applies additional hard gates: it runs `make test`,
`make lint`, and `make accessibility`, then reruns the shared fixed
2 vCPU/2 GiB profile on the exact release checkout before any external
evidence or signing step; the repository root must also contain
`release-evidence.json`, and that bundle must validate against the exact
release revision. The release job also runs the fixed FRP v0.68.0 native
TCP and Plugin network checks before cosign signing. Missing Cloudflare
Sandbox, ACME Staging, target-environment, fault-injection, or three-owner
sign-off evidence stops the release job; a local/mock result cannot bypass it.

## Provider and release evidence

Cloudflare Sandbox, ACME Staging, real SNI/Full (strict), target-hardware
performance, disk-full/clock-skew recovery, key rotation, and cosign signing
are intentionally operator-controlled. After completing those procedures,
provide a redacted machine-readable evidence bundle:

```json
{
  "schema_version": "v1",
  "status": "passed",
  "repository": "sshiong/frp-panel-platform-v3",
  "commit": "<current-40-character-release-commit>",
  "gates": {
    "FRPS-009": {"status": "passed", "environment": {"os": "Ubuntu 24.04", "host": "isolated-release-runner"}, "steps": ["Run the fixed FRPS/FRPC Linux matrix"], "expected": "Supported FRP combinations pass", "actual": "All matrix cases pass", "artifacts": {"logs": ["secure/FRPS-009.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "DNS-012": {"status": "passed", "environment": {"provider": "Cloudflare Sandbox", "zone": "disposable-test-zone"}, "steps": ["Create the timeout ambiguity fixture", "Query provider state"], "expected": "Query-after-timeout resolves without duplicate mutation", "actual": "Provider state matched the idempotent outcome", "artifacts": {"logs": ["secure/DNS-012.log"], "screenshots": [], "request_ids": ["sandbox-request-id"]}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "DNS-013": {"status": "passed", "environment": {"provider": "Cloudflare Sandbox", "zone": "disposable-test-zone"}, "steps": ["Run managed and adopted DNS cleanup"], "expected": "Only panel-managed records are removed", "actual": "Managed records cleaned; adopted records retained", "artifacts": {"logs": ["secure/DNS-013.log"], "screenshots": [], "request_ids": ["sandbox-request-id"]}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "CF-007": {"status": "passed", "environment": {"provider": "Cloudflare Sandbox", "token": "scoped-test-token"}, "steps": ["Run the missing-permission and blocked-job cases"], "expected": "Permission errors are classified and jobs remain retryable", "actual": "Blocked and permission states were recorded correctly", "artifacts": {"logs": ["secure/CF-007.log"], "screenshots": [], "request_ids": ["sandbox-request-id"]}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "TLS-009": {"status": "passed", "environment": {"os": "Ubuntu 24.04", "proxy": "test reverse proxy"}, "steps": ["Rotate certificates while serving SNI and Host traffic"], "expected": "SNI routing switches atomically without serving the wrong certificate", "actual": "Connections used the expected certificate before and after rotation", "artifacts": {"logs": ["secure/TLS-009.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "TLS-010": {"status": "passed", "environment": {"ca": "ACME Staging", "dns": "Cloudflare Sandbox"}, "steps": ["Issue a DNS-01 certificate", "Verify TXT propagation and cleanup"], "expected": "Certificate is issued and temporary TXT records are removed", "actual": "Staging certificate issued; TXT cleanup verified", "artifacts": {"logs": ["secure/TLS-010.log"], "screenshots": [], "request_ids": ["acme-order-id"]}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "TLS-012": {"status": "passed", "environment": {"edge": "Cloudflare Full strict", "origin": "isolated TLS origin"}, "steps": ["Serve the panel through Full (strict)"], "expected": "The edge validates the origin certificate and routes successfully", "actual": "Full (strict) request completed with the expected origin", "artifacts": {"logs": ["secure/TLS-012.log"], "screenshots": [], "request_ids": ["edge-request-id"]}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "KEY-004": {"status": "passed", "environment": {"os": "Ubuntu 24.04", "data": "disposable encrypted fixture"}, "steps": ["Rotate the wrapping key", "Restart and decrypt old and new rows", "Exercise rollback"], "expected": "Old ciphertext remains readable during migration and rollback is recoverable", "actual": "Rotation, restart compatibility, and rollback passed", "artifacts": {"logs": ["secure/KEY-004.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "PERF-003": {"status": "passed", "environment": {"cpu": "2 vCPU", "memory": "2 GiB", "disk": "local SSD"}, "steps": ["Run the target-scale mapping and domain profile"], "expected": "Requests and job lag remain within the documented thresholds", "actual": "All target-scale measurements met the thresholds", "artifacts": {"logs": ["secure/PERF-003.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "REL-005": {"status": "passed", "environment": {"os": "Ubuntu 24.04", "disk": "disposable WAL fixture"}, "steps": ["Apply WAL pressure and checkpoint recovery"], "expected": "The service remains recoverable and reports the pressure", "actual": "Checkpoint and restart completed without data loss", "artifacts": {"logs": ["secure/REL-005.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "REL-007": {"status": "passed", "environment": {"os": "Ubuntu 24.04", "disk": "quota-limited disposable volume"}, "steps": ["Inject disk-full during backup and restore"], "expected": "The operation fails safely and leaves recoverable state", "actual": "Disk-full paths returned bounded errors and preserved the last good state", "artifacts": {"logs": ["secure/REL-007.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "REL-008": {"status": "passed", "environment": {"os": "Ubuntu 24.04", "clock": "isolated skewed clock"}, "steps": ["Inject forward and backward clock skew"], "expected": "Leases, retries, and certificates fail safe under skew", "actual": "Clock-skew cases remained bounded and recoverable", "artifacts": {"logs": ["secure/REL-008.log"], "screenshots": [], "request_ids": []}, "operator": "release-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "SEC-008": {"status": "passed", "environment": {"registry": "isolated artifact registry", "signer": "cosign test identity"}, "steps": ["Sign the tag and verify the attestation"], "expected": "The release artifact has a verifiable signature and provenance", "actual": "Cosign verification and tag attestation passed", "signature": {"tool": "cosign", "verified": true, "identity": "https://github.com/sshiong/frp-panel-platform-v3/.github/workflows/release.yml@refs/tags/v0.1.0", "issuer": "https://token.actions.githubusercontent.com", "artifacts_verified": ["build/frp-panel-server"]}, "artifacts": {"logs": ["secure/SEC-008.log"], "screenshots": [], "request_ids": []}, "operator": "security-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "DOD-001": {"status": "passed", "environment": {"review": "release review record"}, "steps": ["Collect release, security, and test-owner approvals"], "expected": "All three required owners sign the same evidence revision", "actual": "Three-owner sign-off recorded", "approvals": [{"role": "release", "name": "release-owner", "commit": "<current-40-character-release-commit>", "approval_ref": "review-release-1", "signed_at": "2026-08-03T00:00:00Z"}, {"role": "security", "name": "security-owner", "commit": "<current-40-character-release-commit>", "approval_ref": "review-security-1", "signed_at": "2026-08-03T00:00:00Z"}, {"role": "test", "name": "test-owner", "commit": "<current-40-character-release-commit>", "approval_ref": "review-test-1", "signed_at": "2026-08-03T00:00:00Z"}], "artifacts": {"logs": ["secure/DOD-001-signoff.log"], "screenshots": [], "request_ids": []}, "operator": "release-manager", "executed_at": "2026-08-03T00:00:00Z"}
  }
}
```

The evidence bundle must identify this exact repository and the current
40-character release commit; evidence from another revision is rejected. Each
gate must include a test environment, non-empty steps, expected and actual
results, an artifacts object with at least one log, screenshot, or request ID,
the operator, and an ISO-8601 execution time. The example uses placeholders for
redacted artifact paths and request IDs; replace them with reviewed evidence
before invoking the collector. The schema regression is covered by
scripts/test-external-acceptance.rb and the contract CI job.

The `SEC-008` gate must additionally contain `signature.tool=cosign`,
`signature.verified=true`, the keyless certificate `identity` and OIDC
`issuer`, plus a non-empty `artifacts_verified` list. The `DOD-001` gate must
contain exactly three distinct approvals with `release`, `security`, and `test`
roles; every approval must name the owner, reference the same current commit,
include an `approval_ref`, and carry an ISO-8601 `signed_at` value. Missing or
weak sign-off metadata is rejected before release.

Run the collector with that file only after the external report has been
reviewed:

```bash
export EXTERNAL_ACCEPTANCE_EVIDENCE=/secure/reviewed/fpp-v3-evidence.json
make external-acceptance
```

The collector requires every gate listed above and requires the bundle-level
`status` to be `passed`. It records the source path and gate IDs, but does not
copy the evidence contents or any credential into the repository report.

For the real Cloudflare DNS smoke path, use a disposable Sandbox zone and a
fresh record name. The command refuses to write unless the explicit
confirmation is present, refuses to touch an existing record, verifies the
create/update/readback lifecycle, and removes the record in an `ensure` path:

```bash
CLOUDFLARE_E2E_API_TOKEN="$CLOUDFLARE_SANDBOX_TOKEN" \
CLOUDFLARE_E2E_ZONE_ID="<disposable-zone-id>" \
CLOUDFLARE_E2E_EXPECTED_ZONE_NAME="<disposable-zone-name>" \
CLOUDFLARE_E2E_RECORD_NAME="frp-e2e-$(date +%s).example.test" \
CLOUDFLARE_E2E_CONFIRM=disposable-zone \
make cloudflare-e2e
```

The runner only accepts the official `https://api.cloudflare.com/client/v4`
endpoint (with an optional trailing slash), verifies that the record name is a
label of the selected Zone, and refuses a mismatched expected Zone name, so a
misconfigured HTTPS endpoint or cross-zone record cannot receive the Sandbox
token. It prints redacted JSON with step results and Cloudflare request IDs;
it never prints the token. Its output is provider smoke evidence, not a
release sign-off by itself: DNS timeout ambiguity, ACME Staging, Full(strict),
target hardware and owner approvals still require the reviewed evidence bundle.

For the real ACME DNS-01 path, use the same disposable Cloudflare zone and a
DNS name delegated to it. The runner rejects production CA URLs, requires an
explicit confirmation, stores the temporary ACME account key only under a
temporary directory, and relies on the provider's `ensure` cleanup for the
challenge TXT records:

```bash
CLOUDFLARE_E2E_API_TOKEN="$CLOUDFLARE_SANDBOX_TOKEN" \
FRP_ACME_E2E_DIRECTORY_URL="https://acme-staging-v02.api.letsencrypt.org/directory" \
FRP_ACME_E2E_EMAIL="release-operator@example.com" \
FRP_ACME_E2E_DOMAIN="frp-e2e-$(date +%s).example.com" \
FRP_ACME_E2E_EXPECTED_ZONE_NAME="<disposable-zone-name>" \
FRP_ACME_E2E_CONFIRM=acme-staging \
make acme-e2e
```

The command requires the ACME name to be the selected disposable Zone apex or
one of its subdomains, then prints only certificate metadata and never prints the Cloudflare
token, private key, or account key. A successful command is still operator
evidence for TLS-010 only; TLS-009/TLS-012, target deployment and three-owner
release sign-off remain separate gates.

The operator runner accepts only the official Let's Encrypt Staging directory
`https://acme-staging-v02.api.letsencrypt.org/directory`. It rejects production
endpoints, untrusted hosts, userinfo, alternate ports, query strings and
redirect-like URL data before creating any ACME account or DNS record.

After configuring the `external-acceptance` GitHub environment with the
disposable-zone secrets `CLOUDFLARE_E2E_API_TOKEN` and `FRP_ACME_E2E_EMAIL`, the
same two runners can be executed from the manual-only
`.github/workflows/external-acceptance.yml` workflow. It requires the zone,
expected Zone name, and fresh DNS names as inputs, verifies both DNS names stay
within that Zone, and uploads only the redacted runner JSON for 14 days,
and refuses to run automatically on push or pull request. The checkout is
explicitly pinned to `github.sha`; both runners include the repository and
exact 40-character commit in their JSON, and
`scripts/validate-external-runners.rb` rejects failed, malformed, cross-revision,
or cross-repository evidence before the final workflow gate. Runner files and
the generated index use mode `0600`; the artifact is still only redacted
operator evidence. The workflow is a preparation aid; the reviewed evidence
bundle and separate TLS/target/sign-off gates are still required for release.

The release workflow also refuses manual publication from any ref other than
protected `main`, and tag-triggered publication must be running on the pushed
tag ref. This keeps the revision-bound evidence and keyless signature identity
on the same release source.

The tracked status remains in [`acceptance-matrix.md`](acceptance-matrix.md)
and [`PROGRESS.md`](../PROGRESS.md). Until the reviewed bundle exists, the
matrix must continue to show the corresponding entries as `部分通过` or
`待外部`, and the project must not be called production-ready.
