# External acceptance runbook

`scripts/external-acceptance.rb` is the single evidence collector for gates that
cannot be proven by an isolated unit test. It runs the repository-local
contract, migration, secret, license and build checks, then runs fixed-version
FRPS/FRPC checks when their artifacts and isolated configuration are supplied.

The collector never creates a Cloudflare record, requests an ACME certificate,
changes a production DNS zone, or treats missing credentials as success. It
writes a redacted, mode `0600` report to
`output/external-acceptance.json` (or `EXTERNAL_ACCEPTANCE_REPORT`) and prints
the same JSON to stdout.

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
export FRPC_VERIFY_BINARY=/opt/frp/frpc
export FRPC_VERIFY_VERSION=0.68.0
make external-acceptance
```

The FRP configs must use a disposable Linux test host, a loopback-only Panel
Plugin endpoint, a test transport-secret file, and a test mapping/session.
Never copy a production token or database into the report directory.

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
    "SEC-008": {"status": "passed", "environment": {"registry": "isolated artifact registry", "signer": "cosign test identity"}, "steps": ["Sign the tag and verify the attestation"], "expected": "The release artifact has a verifiable signature and provenance", "actual": "Cosign verification and tag attestation passed", "artifacts": {"logs": ["secure/SEC-008.log"], "screenshots": [], "request_ids": []}, "operator": "security-operator", "executed_at": "2026-08-03T00:00:00Z"},
    "DOD-001": {"status": "passed", "environment": {"review": "release review record"}, "steps": ["Collect release, security, and test-owner approvals"], "expected": "All three required owners sign the same evidence revision", "actual": "Three-owner sign-off recorded", "artifacts": {"logs": ["secure/DOD-001-signoff.log"], "screenshots": [], "request_ids": []}, "operator": "release-manager", "executed_at": "2026-08-03T00:00:00Z"}
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

Run the collector with that file only after the external report has been
reviewed:

```bash
export EXTERNAL_ACCEPTANCE_EVIDENCE=/secure/reviewed/fpp-v3-evidence.json
make external-acceptance
```

The collector requires every gate listed above and requires the bundle-level
`status` to be `passed`. It records the source path and gate IDs, but does not
copy the evidence contents or any credential into the repository report.

The tracked status remains in [`acceptance-matrix.md`](acceptance-matrix.md)
and [`PROGRESS.md`](../PROGRESS.md). Until the reviewed bundle exists, the
matrix must continue to show the corresponding entries as `部分通过` or
`待外部`, and the project must not be called production-ready.
