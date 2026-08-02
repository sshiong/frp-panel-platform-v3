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
  "gates": {
    "DNS-012": {"status": "passed", "evidence": "sandbox query-after-timeout"},
    "DNS-013": {"status": "passed", "evidence": "managed/unmanaged cleanup"},
    "CF-007": {"status": "passed", "evidence": "provider blocked job"},
    "TLS-009": {"status": "passed", "evidence": "SNI hot reload"},
    "TLS-010": {"status": "passed", "evidence": "ACME staging TXT propagation"},
    "TLS-012": {"status": "passed", "evidence": "Cloudflare Full strict"},
    "PERF-003": {"status": "passed", "evidence": "2 vCPU/2 GiB baseline"},
    "REL-005": {"status": "passed", "evidence": "WAL pressure run"},
    "REL-007": {"status": "passed", "evidence": "disk-full injection"},
    "REL-008": {"status": "passed", "evidence": "clock skew injection"},
    "SEC-008": {"status": "passed", "evidence": "cosign/tag attestation"},
    "FRPS-009": {"status": "passed", "evidence": "Linux FRPS matrix"},
    "KEY-004": {"status": "passed", "evidence": "rotation and rollback"},
    "DOD-001": {"status": "passed", "evidence": "three-owner sign-off"}
  }
}
```

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
