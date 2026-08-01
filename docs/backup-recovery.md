# Backup and recovery

Server backups use SQLite `VACUUM INTO` so a live WAL database is snapshotted consistently. The resulting archive is encrypted as an `FPPB1` package with scrypt-derived AES-256-GCM encryption and a separate backup password.

The admin endpoint is:

```http
POST /api/v1/admin/backups
Content-Type: application/json

{"password":"a-long-backup-password","reauth_ticket":"short-lived-ticket-from-/api/v1/auth/reauth"}
```

The backup endpoint requires a session-bound reauthentication ticket. The password is never stored in the database. The `backup.Decode` and `backup.Restore` library functions verify the package header, decrypt the archive, check every manifest checksum and SQLite integrity, and install the snapshot atomically. If a target database already exists it is renamed to a timestamped `.before-restore-*` path for recovery. Restore revokes all restored sessions and runtime credentials; the next Server startup schedules a Router rebuild. Stop the Server Panel before restore and produce a recovery report before returning the instance to service. JSON export is for non-sensitive mapping/domain previews only and is not a full restore format.

The package format is `FPPB1`: a random per-package scrypt salt, AES-256-GCM nonce/ciphertext, and a ZIP containing `manifest.json`, `server.db`, and protected `files/` entries from the Server data directory (master/signing/router/certificate keys, ACME account material, certificate chain and metadata). Backup output excludes the database WAL/SHM files, logs, and prior backup archives. Every entry has a SHA-256 checksum in the manifest and all entries are restored with mode `0600` below the explicitly supplied data directory. The backup password is never persisted or logged.

WAL maintenance is explicit and operator-controlled. After checking that no backup or migration is using the database, run `make checkpoint` (or `server/cmd/db-checkpoint -db /path/to/server.db`) and inspect the SQLite/WAL gauges before and after. The checkpoint command is an operational source tool, not a third release binary.

For a controlled restore, stop the server and run:

```bash
export FRP_BACKUP_PASSWORD='provided-out-of-band'
./build/frp-panel-backup-restore \
  -input /var/lib/frp-panel-server/backups/backup.fppb \
  -target /var/lib/frp-panel-server/server.db \
  -data-dir /var/lib/frp-panel-server
```

The restore helper is intentionally kept as a Server-side operational source command and is not a third release artifact. Build it from the checked-out Server module for a controlled maintenance window:

```bash
cd server
go build -o ../build/frp-panel-backup-restore ./cmd/backup-restore
```
