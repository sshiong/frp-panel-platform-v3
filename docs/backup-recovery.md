# Backup and recovery

Server backups use SQLite `VACUUM INTO` so a live WAL database is snapshotted consistently. The resulting archive is encrypted as an `FPPB1` package with scrypt-derived AES-256-GCM encryption and a separate backup password.

The admin endpoint is:

```http
POST /api/v1/admin/backups
Content-Type: application/json

{"password":"a-long-backup-password"}
```

The password is never stored in the database. The `backup.Decode` and `backup.Restore` library functions verify the package header, decrypt the archive, check the manifest and SQLite integrity, and install the snapshot atomically. If a target database already exists it is renamed to a timestamped `.before-restore-*` path for recovery. Stop the Server Panel before restore; the operator must then revoke Sessions, rebuild the Router snapshot, and produce a recovery report before returning the instance to service. JSON export is for non-sensitive mapping/domain previews only and is not a full restore format.

The package format is `FPPB1`: a random per-package scrypt salt, AES-256-GCM nonce/ciphertext, and a ZIP containing `manifest.json` and `server.db`. The backup password is never persisted or logged.

For a controlled restore, stop the server and run:

```bash
export FRP_BACKUP_PASSWORD='provided-out-of-band'
./build/frp-panel-backup-restore \
  -input /var/lib/frp-panel-server/backups/backup.fppb \
  -target /var/lib/frp-panel-server/server.db
```
