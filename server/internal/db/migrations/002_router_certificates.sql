-- statement
CREATE TABLE IF NOT EXISTS certificates (
  id TEXT PRIMARY KEY,
  domain_binding_id TEXT NOT NULL REFERENCES domain_bindings(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'valid', 'renewing', 'expired', 'error', 'revoked')),
  not_before TEXT,
  not_after TEXT,
  renew_after TEXT,
  cert_path TEXT,
  private_key_ciphertext BLOB,
  private_key_nonce BLOB,
  wrapping_key_version INTEGER,
  cert_hash TEXT,
  last_error_code TEXT,
  last_error_message TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE(domain_binding_id, provider)
)
-- statement
CREATE TABLE IF NOT EXISTS router_snapshots (
  version INTEGER PRIMARY KEY,
  schema_version TEXT NOT NULL,
  snapshot_path TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  snapshot_hmac TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'applying', 'active', 'failed', 'superseded')),
  generated_at TEXT NOT NULL,
  applied_at TEXT,
  last_error TEXT
)
-- statement
CREATE TABLE IF NOT EXISTS router_state (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  router_config_version INTEGER NOT NULL DEFAULT 0,
  router_applied_version INTEGER NOT NULL DEFAULT 0,
  last_good_snapshot_version INTEGER,
  last_good_snapshot_path TEXT,
  last_good_snapshot_hash TEXT,
  last_router_apply_error TEXT,
  updated_at TEXT NOT NULL
)
-- statement
INSERT OR IGNORE INTO router_state(singleton_id, updated_at) VALUES (1, datetime('now'))
-- statement
CREATE INDEX IF NOT EXISTS idx_jobs_due ON jobs(status, run_after, lock_expires_at)
-- statement
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain_binding_id, sync_status)
-- statement
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status, renew_after)
