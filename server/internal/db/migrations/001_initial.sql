-- statement
CREATE TABLE IF NOT EXISTS system_identity (
  singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
  server_instance_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  restored_from_backup_at TEXT
)
-- statement
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleting', 'deleted')),
  must_change_password INTEGER NOT NULL DEFAULT 0,
  auth_version INTEGER NOT NULL DEFAULT 1,
  active_session_generation INTEGER NOT NULL DEFAULT 0,
  desired_config_version INTEGER NOT NULL DEFAULT 0,
  applied_config_version INTEGER NOT NULL DEFAULT 0,
  last_failed_config_version INTEGER,
  active_cloudflare_token_version INTEGER,
  max_mappings INTEGER NOT NULL DEFAULT 50,
  max_domains INTEGER NOT NULL DEFAULT 50,
  max_pending_mappings INTEGER NOT NULL DEFAULT 10,
  max_pending_port_leases INTEGER NOT NULL DEFAULT 10,
  max_pending_domain_operations INTEGER NOT NULL DEFAULT 10,
  max_certificate_jobs INTEGER NOT NULL DEFAULT 5,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
)
-- statement
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL UNIQUE,
  login_channel TEXT NOT NULL CHECK (login_channel IN ('admin_panel', 'client_panel')),
  session_generation INTEGER NOT NULL,
  source_ip TEXT NOT NULL,
  client_forwarded_browser_ip TEXT,
  user_agent TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  revoked_at TEXT,
  revoke_reason TEXT,
  created_at TEXT NOT NULL
)
-- statement
CREATE UNIQUE INDEX IF NOT EXISTS one_active_client_session_per_user ON sessions(user_id) WHERE login_channel = 'client_panel' AND revoked_at IS NULL
-- statement
CREATE TABLE IF NOT EXISTS frp_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  frp_username TEXT NOT NULL UNIQUE,
  secret_hash TEXT NOT NULL,
  secret_ciphertext BLOB NOT NULL,
  secret_nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  secret_version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  rotated_at TEXT
)
-- statement
CREATE TABLE IF NOT EXISTS frp_runtime_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
  session_generation INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL
)
-- statement
CREATE TABLE IF NOT EXISTS user_runtime_state (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  active_server_session_id TEXT,
  observed_client_status TEXT NOT NULL DEFAULT 'offline',
  client_panel_version TEXT,
  frpc_version TEXT,
  protocol_version TEXT,
  config_schema_version TEXT,
  last_heartbeat_at TEXT,
  last_applied_config_version INTEGER NOT NULL DEFAULT 0,
  last_error_code TEXT,
  last_error_message TEXT,
  updated_at TEXT NOT NULL
)
-- statement
CREATE TABLE IF NOT EXISTS idempotency_records (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_generation INTEGER NOT NULL,
  http_method TEXT NOT NULL,
  normalized_path TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_body_hash TEXT NOT NULL,
  response_status INTEGER NOT NULL,
  response_body_json TEXT NOT NULL,
  operation_id TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, session_generation, http_method, normalized_path, idempotency_key)
)
-- statement
CREATE TABLE IF NOT EXISTS mappings (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  proxy_type TEXT NOT NULL CHECK (proxy_type IN ('tcp', 'udp', 'http')),
  lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN ('reserved', 'pending_apply', 'running', 'offline', 'config_error', 'disabled', 'deleting', 'deleted')),
  desired_state TEXT NOT NULL DEFAULT 'enabled',
  observed_state TEXT NOT NULL DEFAULT 'offline',
  active_revision_id TEXT,
  pending_revision_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)
-- statement
CREATE TABLE IF NOT EXISTS mapping_revisions (
  id TEXT PRIMARY KEY,
  mapping_id TEXT NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  local_ip TEXT NOT NULL,
  local_port INTEGER NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
  remote_port INTEGER CHECK (remote_port IS NULL OR remote_port BETWEEN 1 AND 65535),
  health_check_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL CHECK (status IN ('pending', 'applying', 'active', 'failed', 'superseded', 'rolled_back')),
  created_at TEXT NOT NULL,
  applied_at TEXT,
  UNIQUE(mapping_id, revision)
)
-- statement
CREATE TABLE IF NOT EXISTS port_leases (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  mapping_id TEXT NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
  mapping_revision_id TEXT NOT NULL REFERENCES mapping_revisions(id) ON DELETE CASCADE,
  remote_port INTEGER NOT NULL CHECK (remote_port BETWEEN 1 AND 65535),
  lease_role TEXT NOT NULL CHECK (lease_role IN ('active', 'pending')),
  created_at TEXT NOT NULL,
  UNIQUE(server_id, remote_port)
)
-- statement
CREATE TABLE IF NOT EXISTS domain_bindings (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mapping_id TEXT NOT NULL REFERENCES mappings(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  normalized_domain TEXT NOT NULL UNIQUE,
  zone_id TEXT,
  https_mode TEXT NOT NULL CHECK (https_mode IN ('auto_certificate', 'cloudflare_proxy', 'http_only')),
  http_redirect INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK (status IN ('reserved', 'pending_dns', 'pending_client', 'pending_certificate', 'pending_router', 'active', 'offline', 'dns_error', 'certificate_error', 'router_error', 'deleting', 'deleted')),
  revision INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
)
-- statement
CREATE TABLE IF NOT EXISTS dns_records (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain_binding_id TEXT REFERENCES domain_bindings(id) ON DELETE SET NULL,
  type TEXT NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME')),
  name TEXT NOT NULL,
  normalized_name TEXT NOT NULL,
  content TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 300,
  proxied INTEGER NOT NULL DEFAULT 0,
  zone_id TEXT,
  record_id TEXT,
  managed_by_panel INTEGER NOT NULL DEFAULT 0,
  adopted INTEGER NOT NULL DEFAULT 0,
  locked INTEGER NOT NULL DEFAULT 0,
  sync_status TEXT NOT NULL DEFAULT 'pending',
  last_synced_at TEXT,
  last_error_code TEXT,
  last_error_message TEXT
)
-- statement
CREATE TABLE IF NOT EXISTS cloudflare_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_version INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN ('missing', 'pending', 'valid', 'invalid', 'permission_denied', 'retired')),
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  verified_at TEXT,
  activated_at TEXT,
  retired_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, token_version)
)
-- statement
CREATE TABLE IF NOT EXISTS operations (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  operation_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'canceled')),
  phase TEXT NOT NULL,
  step TEXT NOT NULL,
  idempotency_key TEXT,
  cancelable INTEGER NOT NULL DEFAULT 1,
  compensation_status TEXT NOT NULL DEFAULT 'not_required',
  error_code TEXT,
  error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
)
-- statement
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'retry_wait', 'succeeded', 'failed', 'canceled')),
  run_after TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  lock_owner TEXT,
  locked_at TEXT,
  lock_expires_at TEXT,
  heartbeat_at TEXT,
  deduplication_key TEXT,
  token_version INTEGER,
  last_error TEXT,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
)
-- statement
CREATE UNIQUE INDEX IF NOT EXISTS one_active_deduplicated_job ON jobs(type, deduplication_key) WHERE status IN ('pending', 'running', 'retry_wait') AND deduplication_key IS NOT NULL
-- statement
CREATE TABLE IF NOT EXISTS config_snapshots (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  schema_version TEXT NOT NULL,
  session_generation INTEGER NOT NULL,
  config_json TEXT NOT NULL,
  config_hash TEXT NOT NULL,
  config_signing_key_id TEXT NOT NULL,
  config_signature TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, version)
)
-- statement
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  server_session_id TEXT,
  session_generation INTEGER,
  source_ip TEXT,
  client_forwarded_browser_ip TEXT,
  user_agent TEXT,
  request_id TEXT NOT NULL,
  operation_id TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  result TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
)
-- statement
CREATE INDEX IF NOT EXISTS idx_mappings_user ON mappings(user_id, lifecycle_status)
-- statement
CREATE INDEX IF NOT EXISTS idx_domains_user ON domain_bindings(user_id, status)
-- statement
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)
