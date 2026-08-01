-- statement
CREATE TABLE IF NOT EXISTS external_residues (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  operation_id TEXT,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  identifier TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT
)
-- statement
CREATE INDEX IF NOT EXISTS idx_external_residues_operation ON external_residues(operation_id, resolved_at)
