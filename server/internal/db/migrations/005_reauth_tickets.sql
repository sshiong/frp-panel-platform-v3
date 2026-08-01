-- statement
CREATE TABLE IF NOT EXISTS reauth_tickets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_generation INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
)
-- statement
CREATE INDEX IF NOT EXISTS idx_reauth_tickets_lookup ON reauth_tickets(user_id, session_generation, expires_at)
