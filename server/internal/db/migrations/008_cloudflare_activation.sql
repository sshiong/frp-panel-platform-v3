-- statement
ALTER TABLE cloudflare_credentials RENAME TO cloudflare_credentials_v007
-- statement
CREATE TABLE cloudflare_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_version INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL CHECK (status IN ('missing', 'pending', 'verified_pending', 'valid', 'invalid', 'permission_denied', 'retired')),
  capabilities_json TEXT NOT NULL DEFAULT '{}',
  impact_domains_json TEXT NOT NULL DEFAULT '[]',
  verified_at TEXT,
  activated_at TEXT,
  retired_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(user_id, token_version)
)
-- statement
INSERT INTO cloudflare_credentials(id,user_id,token_version,ciphertext,nonce,key_version,status,capabilities_json,impact_domains_json,verified_at,activated_at,retired_at,created_at)
SELECT id,user_id,token_version,ciphertext,nonce,key_version,status,capabilities_json,'[]',verified_at,activated_at,retired_at,created_at
FROM cloudflare_credentials_v007
-- statement
DROP TABLE cloudflare_credentials_v007
