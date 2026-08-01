-- statement
ALTER TABLE sessions ADD COLUMN csrf_token_hash TEXT NOT NULL DEFAULT ''
