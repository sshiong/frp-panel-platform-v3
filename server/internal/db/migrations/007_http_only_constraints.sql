-- statement
CREATE TRIGGER IF NOT EXISTS domain_bindings_http_only_redirect_insert
BEFORE INSERT ON domain_bindings
WHEN NEW.https_mode = 'http_only' AND NEW.http_redirect <> 0
BEGIN
  SELECT RAISE(ABORT, 'http_only domains cannot enable HTTP redirect');
END
-- statement
CREATE TRIGGER IF NOT EXISTS domain_bindings_http_only_redirect_update
BEFORE UPDATE OF https_mode, http_redirect ON domain_bindings
WHEN NEW.https_mode = 'http_only' AND NEW.http_redirect <> 0
BEGIN
  SELECT RAISE(ABORT, 'http_only domains cannot enable HTTP redirect');
END
-- statement
UPDATE domain_bindings
SET http_redirect = http_redirect
WHERE https_mode = 'http_only' AND http_redirect <> 0
