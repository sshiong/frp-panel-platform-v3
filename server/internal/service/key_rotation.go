package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
)

// KeyRotationResult records the durable migration work performed by the
// maintenance command. The old key files remain available in the key ring so
// a failed or interrupted migration can be retried without losing access to
// existing ciphertext.
type KeyRotationResult struct {
	MasterKeyVersion      int64 `json:"master_key_version"`
	CertificateKeyVersion int64 `json:"certificate_key_version"`
	FRPCredentials        int   `json:"frp_credentials"`
	CloudflareCredentials int   `json:"cloudflare_credentials"`
	Certificates          int   `json:"certificates"`
}

type encryptedDatabaseRow struct {
	id         string
	owner      string
	ciphertext []byte
	nonce      []byte
	keyVersion int64
}

// RotateEncryptionKeys rotates the purpose-specific key rings and re-wraps
// all encrypted database material in one short SQLite transaction. Callers
// should run it as a maintenance operation with the normal server process
// stopped or drained; the old key versions are intentionally retained for
// rollback and restart compatibility.
func (a *App) RotateEncryptionKeys(ctx context.Context) (KeyRotationResult, error) {
	if a == nil || a.DB == nil || a.Crypto == nil {
		return KeyRotationResult{}, fmt.Errorf("database and crypto manager are required")
	}
	masterVersion, err := a.Crypto.RotateMasterKey()
	if err != nil {
		return KeyRotationResult{}, fmt.Errorf("rotate master key: %w", err)
	}
	certificateVersion, err := a.Crypto.RotateCertificateKey()
	if err != nil {
		return KeyRotationResult{}, fmt.Errorf("rotate certificate wrapping key: %w", err)
	}

	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return KeyRotationResult{}, err
	}
	defer tx.Rollback()
	result := KeyRotationResult{MasterKeyVersion: masterVersion, CertificateKeyVersion: certificateVersion}
	if result.FRPCredentials, err = rotateFRPCredentials(ctx, tx, a.Crypto); err != nil {
		return KeyRotationResult{}, err
	}
	if result.CloudflareCredentials, err = rotateCloudflareCredentials(ctx, tx, a.Crypto); err != nil {
		return KeyRotationResult{}, err
	}
	if result.Certificates, err = rotateCertificates(ctx, tx, a.Crypto); err != nil {
		return KeyRotationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return KeyRotationResult{}, fmt.Errorf("commit key rotation: %w", err)
	}
	return result, nil
}

func rotateFRPCredentials(ctx context.Context, tx *sql.Tx, manager *crypto.Manager) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,user_id,secret_ciphertext,secret_nonce,COALESCE(key_version,0) FROM frp_credentials`)
	if err != nil {
		return 0, err
	}
	records, err := scanEncryptedRows(rows)
	if err != nil {
		return 0, err
	}
	for _, record := range records {
		plaintext, err := manager.DecryptVersioned(record.keyVersion, record.ciphertext, record.nonce, "user:"+record.owner+":frp_secret:v1")
		if err != nil {
			return 0, fmt.Errorf("decrypt FRP credential for user %s: %w", record.owner, err)
		}
		ciphertext, nonce, err := manager.Encrypt(plaintext, "user:"+record.owner+":frp_secret:v1")
		if err != nil {
			return 0, fmt.Errorf("encrypt FRP credential for user %s: %w", record.owner, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE frp_credentials SET secret_ciphertext=?,secret_nonce=?,key_version=? WHERE id=?`, ciphertext, nonce, manager.CurrentMasterKeyVersion(), record.id); err != nil {
			return 0, err
		}
	}
	return len(records), nil
}

func rotateCloudflareCredentials(ctx context.Context, tx *sql.Tx, manager *crypto.Manager) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,user_id,ciphertext,nonce,COALESCE(key_version,0) FROM cloudflare_credentials`)
	if err != nil {
		return 0, err
	}
	records, err := scanEncryptedRows(rows)
	if err != nil {
		return 0, err
	}
	for _, record := range records {
		plaintext, err := manager.DecryptVersioned(record.keyVersion, record.ciphertext, record.nonce, "user:"+record.owner+":cloudflare_token:v1")
		if err != nil {
			return 0, fmt.Errorf("decrypt Cloudflare credential for user %s: %w", record.owner, err)
		}
		ciphertext, nonce, err := manager.Encrypt(plaintext, "user:"+record.owner+":cloudflare_token:v1")
		if err != nil {
			return 0, fmt.Errorf("encrypt Cloudflare credential for user %s: %w", record.owner, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE cloudflare_credentials SET ciphertext=?,nonce=?,key_version=? WHERE id=?`, ciphertext, nonce, manager.CurrentMasterKeyVersion(), record.id); err != nil {
			return 0, err
		}
	}
	return len(records), nil
}

func rotateCertificates(ctx context.Context, tx *sql.Tx, manager *crypto.Manager) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,domain_binding_id,private_key_ciphertext,private_key_nonce,COALESCE(wrapping_key_version,0) FROM certificates WHERE private_key_ciphertext IS NOT NULL AND private_key_nonce IS NOT NULL`)
	if err != nil {
		return 0, err
	}
	records, err := scanEncryptedRows(rows)
	if err != nil {
		return 0, err
	}
	for _, record := range records {
		plaintext, err := manager.DecryptCertificate(record.keyVersion, record.ciphertext, record.nonce, "domain:"+record.owner+":certificate_private_key:v1")
		if err != nil {
			return 0, fmt.Errorf("decrypt certificate key for domain %s: %w", record.owner, err)
		}
		ciphertext, nonce, err := manager.EncryptCertificate(plaintext, "domain:"+record.owner+":certificate_private_key:v1")
		if err != nil {
			return 0, fmt.Errorf("encrypt certificate key for domain %s: %w", record.owner, err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE certificates SET private_key_ciphertext=?,private_key_nonce=?,wrapping_key_version=? WHERE id=?`, ciphertext, nonce, manager.CurrentCertificateKeyVersion(), record.id); err != nil {
			return 0, err
		}
	}
	return len(records), nil
}

func scanEncryptedRows(rows *sql.Rows) ([]encryptedDatabaseRow, error) {
	defer rows.Close()
	records := make([]encryptedDatabaseRow, 0)
	for rows.Next() {
		var record encryptedDatabaseRow
		if err := rows.Scan(&record.id, &record.owner, &record.ciphertext, &record.nonce, &record.keyVersion); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
