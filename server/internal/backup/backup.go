package backup

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/scrypt"
	_ "modernc.org/sqlite"
)

type Manifest struct {
	Format           string `json:"format"`
	CreatedAt        string `json:"created_at"`
	MigrationVersion int    `json:"migration_version"`
}

const (
	packageMagic   = "FPPB1"
	backupSaltSize = 16
)

func Create(ctx context.Context, database *sql.DB, output, password string) error {
	if len(password) < 12 {
		return fmt.Errorf("backup password must be at least 12 characters")
	}
	tmp, err := os.CreateTemp("", "frp-panel-backup-*.db")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)
	if _, err := database.ExecContext(ctx, "VACUUM INTO ?", tmpPath); err != nil {
		return err
	}
	archive := bytes.NewBuffer(nil)
	zw := zip.NewWriter(archive)
	manifest, _ := json.Marshal(Manifest{Format: "frp-panel-backup-v1", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	mw, _ := zw.Create("manifest.json")
	_, _ = mw.Write(manifest)
	dbFile, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	dw, _ := zw.Create("server.db")
	_, err = io.Copy(dw, dbFile)
	_ = dbFile.Close()
	if err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	salt := make([]byte, backupSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, archive.Bytes(), []byte("frp-panel-backup-v1"))
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	packageBytes := append([]byte(packageMagic), salt...)
	packageBytes = append(packageBytes, nonce...)
	packageBytes = append(packageBytes, ciphertext...)
	return os.WriteFile(output, packageBytes, 0o600)
}

// Decode decrypts and validates a backup without changing the target database.
// The returned database bytes are a SQLite snapshot and must be treated as sensitive.
func Decode(input, password string) (Manifest, []byte, error) {
	if len(password) < 12 {
		return Manifest{}, nil, errors.New("backup password must be at least 12 characters")
	}
	encoded, err := os.ReadFile(input)
	if err != nil {
		return Manifest{}, nil, err
	}
	minimum := len(packageMagic) + backupSaltSize + 12 + 16
	if len(encoded) < minimum || string(encoded[:len(packageMagic)]) != packageMagic {
		return Manifest{}, nil, errors.New("invalid backup package")
	}
	pos := len(packageMagic)
	salt := encoded[pos : pos+backupSaltSize]
	pos += backupSaltSize
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return Manifest{}, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Manifest{}, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Manifest{}, nil, err
	}
	if len(encoded) < pos+gcm.NonceSize() {
		return Manifest{}, nil, errors.New("invalid backup nonce")
	}
	nonce := encoded[pos : pos+gcm.NonceSize()]
	archive, err := gcm.Open(nil, nonce, encoded[pos+gcm.NonceSize():], []byte("frp-panel-backup-v1"))
	if err != nil {
		return Manifest{}, nil, errors.New("backup authentication failed")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	var database []byte
	for _, file := range reader.File {
		if file.Name != "manifest.json" && file.Name != "server.db" {
			continue
		}
		opened, err := file.Open()
		if err != nil {
			return Manifest{}, nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(opened, 512<<20))
		_ = opened.Close()
		if readErr != nil {
			return Manifest{}, nil, readErr
		}
		if file.Name == "manifest.json" {
			if err := json.Unmarshal(data, &manifest); err != nil {
				return Manifest{}, nil, err
			}
		} else {
			database = data
		}
	}
	if manifest.Format != "frp-panel-backup-v1" || len(database) == 0 {
		return Manifest{}, nil, errors.New("backup manifest or database is missing")
	}
	return manifest, database, nil
}

// Restore validates and atomically installs a decoded SQLite snapshot. The current
// database is renamed with a timestamp so an operator can recover it if needed.
// Stop the Server Panel before calling this function.
func Restore(input, password, target string) (string, error) {
	if filepath.Clean(target) == "." || target == "" {
		return "", errors.New("restore target is required")
	}
	_, database, err := Decode(input, password)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(parent, ".frp-panel-restore-*.db")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(database); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	check, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return "", err
	}
	var integrity string
	err = check.QueryRow("PRAGMA integrity_check").Scan(&integrity)
	_ = check.Close()
	if err != nil || integrity != "ok" {
		return "", fmt.Errorf("restored database integrity check failed: %s", integrity)
	}
	previous := ""
	if _, err := os.Stat(target); err == nil {
		previous = target + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(target, previous); err != nil {
			return "", err
		}
	}
	if err := os.Rename(tmpPath, target); err != nil {
		if previous != "" {
			_ = os.Rename(previous, target)
		}
		return "", err
	}
	return previous, nil
}
