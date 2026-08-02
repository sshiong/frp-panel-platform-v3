package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ricardo/frp-panel-platform/server/internal/acme"
	"github.com/ricardo/frp-panel-platform/server/internal/crypto"
	"github.com/ricardo/frp-panel-platform/server/internal/id"
	"github.com/ricardo/frp-panel-platform/server/internal/jobs"
	"github.com/ricardo/frp-panel-platform/server/internal/providers/cloudflare"
)

// RunJobs starts the Server Panel's durable external-operation worker. The
// worker owns no SQLite write transaction while calling Cloudflare.
func (a *App) RunJobs(ctx context.Context) error {
	if err := a.seedPendingJobs(ctx); err != nil {
		return err
	}
	seedCtx, stopSeeding := context.WithCancel(ctx)
	defer stopSeeding()
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = a.seedPendingJobs(seedCtx)
			case <-seedCtx.Done():
				return
			}
		}
	}()
	return a.Jobs.Run(ctx, 500*time.Millisecond, a.handleJob)
}

func (a *App) seedPendingJobs(ctx context.Context) error {
	userDeleteRows, err := a.DB.QueryContext(ctx, `SELECT resource_id,id,compensation_status FROM operations WHERE resource_type='user' AND operation_type='delete' AND status IN ('pending','running')`)
	if err != nil {
		return err
	}
	type userDeleteSeed struct{ userID, operationID, compensationStatus string }
	userDeleteSeeds := make([]userDeleteSeed, 0)
	for userDeleteRows.Next() {
		var userID, operationID, compensationStatus string
		if err := userDeleteRows.Scan(&userID, &operationID, &compensationStatus); err != nil {
			_ = userDeleteRows.Close()
			return err
		}
		userDeleteSeeds = append(userDeleteSeeds, userDeleteSeed{userID: userID, operationID: operationID, compensationStatus: compensationStatus})
	}
	if err := userDeleteRows.Err(); err != nil {
		_ = userDeleteRows.Close()
		return err
	}
	if err := userDeleteRows.Close(); err != nil {
		return err
	}
	for _, seed := range userDeleteSeeds {
		force := seed.compensationStatus == "force_requested" || seed.compensationStatus == "external_residue"
		if _, err := a.enqueueUserDeleteJob(ctx, seed.userID, seed.operationID, force); err != nil {
			return err
		}
	}
	rows, err := a.DB.QueryContext(ctx, `SELECT user_id,id FROM domain_bindings WHERE status IN ('pending_dns','dns_error','pending_client','pending_router')`)
	if err != nil {
		return err
	}
	type domainSeed struct{ userID, domainID string }
	domainSeeds := make([]domainSeed, 0)
	for rows.Next() {
		var userID, domainID string
		if err := rows.Scan(&userID, &domainID); err != nil {
			_ = rows.Close()
			return err
		}
		domainSeeds = append(domainSeeds, domainSeed{userID: userID, domainID: domainID})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, seed := range domainSeeds {
		if _, err := a.Jobs.Enqueue(ctx, "domain_dns_sync", "domain", seed.domainID, "domain:"+seed.domainID+":dns", map[string]interface{}{"user_id": seed.userID, "domain_id": seed.domainID, "action": "check"}, nil); err != nil {
			return err
		}
	}
	rows, err = a.DB.QueryContext(ctx, `SELECT user_id,token_version FROM cloudflare_credentials WHERE status='pending'`)
	if err != nil {
		return err
	}
	type tokenSeed struct {
		userID  string
		version int64
	}
	tokenSeeds := make([]tokenSeed, 0)
	for rows.Next() {
		var userID string
		var version int64
		if err := rows.Scan(&userID, &version); err != nil {
			_ = rows.Close()
			return err
		}
		tokenSeeds = append(tokenSeeds, tokenSeed{userID: userID, version: version})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, seed := range tokenSeeds {
		version := seed.version
		if _, err := a.Jobs.Enqueue(ctx, "cloudflare_token_verify", "cloudflare_token", seed.userID, fmt.Sprintf("cloudflare:%s:%d", seed.userID, version), map[string]interface{}{"user_id": seed.userID, "token_version": version}, &version); err != nil {
			return err
		}
	}
	if a.Config.ACMEEnabled {
		// A missing ACME provider is represented as a blocked job with a long
		// wake-up window. Recheck it immediately after a restart/configuration
		// change instead of waiting for that window to expire.
		if _, err := a.DB.ExecContext(ctx, `UPDATE jobs SET run_after=? WHERE type='acme_certificate_issue' AND status='retry_wait'`, nowString()); err != nil {
			return err
		}
		rows, err = a.DB.QueryContext(ctx, `SELECT d.user_id,d.id FROM certificates c JOIN domain_bindings d ON d.id=c.domain_binding_id WHERE c.provider='acme' AND (c.status='pending' OR (c.status='valid' AND c.renew_after IS NOT NULL AND c.renew_after <= ?))`, nowString())
		if err != nil {
			return err
		}
		type acmeSeed struct{ userID, domainID string }
		acmeSeeds := make([]acmeSeed, 0)
		for rows.Next() {
			var userID, domainID string
			if err := rows.Scan(&userID, &domainID); err != nil {
				return err
			}
			acmeSeeds = append(acmeSeeds, acmeSeed{userID: userID, domainID: domainID})
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, seed := range acmeSeeds {
			if _, err := a.Jobs.Enqueue(ctx, "acme_certificate_issue", "domain", seed.domainID, "domain:"+seed.domainID+":acme", map[string]interface{}{"user_id": seed.userID, "domain_id": seed.domainID}, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *App) handleJob(ctx context.Context, job jobs.Job) error {
	switch job.Type {
	case "cloudflare_token_verify":
		return a.verifyCloudflareToken(ctx, job)
	case "domain_dns_sync":
		return a.syncDomainDNS(ctx, job)
	case "domain_delete":
		return a.deleteDomainExternal(ctx, job)
	case "user_delete":
		return a.deleteUserExternal(ctx, job)
	case "acme_certificate_issue":
		return a.issueCertificate(ctx, job)
	case "router_snapshot_apply":
		_, err := a.BuildRouterSnapshot(ctx)
		return err
	default:
		return fmt.Errorf("unsupported job type %q", job.Type)
	}
}

func (a *App) deleteUserExternal(ctx context.Context, job jobs.Job) error {
	userID := payloadString(job.Payload, "user_id")
	operationID := payloadString(job.Payload, "operation_id")
	force := payloadBool(job.Payload, "force")
	if userID == "" || operationID == "" {
		return errors.New("user deletion job payload is invalid")
	}
	var userStatus string
	if err := a.DB.QueryRowContext(ctx, `SELECT status FROM users WHERE id=? AND role='user'`, userID).Scan(&userStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if userStatus != "deleting" {
		return errors.New("user is not in deleting state")
	}
	rows, err := a.DB.QueryContext(ctx, `SELECT id FROM domain_bindings WHERE user_id=? AND status='deleting' ORDER BY created_at ASC`, userID)
	if err != nil {
		return err
	}
	domainIDs := make([]string, 0)
	for rows.Next() {
		var domainID string
		if err := rows.Scan(&domainID); err != nil {
			_ = rows.Close()
			return err
		}
		domainIDs = append(domainIDs, domainID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, domainID := range domainIDs {
		domainJob := jobs.Job{Payload: map[string]interface{}{"user_id": userID, "domain_id": domainID}}
		cleanupErr := a.deleteDomainExternal(ctx, domainJob)
		var stillPresent int
		if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM domain_bindings WHERE id=?`, domainID).Scan(&stillPresent); err != nil {
			return err
		}
		if cleanupErr != nil || stillPresent != 0 {
			if !force {
				if cleanupErr == nil {
					cleanupErr = errors.New("domain deletion is blocked by external cleanup")
				}
				_ = a.markUserDeleteFailure(ctx, operationID, cleanupErr)
				return cleanupErr
			}
			identifier := a.domainResidueIdentifier(ctx, domainID)
			reason := "domain cleanup left an external record"
			if cleanupErr != nil {
				reason = safeError(cleanupErr.Error())
			}
			if residueErr := a.recordExternalResidue(ctx, userID, operationID, "domain", domainID, "cloudflare", identifier, reason); residueErr != nil {
				return residueErr
			}
			_ = a.Audit(ctx, AuthContext{UserID: userID, Role: "system"}, "user_delete_external_residue", "domain", domainID, "external_residue", map[string]interface{}{"provider": "cloudflare", "residue_count": 1}, operationID)
			if finalizeErr := a.finalizeDeletedDomain(ctx, domainID); finalizeErr != nil {
				return finalizeErr
			}
		}
	}
	if err := a.finalizeDeletedMappings(ctx, userID); err != nil {
		return err
	}
	var mappingCount, domainCount int
	if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM mappings WHERE user_id=?`, userID).Scan(&mappingCount); err != nil {
		return err
	}
	if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM domain_bindings WHERE user_id=?`, userID).Scan(&domainCount); err != nil {
		return err
	}
	if mappingCount != 0 || domainCount != 0 {
		return fmt.Errorf("user deletion is waiting for local resources: mappings=%d domains=%d", mappingCount, domainCount)
	}
	residueCount := 0
	if err := a.DB.QueryRowContext(ctx, `SELECT COUNT(1) FROM external_residues WHERE operation_id=? AND resolved_at IS NULL`, operationID).Scan(&residueCount); err != nil {
		return err
	}
	transaction, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	now := nowString()
	if _, err := transaction.ExecContext(ctx, `UPDATE operations SET user_id=NULL WHERE user_id=? AND id<>?`, userID, operationID); err != nil {
		return err
	}
	compensationStatus := "not_required"
	if residueCount > 0 {
		compensationStatus = "external_residue"
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE operations SET user_id=NULL,status='succeeded',phase='cleanup',step='completed',compensation_status=?,error_code=NULL,error_message=NULL,updated_at=?,completed_at=? WHERE id=?`, compensationStatus, now, now, operationID); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM users WHERE id=? AND status='deleting'`, userID); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	_ = a.EnqueueRouterSnapshot(ctx)
	return nil
}

func (a *App) markUserDeleteFailure(ctx context.Context, operationID string, jobErr error) error {
	now := nowString()
	_, err := a.DB.ExecContext(ctx, `UPDATE operations SET status='failed',phase='external',step='failed',error_code='USER_DELETE_EXTERNAL_CLEANUP_FAILED',error_message=?,updated_at=?,completed_at=? WHERE id=? AND status IN ('pending','running')`, safeError(jobErr.Error()), now, now, operationID)
	return err
}

func (a *App) domainResidueIdentifier(ctx context.Context, domainID string) string {
	var zoneID, recordID string
	if err := a.DB.QueryRowContext(ctx, `SELECT COALESCE(zone_id,''),COALESCE(record_id,'') FROM dns_records WHERE domain_binding_id=? ORDER BY last_synced_at DESC LIMIT 1`, domainID).Scan(&zoneID, &recordID); err != nil {
		return domainID
	}
	identifier := strings.Trim(strings.TrimSpace(zoneID)+"/"+strings.TrimSpace(recordID), "/")
	if identifier == "" {
		return domainID
	}
	return identifier
}

func (a *App) recordExternalResidue(ctx context.Context, userID, operationID, resourceType, resourceID, provider, identifier, reason string) error {
	_, err := a.DB.ExecContext(ctx, `INSERT INTO external_residues(id,user_id,operation_id,resource_type,resource_id,provider,identifier,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)`, id.New(), userID, operationID, resourceType, resourceID, provider, identifier, reason, nowString())
	return err
}

func (a *App) deleteDomainExternal(ctx context.Context, job jobs.Job) error {
	userID := payloadString(job.Payload, "user_id")
	domainID := payloadString(job.Payload, "domain_id")
	if userID == "" || domainID == "" {
		return errors.New("domain deletion job payload is invalid")
	}
	var managed, adopted int
	var recordID, zoneID string
	if err := a.DB.QueryRowContext(ctx, `SELECT managed_by_panel,adopted,COALESCE(record_id,''),COALESCE(zone_id,'') FROM dns_records WHERE domain_binding_id=? ORDER BY last_synced_at DESC LIMIT 1`, domainID).Scan(&managed, &adopted, &recordID, &zoneID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return a.finalizeDeletedDomain(ctx, domainID)
		}
		return err
	}
	if managed != 1 || adopted == 1 && managed != 1 || recordID == "" || zoneID == "" {
		return a.finalizeDeletedDomain(ctx, domainID)
	}
	var ciphertext, nonce []byte
	if err := a.DB.QueryRowContext(ctx, `SELECT c.ciphertext,c.nonce FROM cloudflare_credentials c JOIN users u ON u.active_cloudflare_token_version=c.token_version AND u.id=c.user_id WHERE c.user_id=? AND c.status='valid'`, userID).Scan(&ciphertext, &nonce); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return a.markDomainDeleteFailure(ctx, domainID, "CLOUDFLARE_TOKEN_MISSING", "Cloudflare Token is required to remove the managed DNS record.")
		}
		return err
	}
	token, err := a.Crypto.Decrypt(ciphertext, nonce, "user:"+userID+":cloudflare_token:v1")
	if err != nil {
		return err
	}
	provider := a.cloudflareProvider(string(token))
	if err := provider.DeleteDNS(ctx, cloudflare.Zone{ID: zoneID}, recordID); err != nil {
		if code, message, denied := cloudflarePermissionError(err); denied {
			return a.markDomainDeleteFailure(ctx, domainID, code, message)
		}
		return err
	}
	return a.finalizeDeletedDomain(ctx, domainID)
}

func (a *App) finalizeDeletedDomain(ctx context.Context, domainID string) error {
	var mappingID string
	_ = a.DB.QueryRowContext(ctx, `SELECT mapping_id FROM domain_bindings WHERE id=?`, domainID).Scan(&mappingID)
	now := nowString()
	if _, err := a.DB.ExecContext(ctx, `DELETE FROM dns_records WHERE domain_binding_id=?`, domainID); err != nil {
		return err
	}
	if _, err := a.DB.ExecContext(ctx, `DELETE FROM certificates WHERE domain_binding_id=?`, domainID); err != nil {
		return err
	}
	if _, err := a.DB.ExecContext(ctx, `DELETE FROM domain_bindings WHERE id=? AND status='deleting'`, domainID); err != nil {
		return err
	}
	_, err := a.DB.ExecContext(ctx, `UPDATE operations SET status='succeeded',phase='cleanup',step='completed',error_code=NULL,error_message=NULL,updated_at=?,completed_at=? WHERE resource_type='domain' AND resource_id=? AND operation_type='delete' AND status IN ('pending','running','failed')`, now, now, domainID)
	if err != nil {
		return err
	}
	if mappingID != "" {
		return a.finalizeDeletedMapping(ctx, mappingID)
	}
	return nil
}

func (a *App) finalizeDeletedMappings(ctx context.Context, userID string) error {
	rows, err := a.DB.QueryContext(ctx, `SELECT id FROM mappings WHERE user_id=? AND lifecycle_status='deleting' AND NOT EXISTS (SELECT 1 FROM domain_bindings WHERE mapping_id=mappings.id AND status <> 'deleted')`, userID)
	if err != nil {
		return err
	}
	ids := make([]string, 0)
	for rows.Next() {
		var mappingID string
		if err := rows.Scan(&mappingID); err != nil {
			_ = rows.Close()
			return err
		}
		ids = append(ids, mappingID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, mappingID := range ids {
		if err := a.finalizeDeletedMapping(ctx, mappingID); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) finalizeDeletedMapping(ctx context.Context, mappingID string) error {
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM mappings WHERE id=? AND lifecycle_status='deleting' AND NOT EXISTS (SELECT 1 FROM domain_bindings WHERE mapping_id=? AND status <> 'deleted')`, mappingID, mappingID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return tx.Commit()
	}
	now := nowString()
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET status='succeeded',phase='cleanup',step='completed',error_code=NULL,error_message=NULL,updated_at=?,completed_at=? WHERE resource_type='mapping' AND resource_id=? AND operation_type='delete' AND status IN ('pending','running')`, now, now, mappingID); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *App) markDomainDeleteFailure(ctx context.Context, domainID, code, message string) error {
	now := nowString()
	_, err := a.DB.ExecContext(ctx, `UPDATE operations SET status='failed',phase='dns',step='failed',error_code=?,error_message=?,updated_at=?,completed_at=? WHERE resource_type='domain' AND resource_id=? AND operation_type='delete' AND status IN ('pending','running')`, code, message, now, now, domainID)
	return err
}

func (a *App) verifyCloudflareToken(ctx context.Context, job jobs.Job) error {
	userID := payloadString(job.Payload, "user_id")
	version := payloadInt64(job.Payload, "token_version")
	if userID == "" || version <= 0 {
		return errors.New("cloudflare token job payload is invalid")
	}
	var credentialID string
	var ciphertext, nonce []byte
	if err := a.DB.QueryRowContext(ctx, `SELECT id,ciphertext,nonce FROM cloudflare_credentials WHERE user_id=? AND token_version=? AND status='pending'`, userID, version).Scan(&credentialID, &ciphertext, &nonce); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	token, err := a.Crypto.Decrypt(ciphertext, nonce, "user:"+userID+":cloudflare_token:v1")
	if err != nil {
		return err
	}
	provider := a.cloudflareProvider(string(token))
	capabilities, err := provider.VerifyToken(ctx)
	if err != nil {
		return err
	}
	encoded, _ := json.Marshal(capabilities)
	status := "valid"
	if !capabilities.TokenValid {
		status = "invalid"
	} else if len(capabilities.Missing) > 0 {
		status = "permission_denied"
	}
	now := nowString()
	if status == "valid" {
		_, err = a.DB.ExecContext(ctx, `UPDATE cloudflare_credentials SET status='retired',retired_at=? WHERE user_id=? AND status='valid' AND token_version <> ?`, now, userID, version)
		if err == nil {
			_, err = a.DB.ExecContext(ctx, `UPDATE users SET active_cloudflare_token_version=?,updated_at=? WHERE id=?`, version, now, userID)
		}
	}
	if err == nil {
		_, err = a.DB.ExecContext(ctx, `UPDATE cloudflare_credentials SET status=?,capabilities_json=?,verified_at=?,activated_at=CASE WHEN ?='valid' THEN ? ELSE activated_at END WHERE id=?`, status, string(encoded), now, status, now, credentialID)
	}
	if err == nil {
		_ = a.Audit(ctx, AuthContext{UserID: userID, Role: "system"}, "cloudflare_token_verified", "cloudflare_token", fmt.Sprint(version), status, map[string]interface{}{"token_status": status}, "")
	}
	return err
}

func (a *App) syncDomainDNS(ctx context.Context, job jobs.Job) error {
	userID := payloadString(job.Payload, "user_id")
	domainID := payloadString(job.Payload, "domain_id")
	action := payloadString(job.Payload, "action")
	if action == "" {
		action = "check"
	}
	if userID == "" || domainID == "" {
		return errors.New("domain DNS job payload is invalid")
	}
	var hostname, normalized, httpsMode, status string
	if err := a.DB.QueryRowContext(ctx, `SELECT hostname,normalized_domain,https_mode,status FROM domain_bindings WHERE id=? AND user_id=?`, domainID, userID).Scan(&hostname, &normalized, &httpsMode, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if status == "deleted" || status == "deleting" {
		return nil
	}
	if action == "cancel" {
		return a.markDomainDNSCanceled(ctx, domainID)
	}
	var version int64
	var ciphertext, nonce []byte
	err := a.DB.QueryRowContext(ctx, `SELECT c.token_version,c.ciphertext,c.nonce FROM cloudflare_credentials c JOIN users u ON u.active_cloudflare_token_version=c.token_version AND u.id=c.user_id WHERE c.user_id=? AND c.status='valid'`, userID).Scan(&version, &ciphertext, &nonce)
	if errors.Is(err, sql.ErrNoRows) {
		return a.markDomainDNSFailure(ctx, domainID, "CLOUDFLARE_TOKEN_MISSING", "No verified Cloudflare Token is active.")
	}
	if err != nil {
		return err
	}
	token, err := a.Crypto.Decrypt(ciphertext, nonce, "user:"+userID+":cloudflare_token:v1")
	if err != nil {
		return err
	}
	provider := a.cloudflareProvider(string(token))
	zones := make([]cloudflare.Zone, 0)
	for page := 1; page <= 100; page++ {
		items, more, listErr := provider.ListZones(ctx, page)
		if listErr != nil {
			if code, message, denied := cloudflarePermissionError(listErr); denied {
				return a.markDomainDNSFailure(ctx, domainID, code, message)
			}
			return listErr
		}
		zones = append(zones, items...)
		if !more {
			break
		}
	}
	zone, ok := cloudflare.MatchZone(normalized, zones)
	if !ok {
		return a.markDomainDNSFailure(ctx, domainID, "CLOUDFLARE_ZONE_NOT_FOUND", "No accessible Cloudflare Zone matches this hostname.")
	}
	records, err := provider.ListDNS(ctx, zone, normalized, "")
	if err != nil {
		if code, message, denied := cloudflarePermissionError(err); denied {
			return a.markDomainDNSFailure(ctx, domainID, code, message)
		}
		return err
	}
	desired := cloudflare.Record{Type: "CNAME", Name: normalized, Content: a.Config.FRPSPublicHost, TTL: 300, Proxied: httpsMode == "cloudflare_proxy"}
	var desiredProxied, desiredManaged int
	if err := a.DB.QueryRowContext(ctx, `SELECT COALESCE(type,'CNAME'),COALESCE(content,?),COALESCE(ttl,300),COALESCE(proxied,0),COALESCE(managed_by_panel,0) FROM dns_records WHERE domain_binding_id=? ORDER BY last_synced_at DESC LIMIT 1`, a.Config.FRPSPublicHost, domainID).Scan(&desired.Type, &desired.Content, &desired.TTL, &desiredProxied, &desiredManaged); err == nil {
		desired.Proxied = httpsMode == "cloudflare_proxy"
	}
	if action == "sync" && desiredManaged != 1 {
		return a.markDomainDNSFailure(ctx, domainID, "DNS_RECORD_NOT_MANAGED", "Only DNS records managed by the panel can be updated by this action.")
	}
	managed, adopted := false, false
	var selected cloudflare.Record
	for _, record := range records {
		if strings.EqualFold(record.Type, desired.Type) && strings.EqualFold(record.Content, desired.Content) && record.Proxied == desired.Proxied && (action != "sync" || record.TTL == desired.TTL) {
			selected = record
			adopted = true
			break
		}
	}
	if selected.ID == "" && len(records) > 0 && action != "adopt" && action != "overwrite" && action != "sync" {
		return a.markDomainDNSFailure(ctx, domainID, "DNS_CONFLICT_REQUIRES_ACTION", "Cloudflare already has a conflicting record; choose adopt or overwrite.")
	}
	if selected.ID == "" && action == "adopt" {
		selected = records[0]
		adopted = true
	}
	if selected.ID == "" {
		selected, err = a.upsertDNSWithRecovery(ctx, provider, zone, desired)
		if err != nil {
			if code, message, denied := cloudflarePermissionError(err); denied {
				return a.markDomainDNSFailure(ctx, domainID, code, message)
			}
			return err
		}
		managed = true
	} else if (action == "overwrite" || action == "sync") && (selected.Content != desired.Content || selected.Proxied != desired.Proxied || selected.Type != desired.Type || selected.TTL != desired.TTL) {
		selected, err = a.upsertDNSWithRecovery(ctx, provider, zone, desired)
		if err != nil {
			if code, message, denied := cloudflarePermissionError(err); denied {
				return a.markDomainDNSFailure(ctx, domainID, code, message)
			}
			return err
		}
		managed = true
	} else if action == "sync" {
		managed = true
		adopted = false
	}
	if selected.ID == "" {
		return errors.New("provider returned an empty DNS record id")
	}
	if err := a.saveDNSRecord(ctx, userID, domainID, zone, selected, managed, adopted); err != nil {
		return err
	}
	now := nowString()
	nextStatus := "pending_router"
	phase, step := "router", "awaiting_snapshot"
	if httpsMode != "http_only" {
		nextStatus = "pending_certificate"
		phase, step = "certificate", "awaiting_acme"
		if _, err := a.DB.ExecContext(ctx, `INSERT OR IGNORE INTO certificates(id,domain_binding_id,provider,status,updated_at) VALUES(?,?,?,?,?)`, id.New(), domainID, "acme", "pending", now); err != nil {
			return err
		}
	}
	_, err = a.DB.ExecContext(ctx, `UPDATE domain_bindings SET zone_id=?,status=?,updated_at=? WHERE id=? AND user_id=?`, zone.ID, nextStatus, now, domainID, userID)
	if err != nil {
		return err
	}
	if _, err = a.DB.ExecContext(ctx, `UPDATE operations SET status='running',phase=?,step=?,updated_at=? WHERE resource_type='domain' AND resource_id=? AND status IN ('pending','running')`, phase, step, now, domainID); err != nil {
		return err
	}
	if httpsMode == "http_only" {
		return a.EnqueueRouterSnapshot(ctx)
	}
	if a.Config.ACMEEnabled {
		_, err = a.Jobs.Enqueue(ctx, "acme_certificate_issue", "domain", domainID, "domain:"+domainID+":acme", map[string]interface{}{"user_id": userID, "domain_id": domainID}, nil)
	}
	return err
}

func (a *App) issueCertificate(ctx context.Context, job jobs.Job) error {
	userID := payloadString(job.Payload, "user_id")
	domainID := payloadString(job.Payload, "domain_id")
	if userID == "" || domainID == "" {
		return errors.New("ACME job payload is invalid")
	}
	var domain string
	if err := a.DB.QueryRowContext(ctx, `SELECT normalized_domain FROM domain_bindings WHERE id=? AND user_id=? AND status NOT IN ('deleted','deleting')`, domainID, userID).Scan(&domain); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if !a.Config.ACMEEnabled || a.ACMEProvider == nil {
		return &jobs.BlockedError{Err: acme.ErrUnavailable}
	}
	var ciphertext, nonce []byte
	if err := a.DB.QueryRowContext(ctx, `SELECT c.ciphertext,c.nonce FROM cloudflare_credentials c JOIN users u ON u.active_cloudflare_token_version=c.token_version AND u.id=c.user_id WHERE c.user_id=? AND c.status='valid'`, userID).Scan(&ciphertext, &nonce); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &jobs.BlockedError{Err: errors.New("ACME is waiting for a verified Cloudflare Token")}
		}
		return err
	}
	token, err := a.Crypto.Decrypt(ciphertext, nonce, "user:"+userID+":cloudflare_token:v1")
	if err != nil {
		return err
	}
	certificate, err := a.ACMEProvider.IssueDNS01(acme.WithCloudflareToken(ctx, string(token)), domain)
	if err != nil {
		return err
	}
	if len(certificate.CertPEM) == 0 || len(certificate.PrivateKey) == 0 || len(a.Crypto.CertificateKey) != 32 {
		return errors.New("ACME provider returned incomplete certificate material")
	}
	certificateDir := filepath.Join(a.Config.DataDir, "certificates", domainID)
	if err := os.MkdirAll(certificateDir, 0o700); err != nil {
		return err
	}
	certPath := filepath.Join(certificateDir, "cert.pem")
	chainPath := filepath.Join(certificateDir, "chain.pem")
	fullChain := append(append([]byte(nil), certificate.CertPEM...), certificate.ChainPEM...)
	if err := writeAtomicPrivate(certPath, fullChain); err != nil {
		return err
	}
	if len(certificate.ChainPEM) > 0 {
		if err := writeAtomicPrivate(chainPath, certificate.ChainPEM); err != nil {
			return err
		}
	}
	privateCiphertext, privateNonce, err := crypto.EncryptWithKey(a.Crypto.CertificateKey, certificate.PrivateKey, "domain:"+domainID+":certificate_private_key:v1")
	if err != nil {
		return err
	}
	now := nowString()
	renewAfter := time.Time{}
	if !certificate.NotAfter.IsZero() {
		renewAfter = certificate.NotAfter.Add(-30 * 24 * time.Hour)
	}
	result, err := a.DB.ExecContext(ctx, `UPDATE certificates SET status='valid',not_before=?,not_after=?,renew_after=?,cert_path=?,private_key_ciphertext=?,private_key_nonce=?,wrapping_key_version=1,cert_hash=?,last_error_code=NULL,last_error_message=NULL,updated_at=? WHERE domain_binding_id=? AND provider='acme'`, nullableTime(certificate.NotBefore), nullableTime(certificate.NotAfter), nullableTime(renewAfter), certPath, privateCiphertext, privateNonce, sha256Hex(string(fullChain)), now, domainID)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return errors.New("ACME certificate row is missing")
	}
	if _, err := a.DB.ExecContext(ctx, `UPDATE domain_bindings SET status='pending_router',updated_at=? WHERE id=?`, now, domainID); err != nil {
		return err
	}
	if _, err := a.DB.ExecContext(ctx, `UPDATE operations SET phase='router',step='awaiting_snapshot',status='running',updated_at=? WHERE resource_type='domain' AND resource_id=? AND status IN ('pending','running')`, now, domainID); err != nil {
		return err
	}
	return a.EnqueueRouterSnapshot(ctx)
}

func nullableTime(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func writeAtomicPrivate(path string, content []byte) error {
	tmp := path + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	defer os.Remove(tmp)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// upsertDNSWithRecovery handles the ambiguous window where Cloudflare may have
// committed a record but the HTTP response was lost. A follow-up read turns an
// already-applied desired record into success instead of creating duplicates on
// every retry; unrelated errors are returned unchanged for the job backoff.
func (a *App) upsertDNSWithRecovery(ctx context.Context, provider cloudflare.Provider, zone cloudflare.Zone, desired cloudflare.Record) (cloudflare.Record, error) {
	selected, err := provider.UpsertDNS(ctx, zone, desired)
	if err == nil {
		return selected, nil
	}
	actual, readErr := provider.ListDNS(ctx, zone, desired.Name, desired.Type)
	if readErr == nil {
		for _, record := range actual {
			if strings.EqualFold(record.Type, desired.Type) && strings.EqualFold(record.Name, desired.Name) && record.Content == desired.Content && record.TTL == desired.TTL && record.Proxied == desired.Proxied {
				return record, nil
			}
		}
	}
	return cloudflare.Record{}, err
}

func (a *App) saveDNSRecord(ctx context.Context, userID, domainID string, zone cloudflare.Zone, record cloudflare.Record, managed, adopted bool) error {
	now := nowString()
	_, err := a.DB.ExecContext(ctx, `DELETE FROM dns_records WHERE domain_binding_id=?`, domainID)
	if err != nil {
		return err
	}
	_, err = a.DB.ExecContext(ctx, `INSERT INTO dns_records(id,user_id,domain_binding_id,type,name,normalized_name,content,ttl,proxied,zone_id,record_id,managed_by_panel,adopted,locked,sync_status,last_synced_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id.New(), userID, domainID, record.Type, record.Name, strings.ToLower(strings.TrimSuffix(record.Name, ".")), record.Content, record.TTL, boolInt(record.Proxied), zone.ID, record.ID, boolInt(managed), boolInt(adopted), 0, "synced", now)
	return err
}

func (a *App) markDomainDNSFailure(ctx context.Context, domainID, code, message string) error {
	now := nowString()
	_, err := a.DB.ExecContext(ctx, `UPDATE domain_bindings SET status='dns_error',updated_at=? WHERE id=?`, now, domainID)
	if err == nil {
		_, err = a.DB.ExecContext(ctx, `UPDATE operations SET status='failed',phase='dns',step='failed',error_code=?,error_message=?,updated_at=?,completed_at=? WHERE resource_type='domain' AND resource_id=? AND status IN ('pending','running')`, code, message, now, now, domainID)
	}
	return err
}

func (a *App) markDomainDNSCanceled(ctx context.Context, domainID string) error {
	now := nowString()
	if _, err := a.DB.ExecContext(ctx, `UPDATE domain_bindings SET status='pending_dns',updated_at=? WHERE id=?`, now, domainID); err != nil {
		return err
	}
	_, err := a.DB.ExecContext(ctx, `UPDATE operations SET status='canceled',phase='dns',step='canceled',error_code='DNS_OPERATION_CANCELED',error_message='Cloudflare DNS operation was canceled.',updated_at=?,completed_at=? WHERE resource_type='domain' AND resource_id=? AND status IN ('pending','running')`, now, now, domainID)
	return err
}

func payloadString(payload map[string]interface{}, key string) string {
	value, _ := payload[key].(string)
	return value
}

func payloadInt64(payload map[string]interface{}, key string) int64 {
	switch value := payload[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	}
	return 0
}

func payloadBool(payload map[string]interface{}, key string) bool {
	switch value := payload[key].(type) {
	case bool:
		return value
	case string:
		return value == "true"
	default:
		return false
	}
}

func (a *App) cloudflareProvider(token string) *cloudflare.HTTPProvider {
	provider := cloudflare.NewAt(token, a.Config.CloudflareAPIBaseURL)
	if a.CloudflareHTTPClient != nil {
		provider.Client = a.CloudflareHTTPClient
	}
	return provider
}

func cloudflarePermissionError(err error) (code, message string, denied bool) {
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || (apiErr.Status != 401 && apiErr.Status != 403) {
		return "", "", false
	}
	return "CLOUDFLARE_PERMISSION_DENIED", "Cloudflare denied the required Zone or DNS permission.", true
}
