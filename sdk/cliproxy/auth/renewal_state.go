package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// RenewalStateRecord persists the in-memory renewal decision of one auth in its
// auth-level cooldown state record, so a restart does not forget a refresh
// grant that upstream already rejected. Token values are never stored: each
// rejected-token marker is kept as a SHA-256 fingerprint and restored only
// while the credential still carries the token it fingerprints.
//
// Only a sign-in decision is persisted with its RefreshError, and that error
// keeps only an allowlisted code, the HTTP status and retryability: upstream
// diagnostics never reach disk, and the message is rebuilt on restore.
type RenewalStateRecord struct {
	RequiresSignIn bool      `json:"requires_sign_in,omitempty"`
	RefreshError   *Error    `json:"refresh_error,omitempty"`
	RenewalEventAt time.Time `json:"renewal_event_at,omitempty"`
	// GrantSHA256 fingerprints the credential tokens the decision was made for.
	GrantSHA256                     string `json:"grant_sha256,omitempty"`
	RejectedAccessTokenSHA256       string `json:"rejected_access_token_sha256,omitempty"`
	RejectedSIWCAccessTokenSHA256   string `json:"rejected_siwc_access_token_sha256,omitempty"`
	RejectedRefreshTokenSHA256      string `json:"rejected_refresh_token_sha256,omitempty"`
	RejectedSIWCRefreshTokenSHA256  string `json:"rejected_siwc_refresh_token_sha256,omitempty"`
	RenewalWarnedRefreshTokenSHA256 string `json:"renewal_warned_refresh_token_sha256,omitempty"`
}

func renewalFingerprint(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// renewalGrantSHA256 fingerprints the token fields secretGrantChanged compares.
func renewalGrantSHA256(auth *Auth) string {
	if auth == nil {
		return ""
	}
	idToken := authMetadataString(auth, "id_token")
	if idToken == "" {
		idToken = authMetadataString(auth, "idToken")
	}
	apiKey := ""
	if auth.Attributes != nil {
		apiKey = auth.Attributes[AttributeAPIKey]
	}
	if apiKey == "" {
		apiKey = authMetadataString(auth, "api_key")
	}
	return renewalFingerprint(strings.Join([]string{
		authAccessToken(auth),
		authOuterAccessToken(auth),
		authRefreshToken(auth),
		idToken,
		apiKey,
		authSIWCTokenField(auth, "access_token"),
		authSIWCTokenField(auth, "refresh_token"),
		authSIWCTokenField(auth, "id_token"),
		authSIWCTokenField(auth, "client_id"),
	}, "\x00"))
}

func authHasRenewalState(auth *Auth) bool {
	return auth != nil && (auth.RequiresSignIn || auth.RefreshError != nil || !auth.RenewalEventAt.IsZero() ||
		auth.RejectedAccessToken != "" || auth.RejectedSIWCAccessToken != "" ||
		auth.RejectedRefreshToken != "" || auth.RejectedSIWCRefreshToken != "" ||
		auth.RenewalWarnedRefreshToken != "")
}

// persistedRenewalErrorCode returns code when it is a known safe OAuth or
// renewal code, and "refresh_failed" otherwise.
func persistedRenewalErrorCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if isKnownSafeOAuthErrorCode(code) {
		return code
	}
	return "refresh_failed"
}

// restoredRenewalErrorMessage is the local text a restored RefreshError carries.
func restoredRenewalErrorMessage(code string) string {
	return "token refresh rejected (" + code + "); sign in again"
}

// renewalStateRecordOf returns the persisted form of the auth's renewal state,
// or nil when there is nothing to remember. A transient refresh failure is not
// persisted: its retry schedule is not either, so it would outlive its meaning.
func renewalStateRecordOf(auth *Auth) *RenewalStateRecord {
	if auth == nil {
		return nil
	}
	record := &RenewalStateRecord{
		RejectedAccessTokenSHA256:      renewalFingerprint(auth.RejectedAccessToken),
		RejectedSIWCAccessTokenSHA256:  renewalFingerprint(auth.RejectedSIWCAccessToken),
		RejectedRefreshTokenSHA256:     renewalFingerprint(auth.RejectedRefreshToken),
		RejectedSIWCRefreshTokenSHA256: renewalFingerprint(auth.RejectedSIWCRefreshToken),
	}
	if auth.RequiresSignIn {
		record.RequiresSignIn = true
		record.RenewalEventAt = auth.RenewalEventAt
		record.RenewalWarnedRefreshTokenSHA256 = renewalFingerprint(auth.RenewalWarnedRefreshToken)
		if auth.RefreshError != nil {
			record.RefreshError = &Error{
				Code:       persistedRenewalErrorCode(auth.RefreshError.Code),
				Retryable:  auth.RefreshError.Retryable,
				HTTPStatus: auth.RefreshError.HTTPStatus,
			}
		}
	}
	if !record.RequiresSignIn && record.RejectedAccessTokenSHA256 == "" && record.RejectedSIWCAccessTokenSHA256 == "" &&
		record.RejectedRefreshTokenSHA256 == "" && record.RejectedSIWCRefreshTokenSHA256 == "" {
		return nil
	}
	record.GrantSHA256 = renewalGrantSHA256(auth)
	return record
}

func renewalStateRecordEqual(a, b *RenewalStateRecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.RequiresSignIn == b.RequiresSignIn &&
		cooldownErrorEqual(a.RefreshError, b.RefreshError) &&
		a.RenewalEventAt.Equal(b.RenewalEventAt) &&
		a.GrantSHA256 == b.GrantSHA256 &&
		a.RejectedAccessTokenSHA256 == b.RejectedAccessTokenSHA256 &&
		a.RejectedSIWCAccessTokenSHA256 == b.RejectedSIWCAccessTokenSHA256 &&
		a.RejectedRefreshTokenSHA256 == b.RejectedRefreshTokenSHA256 &&
		a.RejectedSIWCRefreshTokenSHA256 == b.RejectedSIWCRefreshTokenSHA256 &&
		a.RenewalWarnedRefreshTokenSHA256 == b.RenewalWarnedRefreshTokenSHA256
}

// attachRenewalStateLocked adds the auth's renewal state to its auth-level
// record, appending a renewal-only record (zero NextRetryAfter) when the auth
// is not cooling. Restore ignores such records for cooldown purposes.
func attachRenewalStateLocked(auth *Auth, records []CooldownStateRecord) []CooldownStateRecord {
	renewal := renewalStateRecordOf(auth)
	if renewal == nil || auth.ID == "" {
		return records
	}
	for i := range records {
		if records[i].Model == "" {
			records[i].Renewal = renewal
			return records
		}
	}
	return append(records, CooldownStateRecord{
		Provider: strings.TrimSpace(auth.Provider),
		AuthID:   auth.ID,
		AuthFile: cooldownAuthFile(auth),
		Status:   "renewal",
		Renewal:  renewal,
	})
}

// matchRenewalToken returns the candidate whose fingerprint is fingerprint.
func matchRenewalToken(fingerprint string, candidates ...string) string {
	if fingerprint == "" {
		return ""
	}
	for _, candidate := range candidates {
		if candidate != "" && renewalFingerprint(candidate) == fingerprint {
			return candidate
		}
	}
	return ""
}

// restoreRenewalState restores a persisted renewal decision into an auth that
// holds none. A marker is restored only when the credential still carries the
// token it fingerprints. The sign-in decision itself is restored when the
// credential is unchanged, or, like a credential replacement in memory, when a
// rejected refresh token is still present. Status and availability are not
// touched: the access-token eligibility rules decide whether it can serve.
func restoreRenewalState(auth *Auth, saved *RenewalStateRecord) bool {
	if auth == nil || saved == nil || authHasRenewalState(auth) {
		return false
	}
	outerRT := authRefreshToken(auth)
	siwcRT := authSIWCTokenField(auth, "refresh_token")
	siwcAT := authSIWCTokenField(auth, "access_token")
	rejectedRT := matchRenewalToken(saved.RejectedRefreshTokenSHA256, outerRT)
	rejectedSIWCRT := matchRenewalToken(saved.RejectedSIWCRefreshTokenSHA256, siwcRT)
	rejectedAT := matchRenewalToken(saved.RejectedAccessTokenSHA256, authAccessToken(auth), authOuterAccessToken(auth), siwcAT)
	rejectedSIWCAT := matchRenewalToken(saved.RejectedSIWCAccessTokenSHA256, siwcAT)

	grantUnchanged := saved.GrantSHA256 != "" && saved.GrantSHA256 == renewalGrantSHA256(auth)
	keepDecision := grantUnchanged || (saved.RequiresSignIn && (rejectedRT != "" || rejectedSIWCRT != ""))
	if keepDecision {
		auth.RequiresSignIn = saved.RequiresSignIn
		if saved.RequiresSignIn && saved.RefreshError != nil {
			code := persistedRenewalErrorCode(saved.RefreshError.Code)
			auth.RefreshError = &Error{
				Code:       code,
				Message:    restoredRenewalErrorMessage(code),
				Retryable:  saved.RefreshError.Retryable,
				HTTPStatus: saved.RefreshError.HTTPStatus,
			}
		}
		auth.RenewalEventAt = saved.RenewalEventAt
		auth.RejectedRefreshToken = rejectedRT
		auth.RejectedSIWCRefreshToken = rejectedSIWCRT
		auth.RenewalWarnedRefreshToken = matchRenewalToken(saved.RenewalWarnedRefreshTokenSHA256, rejectedRT+"|"+rejectedSIWCRT, "terminal")
	}
	auth.RejectedAccessToken = rejectedAT
	auth.RejectedSIWCAccessToken = rejectedSIWCAT
	if !authHasRenewalState(auth) {
		return false
	}
	auth.Generation++
	return true
}

// renewalRestoreFence identifies the runtime auth a renewal restore may write:
// the same published object at the same generation as when the load began.
type renewalRestoreFence struct {
	auth       *Auth
	generation uint64
}

// renewalRestoreFencesLocked captures the fence for every registered auth.
// Callers hold m.mu.
func (m *Manager) renewalRestoreFencesLocked() map[string]renewalRestoreFence {
	fences := make(map[string]renewalRestoreFence, len(m.auths))
	for id, auth := range m.auths {
		if auth != nil {
			fences[id] = renewalRestoreFence{auth: auth, generation: auth.Generation}
		}
	}
	return fences
}

// restoreRenewalStateLocked restores a loaded renewal record. An auth that
// changed while the records were loading is skipped: the loaded copy may be
// older than its current state. A record whose auth is not registered yet is
// kept so a later registration can use it and later saves keep it on disk.
// Callers hold m.mu.
func (m *Manager) restoreRenewalStateLocked(record CooldownStateRecord, fences map[string]renewalRestoreFence) bool {
	authID := strings.TrimSpace(record.AuthID)
	if record.Renewal == nil || authID == "" || strings.TrimSpace(record.Model) != "" {
		return false
	}
	auth := m.auths[authID]
	if auth == nil {
		if _, known := fences[authID]; !known {
			if m.pendingRenewalStates == nil {
				m.pendingRenewalStates = make(map[string]pendingRenewalState)
			}
			m.pendingRenewalStates[authID] = pendingRenewalState{provider: strings.TrimSpace(record.Provider), renewal: record.Renewal}
		}
		return false
	}
	if fence, ok := fences[authID]; !ok || fence.auth != auth || fence.generation != auth.Generation {
		return false
	}
	return restoreRenewalState(auth, record.Renewal)
}

// pendingRenewalState is a loaded renewal record whose auth is not registered.
type pendingRenewalState struct {
	provider string
	renewal  *RenewalStateRecord
}

// pendingRenewalRecordsLocked returns renewal-only records for pending states
// so saves keep them. Callers hold m.mu.
func (m *Manager) pendingRenewalRecordsLocked() []CooldownStateRecord {
	records := make([]CooldownStateRecord, 0, len(m.pendingRenewalStates))
	for authID, pending := range m.pendingRenewalStates {
		if m.auths[authID] != nil {
			continue
		}
		records = append(records, CooldownStateRecord{Provider: pending.provider, AuthID: authID, Status: "renewal", Renewal: pending.renewal})
	}
	return records
}

// takePendingRenewalStateLocked restores and forgets the pending renewal state
// of a newly registered auth. Callers hold m.mu.
func (m *Manager) takePendingRenewalStateLocked(auth *Auth) {
	if auth == nil {
		return
	}
	pending, ok := m.pendingRenewalStates[auth.ID]
	if !ok {
		return
	}
	delete(m.pendingRenewalStates, auth.ID)
	restoreRenewalState(auth, pending.renewal)
}

// renewalSavedState holds the renewal state of the last successful cooldown
// state save, keyed by auth ID. Its own lock lets a caller see that nothing
// changed without waiting behind a save in progress.
type renewalSavedState struct {
	mu      sync.Mutex
	records map[string]*RenewalStateRecord
}

// noteRenewalStatesSaved records the renewal state written by a successful save.
func (m *Manager) noteRenewalStatesSaved(records []CooldownStateRecord) {
	saved := make(map[string]*RenewalStateRecord)
	for _, record := range records {
		if record.Renewal != nil {
			saved[record.AuthID] = record.Renewal
		}
	}
	m.renewalSaved.mu.Lock()
	m.renewalSaved.records = saved
	m.renewalSaved.mu.Unlock()
}

// persistRenewalStateIfChanged saves runtime state when the auth's renewal
// state differs from the last saved copy, including when it was cleared or the
// auth was removed. Callers must not hold m.mu or configCooldownMu.
func (m *Manager) persistRenewalStateIfChanged(authID string) {
	if m == nil || authID == "" {
		return
	}
	m.mu.RLock()
	store := m.cooldownStore
	current := renewalStateRecordOf(m.auths[authID])
	m.mu.RUnlock()
	if store == nil {
		return
	}
	m.renewalSaved.mu.Lock()
	unchanged := renewalStateRecordEqual(m.renewalSaved.records[authID], current)
	m.renewalSaved.mu.Unlock()
	if unchanged {
		return
	}
	m.persistCooldownStates(context.Background())
}
