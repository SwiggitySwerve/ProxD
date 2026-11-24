package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
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

// renewalStateRecordEqual compares records built from runtime state.
func renewalStateRecordEqual(a, b *RenewalStateRecord) bool {
	return reflect.DeepEqual(a, b)
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
	if auth == nil || saved == nil || renewalStateRecordOf(auth) != nil {
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
	return renewalStateRecordOf(auth) != nil
}

// renewalRestoreBaseline is what a loaded renewal record may be restored over:
// the credential's tokens and its renewal state when the load began.
type renewalRestoreBaseline struct {
	grant   string
	renewal *RenewalStateRecord
}

// renewalRestoreBaselinesLocked captures the baseline of every registered auth.
// Callers hold m.mu.
func (m *Manager) renewalRestoreBaselinesLocked() map[string]renewalRestoreBaseline {
	baselines := make(map[string]renewalRestoreBaseline, len(m.auths))
	for id, auth := range m.auths {
		if auth != nil {
			baselines[id] = renewalRestoreBaseline{grant: renewalGrantSHA256(auth), renewal: renewalStateRecordOf(auth)}
		}
	}
	return baselines
}

// restoreRenewalStateLocked restores a loaded renewal record into a registered
// auth whose tokens and renewal state did not change while the records were
// loading: otherwise the loaded copy may be older than the current state.
// Callers hold m.mu.
func (m *Manager) restoreRenewalStateLocked(record CooldownStateRecord, baselines map[string]renewalRestoreBaseline) bool {
	authID := strings.TrimSpace(record.AuthID)
	auth := m.auths[authID]
	baseline, ok := baselines[authID]
	if auth == nil || !ok || strings.TrimSpace(record.Model) != "" || baseline.grant != renewalGrantSHA256(auth) ||
		!renewalStateRecordEqual(baseline.renewal, renewalStateRecordOf(auth)) || !restoreRenewalState(auth, record.Renewal) {
		return false
	}
	auth.Generation++
	return true
}

// restoreRenewalStateFromStore restores a newly registered auth's renewal state
// from its own state file, when the store can read one file. Callers must not
// hold m.mu.
func (m *Manager) restoreRenewalStateFromStore(ctx context.Context, auth *Auth) {
	m.mu.RLock()
	store, ok := m.cooldownStore.(cooldownStateScopedStore)
	m.mu.RUnlock()
	if !ok || auth == nil {
		return
	}
	records, errLoad := store.LoadAuth(ctx, CooldownStateRecord{AuthID: auth.ID, AuthFile: cooldownAuthFile(auth)})
	if errLoad != nil {
		return
	}
	for _, record := range records {
		if record.AuthID == auth.ID && strings.TrimSpace(record.Model) == "" && restoreRenewalState(auth, record.Renewal) {
			return
		}
	}
}

// cooldownStateScopedStore saves only the state files of registered or removed
// credentials and reads one credential's state file.
type cooldownStateScopedStore interface {
	SaveScoped(ctx context.Context, records, owners []CooldownStateRecord) error
	LoadAuth(ctx context.Context, owner CooldownStateRecord) ([]CooldownStateRecord, error)
}

// authCannotObtainAccessToken reports that the auth holds refresh grants, all
// known rejected, and no other credential (API key or Meta device token) from
// which an access token could be obtained.
func authCannotObtainAccessToken(auth *Auth) bool {
	if auth == nil || (authRefreshToken(auth) == "" && authSIWCTokenField(auth, "refresh_token") == "") {
		return false
	}
	if authMetadataString(auth, "api_key") != "" || (auth.Attributes != nil && strings.TrimSpace(auth.Attributes[AttributeAPIKey]) != "") ||
		(strings.EqualFold(strings.TrimSpace(auth.Provider), "meta") &&
			(authMetadataString(auth, "dca_token") != "" || strings.TrimSpace(auth.Attributes["dca_token"]) != "")) {
		return false
	}
	return authHasUnchangedRejectedRefreshToken(auth)
}

// withoutRefreshDiagnostics keeps refresh failure text out of a persisted
// auth-level cooldown record: while a refresh failure is recorded, its error
// message and a reason copied from it carry local text instead.
func withoutRefreshDiagnostics(auth *Auth, record CooldownStateRecord) CooldownStateRecord {
	if auth.RefreshError == nil {
		return record
	}
	const local = "credential refresh failed"
	if record.Reason == auth.RefreshError.Message || (auth.LastError != nil && record.Reason == auth.LastError.Message) {
		record.Reason = local
	}
	if record.LastError != nil {
		record.LastError.Message = local
	}
	return record
}
