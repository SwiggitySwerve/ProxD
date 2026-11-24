package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// RenewalStateRecord persists the in-memory renewal decision of one auth in its
// auth-level cooldown state record, so a restart does not forget a refresh
// grant that upstream already rejected. Token values are never stored: each
// rejected-token marker is kept as a SHA-256 fingerprint and restored only
// while the credential still carries the token it fingerprints.
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

// renewalStateRecordOf returns the persisted form of the auth's renewal state,
// or nil when there is nothing to remember.
func renewalStateRecordOf(auth *Auth) *RenewalStateRecord {
	if !authHasRenewalState(auth) {
		return nil
	}
	var refreshErr *Error
	if auth.RefreshError != nil {
		refreshErr = &Error{
			Code:       auth.RefreshError.Code,
			Message:    sanitizeRenewalMessage(auth.RefreshError.Message),
			Retryable:  auth.RefreshError.Retryable,
			HTTPStatus: auth.RefreshError.HTTPStatus,
		}
	}
	return &RenewalStateRecord{
		RequiresSignIn:                  auth.RequiresSignIn,
		RefreshError:                    refreshErr,
		RenewalEventAt:                  auth.RenewalEventAt,
		GrantSHA256:                     renewalGrantSHA256(auth),
		RejectedAccessTokenSHA256:       renewalFingerprint(auth.RejectedAccessToken),
		RejectedSIWCAccessTokenSHA256:   renewalFingerprint(auth.RejectedSIWCAccessToken),
		RejectedRefreshTokenSHA256:      renewalFingerprint(auth.RejectedRefreshToken),
		RejectedSIWCRefreshTokenSHA256:  renewalFingerprint(auth.RejectedSIWCRefreshToken),
		RenewalWarnedRefreshTokenSHA256: renewalFingerprint(auth.RenewalWarnedRefreshToken),
	}
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

// restoreRenewalStateLocked restores a persisted renewal decision into an auth
// that holds none. A marker is restored only when the credential still carries
// the token it fingerprints. The sign-in decision itself is restored when the
// credential is unchanged, or, like a credential replacement in memory, when a
// rejected refresh token is still present. Status and availability are not
// touched: the access-token eligibility rules decide whether it can serve.
func (m *Manager) restoreRenewalStateLocked(record CooldownStateRecord) bool {
	saved := record.Renewal
	if saved == nil || strings.TrimSpace(record.Model) != "" {
		return false
	}
	auth := m.auths[strings.TrimSpace(record.AuthID)]
	if auth == nil || authHasRenewalState(auth) {
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
		auth.RefreshError = cloneError(saved.RefreshError)
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

// noteRenewalStatesSaved records the renewal state written by a successful
// save. Callers hold configCooldownMu.
func (m *Manager) noteRenewalStatesSaved(records []CooldownStateRecord) {
	saved := make(map[string]*RenewalStateRecord)
	for _, record := range records {
		if record.Renewal != nil {
			saved[record.AuthID] = record.Renewal
		}
	}
	m.renewalStateSaved = saved
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
	m.configCooldownMu.Lock()
	defer m.configCooldownMu.Unlock()
	if renewalStateRecordEqual(m.renewalStateSaved[authID], current) {
		return
	}
	m.persistCooldownStatesLocked(context.Background())
}
