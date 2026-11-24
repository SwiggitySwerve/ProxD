package auth

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const claudeRefreshExpiredErr = `token refresh failed with status 400: {"error": "invalid_grant", "error_description": "Refresh token expired"}`

// renewalRestartHub is one hub process: a Manager whose runtime state store
// and credential files live in authDir, like the deployed file store.
type renewalRestartHub struct {
	authDir string
	store   *FileCooldownStateStore
}

func newRenewalRestartHub(t *testing.T) *renewalRestartHub {
	t.Helper()
	authDir := t.TempDir()
	return &renewalRestartHub{authDir: authDir, store: NewFileCooldownStateStoreWithAuthDir(authDir, authDir)}
}

func (h *renewalRestartHub) path(id string) string { return filepath.Join(h.authDir, id) }

// writeCredential writes the credential file the way a sign-in or a token save does.
func (h *renewalRestartHub) writeCredential(t *testing.T, id string, metadata map[string]any) {
	t.Helper()
	data, errMarshal := json.Marshal(metadata)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errMkdir := os.MkdirAll(filepath.Dir(h.path(id)), 0o700); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	if errWrite := os.WriteFile(h.path(id), data, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
}

// loadCredential reads the credential file back as file synthesis does: status active.
func (h *renewalRestartHub) loadCredential(t *testing.T, id, provider string) *Auth {
	t.Helper()
	data, errRead := os.ReadFile(h.path(id))
	if errRead != nil {
		t.Fatal(errRead)
	}
	metadata := map[string]any{}
	if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	return &Auth{
		ID:         id,
		FileName:   id,
		Provider:   provider,
		Status:     StatusActive,
		Attributes: map[string]string{"path": h.path(id), "source": h.path(id)},
		Metadata:   metadata,
	}
}

// renewalFileAuthStore lists the hub's credential files, like the file token store.
type renewalFileAuthStore struct {
	t        *testing.T
	hub      *renewalRestartHub
	provider string
	ids      []string
	onSave   func()
}

func (s *renewalFileAuthStore) List(context.Context) ([]*Auth, error) {
	auths := make([]*Auth, 0, len(s.ids))
	for _, id := range s.ids {
		auths = append(auths, s.hub.loadCredential(s.t, id, s.provider))
	}
	return auths, nil
}

func (s *renewalFileAuthStore) Save(context.Context, *Auth) (string, error) {
	if s.onSave != nil {
		s.onSave()
	}
	return "", nil
}

func (s *renewalFileAuthStore) Delete(context.Context, string) error { return nil }

// load boots a fresh Manager over the credential files and state store, without
// restoring state yet.
func (h *renewalRestartHub) load(t *testing.T, store CooldownStateStore, exec ProviderExecutor, provider string, ids ...string) *Manager {
	t.Helper()
	m := NewManager(&renewalFileAuthStore{t: t, hub: h, provider: provider, ids: ids}, &FillFirstSelector{}, nil)
	m.SetCooldownStateStore(store)
	m.RegisterExecutor(exec)
	if errLoad := m.Load(context.Background()); errLoad != nil {
		t.Fatalf("Load: %v", errLoad)
	}
	return m
}

// start boots a fresh Manager as service startup does: load the credential
// files, then restore the persisted runtime state.
func (h *renewalRestartHub) start(t *testing.T, exec ProviderExecutor, provider string, ids ...string) *Manager {
	t.Helper()
	m := h.load(t, h.store, exec, provider, ids...)
	if errRestore := m.RestoreCooldownStates(context.Background()); errRestore != nil {
		t.Fatalf("RestoreCooldownStates: %v", errRestore)
	}
	return m
}

// saveCredential writes the manager's current tokens back to the credential file.
func (h *renewalRestartHub) saveCredential(t *testing.T, m *Manager, id string) {
	t.Helper()
	current, ok := m.GetByID(id)
	if !ok {
		t.Fatalf("auth %s missing", id)
	}
	h.writeCredential(t, id, current.Metadata)
}

func (h *renewalRestartHub) renewalRecord(t *testing.T, id string) *RenewalStateRecord {
	t.Helper()
	records, errLoad := h.store.Load(context.Background())
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	for _, record := range records {
		if record.AuthID == id && record.Model == "" && record.Renewal != nil {
			if !record.NextRetryAfter.IsZero() {
				t.Fatalf("renewal record for %s carries a cooldown: %+v", id, record)
			}
			return record.Renewal
		}
	}
	return nil
}

// assertNoTokensPersisted fails when a token value appears in any runtime state file.
func (h *renewalRestartHub) assertNoTokensPersisted(t *testing.T, tokens ...string) {
	t.Helper()
	found := 0
	errWalk := filepath.WalkDir(h.authDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".cds" {
			return err
		}
		found++
		data, errRead := os.ReadFile(path)
		if errRead != nil {
			return errRead
		}
		for _, token := range tokens {
			if strings.Contains(string(data), token) {
				t.Fatalf("%s contains token value %q:\n%s", path, token, data)
			}
		}
		return nil
	})
	if errWalk != nil {
		t.Fatal(errWalk)
	}
	if found == 0 {
		t.Fatal("no runtime state file was written")
	}
}

func registerRenewalTestModel(t *testing.T, provider string, ids ...string) string {
	t.Helper()
	model := "renewal-restart-model"
	reg := registry.GetGlobalRegistry()
	for _, id := range ids {
		reg.RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
	}
	t.Cleanup(func() {
		for _, id := range ids {
			reg.UnregisterClient(id)
		}
	})
	return model
}

func assertSameRenewalState(t *testing.T, before, after *Auth) {
	t.Helper()
	if after.RequiresSignIn != before.RequiresSignIn {
		t.Fatalf("RequiresSignIn after restart = %v, want %v", after.RequiresSignIn, before.RequiresSignIn)
	}
	assertRestoredRefreshError(t, before.RefreshError, after.RefreshError)
	if !after.RenewalEventAt.Equal(before.RenewalEventAt) {
		t.Fatalf("RenewalEventAt after restart = %v, want %v", after.RenewalEventAt, before.RenewalEventAt)
	}
	if after.RejectedAccessToken != before.RejectedAccessToken || after.RejectedSIWCAccessToken != before.RejectedSIWCAccessToken ||
		after.RejectedRefreshToken != before.RejectedRefreshToken || after.RejectedSIWCRefreshToken != before.RejectedSIWCRefreshToken ||
		after.RenewalWarnedRefreshToken != before.RenewalWarnedRefreshToken {
		t.Fatalf("rejection markers after restart = %q/%q/%q/%q/%q, want %q/%q/%q/%q/%q",
			after.RejectedAccessToken, after.RejectedSIWCAccessToken, after.RejectedRefreshToken, after.RejectedSIWCRefreshToken, after.RenewalWarnedRefreshToken,
			before.RejectedAccessToken, before.RejectedSIWCAccessToken, before.RejectedRefreshToken, before.RejectedSIWCRefreshToken, before.RenewalWarnedRefreshToken)
	}
}

// assertRestoredRefreshError checks a restored RefreshError: same code, status
// and retryability, with the local message instead of upstream diagnostics.
func assertRestoredRefreshError(t *testing.T, before, after *Error) {
	t.Helper()
	if before == nil || after == nil {
		if before != after {
			t.Fatalf("RefreshError after restart = %+v, want %+v", after, before)
		}
		return
	}
	code := persistedRenewalErrorCode(before.Code)
	if after.Code != code || after.HTTPStatus != before.HTTPStatus || after.Retryable != before.Retryable || after.Message != restoredRenewalErrorMessage(code) {
		t.Fatalf("RefreshError after restart = %+v, want code %q status %d retryable %v with the local message", after, code, before.HTTPStatus, before.Retryable)
	}
}

func authHasRenewalState(auth *Auth) bool {
	return auth != nil && (auth.RequiresSignIn || auth.RefreshError != nil || !auth.RenewalEventAt.IsZero() ||
		auth.RejectedAccessToken != "" || auth.RejectedSIWCAccessToken != "" ||
		auth.RejectedRefreshToken != "" || auth.RejectedSIWCRefreshToken != "" ||
		auth.RenewalWarnedRefreshToken != "")
}

func assertNoRenewalState(t *testing.T, auth *Auth) {
	t.Helper()
	if authHasRenewalState(auth) {
		t.Fatalf("renewal state not cleared: RequiresSignIn=%v RefreshError=%+v EventAt=%v markers=%q/%q/%q/%q/%q",
			auth.RequiresSignIn, auth.RefreshError, auth.RenewalEventAt, auth.RejectedAccessToken, auth.RejectedSIWCAccessToken,
			auth.RejectedRefreshToken, auth.RejectedSIWCRefreshToken, auth.RenewalWarnedRefreshToken)
	}
}

func getAuth(t *testing.T, m *Manager, id string) *Auth {
	t.Helper()
	auth, ok := m.GetByID(id)
	if !ok || auth == nil {
		t.Fatalf("auth %s missing", id)
	}
	return auth
}

// rotatingRefreshExecutor renews both tokens, as a successful upstream refresh does.
type rotatingRefreshExecutor struct {
	*unauthorizedRefreshExecutor
	accessToken  string
	refreshToken string
}

func (e *rotatingRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.mu.Lock()
	e.refreshCalls++
	e.mu.Unlock()
	auth.Metadata["access_token"] = e.accessToken
	auth.Metadata["refresh_token"] = e.refreshToken
	auth.Metadata["expired"] = time.Now().Add(8 * time.Hour).UTC().Format(time.RFC3339)
	return auth, nil
}

func TestRenewalRestart_RejectedRefreshWithWorkingAccessTokenKeepsServing(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-live.json"
	model := registerRenewalTestModel(t, "claude", id)
	hub.writeCredential(t, id, map[string]any{
		"type":          "claude",
		"access_token":  "claude-at-live-secret",
		"refresh_token": "claude-rt-dead-secret",
		"expired":       time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	})

	exec1 := &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}
	m1 := hub.start(t, exec1, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)
	if !before.RequiresSignIn || before.RefreshError == nil || before.RejectedRefreshToken != "claude-rt-dead-secret" {
		t.Fatalf("precondition: RequiresSignIn=%v RefreshError=%+v RejectedRefreshToken=%q", before.RequiresSignIn, before.RefreshError, before.RejectedRefreshToken)
	}
	if before.Unavailable || before.Status != StatusActive {
		t.Fatalf("precondition: working access token must keep serving, status=%s unavailable=%v", before.Status, before.Unavailable)
	}
	hub.assertNoTokensPersisted(t, "claude-at-live-secret", "claude-rt-dead-secret")

	exec2 := &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}
	m2 := hub.start(t, exec2, "claude", id)
	after := getAuth(t, m2, id)
	assertSameRenewalState(t, before, after)
	if after.Unavailable || after.Status != StatusActive {
		t.Fatalf("after restart status=%s unavailable=%v, want active and available", after.Status, after.Unavailable)
	}
	if after.RenewalStateAt(time.Now()) != RenewalStateSignInRequired {
		t.Fatalf("RenewalState after restart = %q, want %q", after.RenewalStateAt(time.Now()), RenewalStateSignInRequired)
	}

	// The dead refresh token is not submitted again after the restart.
	m2.refreshAuth(ctx, id)
	if calls := exec2.RefreshCalls(); calls != 0 {
		t.Fatalf("restarted hub retried the rejected refresh token %d times, want 0", calls)
	}
	resp, errExec := m2.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if errExec != nil {
		t.Fatalf("Execute after restart: %v", errExec)
	}
	if got := string(resp.Payload); got != id+":claude-at-live-secret" {
		t.Fatalf("Execute payload = %q, want the working access token", got)
	}
	if still := getAuth(t, m2, id); !still.RequiresSignIn || still.RefreshError == nil {
		t.Fatalf("inference after restart cleared renewal state: %v / %+v", still.RequiresSignIn, still.RefreshError)
	}
}

func TestRenewalRestart_RejectedAccessTokenStillSkipped(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	primary, backup := "aa-claude-revoked.json", "bb-claude-backup.json"
	model := registerRenewalTestModel(t, "claude", primary, backup)
	unexpired := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	hub.writeCredential(t, primary, map[string]any{"type": "claude", "access_token": "claude-at-revoked-secret", "refresh_token": "claude-rt-revoked-secret", "expired": unexpired})
	hub.writeCredential(t, backup, map[string]any{"type": "claude", "access_token": "claude-at-backup-secret", "refresh_token": "claude-rt-backup-secret", "expired": unexpired})

	newExec := func() *unauthorizedRefreshExecutor {
		return &unauthorizedRefreshExecutor{
			id:           "claude",
			tokenInvalid: map[string]struct{}{"claude-at-revoked-secret": {}},
			refreshErr:   errors.New(claudeRefreshExpiredErr),
		}
	}
	exec1 := newExec()
	m1 := hub.start(t, exec1, "claude", primary, backup)
	if _, errExec := m1.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); errExec != nil {
		t.Fatalf("Execute before restart: %v", errExec)
	}
	before := getAuth(t, m1, primary)
	if before.RejectedAccessToken != "claude-at-revoked-secret" || !before.RequiresSignIn {
		t.Fatalf("precondition: RejectedAccessToken=%q RequiresSignIn=%v", before.RejectedAccessToken, before.RequiresSignIn)
	}
	if !before.Unavailable || before.Status != StatusError {
		t.Fatalf("precondition: in-memory status=%s unavailable=%v, want error/unavailable", before.Status, before.Unavailable)
	}
	hub.assertNoTokensPersisted(t, "claude-at-revoked-secret", "claude-rt-revoked-secret", "claude-at-backup-secret", "claude-rt-backup-secret")
	if record := hub.renewalRecord(t, primary); record == nil || record.RejectedAccessTokenSHA256 == "" {
		t.Fatalf("persisted renewal record = %+v, want rejected access token fingerprint", record)
	}

	exec2 := newExec()
	m2 := hub.start(t, exec2, "claude", primary, backup)
	after := getAuth(t, m2, primary)
	assertSameRenewalState(t, before, after)
	// Status is not persisted (the persisted renewal record carries no
	// cooldown either); the access-token rules decide eligibility. The 401's
	// own model cooldown is restored separately by the existing cooldown rules,
	// so check the token rule without it.
	if after.Status != StatusActive {
		t.Fatalf("after restart status=%s, want the loaded active status", after.Status)
	}
	if after.HasValidAccessToken(time.Now()) {
		t.Fatal("the access token that returned 401 counts as valid after restart")
	}
	withoutCooldown := after.Clone()
	withoutCooldown.ModelStates = nil
	withoutCooldown.Unavailable = false
	if blocked, _, _ := isAuthBlockedForModel(withoutCooldown, model, time.Now()); !blocked {
		t.Fatal("the rejected access token does not block the credential after restart")
	}
	resp, errExec := m2.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if errExec != nil {
		t.Fatalf("Execute after restart: %v", errExec)
	}
	if got := string(resp.Payload); got != backup+":claude-at-backup-secret" {
		t.Fatalf("Execute payload = %q, want backup", got)
	}
	for _, call := range exec2.ExecuteCalls() {
		if call == primary {
			t.Fatalf("restarted hub sent a request with the rejected access token: calls=%v", exec2.ExecuteCalls())
		}
	}
	if calls := exec2.RefreshCalls(); calls != 0 {
		t.Fatalf("restarted hub retried the rejected refresh token %d times, want 0", calls)
	}
}

func TestRenewalRestart_PartialCodexRefreshKeepsSignIn(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "codex-siwc-partial.json"
	hub.writeCredential(t, id, map[string]any{
		"type":          "codex",
		"email":         "siwc@example.com",
		"access_token":  "outer-at-secret",
		"refresh_token": "outer-rt-secret",
		"expired":       time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"siwc": map[string]any{
			"access_token":  "siwc-at-secret",
			"refresh_token": "siwc-rt-secret",
			"client_id":     "cid-siwc",
			"expired":       time.Now().Add(45 * time.Minute).UTC().Format(time.RFC3339),
		},
	})

	exec1 := &unauthorizedRefreshExecutor{id: "codex"}
	m1 := hub.start(t, exec1, "codex", id)
	base := getAuth(t, m1, id)
	partialPatch := codex.NewCredentialRefreshPatch(base.Metadata, base.Metadata, false, true)
	partialPatch.SetUpstreamRefreshed(true)
	partialPatch.SetPartitionErrors(errors.New(`token refresh failed with status 401: {"error":{"code":"refresh_token_reused","message":"outer reused"}}`), nil)
	exec1.mu.Lock()
	exec1.refreshPatch = partialPatch
	exec1.mu.Unlock()
	if _, errPartial := m1.ForceRefreshAuth(ctx, id); errPartial != nil {
		t.Fatalf("ForceRefreshAuth (partial refresh): %v", errPartial)
	}
	before := getAuth(t, m1, id)
	if !before.RequiresSignIn || before.RejectedRefreshToken != "outer-rt-secret" || before.RefreshError == nil {
		t.Fatalf("precondition: RequiresSignIn=%v Rejected=%q RefreshError=%+v", before.RequiresSignIn, before.RejectedRefreshToken, before.RefreshError)
	}
	// The refreshed access token reaches the credential file before the restart.
	hub.saveCredential(t, m1, id)
	hub.assertNoTokensPersisted(t, "outer-at-secret", "outer-rt-secret", "siwc-at-secret", "siwc-rt-secret", "refreshed-access-token")

	exec2 := &unauthorizedRefreshExecutor{id: "codex", refreshErr: errors.New(`OpenAI OAuth token request failed (503): service unavailable`)}
	m2 := hub.start(t, exec2, "codex", id)
	after := getAuth(t, m2, id)
	assertSameRenewalState(t, before, after)
	if !isTerminalRefreshError(after, after.RefreshError) {
		t.Fatalf("RefreshError after restart = %+v, want the terminal outer failure", after.RefreshError)
	}

	// A transient failure on the healthy SIWC partition after the restart keeps
	// the terminal decision, as it does in memory.
	m2.refreshAuth(ctx, id)
	if calls := exec2.RefreshCalls(); calls != 1 {
		t.Fatalf("RefreshCalls = %d, want 1 for the healthy SIWC partition", calls)
	}
	transient := getAuth(t, m2, id)
	if !transient.RequiresSignIn || transient.RejectedRefreshToken != "outer-rt-secret" {
		t.Fatalf("transient failure after restart: RequiresSignIn=%v Rejected=%q", transient.RequiresSignIn, transient.RejectedRefreshToken)
	}
	if !cooldownErrorEqual(transient.RefreshError, after.RefreshError) {
		t.Fatalf("transient failure replaced the terminal RefreshError: %+v, want %+v", transient.RefreshError, after.RefreshError)
	}
}

func TestRenewalRestart_SameFileReSignInClearsAndStaysCleared(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-resign.json"
	expiry := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "old-at-secret", "refresh_token": "old-rt-secret", "expired": expiry})

	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	if !getAuth(t, m1, id).RequiresSignIn {
		t.Fatal("precondition: RequiresSignIn not set")
	}

	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	if !getAuth(t, m2, id).RequiresSignIn {
		t.Fatal("RequiresSignIn lost on restart")
	}
	// OAuth re-sign-in writes new tokens to the same file; the watcher adopts it.
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "new-at-secret", "refresh_token": "new-rt-secret", "expired": expiry})
	if _, errUpdate := m2.Update(ctx, hub.loadCredential(t, id, "claude")); errUpdate != nil {
		t.Fatalf("Update after re-sign-in: %v", errUpdate)
	}
	assertNoRenewalState(t, getAuth(t, m2, id))
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("persisted renewal state not cleared after re-sign-in: %+v", record)
	}

	m3 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	assertNoRenewalState(t, getAuth(t, m3, id))
}

func TestRenewalRestart_ReSignInWhileStoppedIsNotRestored(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-offline-resign.json"
	expiry := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "old-at-secret", "refresh_token": "old-rt-secret", "expired": expiry})

	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	if !getAuth(t, m1, id).RequiresSignIn {
		t.Fatal("precondition: RequiresSignIn not set")
	}
	// The credential is replaced while the hub is down.
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "new-at-secret", "refresh_token": "new-rt-secret", "expired": expiry})
	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	assertNoRenewalState(t, getAuth(t, m2, id))
}

func TestRenewalRestart_SuccessfulRefreshClears(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-refresh-recovers.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "old-at-secret", "refresh_token": "old-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})

	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	if !getAuth(t, m1, id).RequiresSignIn {
		t.Fatal("precondition: RequiresSignIn not set")
	}

	exec2 := &rotatingRefreshExecutor{
		unauthorizedRefreshExecutor: &unauthorizedRefreshExecutor{id: "claude"},
		accessToken:                 "rotated-at-secret",
		refreshToken:                "rotated-rt-secret",
	}
	m2 := hub.start(t, exec2, "claude", id)
	if !getAuth(t, m2, id).RequiresSignIn {
		t.Fatal("RequiresSignIn lost on restart")
	}
	if _, errRefresh := m2.ForceRefreshAuth(ctx, id); errRefresh != nil {
		t.Fatalf("ForceRefreshAuth: %v", errRefresh)
	}
	assertNoRenewalState(t, getAuth(t, m2, id))
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("persisted renewal state not cleared after a successful refresh: %+v", record)
	}
	hub.saveCredential(t, m2, id)
	m3 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	assertNoRenewalState(t, getAuth(t, m3, id))
}
