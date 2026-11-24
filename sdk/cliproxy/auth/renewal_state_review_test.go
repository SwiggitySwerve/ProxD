package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// S1: upstream refresh diagnostics never reach the runtime state file.
func TestRenewalRestart_RefreshErrorDiagnosticsNotPersisted(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-diag.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "diag-at-secret", "refresh_token": "diag-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	refreshErr := errors.New(`token refresh failed with status 400: {"error": "invalid_grant", "error_description": "Refresh token expired for grant opaqueGrantSecret42"}`)

	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: refreshErr}, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)
	if !before.RequiresSignIn || !strings.Contains(before.RefreshError.Message, "opaqueGrantSecret42") {
		t.Fatalf("precondition: RequiresSignIn=%v RefreshError=%+v", before.RequiresSignIn, before.RefreshError)
	}
	hub.assertNoTokensPersisted(t, "diag-at-secret", "diag-rt-secret", "opaqueGrantSecret42", "error_description")

	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	after := getAuth(t, m2, id)
	assertRestoredRefreshError(t, before.RefreshError, after.RefreshError)
	if after.RefreshError.Code != "refresh_token_expired" || !isTerminalRefreshError(after, after.RefreshError) {
		t.Fatalf("restored RefreshError = %+v, want terminal refresh_token_expired", after.RefreshError)
	}
}

// S1/S4: a state file written by an earlier format with free-form error text
// is rewritten without it once its credential is registered, and a state file
// of a credential that is not registered is left untouched.
func TestRenewalRestart_OldFormatRecordTextNotRewritten(t *testing.T) {
	hub := newRenewalRestartHub(t)
	id, gone := "claude-old.json", "claude-gone.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "old-at-secret", "refresh_token": "old-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	loaded := hub.loadCredential(t, id, "claude")
	writeOldFormat := func(authID string) []byte {
		data, errMarshal := json.Marshal(map[string]any{"version": 1, "auth_id": authID, "records": []any{map[string]any{
			"auth_id": authID, "status": "renewal", "next_retry_after": time.Time{}, "updated_at": time.Time{},
			"renewal": map[string]any{
				"requires_sign_in":              true,
				"refresh_error":                 map[string]any{"code": "refresh_token_expired", "message": "Refresh token expired for grant opaqueOldSecret77", "retryable": false, "http_status": 400},
				"grant_sha256":                  renewalGrantSHA256(loaded),
				"rejected_refresh_token_sha256": renewalFingerprint("old-rt-secret"),
			},
		}}})
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		path := filepath.Join(hub.authDir, strings.TrimSuffix(authID, ".json")+".cds")
		if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		return data
	}
	writeOldFormat(id)
	goneData := writeOldFormat(gone)

	m := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	m.PersistCooldownStates(context.Background())
	restored := getAuth(t, m, id)
	if !restored.RequiresSignIn || restored.RefreshError == nil || restored.RefreshError.Message != restoredRenewalErrorMessage("refresh_token_expired") {
		t.Fatalf("restored RequiresSignIn=%v RefreshError=%+v", restored.RequiresSignIn, restored.RefreshError)
	}
	data, errRead := os.ReadFile(filepath.Join(hub.authDir, "claude-old.cds"))
	if errRead != nil {
		t.Fatal(errRead)
	}
	if strings.Contains(string(data), "opaqueOldSecret77") {
		t.Fatalf("rewritten state file kept the old error text:\n%s", data)
	}
	if got, _ := os.ReadFile(filepath.Join(hub.authDir, "claude-gone.cds")); string(got) != string(goneData) {
		t.Fatalf("state file of an unregistered credential was rewritten:\n%s", got)
	}
}

// S8: a credential in a subdirectory keeps its own state file path.
func TestRenewalRestart_SubdirectoryCredentialKeepsSidecarPath(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "team/account.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "team-at-secret", "refresh_token": "team-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)

	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	m2.PersistCooldownStates(ctx)
	assertSameRenewalState(t, before, getAuth(t, m2, id))
	if _, errStat := os.Stat(filepath.Join(hub.authDir, "team", "account.cds")); errStat != nil {
		t.Fatalf("subdirectory state file missing: %v", errStat)
	}
	if _, errStat := os.Stat(filepath.Join(hub.authDir, "team_account.cds")); !os.IsNotExist(errStat) {
		t.Fatalf("state file rewritten at the root: %v", errStat)
	}
}

// S2: a credential with no access token and a rejected refresh grant stays out
// of rotation after a restart, as it is before.
func TestRenewalRestart_RefreshTokenOnlyCredentialStaysBlocked(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-rt-only.json"
	model := registerRenewalTestModel(t, "claude", id)
	hub.writeCredential(t, id, map[string]any{"type": "claude", "refresh_token": "rt-only-secret"})

	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	if before := getAuth(t, m1, id); !before.RequiresSignIn {
		t.Fatal("precondition: RequiresSignIn not set")
	}
	exec2 := &unauthorizedRefreshExecutor{id: "claude"}
	m2 := hub.start(t, exec2, "claude", id)
	if !getAuth(t, m2, id).RequiresSignIn {
		t.Fatal("RequiresSignIn lost on restart")
	}
	if _, errExec := m2.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); errExec == nil {
		t.Fatal("Execute after restart succeeded with a credential that has no access token and a rejected refresh grant")
	}
	if calls := exec2.ExecuteCalls(); len(calls) != 0 {
		t.Fatalf("restarted hub selected the credential: %v", calls)
	}
}

// S2: a credential that can obtain a key another way is not blocked by the
// rejected-grant rule.
func TestRenewalSelection_AlternateCredentialPathNotBlocked(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name     string
		provider string
		metadata map[string]any
	}{
		{"meta dca only", "meta", map[string]any{"type": "meta", "dca_token": "dca-secret"}},
		{"meta dca with rejected refresh token", "meta", map[string]any{"type": "meta", "dca_token": "dca-secret", "refresh_token": "meta-rt"}},
		{"api key with rejected refresh token", "claude", map[string]any{"type": "claude", "api_key": "key-secret", "refresh_token": "claude-rt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &Auth{ID: "alt.json", Provider: tc.provider, Status: StatusActive, Metadata: tc.metadata, RequiresSignIn: true}
			auth.RejectedRefreshToken, _ = tc.metadata["refresh_token"].(string)
			if blocked, _, _ := isAuthBlockedForModel(auth, "m", now); blocked {
				t.Fatal("credential with another way to obtain a key is blocked")
			}
		})
	}
}

// loadHookCooldownStore runs afterLoad once, after reading the records and
// before the caller applies them.
type loadHookCooldownStore struct {
	*FileCooldownStateStore
	afterLoad func()
}

func (s *loadHookCooldownStore) Load(ctx context.Context) ([]CooldownStateRecord, error) {
	records, errLoad := s.FileCooldownStateStore.Load(ctx)
	if hook := s.afterLoad; hook != nil {
		s.afterLoad = nil
		hook()
	}
	return records, errLoad
}

// S3: a reload does not restore a marker that a refresh cleared while the
// records loaded.
func TestRenewalRestart_ReloadSkipsAuthChangedDuringLoad(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-reload.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "same-at-secret", "refresh_token": "ok-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	store := &loadHookCooldownStore{FileCooldownStateStore: hub.store}
	m := hub.load(t, store, &unauthorizedRefreshExecutor{id: "claude", refreshTokens: map[string]string{id: "same-at-secret"}}, "claude", id)
	m.markRejectedAccessToken(id, "same-at-secret")
	if record := hub.renewalRecord(t, id); record == nil || record.RejectedAccessTokenSHA256 == "" {
		t.Fatalf("precondition: persisted record = %+v", record)
	}

	// A successful refresh that returns the same access token clears the marker
	// while the reload is reading the old records.
	store.afterLoad = func() {
		if _, errRefresh := m.ForceRefreshAuth(ctx, id); errRefresh != nil {
			t.Errorf("ForceRefreshAuth: %v", errRefresh)
		}
		if cleared := getAuth(t, m, id); cleared.RejectedAccessToken != "" {
			t.Errorf("precondition: refresh kept the marker %q", cleared.RejectedAccessToken)
		}
	}
	if errRestore := m.RestoreCooldownStates(ctx); errRestore != nil {
		t.Fatal(errRestore)
	}
	if got := getAuth(t, m, id).RejectedAccessToken; got != "" {
		t.Fatalf("reload restored a marker cleared during the load: %q", got)
	}
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("persisted renewal state = %+v, want cleared", record)
	}
}

// S3: an unrelated successful request during the load does not prevent the restore.
func TestRenewalRestart_UnrelatedRequestDuringLoadKeepsRestore(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-busy.json"
	model := registerRenewalTestModel(t, "claude", id)
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "busy-at-secret", "refresh_token": "busy-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)

	store := &loadHookCooldownStore{FileCooldownStateStore: hub.store}
	m2 := hub.load(t, store, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	generation := getAuth(t, m2, id).Generation
	store.afterLoad = func() {
		m2.MarkResult(ctx, Result{AuthID: id, Provider: "claude", Model: model, Success: true})
		if getAuth(t, m2, id).Generation == generation {
			t.Error("precondition: the request did not move the generation")
		}
	}
	if errRestore := m2.RestoreCooldownStates(ctx); errRestore != nil {
		t.Fatal(errRestore)
	}
	assertSameRenewalState(t, before, getAuth(t, m2, id))
	if record := hub.renewalRecord(t, id); record == nil || !record.RequiresSignIn {
		t.Fatalf("persisted renewal state = %+v, want kept", record)
	}
}

// S4: a credential registered during the load restores its own state file.
func TestRenewalRestart_RegisterDuringLoadRestoresOwnState(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-late.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "late-at-secret", "refresh_token": "late-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)

	// The credential is missing from the startup inventory and is registered
	// by the watcher while the state records load.
	store := &loadHookCooldownStore{FileCooldownStateStore: hub.store}
	m2 := hub.load(t, store, &unauthorizedRefreshExecutor{id: "claude"}, "claude")
	store.afterLoad = func() {
		if _, errRegister := m2.Register(ctx, hub.loadCredential(t, id, "claude")); errRegister != nil {
			t.Error(errRegister)
		}
	}
	if errRestore := m2.RestoreCooldownStates(ctx); errRestore != nil {
		t.Fatal(errRestore)
	}
	m2.PersistCooldownStates(ctx)
	assertSameRenewalState(t, before, getAuth(t, m2, id))
	if record := hub.renewalRecord(t, id); record == nil || !record.RequiresSignIn {
		t.Fatalf("persisted renewal state = %+v, want kept", record)
	}
}

// S4: state of a credential missing from the startup inventory stays on disk
// and is restored when the credential is registered later; removing a
// registered credential deletes it.
func TestRenewalRestart_LaterRegisteredCredentialKeepsRenewalState(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-later.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "later-at-secret", "refresh_token": "later-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)

	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude")
	m2.PersistCooldownStates(ctx)
	if record := hub.renewalRecord(t, id); record == nil || !record.RequiresSignIn {
		t.Fatalf("startup dropped the renewal state of an unregistered credential: %+v", record)
	}
	if _, errRegister := m2.Register(ctx, hub.loadCredential(t, id, "claude")); errRegister != nil {
		t.Fatal(errRegister)
	}
	assertSameRenewalState(t, before, getAuth(t, m2, id))
	m2.Remove(ctx, id)
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("removal kept renewal state: %+v", record)
	}
}

// S4: a credential removed during the load does not get its state back.
func TestRenewalRestart_RemoveDuringLoadDoesNotReappear(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-removed.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "rm-at-secret", "refresh_token": "rm-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)

	store := &loadHookCooldownStore{FileCooldownStateStore: hub.store}
	m2 := hub.load(t, store, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	store.afterLoad = func() { m2.Remove(ctx, id) }
	if errRestore := m2.RestoreCooldownStates(ctx); errRestore != nil {
		t.Fatal(errRestore)
	}
	m2.PersistCooldownStates(ctx)
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("removed credential's renewal state reappeared: %+v", record)
	}
	if _, ok := m2.GetByID(id); ok {
		t.Fatal("removed credential reappeared")
	}
}

// blockingSaveCooldownStore blocks its first save until release is closed.
type blockingSaveCooldownStore struct {
	*FileCooldownStateStore
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSaveCooldownStore) SaveScoped(ctx context.Context, records, owners []CooldownStateRecord) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return s.FileCooldownStateStore.SaveScoped(ctx, records, owners)
}

func newBlockingSaveManager(t *testing.T, hook Hook) (*Manager, *blockingSaveCooldownStore, string, string) {
	t.Helper()
	authDir := t.TempDir()
	store := &blockingSaveCooldownStore{
		FileCooldownStateStore: NewFileCooldownStateStoreWithAuthDir(authDir, authDir),
		entered:                make(chan struct{}, 1),
		release:                make(chan struct{}),
	}
	id := "claude-blocking.json"
	path := filepath.Join(authDir, id)
	if errWrite := os.WriteFile(path, []byte(`{}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	m := NewManager(nil, &FillFirstSelector{}, hook)
	m.SetCooldownStateStore(store)
	m.RegisterExecutor(&unauthorizedRefreshExecutor{id: "claude"})
	if _, errRegister := m.Register(context.Background(), &Auth{ID: id, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"path": path},
		Metadata: map[string]any{"type": "claude", "access_token": "blocking-at-1", "refresh_token": "blocking-rt"}}); errRegister != nil {
		t.Fatal(errRegister)
	}
	return m, store, id, authDir
}

// S5: a refresh cancelled while waiting for the credential's refresh lock
// does not wait behind an unrelated state save.
func TestRenewalPersist_CancelledRefreshDoesNotWaitForSave(t *testing.T) {
	ctx := context.Background()
	m, store, id, _ := newBlockingSaveManager(t, nil)
	saveDone := make(chan struct{})
	go func() {
		m.PersistCooldownStates(ctx)
		close(saveDone)
	}()
	<-store.entered
	t.Cleanup(func() {
		close(store.release)
		<-saveDone
	})
	releaseRefresh, errLock := m.lockRefreshContext(ctx, id)
	if errLock != nil {
		t.Fatal(errLock)
	}
	defer releaseRefresh()

	refreshCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, errRefresh := m.refreshAuthForRequest(refreshCtx, id, "")
		done <- errRefresh
	}()
	cancel()
	select {
	case errRefresh := <-done:
		if !errors.Is(errRefresh, context.Canceled) {
			t.Fatalf("refresh error = %v, want context.Canceled", errRefresh)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled refresh waited behind an unrelated state save")
	}
}

// updatedSignalHook signals each committed update before its state is saved.
type updatedSignalHook struct {
	NoopHook
	updated chan struct{}
}

func (h *updatedSignalHook) OnAuthUpdated(context.Context, *Auth) { h.updated <- struct{}{} }

// S7: a marker cleared while a save of the marked state is in flight does not
// end up on disk.
func TestRenewalPersist_ClearDuringInFlightSaveIsWritten(t *testing.T) {
	ctx := context.Background()
	hook := &updatedSignalHook{updated: make(chan struct{}, 1)}
	m, store, id, authDir := newBlockingSaveManager(t, hook)

	markDone := make(chan struct{})
	go func() {
		m.markRejectedAccessToken(id, "blocking-at-1")
		close(markDone)
	}()
	<-store.entered // the save of the marked state is in flight

	updated := getAuth(t, m, id)
	updated.Metadata["access_token"] = "blocking-at-2"
	updateDone := make(chan struct{})
	go func() {
		if _, errUpdate := m.Update(ctx, updated); errUpdate != nil {
			t.Error(errUpdate)
		}
		close(updateDone)
	}()
	<-hook.updated // the marker is cleared in memory while the old save is in flight
	if got := getAuth(t, m, id).RejectedAccessToken; got != "" {
		t.Fatalf("precondition: marker not cleared: %q", got)
	}
	close(store.release)
	<-markDone
	<-updateDone

	records, errLoad := NewFileCooldownStateStoreWithAuthDir(authDir, authDir).Load(ctx)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	for _, record := range records {
		if record.AuthID == id && record.Renewal != nil {
			t.Fatalf("stale renewal state on disk after the clear: %+v", record.Renewal)
		}
	}
}

// S6: a transient refresh failure is not persisted, so a restart does not
// report a retry whose schedule was lost.
func TestRenewalRestart_TransientRefreshErrorNotPersisted(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-transient.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "tr-at-secret", "refresh_token": "tr-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New("token refresh failed with status 503: upstream connect error")}, "claude", id)
	m1.refreshAuth(ctx, id)
	if before := getAuth(t, m1, id); before.RequiresSignIn || before.RefreshError == nil {
		t.Fatalf("precondition: RequiresSignIn=%v RefreshError=%+v", before.RequiresSignIn, before.RefreshError)
	}
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("transient refresh failure persisted: %+v", record)
	}
	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude", id)
	after := getAuth(t, m2, id)
	assertNoRenewalState(t, after)
	if state := after.RenewalStateAt(time.Now()); state == RenewalStateRetryScheduled {
		t.Fatalf("RenewalState after restart = %q", state)
	}
}
