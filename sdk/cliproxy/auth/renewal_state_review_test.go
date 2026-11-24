package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// S3: a reload does not restore a marker that was cleared while the records loaded.
func TestRenewalRestart_ReloadSkipsAuthChangedDuringLoad(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-reload.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "same-at-secret", "refresh_token": "ok-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	store := &loadHookCooldownStore{FileCooldownStateStore: hub.store}
	exec := &unauthorizedRefreshExecutor{id: "claude", refreshTokens: map[string]string{id: "same-at-secret"}}
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.SetCooldownStateStore(store)
	m.RegisterExecutor(exec)
	if _, errRegister := m.Register(ctx, hub.loadCredential(t, id, "claude")); errRegister != nil {
		t.Fatal(errRegister)
	}
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

// S4: renewal state of a credential that is not registered at startup is kept
// on disk and applied when the credential is registered later.
func TestRenewalRestart_LaterRegisteredCredentialKeepsRenewalState(t *testing.T) {
	ctx := context.Background()
	hub := newRenewalRestartHub(t)
	id := "claude-later.json"
	hub.writeCredential(t, id, map[string]any{"type": "claude", "access_token": "later-at-secret", "refresh_token": "later-rt-secret", "expired": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)})
	m1 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude", refreshErr: errors.New(claudeRefreshExpiredErr)}, "claude", id)
	m1.refreshAuth(ctx, id)
	before := getAuth(t, m1, id)

	// The credential is missing from the startup inventory; startup saves the state.
	m2 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude")
	m2.PersistCooldownStates(ctx)
	if record := hub.renewalRecord(t, id); record == nil || !record.RequiresSignIn {
		t.Fatalf("startup dropped the renewal state of an unregistered credential: %+v", record)
	}
	if _, errRegister := m2.Register(ctx, hub.loadCredential(t, id, "claude")); errRegister != nil {
		t.Fatal(errRegister)
	}
	assertSameRenewalState(t, before, getAuth(t, m2, id))

	// Explicit removal of an unregistered credential drops its kept state.
	m3 := hub.start(t, &unauthorizedRefreshExecutor{id: "claude"}, "claude")
	m3.Remove(ctx, id)
	if record := hub.renewalRecord(t, id); record != nil {
		t.Fatalf("removal kept renewal state: %+v", record)
	}
}

// blockingSaveCooldownStore blocks Save until release is closed.
type blockingSaveCooldownStore struct {
	*FileCooldownStateStore
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSaveCooldownStore) Save(ctx context.Context, records []CooldownStateRecord) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	return s.FileCooldownStateStore.Save(ctx, records)
}

// S5: a refresh cancelled while waiting for the credential's refresh lock
// does not wait behind an unrelated state save when no renewal state changed.
func TestRenewalPersist_CancelledRefreshDoesNotWaitForSave(t *testing.T) {
	ctx := context.Background()
	authDir := t.TempDir()
	store := &blockingSaveCooldownStore{
		FileCooldownStateStore: NewFileCooldownStateStoreWithAuthDir(authDir, authDir),
		entered:                make(chan struct{}, 1),
		release:                make(chan struct{}),
	}
	id := "claude-cancel.json"
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.SetCooldownStateStore(store)
	m.RegisterExecutor(&unauthorizedRefreshExecutor{id: "claude"})
	path := filepath.Join(authDir, id)
	if errWrite := os.WriteFile(path, []byte(`{}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	if _, errRegister := m.Register(ctx, &Auth{ID: id, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"path": path},
		Metadata: map[string]any{"type": "claude", "access_token": "cancel-at", "refresh_token": "cancel-rt"}}); errRegister != nil {
		t.Fatal(errRegister)
	}

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
