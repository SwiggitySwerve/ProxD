package pluginhost

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// A caller that gives up during a cold DescribeQuota over a guarded RPC client returns at once,
// but its quota slot stays held until the native describe call returns.
func TestFetchQuotaForCredentialHoldsSlotThroughCanceledDescribe(t *testing.T) {
	baseline := len(quotaFetchSlots)
	manager := coreauth.NewManager(nil, nil, nil)
	auth, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: "slow-cred", Provider: "slow-runtime", Status: coreauth.StatusActive})
	if errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	auth.EnsureIndex()

	inner := &blockingGuardPluginClient{started: make(chan struct{}), release: make(chan struct{})}
	guarded := newGuardedPluginClient(inner)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(inner.release) }) }
	t.Cleanup(release)
	host := New()
	host.SetAuthManager(manager)
	host.RegisterPluginForTest("slow-plugin", pluginapi.Plugin{
		Capabilities: pluginapi.Capabilities{
			QuotaProvider: rpcQuotaProvider{
				rpcPluginAdapter: &rpcPluginAdapter{id: "slow-plugin", host: host, client: guarded},
				identifier:       "slow",
			},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := host.FetchQuotaForCredential(ctx, "slow-runtime", "", auth.Index, auth.ID)
		done <- err
	}()
	select {
	case <-inner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("DescribeQuota never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled call err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled call did not return")
	}
	if len(quotaFetchSlots) != baseline+1 {
		t.Fatalf("slots held after the caller left while DescribeQuota still runs = %d, want %d", len(quotaFetchSlots), baseline+1)
	}

	release()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	guarded.ShutdownContext(shutdownCtx)
	select {
	case <-guarded.shutdownDone:
	default:
		t.Fatal("guarded client shutdown did not finish")
	}
	if len(quotaFetchSlots) != baseline {
		t.Fatalf("slots held after the native call returned = %d, want %d", len(quotaFetchSlots), baseline)
	}
}

// Saves replace a published plugin credential's metadata while executors and quota fetch read its
// storage; run with -race.
func TestPluginTokenStorageConcurrentMetadataAndRead(t *testing.T) {
	storage := &pluginTokenStorage{provider: "race", rawJSON: []byte(`{"type":"race","priority":1}`), meta: map[string]any{"priority": 1}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			storage.SetMetadata(map[string]any{"email": "user@example.test", "n": i})
		}
	}()
	for i := 0; i < 200; i++ {
		if storage.RawJSON() == nil {
			t.Fatal("RawJSON returned nil")
		}
	}
	<-done
}

// The watcher compares Auths, storage included, with reflect.DeepEqual; a quota read holding the
// storage lock must not make an unchanged plugin credential look modified.
func TestPluginTokenStorageEqualWhileReadLocked(t *testing.T) {
	newAuth := func() *coreauth.Auth {
		return &coreauth.Auth{ID: "same", Provider: "race", Storage: &pluginTokenStorage{provider: "race", rawJSON: []byte(`{"type":"race"}`), meta: map[string]any{"email": "user@example.test"}}}
	}
	held, other := newAuth(), newAuth()
	unlock := held.Storage.(*pluginTokenStorage).readLock()
	defer unlock()
	if !reflect.DeepEqual(held, other) {
		t.Fatal("an unchanged plugin credential compares as modified while its storage is read-locked")
	}
}
