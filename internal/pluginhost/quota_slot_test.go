package pluginhost

import (
	"context"
	"errors"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// A caller that gives up during a cold DescribeQuota over a guarded RPC client returns at once,
// but its quota slot stays held until the native describe call returns.
func TestFetchQuotaForCredentialHoldsSlotThroughCanceledDescribe(t *testing.T) {
	saved := quotaFetchSlots
	quotaFetchSlots = make(chan struct{}, 1)
	defer func() { quotaFetchSlots = saved }()

	manager := coreauth.NewManager(nil, nil, nil)
	auth, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: "slow-cred", Provider: "slow-runtime", Status: coreauth.StatusActive})
	if errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	auth.EnsureIndex()

	inner := &blockingGuardPluginClient{started: make(chan struct{}), release: make(chan struct{})}
	guarded := newGuardedPluginClient(inner)
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
	done := make(chan error, 1)
	go func() {
		_, _, err := host.FetchQuotaForCredential(ctx, "slow-runtime", "", auth.Index, auth.ID)
		done <- err
	}()
	<-inner.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled call err = %v, want context.Canceled", err)
	}
	if len(quotaFetchSlots) != 1 {
		t.Fatalf("slots held after the caller left while DescribeQuota still runs = %d, want 1", len(quotaFetchSlots))
	}

	close(inner.release)
	guarded.Shutdown()
	if len(quotaFetchSlots) != 0 {
		t.Fatalf("slots held after the native call returned = %d, want 0", len(quotaFetchSlots))
	}
}
