package watcher

import (
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// A save (SetMetadata on the published plugin credential's storage) can run while the watcher
// compares that credential with a rescanned copy; run with -race.
func TestAuthEqualConcurrentWithPluginStorageSave(t *testing.T) {
	host := pluginhost.New()
	data := pluginapi.AuthData{
		Provider:    "race-plugin",
		ID:          "race.json",
		FileName:    "race.json",
		StorageJSON: []byte(`{"type":"race-plugin","access_token":"tok"}`),
		Metadata:    map[string]any{"type": "race-plugin", "email": "user@example.test"},
	}
	published := host.AuthDataToCoreAuth(data, "/tmp/race.json", "race.json")
	rescanned := host.AuthDataToCoreAuth(data, "/tmp/race.json", "race.json")
	setter, ok := published.Storage.(interface{ SetMetadata(map[string]any) })
	if !ok {
		t.Fatalf("plugin storage %T has no SetMetadata", published.Storage)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			setter.SetMetadata(map[string]any{"type": "race-plugin", "email": "user@example.test"})
		}
	}()
	for i := 0; i < 200; i++ {
		_ = authEqual(published, rescanned)
	}
	wg.Wait()
	if !authEqual(published, rescanned) {
		t.Fatal("identical plugin credentials compare as different")
	}
}
