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

// A carried-forward credential shares its storage with the rescanned one; a save between two reads
// of that storage must not make it look modified.
func TestAuthEqualSharedPluginStorageDuringSave(t *testing.T) {
	host := pluginhost.New()
	published := host.AuthDataToCoreAuth(pluginapi.AuthData{
		Provider:    "race-plugin",
		ID:          "shared.json",
		FileName:    "shared.json",
		StorageJSON: []byte(`{"type":"race-plugin","access_token":"tok"}`),
		Metadata:    map[string]any{"type": "race-plugin", "n": 0},
	}, "/tmp/shared.json", "shared.json")
	carried := published.Clone()
	setter := published.Storage.(interface{ SetMetadata(map[string]any) })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				setter.SetMetadata(map[string]any{"type": "race-plugin", "n": i})
			}
		}
	}()
	mismatches := 0
	for i := 0; i < 5000; i++ {
		if !authEqual(published, carried) {
			mismatches++
		}
	}
	close(stop)
	wg.Wait()
	if mismatches != 0 {
		t.Fatalf("a credential sharing its storage looked modified %d of 5000 times during saves", mismatches)
	}
}
