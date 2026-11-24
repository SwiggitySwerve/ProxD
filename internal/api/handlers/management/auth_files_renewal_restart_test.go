package management

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// TestListAuthFiles_TerminalRenewalSurvivesRestart checks that a credential
// whose refresh grant was rejected reports the same renewal fields from the
// management API after a hub restart as before it.
func TestListAuthFiles_TerminalRenewalSurvivesRestart(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name   string
		expiry time.Duration
	}{
		{"working access token", 24 * time.Hour},
		{"expired access token", -time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authDir := t.TempDir()
			cfg := &config.Config{AuthDir: authDir}
			store := coreauth.NewFileCooldownStateStoreWithAuthDir(authDir, authDir)
			credPath := filepath.Join(authDir, "claude-a.json")
			expired := time.Now().Add(tc.expiry).UTC().Format(time.RFC3339)
			data := `{"type":"claude","email":"a@example.com","access_token":"claude-at-secret","refresh_token":"claude-rt-secret","expired":"` + expired + `"}`
			if errWrite := os.WriteFile(credPath, []byte(data), 0o600); errWrite != nil {
				t.Fatal(errWrite)
			}
			// start boots a hub: load the credential file as file synthesis does, then restore runtime state.
			start := func() *coreauth.Manager {
				manager := coreauth.NewManager(nil, nil, nil)
				manager.SetConfig(cfg)
				manager.SetCooldownStateStore(store)
				manager.RegisterExecutor(&failingRefreshManagementExecutor{
					provider: "claude",
					err:      fmt.Errorf(`token refresh failed with status 400: {"error": "invalid_grant", "error_description": "Refresh token expired"}`),
				})
				var metadata map[string]any
				if errUnmarshal := json.Unmarshal([]byte(data), &metadata); errUnmarshal != nil {
					t.Fatal(errUnmarshal)
				}
				registerAuthForLookupTest(t, manager, &coreauth.Auth{
					ID:         "claude-a.json",
					FileName:   "claude-a.json",
					Provider:   "claude",
					Status:     coreauth.StatusActive,
					Metadata:   metadata,
					Attributes: map[string]string{"path": credPath, "source": credPath},
				})
				if errRestore := manager.RestoreCooldownStates(context.Background()); errRestore != nil {
					t.Fatalf("RestoreCooldownStates: %v", errRestore)
				}
				return manager
			}
			list := func(manager *coreauth.Manager) map[string]any {
				h := NewHandlerWithoutConfigFilePath(cfg, manager)
				rec := httptest.NewRecorder()
				ginCtx, _ := gin.CreateTestContext(rec)
				ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v8/management/credentials?name=claude-a.json", nil)
				ginCtx.Set(ConfigV8ContextKey, true)
				h.ListAuthFiles(ginCtx)
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
				}
				var resp struct {
					Files []map[string]any `json:"files"`
				}
				if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &resp); errUnmarshal != nil {
					t.Fatal(errUnmarshal)
				}
				if len(resp.Files) != 1 {
					t.Fatalf("len(files) = %d, want 1", len(resp.Files))
				}
				return resp.Files[0]
			}

			before := start()
			_, _ = before.ForceRefreshAuth(context.Background(), "claude-a.json")
			entryBefore := list(before)
			if entryBefore["requires_sign_in"] != true {
				t.Fatalf("precondition: requires_sign_in = %v (entry=%#v)", entryBefore["requires_sign_in"], entryBefore)
			}
			if tc.expiry < 0 && entryBefore["status_message"] != "unauthorized (refresh token invalid)" {
				t.Fatalf("precondition: status_message = %#v, want the sign-in message", entryBefore["status_message"])
			}

			entryAfter := list(start())
			for _, key := range []string{"requires_sign_in", "status", "status_message", "unavailable", "renewal_state", "recovery_stage", "refresh_error", "next_action", "renewal_event"} {
				if !reflect.DeepEqual(entryAfter[key], entryBefore[key]) {
					t.Fatalf("%s after restart = %#v, want %#v", key, entryAfter[key], entryBefore[key])
				}
			}
		})
	}
}
