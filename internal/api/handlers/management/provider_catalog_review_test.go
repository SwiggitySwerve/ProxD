package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

var (
	proxUIProviderIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	proxUIInstanceIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// proxUIString mirrors ProxUI's nonEmptyString: JS trim, then 1..max UTF-16 code units.
func proxUIString(value any, maxUnits int) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	s = strings.TrimFunc(s, isCatalogWhitespace)
	units := len(utf16.Encode([]rune(s)))
	return units > 0 && units <= maxUnits
}

func proxUIStringList(value any) bool {
	if value == nil {
		return true
	}
	items, ok := value.([]any)
	if !ok || len(items) > 32 {
		return false
	}
	for _, item := range items {
		if !proxUIString(item, 128) {
			return false
		}
	}
	return true
}

func proxUINonNegInt(value any) bool {
	n, ok := value.(float64)
	return ok && n >= 0 && n == float64(int64(n))
}

func proxUINullableString(value any) bool {
	if value == nil {
		return true
	}
	_, ok := value.(string)
	return ok
}

// assertProxUICatalog applies the rules of ProxUI's parseProviderCatalog
// (src/domain/providerCatalog/validate.ts), which rejects the whole catalog on any violation.
func assertProxUICatalog(t *testing.T, raw []byte) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("catalog is not JSON: %v", err)
	}
	if doc["schema_version"] != float64(1) {
		t.Fatalf("schema_version = %#v", doc["schema_version"])
	}
	if id, ok := doc["instance_id"].(string); ok && id != "" && !proxUIInstanceIDRe.MatchString(id) {
		t.Fatalf("instance_id %q fails ProxUI rule", id)
	}
	if accepted := doc["accepted_providers"]; accepted != nil {
		list, ok := accepted.([]any)
		if !ok || len(list) > 128 {
			t.Fatalf("accepted_providers = %#v", accepted)
		}
		seen := map[string]bool{}
		for _, item := range list {
			id, okID := item.(string)
			if !okID || !proxUIProviderIDRe.MatchString(id) || seen[id] {
				t.Fatalf("accepted_providers item %#v fails ProxUI rule", item)
			}
			seen[id] = true
		}
	}
	providers, ok := doc["providers"].([]any)
	if !ok || len(providers) > 256 {
		t.Fatalf("providers = %#v", doc["providers"])
	}
	seen := map[string]bool{}
	for _, rawEntry := range providers {
		entry, okEntry := rawEntry.(map[string]any)
		if !okEntry {
			t.Fatalf("provider entry %#v is not an object", rawEntry)
		}
		id, _ := entry["id"].(string)
		if !proxUIProviderIDRe.MatchString(id) || seen[id] {
			t.Fatalf("provider id %q fails ProxUI rule or repeats", id)
		}
		seen[id] = true
		if !proxUIString(entry["display_name"], 128) {
			t.Fatalf("%s display_name %#v fails ProxUI rule", id, entry["display_name"])
		}
		if source := entry["source"]; source != "builtin" && source != "plugin" {
			t.Fatalf("%s source %#v", id, source)
		}
		switch entry["lifecycle"] {
		case lifecycleAwaitingAuth, lifecycleActive, lifecycleDisabled, lifecycleNeedsAttention:
		default:
			t.Fatalf("%s lifecycle %#v", id, entry["lifecycle"])
		}
		if !proxUINullableString(entry["plugin_id"]) || !proxUINullableString(entry["logo"]) {
			t.Fatalf("%s plugin_id/logo not string or null", id)
		}
		creds, okCreds := entry["credentials"].(map[string]any)
		if !okCreds || !proxUINonNegInt(creds["total"]) || !proxUINonNegInt(creds["active"]) || !proxUINonNegInt(creds["disabled"]) || !proxUINonNegInt(creds["problem"]) {
			t.Fatalf("%s credentials %#v", id, entry["credentials"])
		}
		if oauthRaw := entry["oauth"]; oauthRaw != nil {
			oauth, okOAuth := oauthRaw.(map[string]any)
			if !okOAuth || (oauth["flow"] != "browser" && oauth["flow"] != "device") || !proxUIStringList(oauth["aliases"]) || !proxUIStringList(oauth["domains"]) {
				t.Fatalf("%s oauth %#v", id, oauthRaw)
			}
			if _, okBool := oauth["manual_callback"].(bool); !okBool {
				t.Fatalf("%s oauth.manual_callback %#v", id, oauth["manual_callback"])
			}
			if _, okBool := oauth["webui"].(bool); !okBool {
				t.Fatalf("%s oauth.webui %#v", id, oauth["webui"])
			}
		}
		quota, okQuota := entry["quota"].(map[string]any)
		if !okQuota {
			t.Fatalf("%s quota %#v", id, entry["quota"])
		}
		_, okSupported := quota["supported"].(bool)
		_, okReset := quota["supports_reset"].(bool)
		reader := quota["reader"]
		if !okSupported || !okReset || (reader != "builtin" && reader != "plugin" && reader != "none") || !proxUINullableString(quota["plugin_id"]) {
			t.Fatalf("%s quota %#v", id, quota)
		}
	}
}

func catalogEntry(t *testing.T, resp providerCatalogResponse, id string) providerCatalogEntry {
	t.Helper()
	for _, entry := range resp.Providers {
		if entry.ID == id {
			return entry
		}
	}
	t.Fatalf("catalog has no %q entry: %+v", id, resp.Providers)
	return providerCatalogEntry{}
}

func fetchCatalog(t *testing.T, h *Handler) (providerCatalogResponse, []byte) {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v8/management/providers", nil)
	h.GetProviderCatalogV8(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalog status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp providerCatalogResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	assertProxUICatalog(t, rec.Body.Bytes())
	return resp, rec.Body.Bytes()
}

func registerFileAuth(t *testing.T, manager *coreauth.Manager, authDir string, auth *coreauth.Auth, content string) *coreauth.Auth {
	t.Helper()
	path := filepath.Join(authDir, auth.ID)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", auth.ID, err)
	}
	if auth.Attributes == nil {
		auth.Attributes = map[string]string{}
	}
	auth.Attributes[coreauth.AttributePath] = path
	registered, err := manager.Register(context.Background(), auth)
	if err != nil {
		t.Fatalf("register %s: %v", auth.ID, err)
	}
	registered.EnsureIndex()
	return registered
}

type multiPortalAuthProvider struct {
	mockCatalogAuthProvider
	identifiers []string
}

func (m *multiPortalAuthProvider) Identifiers() []string { return m.identifiers }

// credentialOwningAuthProvider declares the runtime provider its logins produce.
type credentialOwningAuthProvider struct {
	mockCatalogAuthProvider
	credentialProviders []string
}

func (m *credentialOwningAuthProvider) CredentialProviders() []string { return m.credentialProviders }

// S1: credentials are rechecked where they are persisted, which covers the v0 OAuth starts, a v8
// session whose provider was removed after it started, and the v0 Vertex import route.
func TestAcceptedProvidersRecheckedWhenCredentialsPersist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, AcceptedProviders: []string{"antigravity"}}, coreauth.NewManager(nil, nil, nil))

	_, errSave := h.saveTokenRecord(context.Background(), &coreauth.Auth{
		ID:       "codex-late.json",
		FileName: "codex-late.json",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex", "email": "late@example.test"},
	})
	var notAccepted *providerNotAcceptedError
	if !errors.As(errSave, &notAccepted) || notAccepted.Provider != "codex" {
		t.Fatalf("saveTokenRecord error = %v, want provider_not_accepted for codex", errSave)
	}
	if _, errStat := os.Stat(filepath.Join(authDir, "codex-late.json")); !os.IsNotExist(errStat) {
		t.Fatalf("rejected credential was written: %v", errStat)
	}

	key, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatalf("generate key: %v", errKey)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	serviceAccount, _ := json.Marshal(map[string]any{
		"type":         "service_account",
		"project_id":   "demo-project",
		"client_email": "svc@demo-project.iam.gserviceaccount.com",
		"private_key":  string(keyPEM),
	})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "sa.json")
	_, _ = fw.Write(serviceAccount)
	_ = mw.Close()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/vertex/import", &buf)
	ctx.Request.Header.Set("Content-Type", mw.FormDataContentType())
	h.ImportVertexCredential(ctx)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "provider_not_accepted") {
		t.Fatalf("v0 vertex import status = %d, body = %s, want 409 provider_not_accepted", rec.Code, rec.Body.String())
	}
	if _, errStat := os.Stat(filepath.Join(authDir, "vertex-demo-project.json")); !os.IsNotExist(errStat) {
		t.Fatalf("rejected vertex credential was written: %v", errStat)
	}
}

// S1 and S15: a built-in OAuth commit reports provider_not_accepted from the persistence check, and
// a plugin session whose provider was removed cannot save a credential for another allowed portal.
func TestAcceptedProvidersRecheckedAtOAuthCommit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, Port: 8317, AcceptedProviders: []string{"antigravity"}}, coreauth.NewManager(nil, nil, nil))

	builtinState := "accepted-builtin-commit"
	RegisterOAuthSession(builtinState, "codex")
	t.Cleanup(func() { CompleteOAuthSession(builtinState) })
	if _, ok := h.commitAndCompleteBuiltinOAuthSession(context.Background(), builtinState, "codex", "", &coreauth.Auth{
		ID:       "codex-commit.json",
		FileName: "codex-commit.json",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex", "email": "commit@example.test"},
	}, "save failed", false); ok {
		t.Fatalf("built-in commit saved a credential for an unaccepted provider")
	}
	if _, status, _ := GetOAuthSession(builtinState); status != "provider_not_accepted" {
		t.Fatalf("built-in session status = %q, want provider_not_accepted", status)
	}

	host := pluginhost.New()
	host.RegisterPluginForTest("zcode-plugin", pluginapi.Plugin{
		Metadata: pluginapi.Metadata{Name: "ZCode", Version: "1.0.0"},
		Capabilities: pluginapi.Capabilities{
			AuthProvider: &testAuthProvider{
				identifier:  "zcode-zai",
				identifiers: []string{"zcode-zai", "zcode-bigmodel"},
				startLogin: func(_ context.Context, req pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
					state := "state-accepted-" + req.Provider
					t.Cleanup(func() { CancelOAuthSession(state) })
					return pluginapi.AuthLoginStartResponse{Provider: req.Provider, URL: "https://example.test/login", State: state}, nil
				},
				pollLogin: func(context.Context, pluginapi.AuthLoginPollRequest) (pluginapi.AuthLoginPollResponse, error) {
					return pluginapi.AuthLoginPollResponse{
						Status: pluginapi.AuthLoginStatusSuccess,
						Auth: pluginapi.AuthData{
							Provider:    "zcode",
							ID:          "zcode-late.json",
							FileName:    "zcode-late.json",
							StorageJSON: []byte(`{"type":"zcode","access_token":"tok"}`),
							Metadata:    map[string]any{"type": "zcode", "portal": "zcode-zai"},
						},
					}, nil
				},
			},
		},
	})
	h.SetPluginHost(host)
	t.Setenv(acceptedProvidersEnvVar, "zcode-zai,zcode-bigmodel")
	startRec := httptest.NewRecorder()
	startCtx, _ := gin.CreateTestContext(startRec)
	startCtx.Request = httptest.NewRequest(http.MethodGet, "/v8/management/oauth/auth-url?provider=zcode-bigmodel", nil)
	h.StartOAuthV8(startCtx)
	if startRec.Code != http.StatusOK {
		t.Fatalf("start zcode-bigmodel status = %d, body = %s", startRec.Code, startRec.Body.String())
	}

	t.Setenv(acceptedProvidersEnvVar, "zcode-zai")
	pollRec := httptest.NewRecorder()
	pollCtx, _ := gin.CreateTestContext(pollRec)
	pollCtx.Request = httptest.NewRequest(http.MethodGet, "/v8/management/get-auth-status?state=state-accepted-zcode-bigmodel", nil)
	h.GetAuthStatus(pollCtx)
	if !strings.Contains(pollRec.Body.String(), "provider_not_accepted") {
		t.Fatalf("poll after removing zcode-bigmodel = %s, want provider_not_accepted", pollRec.Body.String())
	}
	if _, errStat := os.Stat(filepath.Join(authDir, "zcode-late.json")); !os.IsNotExist(errStat) {
		t.Fatalf("credential saved for a removed provider: %v", errStat)
	}
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return der
}

// S2 and S11: admission uses one sign-in identity. Another portal of the same plugin is not
// admitted, a kimi.ai credential is kimi-ai rather than kimi, and a batch upload through the v8
// handler reports the rejection as a machine-readable failure.
func TestAcceptedProvidersUseSignInIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	host := pluginhost.New()
	host.RegisterPluginForTest("zcode-plugin", pluginapi.Plugin{
		Metadata: pluginapi.Metadata{Name: "ZCode"},
		Capabilities: pluginapi.Capabilities{
			AuthProvider: &multiPortalAuthProvider{
				mockCatalogAuthProvider: mockCatalogAuthProvider{identifier: "zcode-zai"},
				identifiers:             []string{"zcode-zai", "zcode-bigmodel"},
			},
		},
	})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, AcceptedProviders: []string{"zcode-zai", "Kimi", "anthropic"}}, coreauth.NewManager(nil, nil, nil))
	h.SetPluginHost(host)

	if err := h.checkAcceptedProvider("zcode-zai"); err != nil {
		t.Fatalf("zcode-zai rejected: %v", err)
	}
	if err := h.checkAcceptedProvider("zcode-bigmodel"); err == nil {
		t.Fatalf("zcode-bigmodel admitted by allowing zcode-zai")
	}
	if err := h.checkAcceptedProvider("claude"); err != nil {
		t.Fatalf("claude rejected though anthropic is accepted: %v", err)
	}
	// A credential whose provider is itself a sign-in provider keeps that identity.
	if err := h.checkAcceptedAuth(&coreauth.Auth{Provider: "zcode-bigmodel", Attributes: map[string]string{"oauth_provider": "zcode-zai"}}); err == nil {
		t.Fatalf("zcode-bigmodel credential admitted through a zcode-zai portal hint")
	}
	// A built-in credential keeps its provider even when a plugin claims it and names a portal.
	host.RegisterPluginForTest("claude-claimer", pluginapi.Plugin{
		Capabilities: pluginapi.Capabilities{
			AuthProvider: &credentialOwningAuthProvider{
				mockCatalogAuthProvider: mockCatalogAuthProvider{identifier: "claimer-portal"},
				credentialProviders:     []string{"claude"},
			},
		},
	})
	if err := h.checkAcceptedAuth(&coreauth.Auth{Provider: "claude", Attributes: map[string]string{"oauth_provider": "claimer-portal"}}); err != nil {
		t.Fatalf("claude credential relabeled by a plugin portal hint: %v", err)
	}
	// Kimi ignores portal hints: a kimi.ai credential naming an accepted plugin portal is kimi-ai.
	if err := h.checkAcceptedAuth(&coreauth.Auth{Provider: "kimi", Metadata: map[string]any{"domain": "kimi.ai"}, Attributes: map[string]string{"oauth_provider": "zcode-zai"}}); err == nil {
		t.Fatalf("kimi.ai credential admitted through a zcode-zai portal hint")
	}
	// Every Kimi spelling resolves its sign-in entry from the domain.
	kimiOnly := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, AcceptedProviders: []string{"kimi-ai"}}, coreauth.NewManager(nil, nil, nil))
	if err := kimiOnly.checkAcceptedAuth(&coreauth.Auth{Provider: "kimi.ai", Metadata: map[string]any{"domain": "kimi.ai"}}); err != nil {
		t.Fatalf("kimi.ai credential rejected on a kimi-ai hub: %v", err)
	}
	if err := kimiOnly.checkAcceptedAuth(&coreauth.Auth{Provider: "kimi-ai", Metadata: map[string]any{"domain": "kimi.com"}}); err == nil {
		t.Fatalf("kimi.com credential admitted as kimi-ai")
	}

	kimiCom := `{"type":"kimi","domain":"kimi.com","access_token":"a","refresh_token":"r"}`
	kimiAI := `{"type":"kimi","domain":"kimi.ai","access_token":"a","refresh_token":"r"}`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for name, content := range map[string]string{"kimi-com.json": kimiCom, "kimi-ai.json": kimiAI} {
		fw, _ := mw.CreateFormFile("file", name)
		_, _ = fw.Write([]byte(content))
	}
	_ = mw.Close()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v8/management/credentials", &buf)
	ctx.Request.Header.Set("Content-Type", mw.FormDataContentType())
	h.UploadAuthFileV8(ctx)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("batch upload status = %d, body = %s, want 207", rec.Code, rec.Body.String())
	}
	var body struct {
		Files  []string         `json:"files"`
		Failed []map[string]any `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode batch body: %v", err)
	}
	if len(body.Files) != 1 || body.Files[0] != "kimi-com.json" {
		t.Fatalf("uploaded = %#v, want only kimi-com.json", body.Files)
	}
	if len(body.Failed) != 1 || body.Failed[0]["name"] != "kimi-ai.json" || body.Failed[0]["error"] != "provider_not_accepted" || body.Failed[0]["provider"] != "kimi-ai" {
		t.Fatalf("failed = %#v, want kimi-ai.json provider_not_accepted kimi-ai", body.Failed)
	}
	if _, ok := body.Failed[0]["accepted_providers"].([]any); !ok {
		t.Fatalf("failed entry lacks accepted_providers: %#v", body.Failed[0])
	}

	// A credential cannot borrow an accepted portal the plugin does not use for its provider.
	forged := `{"type":"evil","oauth_provider":"zcode-zai","access_token":"a"}`
	recForged := httptest.NewRecorder()
	ctxForged, _ := gin.CreateTestContext(recForged)
	ctxForged.Request = httptest.NewRequest(http.MethodPost, "/v8/management/credentials?name=forged.json", strings.NewReader(forged))
	ctxForged.Request.Header.Set("Content-Type", "application/json")
	h.UploadAuthFileV8(ctxForged)
	if recForged.Code != http.StatusConflict || !strings.Contains(recForged.Body.String(), `"provider":"evil"`) {
		t.Fatalf("forged portal upload status = %d, body = %s, want 409 for evil", recForged.Code, recForged.Body.String())
	}
}

// S5, S6, S9 and S10: the catalog stays valid for ProxUI, problems win, built-ins and the
// dispatch-first plugin keep their entries, and unaccepted providers are still listed.
func TestProviderCatalogWireAndPrecedence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "ag-ok.json", Provider: "antigravity", Status: coreauth.StatusActive}, `{"type":"antigravity"}`)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "ag-signin.json", Provider: "antigravity", Status: coreauth.StatusError, RequiresSignIn: true}, `{"type":"antigravity"}`)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "gw.json", Provider: "openai-compatible-my gateway", Status: coreauth.StatusActive}, `{"type":"openai-compatible-my gateway"}`)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "gone.json", Provider: "gone-plugin", Status: coreauth.StatusActive}, `{"type":"gone-plugin"}`)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "exec.json", Provider: "exec-only", Status: coreauth.StatusActive}, `{"type":"exec-only"}`)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "gemini.json", Provider: "gemini", Status: coreauth.StatusActive}, `{"type":"gemini"}`)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "compat.json", Provider: "own-endpoint", Status: coreauth.StatusActive, Attributes: map[string]string{"base_url": "https://llm.example.test/v1"}}, `{"type":"own-endpoint","base_url":"https://llm.example.test/v1"}`)

	host := pluginhost.New()
	host.RegisterPluginWithPriorityForTest("first-plugin", 10, pluginapi.Plugin{
		Metadata: pluginapi.Metadata{Name: strings.Repeat("😀", 100)},
		Capabilities: pluginapi.Capabilities{
			AuthProvider: &multiPortalAuthProvider{
				mockCatalogAuthProvider: mockCatalogAuthProvider{identifier: "dup-provider"},
				identifiers:             []string{"dup-provider", "codex", "under_score"},
			},
		},
	})
	host.RegisterPluginWithPriorityForTest("exec-plugin", 1, pluginapi.Plugin{
		Metadata:     pluginapi.Metadata{Name: "Exec Only"},
		Capabilities: pluginapi.Capabilities{Executor: catalogTestExecutor{identifier: "exec-only"}},
	})
	host.RegisterPluginWithPriorityForTest("gemini-extender", 1, pluginapi.Plugin{
		Capabilities: pluginapi.Capabilities{Executor: catalogTestExecutor{identifier: "gemini"}},
	})
	host.RegisterPluginWithPriorityForTest("second-plugin", 1, pluginapi.Plugin{
		Metadata:     pluginapi.Metadata{Name: "Second"},
		Capabilities: pluginapi.Capabilities{AuthProvider: &mockCatalogAuthProvider{identifier: "dup-provider"}},
	})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, AcceptedProviders: []string{"antigravity", "My Provider", "antigravity"}}, manager)
	h.SetPluginHost(host)

	resp, _ := fetchCatalog(t, h)

	if len(resp.AcceptedProviders) != 1 || resp.AcceptedProviders[0] != "antigravity" {
		t.Fatalf("accepted_providers = %#v, want [antigravity]", resp.AcceptedProviders)
	}
	if anti := catalogEntry(t, resp, "antigravity"); anti.Lifecycle != lifecycleNeedsAttention || anti.Credentials.Active != 1 || anti.Credentials.Problem != 1 {
		t.Fatalf("antigravity = %+v, want needs_attention with 1 active and 1 problem", anti)
	}
	for _, entry := range resp.Providers {
		if strings.Contains(entry.ID, " ") {
			t.Fatalf("invalid id %q emitted", entry.ID)
		}
	}
	if codex := catalogEntry(t, resp, "codex"); codex.Source != "builtin" || codex.Lifecycle != lifecycleAwaitingAuth {
		t.Fatalf("codex = %+v, want the built-in entry listed though not accepted", codex)
	}
	dup := catalogEntry(t, resp, "dup-provider")
	if dup.PluginID == nil || *dup.PluginID != host.AuthProviderPluginID("dup-provider") || *dup.PluginID != "first-plugin" {
		t.Fatalf("dup-provider plugin_id = %v, want the dispatch owner first-plugin", dup.PluginID)
	}
	gone := catalogEntry(t, resp, "gone-plugin")
	if gone.Source != "plugin" || gone.Lifecycle != lifecycleDisabled || gone.PluginID != nil {
		t.Fatalf("gone-plugin = %+v, want a disabled plugin provider", gone)
	}
	if exec := catalogEntry(t, resp, "exec-only"); exec.Source != "plugin" || exec.PluginID == nil || *exec.PluginID != "exec-plugin" || exec.Lifecycle != lifecycleActive {
		t.Fatalf("exec-only = %+v, want the active executor plugin's provider", exec)
	}
	if gemini := catalogEntry(t, resp, "gemini"); gemini.Source != "builtin" || gemini.PluginID != nil || gemini.Lifecycle != lifecycleActive {
		t.Fatalf("gemini = %+v, want the native built-in provider though a plugin executor extends it", gemini)
	}
	if own := catalogEntry(t, resp, "own-endpoint"); own.Source != "builtin" || own.Lifecycle != lifecycleActive {
		t.Fatalf("own-endpoint = %+v, want an active built-in OpenAI-compatible provider", own)
	}
	if under := catalogEntry(t, resp, "under_score"); under.OAuth != nil {
		t.Fatalf("under_score advertises sign-in the plugin OAuth routes refuse: %+v", under.OAuth)
	}
}

// S5: ProxUI's list limits hold however many providers a hub has.
func TestProviderCatalogListLimits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	accepted := make([]string, 0, 200)
	for i := 0; i < 300; i++ {
		id := fmt.Sprintf("p%03d", i)
		registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: id + ".json", Provider: id, Status: coreauth.StatusActive}, `{"type":"`+id+`"}`)
		if i < 200 {
			accepted = append(accepted, id)
		}
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, AcceptedProviders: accepted}, manager)
	resp, _ := fetchCatalog(t, h)
	if len(resp.Providers) != catalogMaxProviders || len(resp.AcceptedProviders) != catalogMaxAcceptedProviders {
		t.Fatalf("providers = %d, accepted = %d; want %d and %d", len(resp.Providers), len(resp.AcceptedProviders), catalogMaxProviders, catalogMaxAcceptedProviders)
	}
	// Sign-in entries survive truncation ahead of credential-only ones.
	for _, spec := range builtinOAuthProviders {
		catalogEntry(t, resp, spec.ID)
	}
}

type catalogTestExecutor struct{ identifier string }

func (e catalogTestExecutor) Identifier() string { return e.identifier }
func (catalogTestExecutor) Execute(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	return pluginapi.ExecutorResponse{}, nil
}
func (catalogTestExecutor) ExecuteStream(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
	return pluginapi.ExecutorStreamResponse{}, nil
}
func (catalogTestExecutor) CountTokens(context.Context, pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	return pluginapi.ExecutorResponse{}, nil
}
func (catalogTestExecutor) HttpRequest(context.Context, pluginapi.ExecutorHTTPRequest) (pluginapi.ExecutorHTTPResponse, error) {
	return pluginapi.ExecutorHTTPResponse{}, nil
}

// S20: a mixed login result is refused before any credential is written.
func TestSavePluginLoginRecordsRefusesMixedBatchBeforeWriting(t *testing.T) {
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, AcceptedProviders: []string{"antigravity"}}, coreauth.NewManager(nil, nil, nil))
	hookCalls := 0
	h.SetPostAuthHook(func(context.Context, *coreauth.Auth) error {
		hookCalls++
		return nil
	})
	err := h.savePluginLoginRecords(context.Background(), []*coreauth.Auth{
		{ID: "ok.json", FileName: "ok.json", Provider: "antigravity", Metadata: map[string]any{"type": "antigravity"}},
		{ID: "denied.json", FileName: "denied.json", Provider: "codex", Metadata: map[string]any{"type": "codex"}},
	})
	var notAccepted *providerNotAcceptedError
	if !errors.As(err, &notAccepted) {
		t.Fatalf("savePluginLoginRecords error = %v, want provider_not_accepted", err)
	}
	if hookCalls != 0 {
		t.Fatalf("persistence hook ran %d times for a refused batch, want 0", hookCalls)
	}
	entries, _ := os.ReadDir(authDir)
	if len(entries) != 0 {
		t.Fatalf("auth dir has %d entries after a refused batch, want none", len(entries))
	}
}

// S7: a plugin whose login ID (zcode-zai) differs from its runtime provider (zcode) gets a
// catalog entry under the runtime provider, which is what /credentials and quota fetch use.
func TestProviderCatalogListsRuntimeProviderOfPluginLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	cred := registerFileAuth(t, manager, authDir, &coreauth.Auth{
		ID:         "zcode-1.json",
		Provider:   "zcode",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"oauth_provider": "zcode-zai"},
		Metadata:   map[string]any{"type": "zcode", "oauth_provider": "zcode-zai"},
	}, `{"type":"zcode","oauth_provider":"zcode-zai"}`)

	host := pluginhost.New()
	host.SetAuthManager(manager)
	host.RegisterPluginForTest("zcode-plugin", pluginapi.Plugin{
		Metadata: pluginapi.Metadata{Name: "ZCode"},
		Capabilities: pluginapi.Capabilities{
			AuthProvider: &credentialOwningAuthProvider{
				mockCatalogAuthProvider: mockCatalogAuthProvider{identifier: "zcode-zai"},
				credentialProviders:     []string{"zcode"},
			},
			QuotaProvider: &mockQuotaProvider{
				identifier: "zcode",
				supported:  []string{"zcode"},
			},
		},
	})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.SetPluginHost(host)

	resp, _ := fetchCatalog(t, h)
	login := catalogEntry(t, resp, "zcode-zai")
	if login.OAuth == nil || login.Lifecycle != lifecycleActive || login.Credentials.Total != 1 {
		t.Fatalf("zcode-zai = %+v, want an active sign-in entry with its credential", login)
	}
	runtime := catalogEntry(t, resp, "zcode")
	if runtime.Source != "plugin" || runtime.PluginID == nil || *runtime.PluginID != "zcode-plugin" || runtime.Lifecycle != lifecycleActive ||
		runtime.Credentials.Total != 1 || !runtime.Quota.Supported || runtime.Quota.Reader != "plugin" {
		t.Fatalf("zcode = %+v, want an active plugin runtime entry with a plugin quota reader", runtime)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v8/management/quota/fetch", strings.NewReader(`{"auth_index":"`+cred.Index+`"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.FetchCredentialQuotaV8(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("quota fetch for the runtime provider status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// S8: a real handler response for a built-in matches ProxUI's golden fixture entry.
func TestProviderCatalogBuiltinMatchesProxUIGolden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv(acceptedProvidersEnvVar, "")
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "ag.json", Provider: "antigravity", Status: coreauth.StatusActive}, `{"type":"antigravity"}`)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	_, raw := fetchCatalog(t, h)
	var doc struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Entry copied from ProxUI tests/fixtures/providerCatalog/catalog.golden.json.
	const golden = `{"id":"antigravity","display_name":"Antigravity","source":"builtin","plugin_id":null,"logo":null,"lifecycle":"active","credentials":{"total":1,"active":1,"disabled":0,"problem":0},"oauth":{"flow":"browser","aliases":[],"manual_callback":true,"webui":true,"domains":[]},"quota":{"supported":true,"reader":"builtin","plugin_id":null,"supports_reset":false}}`
	var want map[string]any
	if err := json.Unmarshal([]byte(golden), &want); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	for _, entry := range doc.Providers {
		if entry["id"] != "antigravity" {
			continue
		}
		gotJSON, _ := json.Marshal(entry)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("antigravity entry\n got %s\nwant %s", gotJSON, wantJSON)
		}
		return
	}
	t.Fatalf("no antigravity entry")
}

// S3 and S4: quota fetch is bounded (request and response size, concurrency) and the plugin is
// invoked for the credential the binding was resolved for.
func TestFetchCredentialQuotaV8Bounds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	cred := registerFileAuth(t, manager, authDir, &coreauth.Auth{ID: "bounded.json", Provider: "bounded", Status: coreauth.StatusActive, Metadata: map[string]any{"type": "bounded"}}, `{"type":"bounded"}`)
	runtimeOnly, errRuntime := manager.Register(context.Background(), &coreauth.Auth{ID: "runtime-only", Provider: "bounded", Status: coreauth.StatusActive})
	if errRuntime != nil {
		t.Fatalf("register runtime-only: %v", errRuntime)
	}
	runtimeOnly.EnsureIndex()

	release := make(chan struct{})
	var started sync.WaitGroup
	blocking := false
	var mu sync.Mutex
	huge := false
	host := pluginhost.New()
	host.SetAuthManager(manager)
	host.RegisterPluginForTest("bounded-plugin", pluginapi.Plugin{
		Capabilities: pluginapi.Capabilities{
			QuotaProvider: &mockQuotaProvider{
				identifier: "bounded",
				fetchFn: func(ctx context.Context, req pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
					mu.Lock()
					block, big := blocking, huge
					mu.Unlock()
					if block {
						started.Done()
						<-release
					}
					if big {
						return pluginapi.QuotaFetchResponse{Groups: []pluginapi.QuotaGroup{{DisplayName: strings.Repeat("x", quotaFetchV8ResponseLimit)}}}, nil
					}
					return pluginapi.QuotaFetchResponse{}, nil
				},
			},
		},
	})
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.SetPluginHost(host)

	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/v8/management/quota/fetch", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		h.FetchCredentialQuotaV8(ctx)
		return rec
	}
	validBody := `{"auth_index":"` + cred.Index + `"}`

	if rec := post(`{"auth_index":"` + strings.Repeat("a", quotaFetchV8RequestLimit) + `"}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want 413", rec.Code)
	}
	if rec := post(validBody + strings.Repeat(" ", quotaFetchV8RequestLimit)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request with a valid prefix status = %d, want 413", rec.Code)
	}
	// A credential without a file still reaches the plugin, with its record but no storage bytes.
	if rec := post(`{"auth_index":"` + runtimeOnly.Index + `"}`); rec.Code != http.StatusOK {
		t.Fatalf("runtime-only credential status = %d, body = %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	huge = true
	mu.Unlock()
	if rec := post(validBody); rec.Code != http.StatusBadGateway {
		t.Fatalf("oversized plugin response status = %d, want 502", rec.Code)
	}
	mu.Lock()
	huge = false
	blocking = true
	mu.Unlock()

	fetch := func(ctx context.Context) (bool, error) {
		_, handled, err := host.FetchQuotaForCredential(ctx, "bounded", "", cred.Index, cred.ID)
		return handled, err
	}
	const slots = 4
	started.Add(slots)
	var done sync.WaitGroup
	for i := 0; i < slots; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			_, _ = fetch(context.Background())
		}()
	}
	started.Wait()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if handled, err := fetch(canceled); !handled || !errors.Is(err, context.Canceled) {
		t.Fatalf("call past the concurrency limit = handled %v, err %v; want it to wait for a slot", handled, err)
	}
	mu.Lock()
	blocking = false
	mu.Unlock()
	close(release)
	done.Wait()
	if rec := post(validBody); rec.Code != http.StatusOK {
		t.Fatalf("after slots free status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The credential must still be under the provider the plugin was resolved for.
	if _, err := manager.Update(context.Background(), &coreauth.Auth{ID: cred.ID, Provider: "other", Status: coreauth.StatusActive, Attributes: cred.Attributes}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if handled, err := fetch(context.Background()); !handled || err == nil {
		t.Fatalf("fetch after provider change = handled %v, err %v; want an error", handled, err)
	}
}
