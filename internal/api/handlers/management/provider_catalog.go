package management

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/kimi"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/htmlsanitize"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/redisqueue"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

const (
	providerCatalogSchemaVersion = 1
	acceptedProvidersEnvVar      = "CLIPROXY_ACCEPTED_PROVIDERS"
)

const (
	lifecycleAwaitingAuth   = "awaiting_auth"
	lifecycleActive         = "active"
	lifecycleDisabled       = "disabled"
	lifecycleNeedsAttention = "needs_attention"
)

type providerCatalogResponse struct {
	SchemaVersion     int                    `json:"schema_version"`
	InstanceID        *string                `json:"instance_id"`
	AcceptedProviders []string               `json:"accepted_providers"`
	Providers         []providerCatalogEntry `json:"providers"`
}

type providerCatalogEntry struct {
	ID          string                     `json:"id"`
	DisplayName string                     `json:"display_name"`
	Source      string                     `json:"source"`
	PluginID    *string                    `json:"plugin_id"`
	Logo        *string                    `json:"logo"`
	Lifecycle   string                     `json:"lifecycle"`
	Credentials providerCatalogCredentials `json:"credentials"`
	OAuth       *providerCatalogOAuth      `json:"oauth"`
	Quota       providerCatalogQuota       `json:"quota"`
}

type providerCatalogCredentials struct {
	Total    int `json:"total"`
	Active   int `json:"active"`
	Disabled int `json:"disabled"`
	Problem  int `json:"problem"`
}

type providerCatalogOAuth struct {
	Flow           string   `json:"flow"`
	Aliases        []string `json:"aliases"`
	ManualCallback bool     `json:"manual_callback"`
	WebUI          bool     `json:"webui"`
	Domains        []string `json:"domains"`
}

type providerCatalogQuota struct {
	Supported     bool    `json:"supported"`
	Reader        string  `json:"reader"`
	PluginID      *string `json:"plugin_id"`
	SupportsReset bool    `json:"supports_reset"`
}

type builtinOAuthProviderSpec struct {
	ID             string
	DisplayName    string
	Flow           string
	Aliases        []string
	ManualCallback bool
	WebUI          bool
	Domains        []string
	QuotaSupported bool
	SupportsReset  bool
	Start          func(*Handler, *gin.Context)
}

// builtinOAuthProviders is the single source of truth shared by StartOAuthV8 and
// GET /v8/management/providers. It is filled in init because its Start handlers reach
// saveTokenRecord, which reads this table through the allowlist check.
var builtinOAuthProviders []builtinOAuthProviderSpec

func init() {
	builtinOAuthProviders = []builtinOAuthProviderSpec{
		{
			ID:             "claude",
			DisplayName:    "Claude",
			Flow:           "browser",
			Aliases:        []string{"anthropic"},
			ManualCallback: true,
			WebUI:          true,
			Domains:        []string{},
			QuotaSupported: true,
			SupportsReset:  true,
			Start:          (*Handler).RequestAnthropicToken,
		},
		{
			ID:             "codex",
			DisplayName:    "Codex",
			Flow:           "browser",
			Aliases:        []string{},
			ManualCallback: true,
			WebUI:          true,
			Domains:        []string{},
			QuotaSupported: true,
			SupportsReset:  true,
			Start:          (*Handler).RequestCodexToken,
		},
		{
			ID:             "antigravity",
			DisplayName:    "Gemini / Antigravity",
			Flow:           "browser",
			Aliases:        []string{},
			ManualCallback: true,
			WebUI:          true,
			Domains:        []string{},
			QuotaSupported: true,
			SupportsReset:  false,
			Start:          (*Handler).RequestAntigravityToken,
		},
		{
			ID:             "kimi",
			DisplayName:    "Kimi (kimi.com)",
			Flow:           "device",
			Aliases:        []string{},
			ManualCallback: false,
			WebUI:          false,
			Domains:        []string{"kimi.com"},
			QuotaSupported: false,
			SupportsReset:  false,
			Start:          (*Handler).RequestKimiToken,
		},
		{
			ID:             "kimi-ai",
			DisplayName:    "Kimi (kimi.ai)",
			Flow:           "device",
			Aliases:        []string{},
			ManualCallback: false,
			WebUI:          false,
			Domains:        []string{"kimi.ai"},
			QuotaSupported: false,
			SupportsReset:  false,
			Start:          (*Handler).RequestKimiAIToken,
		},
		{
			ID:             "xai",
			DisplayName:    "xAI",
			Flow:           "device",
			Aliases:        []string{},
			ManualCallback: false,
			WebUI:          false,
			Domains:        []string{},
			QuotaSupported: false,
			SupportsReset:  false,
			Start:          (*Handler).RequestXAIToken,
		},
		{
			ID:             "devin",
			DisplayName:    "Devin",
			Flow:           "browser",
			Aliases:        []string{},
			ManualCallback: true,
			WebUI:          true,
			Domains:        []string{},
			QuotaSupported: false,
			SupportsReset:  false,
			Start:          (*Handler).RequestDevinToken,
		},
		{
			ID:             "meta",
			DisplayName:    "Meta",
			Flow:           "device",
			Aliases:        []string{},
			ManualCallback: false,
			WebUI:          false,
			Domains:        []string{},
			QuotaSupported: false,
			SupportsReset:  false,
			Start:          (*Handler).RequestMetaToken,
		},
	}
}

func findBuiltinOAuthProvider(provider string) (builtinOAuthProviderSpec, bool) {
	key := strings.ToLower(strings.TrimSpace(provider))
	if key == "" {
		return builtinOAuthProviderSpec{}, false
	}
	for _, spec := range builtinOAuthProviders {
		if spec.ID == key {
			return spec, true
		}
	}
	return builtinOAuthProviderSpec{}, false
}

func (h *Handler) dispatchBuiltinOAuthV8(c *gin.Context, provider string) bool {
	spec, ok := findBuiltinOAuthProvider(provider)
	if !ok || spec.Start == nil {
		return false
	}
	spec.Start(h, c)
	return true
}

func canonicalBuiltinProviderKey(provider string) string {
	key := strings.ToLower(strings.TrimSpace(provider))
	if key == "" {
		return ""
	}
	for _, spec := range builtinOAuthProviders {
		if spec.ID == key {
			return spec.ID
		}
		for _, alias := range spec.Aliases {
			if alias == key {
				return spec.ID
			}
		}
	}
	return key
}

type providerNotAcceptedError struct {
	Provider          string
	AcceptedProviders []string
}

func (e *providerNotAcceptedError) Error() string {
	return fmt.Sprintf("provider %q is not accepted by this hub", e.Provider)
}

func (e *providerNotAcceptedError) responseBody() gin.H {
	accepted := make([]string, len(e.AcceptedProviders))
	copy(accepted, e.AcceptedProviders)
	return gin.H{
		"error":              "provider_not_accepted",
		"provider":           e.Provider,
		"accepted_providers": accepted,
	}
}

// normalizeProviderList lowercases, trims and dedupes provider IDs and folds built-in aliases
// (anthropic -> claude), so every entry is in the identity space signInProviderID uses.
func normalizeProviderList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, raw := range items {
		id := canonicalBuiltinProviderKey(raw)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (h *Handler) effectiveAcceptedProviders() []string {
	if rawEnv, ok := os.LookupEnv(acceptedProvidersEnvVar); ok {
		trimmed := strings.TrimSpace(rawEnv)
		if trimmed != "" {
			parts := strings.Split(trimmed, ",")
			if normalized := normalizeProviderList(parts); len(normalized) > 0 {
				return normalized
			}
		}
	}
	if h == nil {
		return nil
	}
	cfg := h.configSnapshot()
	if cfg == nil {
		return nil
	}
	return normalizeProviderList(cfg.AcceptedProviders)
}

// signInProviderID is the one provider identity used for admission: the sign-in provider that
// StartOAuthV8 takes and the catalog lists as a sign-in entry (a plugin portal, or kimi vs kimi-ai
// by domain), with built-in aliases folded. A credential whose provider is itself a sign-in
// provider keeps it. Otherwise a portal hint counts only when the plugin owning that portal also
// owns the credential's provider; failing that, the credential's own provider is its identity.
func (h *Handler) signInProviderID(auth *coreauth.Auth) string {
	if auth == nil {
		return ""
	}
	runtimeID := canonicalBuiltinProviderKey(auth.Provider)
	switch runtimeID {
	case "kimi", "kimi-ai", "kimi.ai", "kimi.com":
		// Built-in Kimi picks its sign-in entry from the credential's domain alone.
		if kimi.IsKimiAIAuth(auth) {
			return "kimi-ai"
		}
		return "kimi"
	}
	if _, builtin := findBuiltinOAuthProvider(runtimeID); builtin {
		// Built-in login dispatch wins over plugins, so no portal hint relabels it.
		return runtimeID
	}
	h.mu.Lock()
	host := h.pluginHost
	h.mu.Unlock()
	if host == nil {
		return runtimeID
	}
	for _, loginID := range host.AuthProviderIdentifiers() {
		if loginID == runtimeID {
			return runtimeID
		}
	}
	signInID := canonicalBuiltinProviderKey(h.resolveTargetOAuthProvider(auth))
	if signInID != runtimeID && host.SameAuthProvider(signInID, auth.Provider) {
		return signInID
	}
	return runtimeID
}

// checkAcceptedProvider admits a sign-in provider ID only when it is listed exactly (after alias
// folding); an unset allowlist admits everything.
func (h *Handler) checkAcceptedProvider(provider string) error {
	accepted := h.effectiveAcceptedProviders()
	if len(accepted) == 0 {
		return nil
	}
	id := canonicalBuiltinProviderKey(provider)
	for _, allowed := range accepted {
		if allowed == id {
			return nil
		}
	}
	return &providerNotAcceptedError{
		Provider:          id,
		AcceptedProviders: accepted,
	}
}

// checkAcceptedAuth admits a credential by its sign-in provider before it is persisted.
func (h *Handler) checkAcceptedAuth(auth *coreauth.Auth) error {
	if auth == nil {
		return nil
	}
	return h.checkAcceptedProvider(h.signInProviderID(auth))
}

func (h *Handler) rejectIfProviderNotAccepted(c *gin.Context, provider string) bool {
	var notAccepted *providerNotAcceptedError
	if !errors.As(h.checkAcceptedProvider(provider), &notAccepted) {
		return false
	}
	c.JSON(http.StatusConflict, notAccepted.responseBody())
	return true
}

func credentialLifecycle(auth *coreauth.Auth) string {
	return credentialLifecycleAt(auth, time.Now().UTC())
}

func credentialLifecycleAt(auth *coreauth.Auth, now time.Time) string {
	if auth == nil {
		return lifecycleAwaitingAuth
	}
	if auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return lifecycleDisabled
	}
	unavailable, status, _, _ := reconcileAuthFileCooldownState(auth, now)
	if auth.RequiresSignIn || status == coreauth.StatusError || unavailable {
		return lifecycleNeedsAttention
	}
	return lifecycleActive
}

// deriveProviderLifecycle applies the roadmap rule: any credential needing attention wins over
// healthy ones; disabled only when none is active.
func deriveProviderLifecycle(creds providerCatalogCredentials) string {
	switch {
	case creds.Total == 0:
		return lifecycleAwaitingAuth
	case creds.Problem > 0:
		return lifecycleNeedsAttention
	case creds.Active > 0:
		return lifecycleActive
	default:
		return lifecycleDisabled
	}
}

// collectProviderCredentialCounts counts each listable credential under its runtime provider (the
// provider /credentials and quota fetch report, unfolded) and, when it differs, under its sign-in
// provider too, so sign-in entries and runtime entries both reflect the credentials they own. It
// also reports which runtime providers have a credential the host serves natively (a config API
// key or an OpenAI-compatible credential with its own endpoint).
func (h *Handler) collectProviderCredentialCounts(now time.Time) (map[string]providerCatalogCredentials, map[string]bool) {
	counts := make(map[string]providerCatalogCredentials)
	native := make(map[string]bool)
	if h == nil || h.authManager == nil {
		return counts, native
	}
	add := func(providerID, lifecycle string) {
		entry := counts[providerID]
		entry.Total++
		switch lifecycle {
		case lifecycleDisabled:
			entry.Disabled++
		case lifecycleNeedsAttention:
			entry.Problem++
		default:
			entry.Active++
		}
		counts[providerID] = entry
	}
	for _, auth := range h.authManager.List() {
		if !isAuthFileListable(auth, true) {
			continue
		}
		runtimeID := strings.ToLower(strings.TrimSpace(auth.Provider))
		if runtimeID == "" {
			continue
		}
		lifecycle := credentialLifecycleAt(auth, now)
		add(runtimeID, lifecycle)
		if signInID := h.signInProviderID(auth); signInID != "" && signInID != runtimeID {
			add(signInID, lifecycle)
		}
		if coreauth.IsConfigAPIKeyAuth(auth) || authAttribute(auth, "base_url") != "" || authAttribute(auth, "compat_name") != "" {
			native[runtimeID] = true
		}
	}
	return counts, native
}

// nativeRuntimeProviders are the built-in runtime providers that have no OAuth sign-in entry
// (see baselineExecutorAuths in sdk/cliproxy/service_executors.go).
var nativeRuntimeProviders = map[string]bool{
	constant.Gemini:             true,
	constant.GeminiInteractions: true,
	"vertex":                    true,
	"aistudio":                  true,
	"openai-compatibility":      true,
}

// ProxUI rejects a catalog with more entries than these.
const (
	catalogMaxProviders         = 256
	catalogMaxAcceptedProviders = 128
)

var catalogProviderIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// catalogDisplayNameMaxUnits is ProxUI's display_name cap, counted in UTF-16 code units.
const catalogDisplayNameMaxUnits = 128

func isCatalogWhitespace(r rune) bool {
	return unicode.IsSpace(r) || r == '\uFEFF'
}

// catalogDisplayName sanitizes and trims a display name to ProxUI's limit, falling back when empty.
func catalogDisplayName(raw, fallback string) string {
	name := strings.TrimFunc(htmlsanitize.String(raw), isCatalogWhitespace)
	units := 0
	for index, r := range name {
		width := 1
		if r > 0xFFFF {
			width = 2
		}
		if units+width > catalogDisplayNameMaxUnits {
			name = strings.TrimFunc(name[:index], isCatalogWhitespace)
			break
		}
		units += width
	}
	if name == "" {
		return fallback
	}
	return name
}

// wireProviderIDs keeps only IDs ProxUI's slug rule accepts, up to its list limit; nil stays nil
// (an open hub).
func wireProviderIDs(ids []string) []string {
	if ids == nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if catalogProviderIDPattern.MatchString(id) && len(out) < catalogMaxAcceptedProviders {
			out = append(out, id)
		}
	}
	return out
}

func nonEmptyStringPtr(raw string) *string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func cloneNonNilStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func ifNoneMatchMatches(headerVal, etag string) bool {
	if strings.TrimSpace(headerVal) == "" || etag == "" {
		return false
	}
	cleanTarget := strings.TrimPrefix(strings.TrimSpace(etag), "W/")
	for _, part := range strings.Split(headerVal, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == cleanTarget {
			return true
		}
	}
	return false
}

// GetProviderCatalogV8 returns the authoritative catalog of providers this ProxD hub
// exposes (built-in and plugin-backed), including OAuth, quota, and lifecycle metadata.
// Every supported provider is listed; accepted_providers says which of them this hub takes.
func (h *Handler) GetProviderCatalogV8(c *gin.Context) {
	now := time.Now().UTC()
	var host *pluginhost.Host
	if h != nil {
		h.mu.Lock()
		host = h.pluginHost
		h.mu.Unlock()
	}

	accepted := h.effectiveAcceptedProviders()
	counts, nativeProviders := h.collectProviderCredentialCounts(now)

	quotaPluginIDs := map[string]string{}
	quotaSupportsResetByPlugin := map[string]bool{}
	var registeredQuotaProviders []pluginhost.RegisteredQuotaProviderInfo
	var registeredPlugins []pluginhost.RegisteredPluginInfo
	pluginNames := map[string]string{}
	if host != nil {
		ctx := c.Request.Context()
		quotaPluginIDs = host.QuotaProviderPluginIDs(ctx)
		registeredQuotaProviders = host.QuotaProviders(ctx)
		for _, qp := range registeredQuotaProviders {
			if qp.PluginID != "" {
				quotaSupportsResetByPlugin[qp.PluginID] = qp.SupportsReset
			}
		}
		registeredPlugins = host.RegisteredPlugins()
		for _, info := range registeredPlugins {
			pluginNames[info.ID] = info.Metadata.Name
		}
	}

	resolveQuota := func(providerID string, builtinSupported, builtinReset bool) providerCatalogQuota {
		if pluginID := strings.TrimSpace(quotaPluginIDs[providerID]); pluginID != "" {
			pid := htmlsanitize.String(pluginID)
			return providerCatalogQuota{
				Supported:     true,
				Reader:        "plugin",
				PluginID:      &pid,
				SupportsReset: quotaSupportsResetByPlugin[pluginID],
			}
		}
		if builtinSupported {
			return providerCatalogQuota{
				Supported:     true,
				Reader:        "builtin",
				PluginID:      nil,
				SupportsReset: builtinReset,
			}
		}
		return providerCatalogQuota{
			Supported:     false,
			Reader:        "none",
			PluginID:      nil,
			SupportsReset: false,
		}
	}

	entriesByID := make(map[string]providerCatalogEntry)

	// 1. Built-in OAuth providers from the single source-of-truth table.
	for _, spec := range builtinOAuthProviders {
		creds := counts[spec.ID]
		entriesByID[spec.ID] = providerCatalogEntry{
			ID:          spec.ID,
			DisplayName: spec.DisplayName,
			Source:      "builtin",
			PluginID:    nil,
			Logo:        nil,
			Lifecycle:   deriveProviderLifecycle(creds),
			Credentials: creds,
			OAuth: &providerCatalogOAuth{
				Flow:           spec.Flow,
				Aliases:        cloneNonNilStrings(spec.Aliases),
				ManualCallback: spec.ManualCallback,
				WebUI:          spec.WebUI,
				Domains:        cloneNonNilStrings(spec.Domains),
			},
			Quota: resolveQuota(spec.ID, spec.QuotaSupported, spec.SupportsReset),
		}
	}

	// 2. Active plugin OAuth providers. Login dispatch tries built-ins first and then plugins in
	// snapshot order, so an ID already listed keeps its earlier owner. The host runs every plugin
	// login as a browser flow through the management callback (ServePluginAuthURL), which is what
	// the oauth descriptor states; the plugin API declares no other flow.
	for _, info := range registeredPlugins {
		pluginID := htmlsanitize.String(strings.TrimSpace(info.ID))
		if pluginID == "" {
			continue
		}
		fallbackLogo := htmlsanitize.String(strings.TrimSpace(info.Metadata.Logo))

		addPluginEntry := func(rawID, rawName, rawLogo string) {
			id := strings.ToLower(strings.TrimSpace(rawID))
			if id == "" {
				return
			}
			if _, exists := entriesByID[id]; exists {
				return
			}
			displayName := catalogDisplayName(rawName, catalogDisplayName(info.Metadata.Name, id))
			logoStr := htmlsanitize.String(strings.TrimSpace(rawLogo))
			if logoStr == "" {
				logoStr = fallbackLogo
			}
			pid := pluginID
			creds := counts[id]
			entry := providerCatalogEntry{
				ID:          id,
				DisplayName: displayName,
				Source:      "plugin",
				PluginID:    &pid,
				Logo:        nonEmptyStringPtr(logoStr),
				Lifecycle:   deriveProviderLifecycle(creds),
				Credentials: creds,
				Quota:       resolveQuota(id, false, false),
			}
			// Advertise sign-in only for IDs the plugin OAuth start and callback routes accept.
			if _, errRoute := NormalizePluginOAuthCallbackProvider(id); errRoute == nil {
				entry.OAuth = &providerCatalogOAuth{
					Flow:           "browser",
					Aliases:        []string{},
					ManualCallback: true,
					WebUI:          true,
					Domains:        []string{},
				}
			}
			entriesByID[id] = entry
		}

		if len(info.OAuthProviderEntries) > 0 {
			for _, oauthEntry := range info.OAuthProviderEntries {
				addPluginEntry(oauthEntry.Identifier, oauthEntry.Name, oauthEntry.Logo)
			}
		} else if len(info.OAuthProviders) > 0 {
			for _, ident := range info.OAuthProviders {
				addPluginEntry(ident, "", "")
			}
		} else if strings.TrimSpace(info.OAuthProvider) != "" {
			addPluginEntry(info.OAuthProvider, "", "")
		}
	}

	// 3. Quota-only plugin providers (no OAuth capability registered).
	for _, qp := range registeredQuotaProviders {
		candidates := qp.SupportedProviders
		if len(candidates) == 0 && strings.TrimSpace(qp.Provider) != "" {
			candidates = []string{qp.Provider}
		}
		for _, rawID := range candidates {
			id := strings.ToLower(strings.TrimSpace(rawID))
			if id == "" {
				continue
			}
			if _, exists := entriesByID[id]; exists {
				continue
			}
			pid := htmlsanitize.String(strings.TrimSpace(qp.PluginID))
			creds := counts[id]
			entriesByID[id] = providerCatalogEntry{
				ID:          id,
				DisplayName: catalogDisplayName(qp.DisplayName, id),
				Source:      "plugin",
				PluginID:    nonEmptyStringPtr(pid),
				Logo:        nil,
				Lifecycle:   deriveProviderLifecycle(creds),
				Credentials: creds,
				OAuth:       nil,
				Quota:       resolveQuota(id, false, false),
			}
		}
	}

	// 4. Credential-bearing providers not listed yet: runtime providers of plugin logins whose
	// login ID differs, and uploaded or imported credentials. One that no active plugin owns and
	// the host does not serve natively belongs to a plugin that is not loaded, so it is a disabled
	// plugin provider rather than an active built-in. (An executor is no evidence: the host binds a
	// generic OpenAI-compatible executor to any unknown provider.)
	for providerID, creds := range counts {
		if _, exists := entriesByID[providerID]; exists {
			continue
		}
		entry := providerCatalogEntry{
			ID:          providerID,
			DisplayName: catalogDisplayName(providerID, providerID),
			Source:      "builtin",
			Lifecycle:   deriveProviderLifecycle(creds),
			Credentials: creds,
			Quota:       resolveQuota(providerID, false, false),
		}
		// Native providers keep their built-in executor even when a plugin extends them, as
		// executor registration does, so they stay built-in.
		ownerPluginID := ""
		native := nativeRuntimeProviders[providerID] || nativeProviders[providerID]
		if host != nil && !native {
			ownerPluginID = host.AuthProviderPluginID(providerID)
			if ownerPluginID == "" {
				ownerPluginID = quotaPluginIDs[providerID]
			}
			if ownerPluginID == "" {
				ownerPluginID = host.ExecutorPluginID(providerID)
			}
		}
		if ownerPluginID != "" {
			entry.Source = "plugin"
			entry.PluginID = nonEmptyStringPtr(htmlsanitize.String(ownerPluginID))
			entry.DisplayName = catalogDisplayName(pluginNames[ownerPluginID], entry.DisplayName)
		} else if !native {
			entry.Source = "plugin"
			entry.Lifecycle = lifecycleDisabled
		}
		entriesByID[providerID] = entry
	}

	// ProxUI rejects the whole catalog when one ID breaks its slug rule, so such providers
	// (e.g. an OpenAI-compatible name with spaces) are left out.
	ids := make([]string, 0, len(entriesByID))
	for id := range entriesByID {
		if catalogProviderIDPattern.MatchString(id) {
			ids = append(ids, id)
		}
	}
	if len(ids) > catalogMaxProviders {
		// Keep sign-in and quota-capable providers before credential-only ones.
		capable := func(entry providerCatalogEntry) bool { return entry.OAuth != nil || entry.Quota.Supported }
		sort.Slice(ids, func(i, j int) bool {
			ci, cj := capable(entriesByID[ids[i]]), capable(entriesByID[ids[j]])
			if ci != cj {
				return ci
			}
			return ids[i] < ids[j]
		})
		log.Warnf("provider catalog truncated to %d of %d providers", catalogMaxProviders, len(ids))
		ids = ids[:catalogMaxProviders]
	}
	sort.Strings(ids)

	providers := make([]providerCatalogEntry, 0, len(ids))
	for _, id := range ids {
		providers = append(providers, entriesByID[id])
	}

	var instanceIDPtr *string
	if instanceID := redisqueue.DeploymentInstanceID(); instanceID != "" {
		instanceIDPtr = &instanceID
	}

	resp := providerCatalogResponse{
		SchemaVersion:     providerCatalogSchemaVersion,
		InstanceID:        instanceIDPtr,
		AcceptedProviders: wireProviderIDs(accepted),
		Providers:         providers,
	}

	payload, errMarshal := json.Marshal(resp)
	if errMarshal != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode provider catalog"})
		return
	}

	// Weak: the same representation may be served identity, gzip or zstd encoded.
	sum := sha256.Sum256(payload)
	etag := `W/"` + hex.EncodeToString(sum[:]) + `"`
	c.Header("ETag", etag)
	c.Header("Cache-Control", "no-cache")
	if ifNoneMatchMatches(c.GetHeader("If-None-Match"), etag) {
		c.Status(http.StatusNotModified)
		c.Writer.WriteHeaderNow()
		return
	}

	c.Data(http.StatusOK, "application/json; charset=utf-8", payload)
}
