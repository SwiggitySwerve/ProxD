package auth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type antigravityProbeExecutor struct {
	*usageProbeExecutor
	bodies []string
}

func (e *antigravityProbeExecutor) Identifier() string { return "antigravity" }

func (e *antigravityProbeExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	e.bodies = append(e.bodies, string(body))
	return e.usageProbeExecutor.HttpRequest(ctx, auth, req)
}

// antigravitySummary builds a quota summary with a Gemini and a Claude/GPT group.
func antigravitySummary(gemini5h, geminiWeekly, thirdParty string) string {
	bucket := func(id, fraction string) string {
		if fraction == "" {
			return `{"bucketId":"` + id + `"}`
		}
		return `{"bucketId":"` + id + `","remainingFraction":` + fraction + `}`
	}
	return `{"groups":[` +
		`{"displayName":"Gemini Models","buckets":[` + bucket("gemini-weekly", geminiWeekly) + `,` + bucket("gemini-5h", gemini5h) + `]},` +
		`{"displayName":"Claude and GPT models","buckets":[` + bucket("3p-weekly", thirdParty) + `,` + bucket("3p-5h", thirdParty) + `]}]}`
}

// newAntigravityCooledManager registers one Antigravity credential whose models
// are cooled until the reset a 429 named three hours out. Without models the
// cooldown is credential-wide.
func newAntigravityCooledManager(t *testing.T, exec *antigravityProbeExecutor, models ...string) (*Manager, string) {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(exec)
	manager.SetConfig(&internalconfig.Config{QuotaReconcile: internalconfig.QuotaReconcileConfig{
		"antigravity": {Mode: internalconfig.QuotaReconcileClear},
	}})
	next := time.Now().Add(3 * time.Hour)
	auth := &Auth{ID: "antigravity-1", Provider: "antigravity", Status: StatusActive, Metadata: map[string]any{"project_id": "synthetic-project"}}
	if len(models) == 0 {
		auth.Status, auth.Unavailable, auth.NextRetryAfter = StatusError, true, next
		auth.Quota = QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: next}
	} else {
		auth.ModelStates = make(map[string]*ModelState)
		for _, model := range models {
			auth.ModelStates[model] = &ModelState{
				Status: StatusError, Unavailable: true, NextRetryAfter: next,
				Quota: QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: next},
			}
		}
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register: %v", err)
	}
	return manager, auth.ID
}

func antigravityCooled(t *testing.T, manager *Manager, id string) bool {
	t.Helper()
	got, _ := manager.GetByID(id)
	return authHasQuotaCooldown(got)
}

// An upgrade starts fresh windows while the hub still holds the cooldown the
// last 429 set; the summary shows the Gemini group open, so it clears even
// though the Claude/GPT group is spent.
func TestAntigravityRecheckClearsWhenGeminiGroupReopens(t *testing.T) {
	exec := &antigravityProbeExecutor{usageProbeExecutor: &usageProbeExecutor{status: http.StatusOK, body: antigravitySummary("1", "0.99", "0")}}
	manager, id := newAntigravityCooledManager(t, exec, "gemini-4-neon-xhigh", "gemini-3.1-pro-preview")

	manager.reconcileQuotaCooldowns(context.Background())

	if antigravityCooled(t, manager, id) {
		t.Fatalf("cooldown kept although the Gemini group has quota left")
	}
	if len(exec.urls) != 1 || exec.urls[0] != antigravityQuotaSummaryURL {
		t.Fatalf("probe urls = %v, want one quota summary request", exec.urls)
	}
	if !strings.Contains(exec.bodies[0], `"project":"synthetic-project"`) {
		t.Fatalf("probe body = %s, want the credential's project", exec.bodies[0])
	}
}

func TestAntigravityRecheckKeepsCooldownWhileItsGroupIsSpent(t *testing.T) {
	for name, summary := range map[string]string{
		"five-hour spent":   antigravitySummary("0", "0.5", "1"),
		"weekly spent":      antigravitySummary("1", "0", "1"),
		"fraction omitted":  antigravitySummary("", "0.5", "1"),
		"no groups":         `{"groups":[]}`,
		"no matching group": `{"groups":[{"displayName":"Claude and GPT models","buckets":[{"bucketId":"3p-5h","remainingFraction":1}]}]}`,
		"boolean fraction":  antigravitySummary("true", "0.5", "1"),
		"string fraction":   antigravitySummary(`"NaN"`, "0.5", "1"),
	} {
		t.Run(name, func(t *testing.T) {
			exec := &antigravityProbeExecutor{usageProbeExecutor: &usageProbeExecutor{status: http.StatusOK, body: summary}}
			manager, id := newAntigravityCooledManager(t, exec, "gemini-4-neon-xhigh")
			manager.reconcileQuotaCooldowns(context.Background())
			if !antigravityCooled(t, manager, id) {
				t.Fatalf("cooldown cleared on %s", name)
			}
		})
	}
}

func TestAntigravityRecheckCredentialCooldownNeedsEveryGroup(t *testing.T) {
	for name, tc := range map[string]struct {
		summary string
		cooled  bool
	}{
		"one group spent": {antigravitySummary("1", "1", "0"), true},
		"all groups open": {antigravitySummary("1", "1", "1"), false},
	} {
		t.Run(name, func(t *testing.T) {
			exec := &antigravityProbeExecutor{usageProbeExecutor: &usageProbeExecutor{status: http.StatusOK, body: tc.summary}}
			manager, id := newAntigravityCooledManager(t, exec)
			manager.reconcileQuotaCooldowns(context.Background())
			if got := antigravityCooled(t, manager, id); got != tc.cooled {
				t.Fatalf("cooled = %v, want %v", got, tc.cooled)
			}
		})
	}
}

func TestAntigravityRecheckKeepsCooldownOnUnusableProbe(t *testing.T) {
	t.Run("http error", func(t *testing.T) {
		exec := &antigravityProbeExecutor{usageProbeExecutor: &usageProbeExecutor{status: http.StatusTooManyRequests, body: `{}`}}
		manager, id := newAntigravityCooledManager(t, exec, "gemini-4-neon-xhigh")
		manager.reconcileQuotaCooldowns(context.Background())
		if !antigravityCooled(t, manager, id) {
			t.Fatalf("cooldown cleared on a failed probe")
		}
	})
	t.Run("expired cooldown on another family", func(t *testing.T) {
		exec := &antigravityProbeExecutor{usageProbeExecutor: &usageProbeExecutor{status: http.StatusOK, body: antigravitySummary("1", "1", "0")}}
		manager, id := newAntigravityCooledManager(t, exec, "gemini-4-neon-xhigh", "claude-opus-5-5-high")
		got, _ := manager.GetByID(id)
		expired := got.ModelStates["claude-opus-5-5-high"]
		expired.Quota.NextRecoverAt = time.Now().Add(-time.Minute)
		expired.NextRetryAfter = time.Now().Add(-time.Minute)
		if _, err := manager.Update(context.Background(), got); err != nil {
			t.Fatalf("update: %v", err)
		}
		if got, _ := manager.GetByID(id); isModelStateActiveCooldown(got.ModelStates["claude-opus-5-5-high"], time.Now()) {
			t.Fatal("fixture: the Claude cooldown should already be expired")
		}
		manager.reconcileQuotaCooldowns(context.Background())
		if got, _ := manager.GetByID(id); isModelStateActiveCooldown(got.ModelStates["gemini-4-neon-xhigh"], time.Now()) {
			t.Fatalf("Gemini cooldown kept because an expired Claude cooldown asked for the spent Claude/GPT group")
		}
	})
	t.Run("unknown model family", func(t *testing.T) {
		exec := &antigravityProbeExecutor{usageProbeExecutor: &usageProbeExecutor{status: http.StatusOK, body: antigravitySummary("1", "1", "1")}}
		manager, id := newAntigravityCooledManager(t, exec, "gemini-4-neon-xhigh", "tab_flash_lite_preview")
		manager.reconcileQuotaCooldowns(context.Background())
		if !antigravityCooled(t, manager, id) {
			t.Fatalf("cooldown cleared although one cooled model matches no quota group")
		}
		if exec.calls != 0 {
			t.Fatalf("probe calls = %d, want none before the cooled models are known", exec.calls)
		}
	})
}

// allCooledSummaryExecutor answers the adapter's quota summary request.
type allCooledSummaryExecutor struct {
	*allCooledExecutor
	summary string
}

func (e *allCooledSummaryExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(e.summary))}, nil
}

// The case that blocked Neon: one credential, its Gemini models cooled by a
// 429 until a reset hours away, and the limit already lifted upstream. The next
// request rechecks the summary at once and is served.
func TestAntigravityAllCooledRequestRechecksAndIsServed(t *testing.T) {
	f := newAllCooledFixtureFor(t, "antigravity", nil, internalconfig.QuotaReconcileClear)
	f.manager.RegisterExecutor(&allCooledSummaryExecutor{allCooledExecutor: f.executor, summary: antigravitySummary("1", "1", "0")})
	id, model := "antigravity-a", "gemini-all-cooled-recheck"
	f.model = model
	if _, err := f.manager.Register(WithSkipPersist(context.Background()), &Auth{
		ID: id, Provider: "antigravity", Status: StatusActive, Metadata: map[string]any{"project_id": "synthetic-project"},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "antigravity", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	retry := 3 * time.Hour
	f.manager.MarkResult(context.Background(), Result{
		AuthID: id, Provider: "antigravity", Model: model, Success: false, RetryAfter: &retry,
		Error: &Error{Message: "Individual quota reached.", HTTPStatus: http.StatusTooManyRequests},
	})
	if !f.cooled(id) {
		t.Fatal("credential is not cooled after the 429")
	}
	f.executor.lift(id)

	if _, err := f.execute(cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("Execute error = %v, want the request served after the recheck", err)
	}
	if f.cooled(id) {
		t.Fatal("allowed summary did not clear the cooldown")
	}
}
