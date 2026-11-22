package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
)

const antigravityQuotaSummaryURL = "https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary"

// antigravityQuotaRecheckAdapter rechecks Antigravity credentials against
// Google's quota summary. A 429 stores the reset Google named at that moment,
// but the limit can lift sooner: an upgrade (for example Google AI Ultra Lite
// to Ultra) starts fresh windows at once. Without a recheck the stale cooldown
// blocks the credential until the old reset.
//
// The summary groups models by family ("Gemini Models", "Claude and GPT
// models"); the models of a group share its weekly and five-hour buckets. The
// verdict is allowed only when every bucket of every group a cooled model draws
// from has quota left. A cooled model no group can be matched to, an empty
// summary or a failed request keeps the cooldown.
type antigravityQuotaRecheckAdapter struct{}

func (antigravityQuotaRecheckAdapter) Provider() string { return "antigravity" }

// UsageSnapshot returns the quota snapshot already stored from the last
// response; it makes no upstream call.
func (antigravityQuotaRecheckAdapter) UsageSnapshot(_ context.Context, _ QuotaRecheckHost, auth *Auth) (QuotaUsageSnapshot, error) {
	return QuotaUsageSnapshot{Signals: auth.Quota.Clone().Signals, ObservedAt: auth.Quota.ObservedAt}, nil
}

func (antigravityQuotaRecheckAdapter) Verdict(ctx context.Context, host QuotaRecheckHost, auth *Auth) (QuotaVerdict, error) {
	families, err := antigravityCooledFamilies(auth)
	if err != nil {
		return QuotaVerdict{}, err
	}
	projectID, _ := auth.Metadata["project_id"].(string)
	if strings.TrimSpace(projectID) == "" {
		return QuotaVerdict{}, errors.New("quota summary needs the credential's project id")
	}
	payload, err := json.Marshal(map[string]string{"project": strings.TrimSpace(projectID)})
	if err != nil {
		return QuotaVerdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, antigravityQuotaSummaryURL, bytes.NewReader(payload))
	if err != nil {
		return QuotaVerdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := host.HttpRequest(ctx, auth, req)
	if err != nil {
		return QuotaVerdict{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, quotaProbeMaxBody))
	if err != nil {
		return QuotaVerdict{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return QuotaVerdict{}, fmt.Errorf("quota summary returned HTTP %d", resp.StatusCode)
	}
	return antigravitySummaryVerdict(body, families)
}

// antigravityCooledFamilies returns the model families whose quota groups must
// be open before the credential's cooldowns may clear. A credential-wide
// cooldown, or one no model state explains, needs every group, reported as a
// nil slice. A model 429 also marks the credential's aggregate quota, so only
// a credential_quota reason counts as credential-wide.
func antigravityCooledFamilies(auth *Auth) ([]string, error) {
	if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" {
		return nil, nil
	}
	seen := make(map[string]bool)
	var families []string
	for model, state := range auth.ModelStates {
		if state == nil || !state.Quota.Exceeded {
			continue
		}
		family := antigravityQuotaFamily(model)
		if family == "" {
			return nil, fmt.Errorf("no quota group is known for model %q", model)
		}
		if !seen[family] {
			seen[family] = true
			families = append(families, family)
		}
	}
	if len(families) == 0 {
		if auth.Quota.Exceeded {
			return nil, nil
		}
		return nil, errors.New("credential holds no quota cooldown")
	}
	return families, nil
}

// antigravityQuotaFamily names the family a model id draws quota from, matched
// against the summary's group names. Unknown ids return "".
func antigravityQuotaFamily(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	for _, family := range []string{"gemini", "claude", "gpt"} {
		if strings.HasPrefix(model, family+"-") {
			return family
		}
	}
	return ""
}

// antigravitySummaryVerdict judges a retrieveUserQuotaSummary body. families
// nil means every group counts. A bucket without remainingFraction is spent:
// the summary omits zero values.
func antigravitySummaryVerdict(body []byte, families []string) (QuotaVerdict, error) {
	groups := ojson.GetBytes(body, "groups").Array()
	if len(groups) == 0 {
		return QuotaVerdict{}, errors.New("quota summary has no groups")
	}
	verdict := QuotaVerdict{State: QuotaVerdictAllowed, Signals: make(map[string]string), ObservedAt: time.Now(), Source: "quota-summary"}
	matched := make(map[string]bool)
	for _, group := range groups {
		name := strings.ToLower(group.Get("displayName").String())
		counts := families == nil
		for _, family := range families {
			if strings.Contains(name, family) {
				counts = true
				matched[family] = true
			}
		}
		if !counts {
			continue
		}
		buckets := group.Get("buckets").Array()
		if len(buckets) == 0 {
			return QuotaVerdict{}, fmt.Errorf("quota group %q has no buckets", name)
		}
		for _, bucket := range buckets {
			fraction := bucket.Get("remainingFraction")
			verdict.Signals[bucket.Get("bucketId").String()] = fraction.String()
			if fraction.Float() <= 0 {
				verdict.State = QuotaVerdictLimited
			}
		}
	}
	for _, family := range families {
		if !matched[family] {
			return QuotaVerdict{}, fmt.Errorf("quota summary has no group for %s models", family)
		}
	}
	return verdict, nil
}
