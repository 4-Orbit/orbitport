package authz

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// explainBundle is the default 4Orbit organization plus rules that produce
// the explanation kinds the default set alone cannot: a forbid that overrides
// a permit, a grant that has not started yet, and a tag condition.
func explainBundle(t *testing.T) *Compiled {
	t.Helper()
	b := DefaultBundle()
	b.Policies += `
@id("developer-encrypt-prod-key")
permit (principal in Role::"developer", action == Action::"kms.Encrypt", resource == Key::"prod-key");

@id("no-prod-for-developers")
forbid (principal in Role::"developer", action, resource == Key::"prod-key");

@id("deployment-sign-release-key-from-2030")
permit (principal in Role::"deployment", action == Action::"kms.Sign", resource == Key::"release-key")
when { context.currentTime >= 1900000000 };

@id("security-sign-tagged-dev")
permit (principal in Role::"security", action == Action::"kms.Sign", resource)
when { resource.hasTag("env") && resource.getTag("env") == "dev" };
`
	return mustCompile(t, b)
}

func explainReq(agent, action, key string) Request {
	return Request{Principal: Principal{Tenant: tenant, AgentID: agent}, Action: action, Resource: Resource{ID: key}}
}

func TestExplainKinds(t *testing.T) {
	c := explainBundle(t)
	expiry := time.Unix(1_800_000_000, 0)

	cases := []struct {
		name string
		c    *Compiled
		req  Request
		at   time.Time
		kind string
		// Optional checks on the explanation.
		check func(t *testing.T, e Explanation)
	}{
		{
			name: "allowed", c: c, req: explainReq("developer-agent", "kms.Encrypt", "dev-key"), at: beforeExpiry, kind: KindAllowed,
			check: func(t *testing.T, e Explanation) {
				if e.Decision != Allow || !reflect.DeepEqual(e.DeterminingPolicies, []string{"developer-encrypt-dev-key"}) {
					t.Errorf("want ALLOW by developer-encrypt-dev-key, got %+v", e)
				}
			},
		},
		{
			name: "blocked by a tenant forbid, naming the permit it overrode", c: c,
			req: explainReq("developer-agent", "kms.Encrypt", "prod-key"), at: beforeExpiry, kind: KindBlocked,
			check: func(t *testing.T, e Explanation) {
				if !reflect.DeepEqual(e.BlockedBy, []Blocker{{PolicyID: "no-prod-for-developers"}}) {
					t.Errorf("blockedBy = %+v", e.BlockedBy)
				}
				if len(e.Candidates) != 1 || e.Candidates[0].PolicyID != "developer-encrypt-prod-key" {
					t.Errorf("want the overridden permit as candidate, got %+v", e.Candidates)
				}
			},
		},
		{
			name: "blocked by the platform tenant fence", c: c,
			req: Request{Principal: Principal{Tenant: tenant, AgentID: "developer-agent"}, Action: "kms.Encrypt", Resource: Resource{ID: "dev-key", Tenant: "tenant-b"}},
			at:  beforeExpiry, kind: KindBlocked,
			check: func(t *testing.T, e Explanation) {
				if !reflect.DeepEqual(e.BlockedBy, []Blocker{{PolicyID: "platform.tenant-fence", Platform: true}}) {
					t.Errorf("blockedBy = %+v", e.BlockedBy)
				}
			},
		},
		{
			name: "expired at the US5 boundary", c: c, req: explainReq("developer-agent", "kms.Encrypt", "demo-key"), at: expiry, kind: KindExpired,
			check: func(t *testing.T, e Explanation) {
				best := e.Candidates[0]
				if best.PolicyID != "developer-encrypt-demo-key" || best.Window == nil || *best.Window != (TimeWindow{Kind: "expired", At: 1_800_000_000}) {
					t.Errorf("want demo-key grant expired at 1800000000, got %+v", best)
				}
			},
		},
		{
			name: "not yet valid", c: c, req: explainReq("deployment-agent", "kms.Sign", "release-key"), at: beforeExpiry, kind: KindNotYet,
			check: func(t *testing.T, e Explanation) {
				if w := e.Candidates[0].Window; w == nil || *w != (TimeWindow{Kind: "notYet", At: 1_900_000_000}) {
					t.Errorf("want window starting 1900000000, got %+v", w)
				}
			},
		},
		{
			name: "condition false (missing tag)", c: c, req: explainReq("security-agent", "kms.Sign", "dev-key"), at: beforeExpiry, kind: KindConditionFalse,
			check: func(t *testing.T, e Explanation) {
				best := e.Candidates[0]
				if best.PolicyID != "security-sign-tagged-dev" || best.Window != nil ||
					!reflect.DeepEqual(best.Missing, []Requirement{{Part: "condition"}}) {
					t.Errorf("want the tag rule with only its condition missing, got %+v", best)
				}
			},
		},
		{
			name: "closest rule needs another role", c: c, req: explainReq("developer-agent", "kms.RotateKey", "dev-key"), at: beforeExpiry, kind: KindClosest,
			check: func(t *testing.T, e Explanation) {
				best := e.Candidates[0]
				want := []Requirement{{Part: "principal", Op: "in", Entities: []EntityRef{{Type: "Role", ID: "security"}}}}
				if best.PolicyID != "security-rotate-dev-key" || !reflect.DeepEqual(best.Missing, want) {
					t.Errorf("want security-rotate-dev-key missing the security role, got %+v", best)
				}
				if !reflect.DeepEqual(e.AgentRoles, []string{"developer"}) {
					t.Errorf("agentRoles = %v", e.AgentRoles)
				}
			},
		},
		{
			name: "no rule covers the action on the key", c: c, req: explainReq("developer-agent", "kms.Decrypt", "dev-key"), at: beforeExpiry, kind: KindNoRule,
		},
		{
			name: "no rule mentions the key at all", c: c, req: explainReq("developer-agent", "kms.RotateKey", "unrelated-key"), at: beforeExpiry, kind: KindNoRule,
		},
		{name: "unknown agent", c: c, req: explainReq("ghost-agent", "kms.Encrypt", "dev-key"), at: beforeExpiry, kind: KindUnknownAgent},
		{name: "no active policy", c: nil, req: explainReq("developer-agent", "kms.Encrypt", "dev-key"), at: beforeExpiry, kind: KindNoPolicy},
		{
			name: "invalid request", c: c, req: explainReq("developer-agent", "kms.Teleport", "dev-key"), at: beforeExpiry, kind: KindInvalidRequest,
			check: func(t *testing.T, e Explanation) {
				if e.Message != "unknown action" {
					t.Errorf("message = %q", e.Message)
				}
			},
		},
		{
			name: "evaluation error", at: beforeExpiry, kind: KindErrored,
			c: mustCompile(t, Bundle{
				Policies: `
@id("ok") permit (principal, action == Action::"kms.Encrypt", resource);
@id("overflows") forbid (principal, action, resource) when { context.currentTime * 9223372036854775807 > 0 };`,
				Entities: json.RawMessage(`[{"uid":{"type":"Agent","id":"a"},"attrs":{},"parents":[]}]`),
			}),
			req: explainReq("a", "kms.Encrypt", "k"),
			check: func(t *testing.T, e Explanation) {
				if !reflect.DeepEqual(e.ErroredPolicies, []string{"overflows"}) {
					t.Errorf("erroredPolicies = %v", e.ErroredPolicies)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Explain(tc.c, tc.req, tc.at)
			if e.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q (%+v)", e.Kind, tc.kind, e)
			}
			if tc.check != nil {
				tc.check(t, e)
			}
		})
	}
}

// Explain must agree with Evaluate on every cell, and an unblocked DENY can
// never list a candidate with nothing missing (it would have been allowed).
func TestExplainAgreesWithEvaluate(t *testing.T) {
	c := explainBundle(t)
	agents := append(c.Agents(), "ghost-agent")
	keys := []Resource{{ID: "demo-key"}, {ID: "dev-key"}, {ID: "prod-key"}, {ID: "release-key"}, {ID: "unrelated-key"}, {ID: "dev-key", Tags: map[string]string{"env": "dev"}}}
	times := []time.Time{beforeExpiry, time.Unix(1_800_000_000, 0), time.Unix(1_950_000_000, 0)}
	for _, at := range times {
		for _, agent := range agents {
			for _, action := range KeyActions {
				for _, key := range keys {
					req := Request{Principal: Principal{Tenant: tenant, AgentID: agent}, Action: action, Resource: key}
					want := Evaluate(c, req, at)
					got := Explain(c, req, at)
					if got.Decision != want.Decision || !reflect.DeepEqual(got.DeterminingPolicies, want.DeterminingPolicies) {
						t.Fatalf("%s %s %v @%d: explain %+v vs evaluate %+v", agent, action, key, at.Unix(), got, want)
					}
					if got.Kind == KindAllowed {
						continue
					}
					for _, cand := range got.Candidates {
						if got.Kind != KindBlocked && len(cand.Missing) == 0 {
							t.Fatalf("%s %s %v: unblocked DENY with a fully matching candidate %+v", agent, action, key, cand)
						}
					}
					if len(got.Candidates) > maxCandidates {
						t.Fatalf("too many candidates: %d", len(got.Candidates))
					}
				}
			}
		}
	}
}
