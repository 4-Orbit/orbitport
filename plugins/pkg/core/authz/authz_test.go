package authz

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate defaults/4orbit/tests.json from the permission matrix")

const tenant = "tenant-a"

// beforeExpiry is a fixed time before the developer demo-key grant expires,
// so results never depend on the wall clock (same approach as 4Orbit).
var beforeExpiry = time.Unix(1_700_000_000, 0)

func mustCompile(t *testing.T, b Bundle) *Compiled {
	t.Helper()
	c, problems := Compile(b)
	if c == nil {
		t.Fatalf("bundle did not compile: %+v", problems)
	}
	return c
}

func defaultCompiled(t *testing.T) *Compiled { return mustCompile(t, DefaultBundle()) }

func eval(c *Compiled, agent, action, key string, at time.Time) Result {
	return Evaluate(c, Request{
		Principal: Principal{Tenant: tenant, AgentID: agent},
		Action:    action,
		Resource:  Resource{ID: key},
	}, at)
}

// 4Orbit's vocabulary mapped onto the merged action names. "write" and
// "unknown" stand for actions no role is granted.
var matrixActions = []struct{ vocab, action string }{
	{"use", "kms.Encrypt"},
	{"rotate", "kms.RotateKey"},
	{"read", "kms.GetKeyMetadata"},
	{"admin", "kms.CreateKey"},
	{"sign", "kms.Sign"},
	{"decrypt", "kms.Decrypt"},
	{"unknown", "kms.Teleport"},
}

var matrixAgents = []string{"developer-agent", "security-agent", "deployment-agent", "unknown-agent"}
var matrixKeys = []string{"demo-key", "dev-key", "prod-key", "unrelated-key"}

// expectedAllow is the complete set of ALLOW cells and the policy that
// permits each one. Every other cell must be DENY. This is the regression
// specification ported from 4orbit prototype-1/test/permission-matrix.test.ts.
var expectedAllow = map[string]string{
	"developer-agent|kms.Encrypt|demo-key":  "developer-encrypt-demo-key",
	"developer-agent|kms.Encrypt|dev-key":   "developer-encrypt-dev-key",
	"security-agent|kms.RotateKey|demo-key": "security-rotate-demo-key",
	"security-agent|kms.RotateKey|dev-key":  "security-rotate-dev-key",
	"security-agent|kms.RotateKey|prod-key": "security-rotate-prod-key",
	"deployment-agent|kms.Encrypt|prod-key": "deployment-encrypt-prod-key",
}

func TestPermissionMatrix(t *testing.T) {
	c := defaultCompiled(t)
	count := 0
	for _, agent := range matrixAgents {
		for _, a := range matrixActions {
			for _, key := range matrixKeys {
				count++
				cell := agent + "|" + a.action + "|" + key
				res := eval(c, agent, a.action, key, beforeExpiry)
				if want, ok := expectedAllow[cell]; ok {
					if res.Decision != Allow || len(res.DeterminingPolicies) != 1 || res.DeterminingPolicies[0] != want {
						t.Errorf("%s: want ALLOW by %s, got %s %v", cell, want, res.Decision, res.DeterminingPolicies)
					}
					continue
				}
				if res.Decision != Deny {
					t.Errorf("%s (%s): want DENY, got %s %v", cell, a.vocab, res.Decision, res.DeterminingPolicies)
				}
			}
		}
	}
	if count != 112 {
		t.Fatalf("matrix has %d cells, want 112", count)
	}
}

func TestUS5_DeveloperDemoKeyExpiresAtBoundary(t *testing.T) {
	c := defaultCompiled(t)
	cases := []struct {
		at   int64
		want Decision
	}{
		{1_799_999_999, Allow},
		{1_800_000_000, Deny},
		{1_800_000_001, Deny},
	}
	for _, tc := range cases {
		res := eval(c, "developer-agent", "kms.Encrypt", "demo-key", time.Unix(tc.at, 0))
		if res.Decision != tc.want {
			t.Errorf("at %d: want %s, got %s", tc.at, tc.want, res.Decision)
		}
	}
	// The expiry is only on demo-key; dev-key is unaffected.
	if res := eval(c, "developer-agent", "kms.Encrypt", "dev-key", time.Unix(1_900_000_000, 0)); res.Decision != Allow {
		t.Fatalf("dev-key after demo-key expiry: want ALLOW, got %s", res.Decision)
	}
}

func TestAccountPrincipalKeepsOwnerAccess(t *testing.T) {
	for _, c := range []*Compiled{nil, defaultCompiled(t)} {
		for _, action := range Actions() {
			res := Evaluate(c, Request{Principal: Principal{Tenant: tenant}, Action: action, Resource: Resource{ID: "any-key"}}, beforeExpiry)
			if res.Decision != Allow || res.DeterminingPolicies[0] != "platform.owner" {
				t.Errorf("account %s: want ALLOW by platform.owner, got %s %v", action, res.Decision, res.DeterminingPolicies)
			}
		}
	}
}

func TestNoTenantPolicyDeniesEveryAgent(t *testing.T) {
	res := Evaluate(nil, Request{Principal: Principal{Tenant: tenant, AgentID: "developer-agent"}, Action: "kms.Encrypt", Resource: Resource{ID: "dev-key"}}, beforeExpiry)
	if res.Decision != Deny || res.Errored {
		t.Fatalf("want plain DENY, got %+v", res)
	}
}

func TestTenantFenceOverridesPermits(t *testing.T) {
	c := mustCompile(t, Bundle{
		Policies: `@id("allow-all") permit (principal, action, resource);`,
		Entities: json.RawMessage(`[{"uid":{"type":"Agent","id":"a"},"attrs":{},"parents":[]}]`),
	})
	for _, agent := range []string{"", "a"} {
		res := Evaluate(c, Request{
			Principal: Principal{Tenant: tenant, AgentID: agent},
			Action:    "kms.Encrypt",
			Resource:  Resource{ID: "k", Tenant: "tenant-b"},
		}, beforeExpiry)
		if res.Decision != Deny || !contains(res.DeterminingPolicies, "platform.tenant-fence") {
			t.Errorf("agent=%q cross-tenant: want DENY by fence, got %+v", agent, res)
		}
	}
}

func TestAgentsCanNeverAdministerPolicy(t *testing.T) {
	c := mustCompile(t, Bundle{
		Policies: `@id("allow-all") permit (principal, action, resource);`,
		Entities: json.RawMessage(`[{"uid":{"type":"Agent","id":"a"},"attrs":{},"parents":[]}]`),
	})
	for _, action := range []string{"policy.Read", "policy.Write", "policy.Activate", "policy.Simulate", "policy.IssueAgentToken"} {
		res := Evaluate(c, Request{Principal: Principal{Tenant: tenant, AgentID: "a"}, Action: action, Resource: Resource{ID: "active"}}, beforeExpiry)
		if res.Decision != Deny || !contains(res.DeterminingPolicies, "platform.agents-never-administer-policy") {
			t.Errorf("%s: want DENY by platform policy, got %+v", action, res)
		}
	}
	// The same permit-all does let the agent encrypt, proving the forbid is targeted.
	if res := eval(c, "a", "kms.Encrypt", "k", beforeExpiry); res.Decision != Allow {
		t.Fatalf("permit-all encrypt: want ALLOW, got %+v", res)
	}
}

func TestActionGroupsAndTags(t *testing.T) {
	c := mustCompile(t, Bundle{
		Policies: `
@id("ops-use-prod-tagged")
permit (principal in Role::"ops", action in Action::"use", resource)
when { resource.hasTag("env") && resource.getTag("env") == "prod" };`,
		Entities: json.RawMessage(`[
			{"uid":{"type":"Role","id":"ops"},"attrs":{},"parents":[]},
			{"uid":{"type":"Agent","id":"ops-agent"},"attrs":{},"parents":[{"type":"Role","id":"ops"}]}
		]`),
	})
	prod := Resource{ID: "k1", Tags: map[string]string{"env": "prod"}}
	dev := Resource{ID: "k2", Tags: map[string]string{"env": "dev"}}
	for _, action := range []string{"kms.Encrypt", "kms.Decrypt", "kms.Sign", "kms.GenerateDataKey"} {
		if r := Evaluate(c, Request{Principal: Principal{Tenant: tenant, AgentID: "ops-agent"}, Action: action, Resource: prod}, beforeExpiry); r.Decision != Allow {
			t.Errorf("%s on prod-tagged: want ALLOW, got %+v", action, r)
		}
		if r := Evaluate(c, Request{Principal: Principal{Tenant: tenant, AgentID: "ops-agent"}, Action: action, Resource: dev}, beforeExpiry); r.Decision != Deny {
			t.Errorf("%s on dev-tagged: want DENY, got %+v", action, r)
		}
	}
	if r := Evaluate(c, Request{Principal: Principal{Tenant: tenant, AgentID: "ops-agent"}, Action: "kms.RotateKey", Resource: prod}, beforeExpiry); r.Decision != Deny {
		t.Errorf("rotate is outside the use group: got %+v", r)
	}
	// A tag cannot be smuggled in as an attribute of another resource type.
	if r := Evaluate(c, Request{Principal: Principal{Tenant: tenant, AgentID: "ops-agent"}, Action: "kms_keystore.Get", Resource: Resource{ID: "x", Tags: map[string]string{"env": "prod"}}}, beforeExpiry); r.Decision != Deny {
		t.Errorf("keystore with tags: want DENY, got %+v", r)
	}
}

func TestEvaluationErrorFailsClosed(t *testing.T) {
	c := mustCompile(t, Bundle{
		Policies: `
@id("ok") permit (principal, action == Action::"kms.Encrypt", resource);
@id("overflows") forbid (principal, action, resource) when { context.currentTime * 9223372036854775807 > 0 };`,
		Entities: json.RawMessage(`[{"uid":{"type":"Agent","id":"a"},"attrs":{},"parents":[]}]`),
	})
	res := eval(c, "a", "kms.Encrypt", "k", beforeExpiry)
	if res.Decision != Deny || !res.Errored || len(res.Diagnostics) == 0 {
		t.Fatalf("want errored DENY, got %+v", res)
	}
}

func TestMalformedRequestsFailClosed(t *testing.T) {
	c := defaultCompiled(t)
	cases := []Request{
		{Principal: Principal{Tenant: tenant, AgentID: "developer-agent"}, Action: "kms.Teleport", Resource: Resource{ID: "dev-key"}},
		{Principal: Principal{AgentID: "developer-agent"}, Action: "kms.Encrypt", Resource: Resource{ID: "dev-key"}},
		{Principal: Principal{Tenant: tenant, AgentID: "Developer Agent!"}, Action: "kms.Encrypt", Resource: Resource{ID: "dev-key"}},
		{Principal: Principal{Tenant: tenant, AgentID: "developer-agent"}, Action: "kms.Encrypt", Resource: Resource{Type: "PolicySet", ID: "dev-key"}},
		{Principal: Principal{Tenant: tenant, AgentID: "developer-agent"}, Action: "kms.Encrypt", Resource: Resource{ID: ""}},
	}
	for i, req := range cases {
		if res := Evaluate(c, req, beforeExpiry); res.Decision != Deny || !res.Errored {
			t.Errorf("case %d: want errored DENY, got %+v", i, res)
		}
	}
}

func TestRolesComeOnlyFromTrustedStore(t *testing.T) {
	c := defaultCompiled(t)
	// An agent missing from the store gets no role, even with a role-like name.
	if res := eval(c, "developer", "kms.Encrypt", "dev-key", beforeExpiry); res.Decision != Deny {
		t.Fatalf("role id used as agent id: want DENY, got %+v", res)
	}
	if got := c.AgentRoles("developer-agent"); len(got) != 1 || got[0] != "developer" {
		t.Fatalf("AgentRoles: %v", got)
	}
}

func TestValidationProblems(t *testing.T) {
	cases := []struct {
		name     string
		bundle   Bundle
		contains string
	}{
		{"missing id", Bundle{Policies: `permit (principal, action, resource);`}, "@id"},
		{"reserved id", Bundle{Policies: `@id("platform.mine") permit (principal, action, resource);`}, "reserved"},
		{"duplicate id", Bundle{Policies: `@id("x") permit (principal, action, resource); @id("x") forbid (principal, action, resource);`}, "duplicate"},
		{"parse error", Bundle{Policies: `@id("x") permit (principal, action, resource`}, "parse error"},
		{"unknown action", Bundle{Policies: `@id("x") permit (principal, action == Action::"kms.Teleport", resource);`}, ""},
		{"unknown attribute", Bundle{Policies: `@id("x") permit (principal, action == Action::"kms.Encrypt", resource) when { resource.owner == "me" };`}, ""},
		{"undeclared entity type", Bundle{Policies: `@id("ok") permit (principal, action, resource);`, Entities: json.RawMessage(`[{"uid":{"type":"Key","id":"k"},"attrs":{},"parents":[]}]`)}, "only Role and Agent"},
		{"agent with attrs", Bundle{Policies: `@id("ok") permit (principal, action, resource);`, Entities: json.RawMessage(`[{"uid":{"type":"Agent","id":"a"},"attrs":{"tenant":"other"},"parents":[]}]`)}, "attrs and tags"},
		{"undeclared parent", Bundle{Policies: `@id("ok") permit (principal, action, resource);`, Entities: json.RawMessage(`[{"uid":{"type":"Agent","id":"a"},"attrs":{},"parents":[{"type":"Role","id":"ghost"}]}]`)}, "not declared"},
		{"bad entities json", Bundle{Policies: `@id("ok") permit (principal, action, resource);`, Entities: json.RawMessage(`{`)}, "entities"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, problems := Compile(tc.bundle)
			if c != nil || len(problems) == 0 {
				t.Fatalf("want compile failure, got %v / %+v", c != nil, problems)
			}
			if tc.contains != "" && !strings.Contains(fmt.Sprint(problems), tc.contains) {
				t.Fatalf("want problem containing %q, got %+v", tc.contains, problems)
			}
		})
	}
}

func TestParseErrorHasPosition(t *testing.T) {
	_, problems := Compile(Bundle{Policies: "@id(\"x\")\npermit (principal, action, resource)\nwhen { 1 + };"})
	if len(problems) == 0 || problems[0].Line == 0 {
		t.Fatalf("want a positioned parse problem, got %+v", problems)
	}
}

func TestDefaultBundleValidatesCleanly(t *testing.T) {
	_, problems := Compile(DefaultBundle())
	if len(problems) != 0 {
		t.Fatalf("default bundle has problems: %+v", problems)
	}
	c := defaultCompiled(t)
	if got := strings.Join(c.Agents(), ","); got != "deployment-agent,developer-agent,security-agent" {
		t.Fatalf("agents: %s", got)
	}
	if got := strings.Join(c.ReferencedKeys(), ","); got != "demo-key,dev-key,prod-key" {
		t.Fatalf("keys: %s", got)
	}
}

// generatedTests renders the permission matrix plus the US5 boundary as a
// playground test suite.
func generatedTests() []TestCase {
	var cases []TestCase
	for _, agent := range matrixAgents {
		for _, a := range matrixActions {
			if a.vocab == "unknown" {
				continue
			}
			for _, key := range matrixKeys {
				cell := agent + "|" + a.action + "|" + key
				expect := Deny
				if _, ok := expectedAllow[cell]; ok {
					expect = Allow
				}
				cases = append(cases, TestCase{
					Name:     fmt.Sprintf("%s %s %s", agent, a.action, key),
					AgentID:  agent,
					Action:   a.action,
					Resource: Resource{Type: "Key", ID: key},
					At:       beforeExpiry.Unix(),
					Expect:   expect,
				})
			}
		}
	}
	cases = append(cases,
		TestCase{Name: "US5: developer demo-key one second before expiry", AgentID: "developer-agent", Action: "kms.Encrypt", Resource: Resource{Type: "Key", ID: "demo-key"}, At: 1_799_999_999, Expect: Allow},
		TestCase{Name: "US5: developer demo-key at expiry", AgentID: "developer-agent", Action: "kms.Encrypt", Resource: Resource{Type: "Key", ID: "demo-key"}, At: 1_800_000_000, Expect: Deny},
	)
	return cases
}

func TestDefaultTestsMatchMatrix(t *testing.T) {
	want, _ := json.MarshalIndent(generatedTests(), "", "  ")
	want = append(want, '\n')
	if *update {
		if err := os.WriteFile("defaults/4orbit/tests.json", want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile("defaults/4orbit/tests.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("defaults/4orbit/tests.json is stale; run: go test ./pkg/core/authz -run TestDefaultTestsMatchMatrix -update")
	}
}

func TestDefaultTestsPass(t *testing.T) {
	results := RunTests(defaultCompiled(t), tenant, DefaultTests(), time.Unix(1_900_000_000, 0))
	if len(results) == 0 {
		t.Fatal("default suite is empty")
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("%s: expected %s, got %s", r.Name, r.Expect, r.Actual)
		}
	}
}

func TestDiffShowsOnlyChangedCells(t *testing.T) {
	before := defaultCompiled(t)
	b := DefaultBundle()
	b.Policies += `
@id("deployment-sign-prod")
permit (principal in Role::"deployment", action == Action::"kms.Sign", resource == Key::"prod-key");`
	after := mustCompile(t, b)
	changes := Diff(before, after, tenant, KeyActions, nil, beforeExpiry)
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %+v", changes)
	}
	ch := changes[0]
	if ch.Principal != "deployment-agent" || ch.Action != "kms.Sign" || ch.Resource != "prod-key" || ch.Before != Deny || ch.After != Allow {
		t.Fatalf("unexpected change %+v", ch)
	}
}

func TestAuditEventRedaction(t *testing.T) {
	req := Request{Principal: Principal{Tenant: tenant, AgentID: "developer-agent"}, Action: "kms.Encrypt", Resource: Resource{ID: "dev-key\"; drop"}}
	res := Result{Decision: Deny, Errored: true, Diagnostics: []string{"secret policy text"}}
	ev := NewAuditEvent("t", "r", req, res, 3, ModeEnforce)
	raw, _ := json.Marshal(ev)
	s := string(raw)
	if strings.Contains(s, "secret policy text") || strings.Contains(s, "drop") {
		t.Fatalf("audit leaked request data or diagnostics: %s", s)
	}
	if len(ev.AuthzErrors) != 1 || ev.AuthzErrors[0] != AuthzErrorMarker || ev.Resource != `Key::"<invalid>"` {
		t.Fatalf("audit missing marker or invalid placeholder: %+v", ev)
	}
	if HashJTI("abc") == "abc" || HashJTI("") != "" {
		t.Fatal("HashJTI must not return the raw jti")
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
