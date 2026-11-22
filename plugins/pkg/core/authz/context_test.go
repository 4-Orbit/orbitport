package authz

import (
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
)

var sampleFields = []ContextField{
	{Name: "branch", Type: ContextString},
	{Name: "isDefaultBranch", Type: ContextBool},
	{Name: "approvals", Type: ContextLong},
	{Name: "paths", Type: ContextStringSet},
	{Name: "headAgent", Type: ContextAgent, Optional: true},
}

func TestBuildContextConvertsDeclaredFields(t *testing.T) {
	got, msg := buildContext(sampleFields, map[string]any{
		"branch": "agent/dev/x", "isDefaultBranch": false, "approvals": float64(2), "paths": []any{"a.go", "b.go"}, "headAgent": "developer-agent",
	})
	if msg != "" {
		t.Fatal(msg)
	}
	if got["branch"] != cedar.String("agent/dev/x") || got["isDefaultBranch"] != cedar.Boolean(false) || got["approvals"] != cedar.Long(2) {
		t.Fatalf("bad values: %v", got)
	}
	if got["headAgent"] != cedar.NewEntityUID("Agent", "developer-agent") {
		t.Fatalf("agent reference: %v", got["headAgent"])
	}
	if s, ok := got["paths"].(cedar.Set); !ok || s.Len() != 2 {
		t.Fatalf("paths: %v", got["paths"])
	}
	// Optional fields may be left out.
	if _, msg := buildContext(sampleFields, map[string]any{"branch": "b", "isDefaultBranch": true, "approvals": 0, "paths": []string{}}); msg != "" {
		t.Fatal(msg)
	}
}

func TestBuildContextFailsClosed(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"branch": "b", "isDefaultBranch": false, "approvals": 1, "paths": []string{}}
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing required":  func(m map[string]any) { delete(m, "isDefaultBranch") },
		"unknown field":     func(m map[string]any) { m["isAdmin"] = true },
		"currentTime given": func(m map[string]any) { m["currentTime"] = 1 },
		"wrong type":        func(m map[string]any) { m["isDefaultBranch"] = "false" },
		"fractional long":   func(m map[string]any) { m["approvals"] = 1.5 },
		"bad agent id":      func(m map[string]any) { m["headAgent"] = "Not An Id" },
		"set of numbers":    func(m map[string]any) { m["paths"] = []any{1} },
		"huge string":       func(m map[string]any) { m["branch"] = strings.Repeat("x", 2000) },
	} {
		in := base()
		mutate(in)
		if _, msg := buildContext(sampleFields, in); msg == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestContextIsIgnoredOnlyWhereNothingIsDeclared(t *testing.T) {
	// An action without declared fields rejects any supplied context, so a
	// caller can't smuggle attributes into a policy.
	res := Evaluate(nil, Request{Principal: Principal{Tenant: tenant}, Action: "kms.Encrypt", Resource: Resource{ID: "k"}, Context: map[string]any{"x": true}}, beforeExpiry)
	if res.Decision != Deny || !res.Errored {
		t.Fatalf("want an errored DENY, got %+v", res)
	}
}
