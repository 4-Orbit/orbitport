package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

func keyReq(agent, action, key string) map[string]any {
	return map[string]any{"agentId": agent, "action": action, "resource": map[string]any{"type": "Key", "id": key}}
}

func TestExplainActiveVersionAndDraft(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)

	out := mustCall(t, p, "policy.Explain", keyReq("developer-agent", "kms.RotateKey", "dev-key"))
	assert.Equal(t, "v1", out["source"])
	assert.EqualValues(t, 1, out["version"])
	assert.Equal(t, false, out["simulatedTime"])
	e := out["explanation"].(map[string]any)
	assert.Equal(t, "DENY", e["decision"])
	assert.Equal(t, authz.KindClosest, e["kind"])
	best := e["candidates"].([]any)[0].(map[string]any)
	assert.Equal(t, "security-rotate-dev-key", best["policyId"])
	assert.Equal(t, []any{"developer"}, e["agentRoles"])

	// Time travel: the US5 grant has expired.
	req := keyReq("developer-agent", "kms.Encrypt", "demo-key")
	req["at"] = 1_800_000_000
	later := mustCall(t, p, "policy.Explain", req)
	assert.Equal(t, true, later["simulatedTime"])
	assert.Equal(t, authz.KindExpired, later["explanation"].(map[string]any)["kind"])

	// A draft that grants the rotation explains as allowed.
	draft := authz.DefaultBundle()
	draft.Policies += `
@id("developer-rotate-dev-key")
permit (principal in Role::"developer", action == Action::"kms.RotateKey", resource == Key::"dev-key");`
	d := keyReq("developer-agent", "kms.RotateKey", "dev-key")
	d["source"] = map[string]any{"draft": draft}
	got := mustCall(t, p, "policy.Explain", d)
	assert.Equal(t, "draft", got["source"])
	assert.Equal(t, authz.KindAllowed, got["explanation"].(map[string]any)["kind"])
}

func TestExplainSavedVersionAndErrors(t *testing.T) {
	p := newTestPlugin(t)

	// Nothing active yet: only the platform policy applies.
	none := mustCall(t, p, "policy.Explain", keyReq("developer-agent", "kms.Encrypt", "dev-key"))
	assert.Equal(t, authz.KindNoPolicy, none["explanation"].(map[string]any)["kind"])

	seed4orbit(t, p)
	req := keyReq("developer-agent", "kms.Encrypt", "dev-key")
	req["source"] = map[string]any{"version": 1}
	v1 := mustCall(t, p, "policy.Explain", req)
	assert.Equal(t, "v1", v1["source"])
	assert.Equal(t, authz.KindAllowed, v1["explanation"].(map[string]any)["kind"])

	req["source"] = map[string]any{"version": 9}
	_, err := callAs(t, p, "", "policy.Explain", req)
	assert.Equal(t, codes.NotFound, status.Code(err))

	// A resource tenant from the caller is ignored: explanations never cross
	// into another tenant, exactly like Simulate.
	cross := keyReq("developer-agent", "kms.Encrypt", "dev-key")
	cross["resource"].(map[string]any)["tenant"] = "someone-else"
	got := mustCall(t, p, "policy.Explain", cross)
	assert.Equal(t, authz.KindAllowed, got["explanation"].(map[string]any)["kind"])

	// Agents may not call it (platform.agents-never-administer-policy).
	_, err = callAs(t, p, "developer-agent", "policy.Explain", keyReq("developer-agent", "kms.Encrypt", "dev-key"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestSimulateExplainsDenialsOnRequest(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	reqs := []any{
		keyReq("developer-agent", "kms.Encrypt", "dev-key"),   // ALLOW
		keyReq("developer-agent", "kms.RotateKey", "dev-key"), // DENY
	}

	plain := mustCall(t, p, "policy.Simulate", map[string]any{"requests": reqs})
	for _, r := range plain["results"].([]any) {
		assert.NotContains(t, r.(map[string]any), "explanation", "explanations are opt-in")
	}

	out := mustCall(t, p, "policy.Simulate", map[string]any{"requests": reqs, "explain": true})
	results := out["results"].([]any)
	assert.NotContains(t, results[0].(map[string]any), "explanation", "ALLOWs are not explained")
	e := results[1].(map[string]any)["explanation"].(map[string]any)
	assert.Equal(t, authz.KindClosest, e["kind"])
	assert.NotContains(t, out, "explanationsTruncated")

	// Past the cap, the rest of the DENYs come back without explanations.
	many := make([]any, 0, maxSimulateExplanations+5)
	for i := 0; i < maxSimulateExplanations+5; i++ {
		many = append(many, keyReq("developer-agent", "kms.RotateKey", "dev-key"))
	}
	capped := mustCall(t, p, "policy.Simulate", map[string]any{"requests": many, "explain": true})
	assert.Equal(t, true, capped["explanationsTruncated"])
	withExplanation := 0
	for _, r := range capped["results"].([]any) {
		if _, ok := r.(map[string]any)["explanation"]; ok {
			withExplanation++
		}
	}
	assert.Equal(t, maxSimulateExplanations, withExplanation)
}

func TestListAuditFiltersByTokenHash(t *testing.T) {
	p := newTestPlugin(t)
	var lines []string
	for i, h := range []string{"aaaa", "bbbb", "aaaa"} {
		ev := authz.AuditEvent{Tenant: tenant, RequestID: string(rune('a' + i)), Principal: `Agent::"developer-agent"`, Action: `Action::"kms.Encrypt"`, Resource: `Key::"dev-key"`, Decision: authz.Allow, JtiHash: h}
		raw, _ := json.Marshal(ev)
		lines = append(lines, string(raw))
	}
	_, err := p.RecordAudit(context.Background(), &proto.RecordAuditRequest{EventsJson: lines})
	require.NoError(t, err)

	out := mustCall(t, p, "policy.ListAudit", map[string]any{"jtiHash": "aaaa"})
	events := out["events"].([]any)
	require.Len(t, events, 2)
	assert.Equal(t, "c", events[0].(map[string]any)["requestId"], "newest first")
	none := mustCall(t, p, "policy.ListAudit", map[string]any{"jtiHash": "cccc"})
	assert.Empty(t, none["events"])
}
