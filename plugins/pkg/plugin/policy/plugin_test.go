package policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const tenant = "noop-tenant"

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	p := newPlugin(newMemStore(), newAuditLog(100, ""))
	p.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	return p
}

func callAs(t *testing.T, p *Plugin, agent, method string, params any) (map[string]any, error) {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	resp, err := p.Call(context.Background(), &proto.CallRequest{Method: method, KmsTenant: tenant, AgentId: agent, JtiHash: "h", ParamsJson: string(raw)})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.ResultJson), &out))
	return out, nil
}

func mustCall(t *testing.T, p *Plugin, method string, params any) map[string]any {
	t.Helper()
	out, err := callAs(t, p, "", method, params)
	require.NoError(t, err, method)
	return out
}

func seed4orbit(t *testing.T, p *Plugin) {
	t.Helper()
	out := mustCall(t, p, "policy.LoadTemplate", map[string]any{"template": "4orbit"})
	require.EqualValues(t, 1, out["version"])
	act := mustCall(t, p, "policy.Activate", map[string]any{"version": 1})
	require.Equal(t, true, act["activated"], "%v", act)
}

func TestLoadTemplateActivateAndGetActive(t *testing.T) {
	p := newTestPlugin(t)
	resp, err := p.GetActive(context.Background(), &proto.GetActiveRequest{KmsTenant: tenant})
	require.NoError(t, err)
	require.False(t, resp.Exists)

	seed4orbit(t, p)
	resp, err = p.GetActive(context.Background(), &proto.GetActiveRequest{KmsTenant: tenant})
	require.NoError(t, err)
	require.True(t, resp.Exists)
	require.EqualValues(t, 1, resp.Version)
	compiled, problems := authz.Compile(authz.Bundle{Policies: resp.Policies, Entities: json.RawMessage(resp.EntitiesJson)})
	require.Empty(t, problems)
	require.Equal(t, []string{"deployment-agent", "developer-agent", "security-agent"}, compiled.Agents())

	// Other tenants are untouched.
	other, err := p.GetActive(context.Background(), &proto.GetActiveRequest{KmsTenant: "someone-else"})
	require.NoError(t, err)
	require.False(t, other.Exists)
}

func TestAgentsCannotCallAnyPolicyMethod(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	for _, m := range Methods() {
		_, err := callAs(t, p, "security-agent", m, map[string]any{})
		require.Error(t, err, m)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), m)
	}
	events := p.audit.list(tenant, auditFilter{Decision: "DENY"})
	require.NotEmpty(t, events)
	assert.Equal(t, []string{"platform.agents-never-administer-policy"}, events[0].DeterminingPolicies)
}

func TestValidateReportsProblemsAndSummary(t *testing.T) {
	p := newTestPlugin(t)
	bad := mustCall(t, p, "policy.Validate", map[string]any{"policies": `permit (principal, action, resource);`})
	assert.Equal(t, false, bad["ok"])
	assert.NotEmpty(t, bad["problems"])

	b := authz.DefaultBundle()
	good := mustCall(t, p, "policy.Validate", map[string]any{"policies": b.Policies, "entities": b.Entities})
	assert.Equal(t, true, good["ok"])
	summary := good["summary"].(map[string]any)
	assert.Len(t, summary["policyIds"], 6)
}

func TestSaveDraftRejectsInvalidBundle(t *testing.T) {
	p := newTestPlugin(t)
	_, err := callAs(t, p, "", "policy.SaveDraft", map[string]any{"policies": `permit (principal, action, resource);`})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUnknownParamsAndMethodsRejected(t *testing.T) {
	p := newTestPlugin(t)
	_, err := callAs(t, p, "", "policy.GetVersion", map[string]any{"version": 1, "sneaky": true})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = callAs(t, p, "", "policy.DropAll", map[string]any{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
	_, err = p.Call(context.Background(), &proto.CallRequest{Method: "policy.GetSchema"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "tenant is required")
}

func TestSimulateDraftAndTimeTravel(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	req := map[string]any{"agentId": "developer-agent", "action": "kms.Encrypt", "resource": map[string]any{"type": "Key", "id": "demo-key"}}

	now := mustCall(t, p, "policy.Simulate", map[string]any{"requests": []any{req}})
	assert.Equal(t, false, now["simulatedTime"])
	assert.Equal(t, "ALLOW", now["results"].([]any)[0].(map[string]any)["decision"])

	later := mustCall(t, p, "policy.Simulate", map[string]any{"requests": []any{req}, "at": 1_800_000_000})
	assert.Equal(t, true, later["simulatedTime"])
	assert.Equal(t, "DENY", later["results"].([]any)[0].(map[string]any)["decision"])

	draft := authz.DefaultBundle()
	draft.Policies = `@id("nothing") forbid (principal, action, resource);`
	d := mustCall(t, p, "policy.Simulate", map[string]any{"requests": []any{req}, "source": map[string]any{"draft": draft}})
	assert.Equal(t, "draft", d["source"])
	r := d["results"].([]any)[0].(map[string]any)
	assert.Equal(t, "DENY", r["decision"])
	assert.Equal(t, []any{"nothing"}, r["determiningPolicies"])
}

func TestMatrixAndDiff(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	m := mustCall(t, p, "policy.Matrix", map[string]any{"includeAccount": true})
	assert.Equal(t, []any{"", "deployment-agent", "developer-agent", "security-agent"}, m["principals"])
	assert.Equal(t, []any{"demo-key", "dev-key", "prod-key"}, m["keys"])
	assert.Len(t, m["cells"], 4*3*len(authz.KeyActions))

	draft := authz.DefaultBundle()
	draft.Policies += "\n@id(\"deployment-sign-prod\") permit (principal in Role::\"deployment\", action == Action::\"kms.Sign\", resource == Key::\"prod-key\");"
	d := mustCall(t, p, "policy.Diff", map[string]any{"to": map[string]any{"draft": draft}})
	changes := d["changes"].([]any)
	require.Len(t, changes, 1)
	ch := changes[0].(map[string]any)
	assert.Equal(t, "deployment-agent", ch["principal"])
	assert.Equal(t, "kms.Sign", ch["action"])
	assert.Equal(t, "ALLOW", ch["after"])
}

func TestActivateIsBlockedByFailingTests(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	// A version that breaks the developer's dev-key grant.
	broken := authz.DefaultBundle()
	broken.Policies = strings.Replace(broken.Policies, `resource == Key::"dev-key"
);`, `resource == Key::"dev-key"
) when { false };`, 1)
	saved := mustCall(t, p, "policy.SaveDraft", map[string]any{"policies": broken.Policies, "entities": broken.Entities, "message": "oops"})
	v := saved["version"]

	res := mustCall(t, p, "policy.Activate", map[string]any{"version": v})
	assert.Equal(t, false, res["activated"])
	assert.EqualValues(t, 1, res["tests"].(map[string]any)["failed"])

	active, _ := p.GetActive(context.Background(), &proto.GetActiveRequest{KmsTenant: tenant})
	assert.EqualValues(t, 1, active.Version, "failed activation leaves the old version active")

	forced := mustCall(t, p, "policy.Activate", map[string]any{"version": v, "force": true})
	assert.Equal(t, true, forced["activated"])
	assert.Equal(t, true, forced["forced"])

	// Rollback = activate the earlier version.
	back := mustCall(t, p, "policy.Activate", map[string]any{"version": 1})
	assert.Equal(t, true, back["activated"])
	versions := mustCall(t, p, "policy.ListVersions", map[string]any{})["versions"].([]any)
	require.Len(t, versions, 2)
	assert.Equal(t, true, versions[1].(map[string]any)["active"])
}

func TestRunTestsAgainstDraft(t *testing.T) {
	p := newTestPlugin(t)
	seed4orbit(t, p)
	out := mustCall(t, p, "policy.RunTests", map[string]any{})
	assert.EqualValues(t, 0, out["failed"])
	assert.EqualValues(t, len(authz.DefaultTests()), out["total"])

	empty := mustCall(t, p, "policy.RunTests", map[string]any{"source": map[string]any{"draft": map[string]any{"policies": ""}}})
	assert.EqualValues(t, 7, empty["failed"], "an empty draft fails exactly the ALLOW cases")
}

func TestPutTestsValidates(t *testing.T) {
	p := newTestPlugin(t)
	_, err := callAs(t, p, "", "policy.PutTests", map[string]any{"tests": []any{map[string]any{"name": "x", "action": "kms.Encrypt", "resource": map[string]any{"id": "k"}, "expect": "MAYBE"}}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	ok := mustCall(t, p, "policy.PutTests", map[string]any{"tests": []any{map[string]any{"name": "x", "action": "kms.Encrypt", "resource": map[string]any{"id": "k"}, "expect": "DENY"}}})
	assert.EqualValues(t, 1, ok["count"])
}

func TestIssueAgentTokenRequiresRegisteredAgent(t *testing.T) {
	p := newTestPlugin(t)
	_, err := callAs(t, p, "", "policy.IssueAgentToken", map[string]any{"agentId": "developer-agent"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "no active version yet")

	seed4orbit(t, p)
	out := mustCall(t, p, "policy.IssueAgentToken", map[string]any{"agentId": "developer-agent", "ttlSeconds": 600})
	assert.Equal(t, "developer-agent", out["agentId"])
	assert.EqualValues(t, 600, out["ttlSeconds"])
	assert.Equal(t, []any{"developer"}, out["roles"])

	_, err = callAs(t, p, "", "policy.IssueAgentToken", map[string]any{"agentId": "ghost-agent"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = callAs(t, p, "", "policy.IssueAgentToken", map[string]any{"agentId": "developer-agent", "ttlSeconds": 10})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRecordAndListAudit(t *testing.T) {
	dir := t.TempDir()
	p := newPlugin(newMemStore(), newAuditLog(3, dir))
	var lines []string
	for i, d := range []authz.Decision{authz.Allow, authz.Deny, authz.Deny, authz.Allow} {
		ev := authz.AuditEvent{Tenant: tenant, RequestID: string(rune('a' + i)), Principal: `Agent::"developer-agent"`, Action: `Action::"kms.Encrypt"`, Resource: `Key::"dev-key"`, Decision: d}
		raw, _ := json.Marshal(ev)
		lines = append(lines, string(raw))
	}
	lines = append(lines, "not json", `{"decision":"ALLOW"}`)
	resp, err := p.RecordAudit(context.Background(), &proto.RecordAuditRequest{EventsJson: lines})
	require.NoError(t, err)
	assert.EqualValues(t, 4, resp.Accepted)

	events := p.audit.list(tenant, auditFilter{})
	require.Len(t, events, 3, "ring keeps the newest N")
	assert.Equal(t, "d", events[0].RequestID, "newest first")
	assert.Len(t, p.audit.list(tenant, auditFilter{Decision: "DENY"}), 2)
	assert.Len(t, p.audit.list(tenant, auditFilter{AgentID: "security-agent"}), 0)

	raw, err := os.ReadFile(filepath.Join(dir, tenantKey(tenant)+".jsonl"))
	require.NoError(t, err)
	assert.Equal(t, 4, strings.Count(string(raw), "\n"), "JSONL keeps every event")
}

// fakeKV is a minimal OpenBao KV v2 with check-and-set.
type fakeKV struct {
	mu   sync.Mutex
	docs map[string]kvDoc
}

type kvDoc struct {
	data    json.RawMessage
	version int
}

func (f *fakeKV) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/v1/orbitport-policy/data/")
	switch r.Method {
	case http.MethodGet:
		d, ok := f.docs[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":` + string(d.data) + `,"metadata":{"version":` + jsonNumber(d.version) + `}}}`))
	case http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Data    json.RawMessage `json:"data"`
			Options *struct {
				CAS int `json:"cas"`
			} `json:"options"`
		}
		_ = json.Unmarshal(body, &payload)
		// Like OpenBao, refuse documents with too many strings.
		var decoded any
		_ = json.Unmarshal(payload.Data, &decoded)
		if countStrings(decoded) > 50 {
			http.Error(w, `{"errors":["refused JSON input due to high complexity: exceeded maximum number of strings"]}`, http.StatusBadRequest)
			return
		}
		cur := f.docs[key]
		if payload.Options != nil && payload.Options.CAS != cur.version {
			http.Error(w, `{"errors":["check-and-set parameter did not match"]}`, http.StatusBadRequest)
			return
		}
		f.docs[key] = kvDoc{data: payload.Data, version: cur.version + 1}
		_, _ = w.Write([]byte(`{"data":{}}`))
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func countStrings(v any) int {
	switch t := v.(type) {
	case string:
		return 1
	case []any:
		n := 0
		for _, x := range t {
			n += countStrings(x)
		}
		return n
	case map[string]any:
		n := len(t)
		for _, x := range t {
			n += countStrings(x)
		}
		return n
	}
	return 0
}

func jsonNumber(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}

func TestBaoStoreRoundTrip(t *testing.T) {
	kv := &fakeKV{docs: map[string]kvDoc{}}
	server := httptest.NewServer(kv)
	defer server.Close()
	p := newPlugin(newBaoStore(server.URL, "orbitport-policy", 5*time.Second), newAuditLog(10, ""))
	seed4orbit(t, p)

	saved := mustCall(t, p, "policy.SaveDraft", map[string]any{"policies": `@id("x") permit (principal is Account, action, resource);`, "message": "second"})
	assert.EqualValues(t, 2, saved["version"])

	versions := mustCall(t, p, "policy.ListVersions", map[string]any{})["versions"].([]any)
	require.Len(t, versions, 2)
	assert.Equal(t, "second", versions[0].(map[string]any)["message"])
	assert.Equal(t, false, versions[0].(map[string]any)["active"])
	assert.Equal(t, true, versions[1].(map[string]any)["active"])

	tests := mustCall(t, p, "policy.GetTests", map[string]any{})["tests"].([]any)
	assert.Len(t, tests, len(authz.DefaultTests()))

	resp, err := p.GetActive(context.Background(), &proto.GetActiveRequest{KmsTenant: tenant})
	require.NoError(t, err)
	assert.EqualValues(t, 1, resp.Version)

	// Writes stay under the tenant's hashed path.
	for k := range kv.docs {
		assert.True(t, strings.HasPrefix(k, "tenants/"+tenantKey(tenant)+"/"), k)
	}
}

func TestBaoStoreConcurrentSavesGetDistinctVersions(t *testing.T) {
	kv := &fakeKV{docs: map[string]kvDoc{}}
	server := httptest.NewServer(kv)
	defer server.Close()
	// Two store instances simulate two replicas sharing OpenBao.
	a := newBaoStore(server.URL, "orbitport-policy", 5*time.Second)
	b := newBaoStore(server.URL, "orbitport-policy", 5*time.Second)
	var wg sync.WaitGroup
	seen := sync.Map{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		s := a
		if i%2 == 1 {
			s = b
		}
		go func(s *baoStore) {
			defer wg.Done()
			n, err := s.SaveVersion(context.Background(), tenant, Version{Policies: ""})
			if err == nil {
				_, dup := seen.LoadOrStore(n, true)
				assert.False(t, dup, "version %d allocated twice", n)
			}
		}(s)
	}
	wg.Wait()
}
