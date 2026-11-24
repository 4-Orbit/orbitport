package githubissues

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
	"google.golang.org/grpc"
)

type policyStub struct {
	proto.PolicyPluginClient
	events      []authz.AuditEvent
	unavailable bool
	rejectAudit bool
	policies    string
	// entities defaults to none.
	entities string
}

func (p *policyStub) GetActive(context.Context, *proto.GetActiveRequest, ...grpc.CallOption) (*proto.GetActiveResponse, error) {
	if p.unavailable {
		return nil, errors.New("offline")
	}
	entities := p.entities
	if entities == "" {
		entities = `[]`
	}
	return &proto.GetActiveResponse{Exists: true, Version: 7, Policies: p.policies, EntitiesJson: entities}, nil
}
func (p *policyStub) RecordAudit(_ context.Context, r *proto.RecordAuditRequest, _ ...grpc.CallOption) (*proto.RecordAuditResponse, error) {
	if p.rejectAudit {
		return &proto.RecordAuditResponse{}, nil
	}
	for _, raw := range r.EventsJson {
		var ev authz.AuditEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			return nil, err
		}
		p.events = append(p.events, ev)
	}
	return &proto.RecordAuditResponse{Accepted: uint32(len(r.EventsJson))}, nil
}

type providerStub struct {
	calls int
	audit *policyStub
	fail  bool
	// last records the text the provider was asked to write.
	last string
	// lookupErr fails every lookup; lookups counts them.
	lookupErr error
	lookups   int
	// pull is what Pull returns; approvals what HumanApprovals returns.
	pull      pullInfo
	approvals int64
	// installs counts installation reads.
	installs int
}

func (p *providerStub) Create(context.Context, string, string, string) (int64, error) {
	if len(p.audit.events) != 1 || p.audit.events[0].Stage != "decision" {
		panic("provider before decision audit")
	}
	p.calls++
	if p.fail {
		return 0, errors.New("provider echoed SECRET")
	}
	return 42, nil
}
func (p *providerStub) ReadContents(_ context.Context, _ string, path, ref string) (contents, error) {
	p.mustFollowDecision()
	p.calls++
	return contents{Type: "file", Path: path, Content: "FILE CONTENT SECRET"}, nil
}

func (p *providerStub) Comment(_ context.Context, _ string, number int64, body string) (int64, error) {
	p.mustFollowDecision()
	p.calls++
	p.last = body
	return 99, nil
}

func (p *providerStub) DefaultBranch(context.Context, string) (string, error) {
	p.lookups++
	return "main", p.lookupErr
}

func (p *providerStub) CreateBranch(_ context.Context, _ string, branch, _ string) (string, error) {
	p.mustFollowDecision()
	p.calls++
	p.last = branch
	return "0123456789abcdef0123456789abcdef01234567", nil
}

func (p *providerStub) Commit(_ context.Context, _ string, _ string, message string, changes []fileChange) (string, error) {
	p.mustFollowDecision()
	p.calls++
	p.last = message
	for _, ch := range changes {
		p.last += "|" + ch.Content
	}
	return "89abcdef0123456789abcdef0123456789abcdef", nil
}

func (p *providerStub) OpenPull(_ context.Context, _ string, head, base, _, body string) (int64, error) {
	p.mustFollowDecision()
	p.calls++
	p.last = head + "->" + base + "|" + body
	return 12, nil
}

func (p *providerStub) Pull(context.Context, string, int64) (pullInfo, error) {
	p.lookups++
	return p.pull, p.lookupErr
}

func (p *providerStub) Review(_ context.Context, _ string, _ int64, event, body string, _ bool) (int64, error) {
	p.mustFollowDecision()
	p.calls++
	p.last = event + "|" + body
	return 4, nil
}

func (p *providerStub) HumanApprovals(context.Context, string, int64, string) (int64, error) {
	p.lookups++
	return p.approvals, p.lookupErr
}

func (p *providerStub) Merge(_ context.Context, _ string, _ int64, head, method string) (string, error) {
	p.mustFollowDecision()
	p.calls++
	p.last = head + "|" + method
	return "fedcba9876543210fedcba9876543210fedcba98", nil
}

func (p *providerStub) OpenPulls(context.Context, string) ([]pullSummary, error) {
	p.mustFollowDecision()
	p.calls++
	return []pullSummary{{Number: 26, Title: "Update README.md", HeadBranch: "agent/developer-agent/x", HeadSHA: agentPull, BaseBranch: "main", AuthorIsApp: true}}, nil
}

func (p *providerStub) Installation(context.Context) (map[string]string, error) {
	p.installs++
	return map[string]string{"issues": "write", "metadata": "read"}, nil
}

// mustFollowDecision panics unless the decision audit was recorded first.
func (p *providerStub) mustFollowDecision() {
	if len(p.audit.events) == 0 || p.audit.events[len(p.audit.events)-1].Stage != "decision" {
		panic("provider before decision audit")
	}
}

// callOp runs one method with params as the agent and returns its result.
func callOp(t *testing.T, p *Plugin, method, agent string, params map[string]any) (Result, error) {
	t.Helper()
	raw, _ := json.Marshal(params)
	out, err := p.Call(context.Background(), &proto.GithubCallRequest{Method: method, KmsTenant: "tenant-a", AgentId: agent, JtiHash: "hash", ParamsJson: string(raw)})
	if err != nil {
		return Result{}, err
	}
	var r Result
	if err := json.Unmarshal([]byte(out.ResultJson), &r); err != nil {
		t.Fatal(err)
	}
	return r, nil
}

func setup() (*Plugin, *policyStub, *providerStub) {
	policy := &policyStub{policies: `@id("issues") permit(principal == Agent::"developer-agent", action == Action::"github.issue.Create", resource == Repository::"test-owner/test-repo");`}
	provider := &providerStub{audit: policy}
	p := &Plugin{policy: policy, provider: provider, repository: "test-owner/test-repo", tenant: "tenant-a", mode: "real", now: time.Now}
	return p, policy, provider
}
func request(agent, tenant, repo string) *proto.GithubCallRequest {
	raw, _ := json.Marshal(map[string]string{"repository": repo, "title": "PRIVATE TITLE", "body": "PRIVATE BODY"})
	return &proto.GithubCallRequest{Method: CreateAction, KmsTenant: tenant, AgentId: agent, JtiHash: "hash", ParamsJson: string(raw)}
}
func TestEnforcementAndAuditPrivacy(t *testing.T) {
	for _, tc := range []struct {
		name, agent, tenant, repo string
		allow                     bool
	}{
		{"allow", "developer-agent", "tenant-a", "test-owner/test-repo", true},
		{"role denied", "security-agent", "tenant-a", "test-owner/test-repo", false},
		{"unknown agent", "unknown-agent", "tenant-a", "test-owner/test-repo", false},
		{"foreign tenant", "developer-agent", "tenant-b", "test-owner/test-repo", false},
		{"unknown repo", "developer-agent", "tenant-a", "other-owner/secret-repo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, policy, provider := setup()
			out, err := p.Call(context.Background(), request(tc.agent, tc.tenant, tc.repo))
			if err != nil {
				t.Fatal(err)
			}
			var result Result
			if err := json.Unmarshal([]byte(out.ResultJson), &result); err != nil {
				t.Fatal(err)
			}
			if tc.allow {
				if result.Decision != authz.Allow || result.IssueNumber != 42 || provider.calls != 1 || len(policy.events) != 2 {
					t.Fatalf("bad allow: %+v", result)
				}
			} else {
				if result.Decision != authz.Deny || provider.calls != 0 || len(policy.events) != 1 {
					t.Fatalf("bad deny: %+v", result)
				}
			}
			raw, _ := json.Marshal(policy.events)
			for _, secret := range []string{"PRIVATE TITLE", "PRIVATE BODY", "SECRET", "secret-repo"} {
				if strings.Contains(string(raw), secret) {
					t.Fatalf("audit leaks %s", secret)
				}
			}
		})
	}
}
func TestFailClosed(t *testing.T) {
	for _, kind := range []string{"policy offline", "audit rejected", "invalid policy"} {
		t.Run(kind, func(t *testing.T) {
			p, policy, provider := setup()
			switch kind {
			case "policy offline":
				policy.unavailable = true
			case "audit rejected":
				policy.rejectAudit = true
			case "invalid policy":
				policy.policies = "not cedar"
			}
			_, err := p.Call(context.Background(), request("developer-agent", "tenant-a", "test-owner/test-repo"))
			if err == nil || provider.calls != 0 {
				t.Fatal("did not fail closed")
			}
		})
	}
}
func TestProviderFailureNoRetry(t *testing.T) {
	p, policy, provider := setup()
	provider.fail = true
	out, err := p.Call(context.Background(), request("developer-agent", "tenant-a", "test-owner/test-repo"))
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 || strings.Contains(out.ResultJson, "SECRET") || policy.events[1].GithubResult.Status != "ERROR" {
		t.Fatal("unsafe provider failure")
	}
}
func TestStrictParamsAndManagement(t *testing.T) {
	p, _, provider := setup()
	for _, raw := range []string{`null`, `{} {}`, `{"repository":"test-owner/test-repo","title":"x","agentId":"developer-agent"}`, `{"repository":"test-owner/test-repo","title":" "}`} {
		req := request("developer-agent", "tenant-a", "test-owner/test-repo")
		req.ParamsJson = raw
		if _, err := p.Call(context.Background(), req); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if provider.calls != 0 {
		t.Fatal("invalid params contacted provider")
	}
	_, err := p.Call(context.Background(), &proto.GithubCallRequest{Method: "github.ListRepositories", KmsTenant: "tenant-a", AgentId: "developer-agent", ParamsJson: `{}`})
	if err == nil {
		t.Fatal("agent read management metadata")
	}
}

func TestLookupFailsClosedAndRunsOnlyWhenItCan(t *testing.T) {
	newOp := func(lookups *int, lookupErr error, ran *int) operation {
		return operation{action: CreateAction, repository: "test-owner/test-repo",
			lookup: func(context.Context) (map[string]any, error) { *lookups++; return nil, lookupErr },
			run:    func(context.Context, string) (outcome, error) { *ran++; return outcome{}, nil }}
	}
	call := request("developer-agent", "tenant-a", "test-owner/test-repo")

	// A failed lookup is an audited DENY with no write.
	p, policy, _ := setup()
	lookups, ran := 0, 0
	out, err := p.enforce(context.Background(), call, newOp(&lookups, errors.New("GitHub down SECRET"), &ran))
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	_ = json.Unmarshal([]byte(out.ResultJson), &result)
	if result.Decision != authz.Deny || result.Status != "LOOKUP_FAILED" || ran != 0 || len(policy.events) != 1 || policy.events[0].GithubResult.Status != "LOOKUP_FAILED" {
		t.Fatalf("lookup failure: %+v events %d ran %d", result, len(policy.events), ran)
	}
	if strings.Contains(out.ResultJson, "SECRET") {
		t.Fatal("lookup error text reached the caller")
	}

	// A stated precondition is refused before any decision.
	p, policy, _ = setup()
	lookups, ran = 0, 0
	if _, err := p.enforce(context.Background(), call, newOp(&lookups, precondition{"the branch moved"}, &ran)); err == nil || ran != 0 || len(policy.events) != 0 {
		t.Fatal("precondition not refused before deciding")
	}

	// No lookup for an unconfigured repository, or while the policy is offline.
	p, _, _ = setup()
	lookups, ran = 0, 0
	other := newOp(&lookups, nil, &ran)
	other.repository = "other-owner/other-repo"
	if _, err := p.enforce(context.Background(), call, other); err != nil || lookups != 0 {
		t.Fatalf("looked up an unconfigured repository: %v %d", err, lookups)
	}
	p, policy, _ = setup()
	policy.unavailable = true
	if _, err := p.enforce(context.Background(), call, newOp(&lookups, nil, &ran)); err == nil || lookups != 0 {
		t.Fatal("looked up while the policy was offline")
	}

	// Context for an action that declares none is an errored DENY.
	p, _, _ = setup()
	lookups, ran = 0, 0
	op := newOp(&lookups, nil, &ran)
	op.lookup = func(context.Context) (map[string]any, error) { return map[string]any{"smuggled": true}, nil }
	out, _ = p.enforce(context.Background(), call, op)
	_ = json.Unmarshal([]byte(out.ResultJson), &result)
	if result.Decision != authz.Deny || ran != 0 {
		t.Fatal("undeclared context was accepted")
	}
}
