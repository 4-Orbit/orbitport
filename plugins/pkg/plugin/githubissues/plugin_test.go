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
}

func (p *policyStub) GetActive(context.Context, *proto.GetActiveRequest, ...grpc.CallOption) (*proto.GetActiveResponse, error) {
	if p.unavailable {
		return nil, errors.New("offline")
	}
	return &proto.GetActiveResponse{Exists: true, Version: 7, Policies: p.policies, EntitiesJson: `[]`}, nil
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
