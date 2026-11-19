// Package githubissues enforces issue creation using Orbitport's shared Cedar
// engine. A single operator-configured repository is bound to one tenant;
// callers cannot supply repository metadata or choose an installation.
package githubissues

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const CreateAction = "github.issue.Create"

var repoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$`)

type provider interface {
	Create(context.Context, string, string, string) (int64, error)
}

type Plugin struct {
	proto.UnimplementedGithubPluginServer
	policy     proto.PolicyPluginClient
	provider   provider
	repository string
	tenant     string
	mode       string
	now        func() time.Time
}

func NewPlugin() (*Plugin, error) {
	mode := env("ORBITPORT_GITHUB_MODE", "mock")
	repo := env("ORBITPORT_GITHUB_REPOSITORY", "demo-owner/orbitport-test")
	tenant := env("ORBITPORT_GITHUB_TENANT", "noop-tenant")
	if !repoRE.MatchString(repo) || tenant == "" {
		return nil, fmt.Errorf("invalid GitHub repository or tenant configuration")
	}
	addr := env("ORBITPORT_GITHUB_POLICY_PLUGIN", "plugin-policy:50009")
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	p := &Plugin{policy: proto.NewPolicyPluginClient(conn), repository: repo, tenant: tenant, mode: mode, now: time.Now}
	switch mode {
	case "mock":
		p.provider = mockProvider{}
	case "real":
		if os.Getenv("ORBITPORT_GITHUB_REPOSITORY") == "" || os.Getenv("ORBITPORT_GITHUB_TENANT") == "" {
			return nil, fmt.Errorf("real mode requires an explicit repository and tenant")
		}
		p.provider, err = newRealProvider()
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("ORBITPORT_GITHUB_MODE must be mock or real")
	}
	return p, nil
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

type createParams struct {
	Repository string `json:"repository"`
	Title      string `json:"title"`
	Body       string `json:"body"`
}

type Result struct {
	Decision            authz.Decision `json:"decision"`
	DeterminingPolicies []string       `json:"determiningPolicies"`
	PolicyVersion       int64          `json:"policyVersion"`
	RequestID           string         `json:"requestId"`
	Mode                string         `json:"mode"`
	GithubCalled        bool           `json:"githubCalled"`
	Status              string         `json:"status"`
	IssueNumber         int64          `json:"issueNumber,omitempty"`
	IssueURL            string         `json:"issueUrl,omitempty"`
}

func (p *Plugin) Call(ctx context.Context, c *proto.GithubCallRequest) (*proto.GithubCallResponse, error) {
	if c.KmsTenant == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant required")
	}
	if c.Method == "github.ListRepositories" {
		// Management metadata is available only to the account principal.
		if c.AgentId != "" {
			return nil, status.Error(codes.PermissionDenied, "request denied by policy")
		}
		var empty struct{}
		if err := decode(c.ParamsJson, &empty); err != nil {
			return nil, err
		}
		repos := []string{}
		if c.KmsTenant == p.tenant {
			repos = append(repos, p.repository)
		}
		return response(map[string]any{"repositories": repos, "mode": p.mode})
	}
	if c.Method != CreateAction {
		return nil, status.Error(codes.Unimplemented, "unsupported GitHub method")
	}
	var args createParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return nil, err
	}
	if !repoRE.MatchString(args.Repository) || strings.TrimSpace(args.Title) == "" || len(args.Title) > 256 || len(args.Body) > 60000 {
		return nil, status.Error(codes.InvalidArgument, "expected repository, title (1–256 bytes), body (up to 60000 bytes)")
	}
	// Bound the whole operation, including both audit acknowledgements.
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	principal := authz.Principal{Tenant: c.KmsTenant, AgentID: c.AgentId}
	resource := authz.Resource{Type: "Repository", ID: "unconfigured", Tenant: p.tenant}
	known := args.Repository == p.repository && c.KmsTenant == p.tenant
	if known {
		resource.ID = p.repository
	}
	req := authz.Request{Principal: principal, Action: CreateAction, Resource: resource}
	decision := authz.Result{Decision: authz.Deny, DeterminingPolicies: []string{}}
	var version int64
	if known {
		active, err := p.policy.GetActive(ctx, &proto.GetActiveRequest{KmsTenant: c.KmsTenant})
		if err != nil {
			return nil, status.Error(codes.Unavailable, "policy store unavailable; GitHub was not called")
		}
		var compiled *authz.Compiled
		if active.Exists {
			compiled, _ = authz.Compile(authz.Bundle{Policies: active.Policies, Entities: json.RawMessage(active.EntitiesJson)})
			if compiled == nil {
				return nil, status.Error(codes.Unavailable, "active policy invalid; GitHub was not called")
			}
			version = active.Version
		}
		decision = authz.Evaluate(compiled, req, p.now())
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, status.Error(codes.Internal, "request id unavailable")
	}
	ev := authz.NewAuditEvent(p.now().UTC().Format(time.RFC3339Nano), hex.EncodeToString(id[:]), req, decision, version, authz.ModeEnforce)
	ev.JtiHash = c.JtiHash
	ev.Stage = "decision"
	ev.GithubMode = p.mode
	// Synchronous: no token exchange or issue POST before audit acceptance.
	if err := p.record(ctx, ev); err != nil {
		return nil, err
	}
	out := Result{Decision: decision.Decision, DeterminingPolicies: decision.DeterminingPolicies, PolicyVersion: version, RequestID: ev.RequestID, Mode: p.mode, Status: "DENIED"}
	if decision.Decision != authz.Allow {
		return response(out)
	}
	number, err := p.provider.Create(ctx, p.repository, args.Title, args.Body)
	out.GithubCalled = p.mode == "real"
	out.Status = "ERROR"
	if err == nil {
		out.Status = "SUCCESS"
		out.IssueNumber = number
		if p.mode == "real" {
			out.IssueURL = fmt.Sprintf("https://github.com/%s/issues/%d", p.repository, number)
		}
	}
	ev.Stage = "outcome"
	ev.GithubCalled = out.GithubCalled
	ev.GithubResult = &authz.GithubResult{Status: out.Status, IssueNumber: out.IssueNumber}
	// The decision remains recorded if the outcome acknowledgement fails.
	// Never retry the provider: a timed-out POST may already have succeeded.
	auditCtx, auditCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer auditCancel()
	if err := p.record(auditCtx, ev); err != nil {
		out.Status = "OUTCOME_AUDIT_UNAVAILABLE"
	}
	return response(out)
}

func (p *Plugin) record(ctx context.Context, ev authz.AuditEvent) error {
	raw, _ := json.Marshal(ev)
	ack, err := p.policy.RecordAudit(ctx, &proto.RecordAuditRequest{EventsJson: []string{string(raw)}})
	if err != nil || ack.Accepted != 1 {
		return status.Error(codes.Unavailable, "audit unavailable; do not retry issue creation automatically")
	}
	return nil
}

func decode(raw string, into any) error {
	if len(raw) > 65000 {
		return status.Error(codes.InvalidArgument, "params too large")
	}
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil || strings.TrimSpace(raw) == "null" {
		return status.Error(codes.InvalidArgument, "invalid GitHub params")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return status.Error(codes.InvalidArgument, "invalid GitHub params")
	}
	return nil
}

func response(v any) (*proto.GithubCallResponse, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode GitHub result")
	}
	return &proto.GithubCallResponse{ResultJson: string(raw)}, nil
}

type mockProvider struct{}

func (mockProvider) Create(context.Context, string, string, string) (int64, error) { return 1, nil }
