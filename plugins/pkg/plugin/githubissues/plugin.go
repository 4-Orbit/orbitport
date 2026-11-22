// Package githubissues enforces GitHub operations using Orbitport's shared
// Cedar engine. A single operator-configured repository is bound to one
// tenant; callers cannot supply repository metadata or choose an installation.
//
// Every operation follows the same path (enforce):
//
//  1. strict params, then the configured repository and tenant (anything
//     else is a DENY without evaluation and without any GitHub call);
//  2. the active policy (an outage means no GitHub call at all);
//  3. for actions with trusted context (D-035), read-only GitHub lookups
//     that compute it; a failed lookup is a DENY with no write;
//  4. Cedar, then a synchronous decision audit before any write;
//  5. on ALLOW, one provider operation with a token narrowed to the one
//     repository and the operation's permissions, never retried;
//  6. an outcome audit with stable metadata only.
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

// provider performs GitHub operations. realProvider talks to api.github.com
// as the App; mockRepo keeps an in-memory repository.
type provider interface {
	Create(ctx context.Context, repo, title, body string) (int64, error)
	// ReadContents returns a file or a directory listing at ref ("" = default branch).
	ReadContents(ctx context.Context, repo, path, ref string) (contents, error)
}

// contents is a file (Content set) or a directory (Entries set).
type contents struct {
	Type    string  `json:"type"`
	Path    string  `json:"path"`
	Size    int64   `json:"size,omitempty"`
	Content string  `json:"content,omitempty"`
	Binary  bool    `json:"binary,omitempty"`
	Entries []entry `json:"entries,omitempty"`
}

type entry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size,omitempty"`
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
		p.provider = newMockRepo()
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

// Result is what every GitHub operation returns. Output carries the
// operation's data (for example file contents) to the caller only; it never
// reaches the audit log.
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
	// Number is the issue, comment, review or pull request number.
	Number int64  `json:"number,omitempty"`
	SHA    string `json:"sha,omitempty"`
	Ref    string `json:"ref,omitempty"`
	URL    string `json:"url,omitempty"`
	// The trusted context the decision used (D-035).
	Context map[string]any `json:"context,omitempty"`
	Output  any            `json:"output,omitempty"`
}

// outcome is what a successful provider operation reports.
type outcome struct {
	IssueNumber int64
	Number      int64
	SHA, Ref    string
	URL         string
	Output      any
}

// operation is one request on its way through enforce.
type operation struct {
	action     string
	repository string
	// lookup computes the trusted context with read-only GitHub calls. It
	// runs only for the configured repository and after the policy loaded.
	lookup func(ctx context.Context) (map[string]any, error)
	// run performs the operation after an ALLOW and its decision audit.
	// requestID is the audit request id, for attribution trailers.
	run     func(ctx context.Context, requestID string) (outcome, error)
	timeout time.Duration
}

// handler parses one method's params into an operation.
type handler func(p *Plugin, c *proto.GithubCallRequest) (operation, error)

// handlers is the action registry: one entry per supported GitHub method.
var handlers = map[string]handler{
	CreateAction:           (*Plugin).createIssue,
	"github.contents.Read": (*Plugin).readContents,
}

// Methods lists the GitHub methods the plugin serves (besides ListRepositories).
func Methods() []string {
	out := make([]string, 0, len(handlers))
	for m := range handlers {
		out = append(out, m)
	}
	return out
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
	h, ok := handlers[c.Method]
	if !ok {
		return nil, status.Error(codes.Unimplemented, "unsupported GitHub method")
	}
	op, err := h(p, c)
	if err != nil {
		return nil, err
	}
	return p.enforce(ctx, c, op)
}

type createParams struct {
	Repository string `json:"repository"`
	Title      string `json:"title"`
	Body       string `json:"body"`
}

func (p *Plugin) createIssue(c *proto.GithubCallRequest) (operation, error) {
	var args createParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	if !repoRE.MatchString(args.Repository) || strings.TrimSpace(args.Title) == "" || len(args.Title) > 256 || len(args.Body) > 60000 {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, title (1–256 bytes), body (up to 60000 bytes)")
	}
	return operation{action: CreateAction, repository: args.Repository, run: func(ctx context.Context, _ string) (outcome, error) {
		n, err := p.provider.Create(ctx, p.repository, args.Title, args.Body)
		if err != nil {
			return outcome{}, err
		}
		out := outcome{IssueNumber: n, Number: n}
		if p.mode == "real" {
			out.URL = fmt.Sprintf("https://github.com/%s/issues/%d", p.repository, n)
		}
		return out, nil
	}}, nil
}

var (
	pathSegmentRE = regexp.MustCompile(`^[A-Za-z0-9._@+=,-][A-Za-z0-9._@+=, -]{0,254}$`)
	refRE         = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._/-]{0,254}$`)
)

// cleanPath validates a repository path: relative, no "." or ".." segments,
// at most 512 bytes. Leading and trailing slashes are dropped; "" is the root.
func cleanPath(path string) (string, bool) {
	path = strings.Trim(path, "/")
	if path == "" {
		return "", true
	}
	if len(path) > 512 {
		return "", false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." || !pathSegmentRE.MatchString(seg) {
			return "", false
		}
	}
	return path, true
}

// validRef accepts a branch, tag or commit id without ".." or "//".
func validRef(ref string) bool {
	return refRE.MatchString(ref) && !strings.Contains(ref, "..") && !strings.Contains(ref, "//") && !strings.HasSuffix(ref, "/")
}

type readParams struct {
	Repository string `json:"repository"`
	Path       string `json:"path"`
	Ref        string `json:"ref,omitempty"`
}

func (p *Plugin) readContents(c *proto.GithubCallRequest) (operation, error) {
	var args readParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	path, ok := cleanPath(args.Path)
	if !repoRE.MatchString(args.Repository) || !ok || (args.Ref != "" && !validRef(args.Ref)) {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, a relative path without . or .. segments, and an optional ref")
	}
	return operation{
		action:     "github.contents.Read",
		repository: args.Repository,
		// The policy sees exactly the path that will be read.
		lookup: func(context.Context) (map[string]any, error) { return map[string]any{"path": path}, nil },
		run: func(ctx context.Context, _ string) (outcome, error) {
			got, err := p.provider.ReadContents(ctx, p.repository, path, args.Ref)
			if err != nil {
				return outcome{}, err
			}
			return outcome{Ref: args.Ref, Output: got}, nil
		},
	}, nil
}

// enforce runs one operation through policy, audit and the provider.
func (p *Plugin) enforce(ctx context.Context, c *proto.GithubCallRequest, op operation) (*proto.GithubCallResponse, error) {
	timeout := op.timeout
	if timeout == 0 {
		timeout = 12 * time.Second
	}
	// Bound the whole operation, including both audit acknowledgements.
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	principal := authz.Principal{Tenant: c.KmsTenant, AgentID: c.AgentId}
	resource := authz.Resource{Type: "Repository", ID: "unconfigured", Tenant: p.tenant}
	known := op.repository == p.repository && c.KmsTenant == p.tenant
	if known {
		resource.ID = p.repository
	}
	req := authz.Request{Principal: principal, Action: op.action, Resource: resource}
	decision := authz.Result{Decision: authz.Deny, DeterminingPolicies: []string{}}
	var version int64
	lookupFailed := false
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
		if op.lookup != nil {
			trusted, err := op.lookup(ctx)
			if err != nil {
				var pre precondition
				if asPrecondition(err, &pre) {
					return nil, status.Error(codes.FailedPrecondition, pre.msg)
				}
				lookupFailed = true
				decision = authz.Result{Decision: authz.Deny, DeterminingPolicies: []string{}, Errored: true}
			}
			req.Context = trusted
		}
		if !lookupFailed {
			decision = authz.Evaluate(compiled, req, p.now())
		}
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, status.Error(codes.Internal, "request id unavailable")
	}
	ev := authz.NewAuditEvent(p.now().UTC().Format(time.RFC3339Nano), hex.EncodeToString(id[:]), req, decision, version, authz.ModeEnforce)
	ev.JtiHash = c.JtiHash
	ev.Stage = "decision"
	ev.GithubMode = p.mode
	ev.Context = req.Context
	if lookupFailed {
		ev.GithubResult = &authz.GithubResult{Status: "LOOKUP_FAILED"}
	}
	// Synchronous: no token exchange or write before audit acceptance.
	if err := p.record(ctx, ev); err != nil {
		return nil, err
	}
	out := Result{Decision: decision.Decision, DeterminingPolicies: decision.DeterminingPolicies, PolicyVersion: version, RequestID: ev.RequestID, Mode: p.mode, Status: "DENIED", Context: req.Context}
	if lookupFailed {
		out.Status = "LOOKUP_FAILED"
	}
	if decision.Decision != authz.Allow {
		return response(out)
	}
	done, err := op.run(ctx, ev.RequestID)
	out.GithubCalled = p.mode == "real"
	out.Status = "ERROR"
	if err == nil {
		out.Status = "SUCCESS"
		out.IssueNumber, out.Number, out.SHA, out.Ref, out.URL, out.Output = done.IssueNumber, done.Number, done.SHA, done.Ref, done.URL, done.Output
		if op.action == CreateAction {
			out.IssueURL = done.URL
		}
	} else if pre := (precondition{}); asPrecondition(err, &pre) {
		// GitHub refused for a stated, safe reason (e.g. the branch moved).
		out.Status = "REFUSED"
	}
	ev.Stage = "outcome"
	ev.GithubCalled = out.GithubCalled
	ev.GithubResult = &authz.GithubResult{Status: out.Status, IssueNumber: out.IssueNumber, Number: out.Number, SHA: out.SHA, Ref: auditRef(out.Ref)}
	// The decision remains recorded if the outcome acknowledgement fails.
	// Never retry the provider: a timed-out write may already have succeeded.
	auditCtx, auditCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer auditCancel()
	if err := p.record(auditCtx, ev); err != nil {
		out.Status = "OUTCOME_AUDIT_UNAVAILABLE"
	}
	if out.Status == "REFUSED" {
		var pre precondition
		asPrecondition(err, &pre)
		out.Output = map[string]string{"reason": pre.msg}
	}
	return response(out)
}

// precondition is a refusal with a message that is safe to show: it never
// carries provider text.
type precondition struct{ msg string }

func (e precondition) Error() string { return e.msg }

func asPrecondition(err error, into *precondition) bool {
	pre, ok := err.(precondition)
	if ok {
		*into = pre
	}
	return ok
}

var auditRefRE = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,255}$`)

// auditRef keeps a branch name in the audit only when it is plain.
func auditRef(ref string) string {
	if ref == "" || !auditRefRE.MatchString(ref) {
		return ""
	}
	return ref
}

func (p *Plugin) record(ctx context.Context, ev authz.AuditEvent) error {
	raw, _ := json.Marshal(ev)
	ack, err := p.policy.RecordAudit(ctx, &proto.RecordAuditRequest{EventsJson: []string{string(raw)}})
	if err != nil || ack.Accepted != 1 {
		return status.Error(codes.Unavailable, "audit unavailable; do not retry this GitHub operation automatically")
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
