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
	"sort"
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
	// Comment adds a comment to an issue and returns the comment id.
	Comment(ctx context.Context, repo string, number int64, body string) (int64, error)
	// DefaultBranch reads the repository's default branch (a lookup).
	DefaultBranch(ctx context.Context, repo string) (string, error)
	// CreateBranch creates branch at from (a branch or commit id; "" = the
	// default branch) and returns the commit id it points to.
	CreateBranch(ctx context.Context, repo, branch, from string) (string, error)
	// Commit writes files to an existing branch as one commit, fast-forward
	// only, and returns the new commit id.
	Commit(ctx context.Context, repo, branch, message string, changes []fileChange) (string, error)
	// OpenPull opens a pull request from head into base and returns its number.
	OpenPull(ctx context.Context, repo, head, base, title, body string) (int64, error)
	// Pull reads a pull request (a lookup).
	Pull(ctx context.Context, repo string, number int64) (pullInfo, error)
	// Review submits a review. human is true only for the account principal
	// in mock mode, which stands in for a person reviewing on GitHub.
	Review(ctx context.Context, repo string, number int64, event, body string, human bool) (int64, error)
	// HumanApprovals counts people whose latest review approves head (a lookup).
	HumanApprovals(ctx context.Context, repo string, number int64, head string) (int64, error)
	// Merge merges the pull request only if its head is still head, and
	// returns the merge commit id.
	Merge(ctx context.Context, repo string, number int64, head, method string) (string, error)
}

// pullInfo is what the plugin needs to know about a pull request.
type pullInfo struct {
	HeadRef, HeadSHA, BaseRef string
	Open                      bool
	AuthorIsApp               bool
	// MergeableState is GitHub's mergeable_state ("clean", "blocked", ...).
	MergeableState string
}

// fileChange adds or replaces a file, or deletes it (Delete set).
type fileChange struct {
	Path    string
	Content string
	Delete  bool
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
	"github.issue.Comment": (*Plugin).commentIssue,
	"github.branch.Create": (*Plugin).createBranch,
	"github.commit.Create": (*Plugin).createCommit,
	"github.pr.Create":     (*Plugin).createPull,
	"github.pr.Review":     (*Plugin).reviewPull,
	"github.pr.Merge":      (*Plugin).mergePull,
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

// attribution marks text written through Orbitport, so GitHub (where every
// agent appears as the App) shows which agent and request it came from. It
// is informational only and never used for authorization.
func attribution(text string, c *proto.GithubCallRequest, requestID string) string {
	who := "the account"
	if c.AgentId != "" {
		who = "agent `" + c.AgentId + "`"
	}
	return strings.TrimRight(text, "\n") + "\n\n---\n_Sent through Orbitport by " + who + " (request `" + requestID + "`)._"
}

type commentParams struct {
	Repository string `json:"repository"`
	Number     int64  `json:"number"`
	Body       string `json:"body"`
}

func (p *Plugin) commentIssue(c *proto.GithubCallRequest) (operation, error) {
	var args commentParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	if !repoRE.MatchString(args.Repository) || args.Number <= 0 || strings.TrimSpace(args.Body) == "" || len(args.Body) > 60000 {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, issue number and body (1–60000 bytes)")
	}
	return operation{action: "github.issue.Comment", repository: args.Repository, run: func(ctx context.Context, requestID string) (outcome, error) {
		id, err := p.provider.Comment(ctx, p.repository, args.Number, attribution(args.Body, c, requestID))
		if err != nil {
			return outcome{}, err
		}
		out := outcome{Number: args.Number}
		if p.mode == "real" {
			out.URL = fmt.Sprintf("https://github.com/%s/issues/%d#issuecomment-%d", p.repository, args.Number, id)
		}
		return out, nil
	}}, nil
}

var agentBranchRE = regexp.MustCompile(`^agent/([a-z0-9][a-z0-9_-]{0,63})/.+`)

// branchAgent returns the agent an agent/<agent-id>/... branch belongs to.
func branchAgent(branch string) string {
	if m := agentBranchRE.FindStringSubmatch(branch); m != nil {
		return m[1]
	}
	return ""
}

// branchContext is the trusted context of a write to branch (D-035).
func (p *Plugin) branchContext(ctx context.Context, branch string) (map[string]any, error) {
	def, err := p.provider.DefaultBranch(ctx, p.repository)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"branch": branch, "isDefaultBranch": branch == def}
	if agent := branchAgent(branch); agent != "" {
		out["branchAgent"] = agent
	}
	return out, nil
}

type branchParams struct {
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	From       string `json:"from,omitempty"`
}

func (p *Plugin) createBranch(c *proto.GithubCallRequest) (operation, error) {
	var args branchParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	if !repoRE.MatchString(args.Repository) || !validRef(args.Branch) || strings.HasPrefix(args.Branch, "refs/") || (args.From != "" && !validRef(args.From)) {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, a branch name and an optional from (branch or commit)")
	}
	return operation{
		action:     "github.branch.Create",
		repository: args.Repository,
		lookup:     func(ctx context.Context) (map[string]any, error) { return p.branchContext(ctx, args.Branch) },
		run: func(ctx context.Context, _ string) (outcome, error) {
			sha, err := p.provider.CreateBranch(ctx, p.repository, args.Branch, args.From)
			if err != nil {
				return outcome{}, err
			}
			return outcome{Ref: args.Branch, SHA: sha}, nil
		},
	}, nil
}

// trailers are git commit trailers naming the agent and request, for the
// same reason as attribution.
func trailers(message string, c *proto.GithubCallRequest, requestID string) string {
	agent := c.AgentId
	if agent == "" {
		agent = "account"
	}
	return strings.TrimRight(message, "\n") + "\n\nOrbitport-Agent: " + agent + "\nOrbitport-Request: " + requestID + "\n"
}

// Commit limits keep one commit inside the gateway's 64 KB params.
const (
	maxCommitFiles   = 20
	maxCommitBytes   = 48000
	maxCommitMessage = 2000
)

type commitParams struct {
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	Message    string `json:"message"`
	Files      []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"files,omitempty"`
	Deletes []string `json:"deletes,omitempty"`
}

func (p *Plugin) createCommit(c *proto.GithubCallRequest) (operation, error) {
	var args commitParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	invalid := status.Error(codes.InvalidArgument, fmt.Sprintf("expected repository, an existing branch, a message (1–%d bytes) and 1–%d file changes (at most %d bytes of content, relative paths, each path once)", maxCommitMessage, maxCommitFiles, maxCommitBytes))
	if !repoRE.MatchString(args.Repository) || !validRef(args.Branch) || strings.HasPrefix(args.Branch, "refs/") || strings.TrimSpace(args.Message) == "" || len(args.Message) > maxCommitMessage {
		return operation{}, invalid
	}
	n := len(args.Files) + len(args.Deletes)
	if n == 0 || n > maxCommitFiles {
		return operation{}, invalid
	}
	var changes []fileChange
	seen := map[string]bool{}
	size := 0
	add := func(raw, content string, del bool) bool {
		path, ok := cleanPath(raw)
		if !ok || path == "" || seen[path] {
			return false
		}
		seen[path] = true
		size += len(content)
		changes = append(changes, fileChange{Path: path, Content: content, Delete: del})
		return true
	}
	for _, f := range args.Files {
		if !add(f.Path, f.Content, false) {
			return operation{}, invalid
		}
	}
	for _, d := range args.Deletes {
		if !add(d, "", true) {
			return operation{}, invalid
		}
	}
	if size > maxCommitBytes {
		return operation{}, invalid
	}
	paths := make([]string, 0, len(changes))
	workflows := false
	for _, ch := range changes {
		paths = append(paths, ch.Path)
		workflows = workflows || ch.Path == ".github/workflows" || strings.HasPrefix(ch.Path, ".github/workflows/")
	}
	sort.Strings(paths)
	return operation{
		action:     "github.commit.Create",
		repository: args.Repository,
		timeout:    30 * time.Second,
		lookup: func(ctx context.Context) (map[string]any, error) {
			out, err := p.branchContext(ctx, args.Branch)
			if err != nil {
				return nil, err
			}
			out["paths"], out["touchesWorkflows"] = paths, workflows
			return out, nil
		},
		run: func(ctx context.Context, requestID string) (outcome, error) {
			sha, err := p.provider.Commit(ctx, p.repository, args.Branch, trailers(args.Message, c, requestID), changes)
			if err != nil {
				return outcome{}, err
			}
			out := outcome{Ref: args.Branch, SHA: sha}
			if p.mode == "real" {
				out.URL = fmt.Sprintf("https://github.com/%s/commit/%s", p.repository, sha)
			}
			return out, nil
		},
	}, nil
}

type pullParams struct {
	Repository string `json:"repository"`
	Head       string `json:"head"`
	Base       string `json:"base,omitempty"`
	Title      string `json:"title"`
	Body       string `json:"body"`
}

func (p *Plugin) createPull(c *proto.GithubCallRequest) (operation, error) {
	var args pullParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	if !repoRE.MatchString(args.Repository) || !validRef(args.Head) || (args.Base != "" && !validRef(args.Base)) || args.Head == args.Base ||
		strings.TrimSpace(args.Title) == "" || len(args.Title) > 256 || len(args.Body) > 60000 {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, head branch, optional base branch, title (1–256 bytes) and body (up to 60000 bytes)")
	}
	base := args.Base
	return operation{
		action:     "github.pr.Create",
		repository: args.Repository,
		lookup: func(ctx context.Context) (map[string]any, error) {
			def, err := p.provider.DefaultBranch(ctx, p.repository)
			if err != nil {
				return nil, err
			}
			if base == "" {
				base = def
			}
			if base == args.Head {
				return nil, precondition{"head and base are the same branch"}
			}
			out := map[string]any{"headBranch": args.Head, "baseBranch": base, "isDefaultBase": base == def}
			if agent := branchAgent(args.Head); agent != "" {
				out["headAgent"] = agent
			}
			return out, nil
		},
		run: func(ctx context.Context, requestID string) (outcome, error) {
			n, err := p.provider.OpenPull(ctx, p.repository, args.Head, base, args.Title, attribution(args.Body, c, requestID))
			if err != nil {
				return outcome{}, err
			}
			out := outcome{Number: n, Ref: args.Head}
			if p.mode == "real" {
				out.URL = fmt.Sprintf("https://github.com/%s/pull/%d", p.repository, n)
			}
			return out, nil
		},
	}, nil
}

type reviewParams struct {
	Repository string `json:"repository"`
	Number     int64  `json:"number"`
	Event      string `json:"event"`
	Body       string `json:"body,omitempty"`
}

func (p *Plugin) reviewPull(c *proto.GithubCallRequest) (operation, error) {
	var args reviewParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	validEvent := args.Event == "COMMENT" || args.Event == "REQUEST_CHANGES" || args.Event == "APPROVE"
	if !repoRE.MatchString(args.Repository) || args.Number <= 0 || !validEvent || len(args.Body) > 60000 || (args.Event != "APPROVE" && strings.TrimSpace(args.Body) == "") {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, pull request number, event (COMMENT, REQUEST_CHANGES or APPROVE) and a body (required unless approving)")
	}
	human := p.mode == "mock" && c.AgentId == ""
	return operation{
		action:     "github.pr.Review",
		repository: args.Repository,
		lookup: func(ctx context.Context) (map[string]any, error) {
			pr, err := p.provider.Pull(ctx, p.repository, args.Number)
			if err != nil {
				return nil, err
			}
			if !pr.Open {
				return nil, precondition{"the pull request is closed"}
			}
			// GitHub never lets an App approve a pull request it opened, and
			// every agent acts as the App. A person approves on GitHub.
			if args.Event == "APPROVE" && pr.AuthorIsApp && !human {
				return nil, precondition{"GitHub doesn't let the App approve a pull request it opened; a person must approve it on GitHub"}
			}
			out := map[string]any{"event": args.Event, "headBranch": pr.HeadRef, "authorIsApp": pr.AuthorIsApp}
			if agent := branchAgent(pr.HeadRef); agent != "" {
				out["headAgent"] = agent
			}
			return out, nil
		},
		run: func(ctx context.Context, requestID string) (outcome, error) {
			body := args.Body
			if body != "" {
				body = attribution(body, c, requestID)
			}
			id, err := p.provider.Review(ctx, p.repository, args.Number, args.Event, body, human)
			if err != nil {
				return outcome{}, err
			}
			out := outcome{Number: args.Number}
			if p.mode == "real" {
				out.URL = fmt.Sprintf("https://github.com/%s/pull/%d#pullrequestreview-%d", p.repository, args.Number, id)
			}
			return out, nil
		},
	}, nil
}

type mergeParams struct {
	Repository      string `json:"repository"`
	Number          int64  `json:"number"`
	ExpectedHeadSHA string `json:"expectedHeadSha"`
	Method          string `json:"method,omitempty"`
}

func (p *Plugin) mergePull(c *proto.GithubCallRequest) (operation, error) {
	var args mergeParams
	if err := decode(c.ParamsJson, &args); err != nil {
		return operation{}, err
	}
	if args.Method == "" {
		args.Method = "squash"
	}
	validMethod := args.Method == "merge" || args.Method == "squash" || args.Method == "rebase"
	if !repoRE.MatchString(args.Repository) || args.Number <= 0 || !commitIDRE.MatchString(args.ExpectedHeadSHA) || !validMethod {
		return operation{}, status.Error(codes.InvalidArgument, "expected repository, pull request number, expectedHeadSha (the 40-character head commit you reviewed) and an optional method (merge, squash or rebase)")
	}
	return operation{
		action:     "github.pr.Merge",
		repository: args.Repository,
		timeout:    20 * time.Second,
		lookup: func(ctx context.Context) (map[string]any, error) {
			pr, err := p.provider.Pull(ctx, p.repository, args.Number)
			if err != nil {
				return nil, err
			}
			if !pr.Open {
				return nil, precondition{"the pull request is closed or already merged"}
			}
			// Merge exactly what was reviewed: a new push means review again.
			if pr.HeadSHA != args.ExpectedHeadSHA {
				return nil, precondition{"the pull request's head is now " + pr.HeadSHA + ", not the expected commit; check what changed before merging"}
			}
			def, err := p.provider.DefaultBranch(ctx, p.repository)
			if err != nil {
				return nil, err
			}
			approvals, err := p.provider.HumanApprovals(ctx, p.repository, args.Number, pr.HeadSHA)
			if err != nil {
				return nil, err
			}
			out := map[string]any{"headBranch": pr.HeadRef, "baseBranch": pr.BaseRef, "isDefaultBase": pr.BaseRef == def, "humanApprovals": approvals, "mergeableState": pr.MergeableState}
			if agent := branchAgent(pr.HeadRef); agent != "" {
				out["headAgent"] = agent
			}
			return out, nil
		},
		run: func(ctx context.Context, _ string) (outcome, error) {
			sha, err := p.provider.Merge(ctx, p.repository, args.Number, args.ExpectedHeadSHA, args.Method)
			if err != nil {
				return outcome{}, err
			}
			out := outcome{Number: args.Number, SHA: sha}
			if p.mode == "real" {
				out.URL = fmt.Sprintf("https://github.com/%s/pull/%d", p.repository, args.Number)
			}
			return out, nil
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
