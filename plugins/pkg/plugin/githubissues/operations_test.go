package githubissues

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
)

const repo = "test-owner/test-repo"

func TestContentsReadDecidesOnTheExactPath(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = `@id("read") permit(principal == Agent::"developer-agent", action == Action::"github.contents.Read", resource == Repository::"test-owner/test-repo") unless { context.path like "secrets/*" };`
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{"README.md", true},
		{"/docs/guide.md/", true},
		{"", true},
		{"secrets/key.pem", false},
	} {
		provider.calls = 0
		policy.events = nil
		r, err := callOp(t, p, "github.contents.Read", "developer-agent", map[string]any{"repository": repo, "path": tc.path})
		if err != nil {
			t.Fatal(err)
		}
		if (r.Decision == authz.Allow) != tc.allow || (provider.calls == 1) != tc.allow {
			t.Fatalf("%q: %+v calls %d", tc.path, r, provider.calls)
		}
		want, _ := cleanPath(tc.path)
		if policy.events[0].Context["path"] != want {
			t.Fatalf("%q: audited context %v", tc.path, policy.events[0].Context)
		}
		raw, _ := json.Marshal(policy.events)
		if strings.Contains(string(raw), "FILE CONTENT SECRET") {
			t.Fatal("file content reached the audit log")
		}
	}
	// Unsafe paths and refs never reach policy or GitHub.
	for _, params := range []map[string]any{
		{"repository": repo, "path": "../etc/passwd"},
		{"repository": repo, "path": "a/./b"},
		{"repository": repo, "path": "a\x00b"},
		{"repository": repo, "path": "README.md", "ref": "main..evil"},
		{"repository": repo, "path": "README.md", "extra": true},
	} {
		if _, err := callOp(t, p, "github.contents.Read", "developer-agent", params); err == nil {
			t.Fatalf("accepted %v", params)
		}
	}
}

func TestMockRepositoryReadsFilesAndDirectories(t *testing.T) {
	m, ctx := newMockRepo(), context.Background()
	f, err := m.ReadContents(ctx, repo, "README.md", "")
	if err != nil || f.Type != "file" || !strings.Contains(f.Content, "tryy") {
		t.Fatalf("file: %+v %v", f, err)
	}
	d, err := m.ReadContents(ctx, repo, "", "main")
	if err != nil || d.Type != "dir" || len(d.Entries) != 4 {
		t.Fatalf("root: %+v %v", d, err)
	}
	if _, err := m.ReadContents(ctx, repo, "nope.txt", ""); err == nil {
		t.Fatal("missing path read")
	}
}

func TestIssueCommentIsAttributedAndPrivate(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = `@id("comment") permit(principal == Agent::"developer-agent", action == Action::"github.issue.Comment", resource == Repository::"test-owner/test-repo");`
	r, err := callOp(t, p, "github.issue.Comment", "developer-agent", map[string]any{"repository": repo, "number": 5, "body": "PRIVATE COMMENT"})
	if err != nil || r.Decision != authz.Allow || r.Status != "SUCCESS" || r.Number != 5 || !strings.Contains(r.URL, "#issuecomment-99") {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(provider.last, "PRIVATE COMMENT") || !strings.Contains(provider.last, "agent `developer-agent`") || !strings.Contains(provider.last, r.RequestID) {
		t.Fatalf("not attributed: %q", provider.last)
	}
	raw, _ := json.Marshal(policy.events)
	if strings.Contains(string(raw), "PRIVATE COMMENT") {
		t.Fatal("comment text reached the audit log")
	}
	if r, _ := callOp(t, p, "github.issue.Comment", "security-agent", map[string]any{"repository": repo, "number": 5, "body": "x"}); r.Decision != authz.Deny || provider.calls != 1 {
		t.Fatal("unpermitted agent commented")
	}
	for _, bad := range []map[string]any{{"repository": repo, "number": 0, "body": "x"}, {"repository": repo, "number": 1, "body": " "}} {
		if _, err := callOp(t, p, "github.issue.Comment", "developer-agent", bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestMockCommentNeedsAnExistingIssue(t *testing.T) {
	m, ctx := newMockRepo(), context.Background()
	if _, err := m.Comment(ctx, repo, 1, "x"); err == nil {
		t.Fatal("commented on a missing issue")
	}
	n, _ := m.Create(ctx, repo, "t", "b")
	if _, err := m.Comment(ctx, repo, n, "x"); err != nil {
		t.Fatal(err)
	}
}

// ownBranches lets developer-agent write only its own agent/<id>/ branches.
const ownBranches = `@id("own") permit(principal == Agent::"developer-agent", action in Action::"github.code", resource == Repository::"test-owner/test-repo") when { context has branchAgent && context.branchAgent == principal };`

func TestBranchCreateOnlyInTheAgentsOwnNamespace(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = ownBranches
	for _, tc := range []struct {
		branch string
		allow  bool
	}{
		{"agent/developer-agent/fix-typo", true},
		{"agent/security-agent/fix-typo", false},
		{"feature/x", false},
	} {
		provider.calls = 0
		r, err := callOp(t, p, "github.branch.Create", "developer-agent", map[string]any{"repository": repo, "branch": tc.branch})
		if err != nil {
			t.Fatal(err)
		}
		if (r.Decision == authz.Allow) != tc.allow || (provider.calls == 1) != tc.allow {
			t.Fatalf("%s: %+v", tc.branch, r)
		}
		if tc.allow && (r.Ref != tc.branch || r.SHA == "" || r.Context["isDefaultBranch"] != false) {
			t.Fatalf("%s: outcome %+v", tc.branch, r)
		}
	}
}

func TestAgentsNeverWriteTheDefaultBranch(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = `@id("all") permit(principal, action, resource);`
	r, err := callOp(t, p, "github.branch.Create", "developer-agent", map[string]any{"repository": repo, "branch": "main"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != authz.Deny || provider.calls != 0 || len(r.DeterminingPolicies) != 1 || r.DeterminingPolicies[0] != "platform.agents-never-write-default-branch" {
		t.Fatalf("default branch write: %+v", r)
	}
}

func TestFailedLookupWritesNothing(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = ownBranches
	provider.lookupErr = errors.New("GitHub down")
	r, err := callOp(t, p, "github.branch.Create", "developer-agent", map[string]any{"repository": repo, "branch": "agent/developer-agent/x"})
	if err != nil || r.Status != "LOOKUP_FAILED" || r.Decision != authz.Deny || provider.calls != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	// No lookup at all for an unconfigured repository.
	provider.lookups = 0
	if _, err := callOp(t, p, "github.branch.Create", "developer-agent", map[string]any{"repository": "other/repo", "branch": "agent/developer-agent/x"}); err != nil || provider.lookups != 0 {
		t.Fatal("looked up an unconfigured repository")
	}
}

func TestMockBranchesCopyTheirBase(t *testing.T) {
	m, ctx := newMockRepo(), context.Background()
	sha, err := m.CreateBranch(ctx, repo, "agent/a/x", "")
	if err != nil || sha != m.heads["main"] {
		t.Fatalf("%s %v", sha, err)
	}
	if _, err := m.CreateBranch(ctx, repo, "agent/a/x", ""); err == nil {
		t.Fatal("created a branch twice")
	}
	if f, _ := m.ReadContents(ctx, repo, "README.md", "agent/a/x"); f.Content == "" {
		t.Fatal("branch didn't copy main")
	}
}

func commitReq(branch string, paths ...string) map[string]any {
	files := []map[string]any{}
	for _, p := range paths {
		files = append(files, map[string]any{"path": p, "content": "SECRET SOURCE " + p})
	}
	return map[string]any{"repository": repo, "branch": branch, "message": "Fix typo", "files": files}
}

func TestCommitDecidesOnBranchAndPaths(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = ownBranches + `
@id("no-workflows") forbid(principal is Agent, action == Action::"github.commit.Create", resource) when { context.touchesWorkflows };`
	r, err := callOp(t, p, "github.commit.Create", "developer-agent", commitReq("agent/developer-agent/fix", "src/b.py", "README.md"))
	if err != nil || r.Decision != authz.Allow || r.Status != "SUCCESS" || r.SHA == "" || r.Ref != "agent/developer-agent/fix" {
		t.Fatalf("%+v %v", r, err)
	}
	if got := r.Context["paths"]; len(got.([]any)) != 2 || got.([]any)[0] != "README.md" {
		t.Fatalf("paths not sorted into context: %v", got)
	}
	if !strings.Contains(provider.last, "Orbitport-Agent: developer-agent") || !strings.Contains(provider.last, "Orbitport-Request: "+r.RequestID) {
		t.Fatalf("no trailers: %q", provider.last)
	}
	raw, _ := json.Marshal(policy.events)
	if strings.Contains(string(raw), "SECRET SOURCE") || strings.Contains(string(raw), "Fix typo") {
		t.Fatal("commit contents or message reached the audit log")
	}
	for name, params := range map[string]map[string]any{
		"workflow file":    commitReq("agent/developer-agent/fix", ".github/workflows/ci.yml"),
		"another's branch": commitReq("agent/security-agent/fix", "README.md"),
		"default branch":   commitReq("main", "README.md"),
	} {
		provider.calls = 0
		r, err := callOp(t, p, "github.commit.Create", "developer-agent", params)
		if err != nil || r.Decision != authz.Deny || provider.calls != 0 {
			t.Fatalf("%s: %+v %v", name, r, err)
		}
	}
	tooMany := make([]string, maxCommitFiles+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("f%d.txt", i)
	}
	for name, params := range map[string]map[string]any{
		"no files":       commitReq("agent/developer-agent/fix"),
		"duplicate path": commitReq("agent/developer-agent/fix", "a.txt", "a.txt"),
		"escape":         commitReq("agent/developer-agent/fix", "../x"),
		"too many":       commitReq("agent/developer-agent/fix", tooMany...),
		"too large":      {"repository": repo, "branch": "agent/developer-agent/fix", "message": "m", "files": []map[string]any{{"path": "a", "content": strings.Repeat("x", maxCommitBytes+1)}}},
	} {
		if _, err := callOp(t, p, "github.commit.Create", "developer-agent", params); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestMockCommitAppliesChanges(t *testing.T) {
	m, ctx := newMockRepo(), context.Background()
	if _, err := m.Commit(ctx, repo, "missing", "m", []fileChange{{Path: "a", Content: "x"}}); err == nil {
		t.Fatal("committed to a missing branch")
	}
	_, _ = m.CreateBranch(ctx, repo, "agent/a/x", "")
	before := m.heads["agent/a/x"]
	sha, err := m.Commit(ctx, repo, "agent/a/x", "m", []fileChange{{Path: "README.md", Content: "fixed"}, {Path: "src/hello.py", Delete: true}})
	if err != nil || sha == before {
		t.Fatalf("%s %v", sha, err)
	}
	if f, _ := m.ReadContents(ctx, repo, "README.md", "agent/a/x"); f.Content != "fixed" {
		t.Fatal("change not applied")
	}
	if f, _ := m.ReadContents(ctx, repo, "README.md", "main"); f.Content == "fixed" {
		t.Fatal("main changed")
	}
	if _, err := m.Commit(ctx, repo, "agent/a/x", "m", []fileChange{{Path: "nope", Delete: true}}); err == nil {
		t.Fatal("deleted a missing file")
	}
}

func TestPullRequestFromTheAgentsOwnBranch(t *testing.T) {
	p, policy, provider := setup()
	policy.policies = `@id("pr") permit(principal == Agent::"developer-agent", action == Action::"github.pr.Create", resource == Repository::"test-owner/test-repo") when { context has headAgent && context.headAgent == principal };`
	r, err := callOp(t, p, "github.pr.Create", "developer-agent", map[string]any{"repository": repo, "head": "agent/developer-agent/fix", "title": "Fix typo", "body": "PRIVATE PR BODY"})
	if err != nil || r.Decision != authz.Allow || r.Number != 12 || !strings.HasSuffix(r.URL, "/pull/12") {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.HasPrefix(provider.last, "agent/developer-agent/fix->main|PRIVATE PR BODY") || !strings.Contains(provider.last, r.RequestID) {
		t.Fatalf("base not defaulted or not attributed: %q", provider.last)
	}
	if r.Context["baseBranch"] != "main" || r.Context["isDefaultBase"] != true {
		t.Fatalf("context %v", r.Context)
	}
	raw, _ := json.Marshal(policy.events)
	if strings.Contains(string(raw), "PRIVATE PR BODY") {
		t.Fatal("pull request body reached the audit log")
	}
	provider.calls = 0
	if r, _ := callOp(t, p, "github.pr.Create", "developer-agent", map[string]any{"repository": repo, "head": "agent/security-agent/fix", "title": "x", "body": ""}); r.Decision != authz.Deny || provider.calls != 0 {
		t.Fatalf("proposed another agent's branch: %+v", r)
	}
	if _, err := callOp(t, p, "github.pr.Create", "developer-agent", map[string]any{"repository": repo, "head": "main", "title": "x", "body": ""}); err == nil {
		t.Fatal("head equal to the default base was accepted")
	}
}

func TestMockPullRequestsNeedChanges(t *testing.T) {
	m, ctx := newMockRepo(), context.Background()
	_, _ = m.CreateBranch(ctx, repo, "agent/a/x", "")
	if _, err := m.OpenPull(ctx, repo, "agent/a/x", "main", "t", "b"); err == nil {
		t.Fatal("opened a pull request with no changes")
	}
	_, _ = m.Commit(ctx, repo, "agent/a/x", "m", []fileChange{{Path: "README.md", Content: "fixed"}})
	n, err := m.OpenPull(ctx, repo, "agent/a/x", "main", "t", "b")
	if err != nil || n <= 0 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := m.OpenPull(ctx, repo, "agent/a/x", "main", "t", "b"); err == nil {
		t.Fatal("opened a second pull request for the same branch")
	}
}

const agentPull = "0123456789abcdef0123456789abcdef01234567"

func TestReviewNeverOfYourOwnPullRequest(t *testing.T) {
	p, policy, provider := setup()
	provider.pull = pullInfo{HeadRef: "agent/developer-agent/fix", HeadSHA: agentPull, BaseRef: "main", Open: true, AuthorIsApp: true}
	policy.policies = `@id("review") permit(principal, action == Action::"github.pr.Review", resource == Repository::"test-owner/test-repo");
@id("not-own") forbid(principal is Agent, action == Action::"github.pr.Review", resource) when { context has headAgent && context.headAgent == principal };`
	r, err := callOp(t, p, "github.pr.Review", "security-agent", map[string]any{"repository": repo, "number": 12, "event": "REQUEST_CHANGES", "body": "Please add a test"})
	if err != nil || r.Decision != authz.Allow || r.Status != "SUCCESS" || r.Context["headAgent"] != "developer-agent" || !strings.HasPrefix(provider.last, "REQUEST_CHANGES|Please add a test") {
		t.Fatalf("%+v %v %q", r, err, provider.last)
	}
	if r, _ := callOp(t, p, "github.pr.Review", "developer-agent", map[string]any{"repository": repo, "number": 12, "event": "COMMENT", "body": "LGTM"}); r.Decision != authz.Deny {
		t.Fatalf("reviewed its own pull request: %+v", r)
	}
	// An agent can't approve an App-authored pull request: GitHub forbids it.
	provider.calls = 0
	if _, err := callOp(t, p, "github.pr.Review", "security-agent", map[string]any{"repository": repo, "number": 12, "event": "APPROVE"}); err == nil || provider.calls != 0 || !strings.Contains(err.Error(), "person must approve") {
		t.Fatalf("agent approval: %v", err)
	}
	provider.pull.Open = false
	if _, err := callOp(t, p, "github.pr.Review", "security-agent", map[string]any{"repository": repo, "number": 12, "event": "COMMENT", "body": "x"}); err == nil {
		t.Fatal("reviewed a closed pull request")
	}
	for _, bad := range []map[string]any{
		{"repository": repo, "number": 12, "event": "MERGE", "body": "x"},
		{"repository": repo, "number": 12, "event": "COMMENT"},
	} {
		if _, err := callOp(t, p, "github.pr.Review", "security-agent", bad); err == nil {
			t.Fatalf("accepted %v", bad)
		}
	}
}

func TestMockAccountReviewsStandInForPeople(t *testing.T) {
	p, policy, _ := setup()
	mock := newMockRepo()
	p.provider, p.mode = mock, "mock"
	policy.policies = ""
	ctx := context.Background()
	_, _ = mock.CreateBranch(ctx, repo, "agent/developer-agent/fix", "")
	_, _ = mock.Commit(ctx, repo, "agent/developer-agent/fix", "m", []fileChange{{Path: "README.md", Content: "x"}})
	n, _ := mock.OpenPull(ctx, repo, "agent/developer-agent/fix", "main", "t", "b")
	r, err := callOp(t, p, "github.pr.Review", "", map[string]any{"repository": repo, "number": n, "event": "APPROVE"})
	if err != nil || r.Status != "SUCCESS" || len(mock.pulls[n].reviews) != 1 || !mock.pulls[n].reviews[0].human {
		t.Fatalf("account approval in mock mode: %+v %v", r, err)
	}
}
