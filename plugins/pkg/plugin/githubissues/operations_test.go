package githubissues

import (
	"context"
	"encoding/json"
	"errors"
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
