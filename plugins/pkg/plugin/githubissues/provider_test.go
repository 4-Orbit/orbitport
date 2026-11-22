package githubissues

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRealProviderScopesAndFixedEndpoints(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	p := &realProvider{appID: "123", installationID: "456", key: key, now: time.Now}
	p.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Scheme != "https" || r.URL.Host != "api.github.com" || r.Method != "POST" {
			t.Fatal("wrong target")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		payload := `{"number":42,"html_url":"https://evil.invalid/secret"}`
		if calls == 1 {
			if r.URL.Path != "/app/installations/456/access_tokens" {
				t.Fatal("wrong token path")
			}
			if stringBody, _ := json.Marshal(body); string(stringBody) != `{"permissions":{"issues":"write"},"repositories":["test-repo"]}` {
				t.Fatalf("scope: %s", stringBody)
			}
			payload = `{"token":"secret-installation-token"}`
		} else {
			if r.URL.Path != "/repos/test-owner/test-repo/issues" || r.Header.Get("Authorization") != "Bearer secret-installation-token" {
				t.Fatal("wrong issue request")
			}
			if body["title"] != "Title" || body["body"] != "Body" {
				t.Fatal("missing issue contents")
			}
		}
		return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})}
	n, err := p.Create(context.Background(), "test-owner/test-repo", "Title", "Body")
	if err != nil || n != 42 || calls != 2 {
		t.Fatalf("%d %v calls %d", n, err, calls)
	}
}

// fakeGithub answers the token exchange, then hands each API request to api.
func fakeGithub(t *testing.T, wantPerms string, api func(r *http.Request, body map[string]any) (int, string)) *realProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &realProvider{appID: "123", installationID: "456", key: key, now: time.Now}
	p.client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "api.github.com" {
			t.Fatalf("wrong target %s", r.URL)
		}
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		status, payload := 0, ""
		if r.URL.Path == "/app/installations/456/access_tokens" {
			if got, _ := json.Marshal(body); string(got) != wantPerms {
				t.Fatalf("token scope %s, want %s", got, wantPerms)
			}
			status, payload = 201, `{"token":"secret-installation-token"}`
		} else {
			if r.Header.Get("Authorization") != "Bearer secret-installation-token" {
				t.Fatal("API call without the narrowed token")
			}
			status, payload = api(r, body)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})}
	return p
}

func TestRealProviderReadsContentsWithAReadOnlyToken(t *testing.T) {
	p := fakeGithub(t, `{"permissions":{"contents":"read"},"repositories":["test-repo"]}`, func(r *http.Request, _ map[string]any) (int, string) {
		if r.Method != "GET" || r.URL.EscapedPath() != "/repos/test-owner/test-repo/contents/docs/a%20b.md" || r.URL.Query().Get("ref") != "main" {
			t.Fatalf("wrong read %s %s", r.Method, r.URL)
		}
		return 200, `{"type":"file","path":"docs/a b.md","size":5,"encoding":"base64","content":"aGVs\nbG8="}`
	})
	got, err := p.ReadContents(context.Background(), "test-owner/test-repo", "docs/a b.md", "main")
	if err != nil || got.Content != "hello" || got.Type != "file" {
		t.Fatalf("%+v %v", got, err)
	}
	missing := fakeGithub(t, `{"permissions":{"contents":"read"},"repositories":["test-repo"]}`, func(*http.Request, map[string]any) (int, string) { return 404, `{"message":"SECRET"}` })
	if _, err := missing.ReadContents(context.Background(), "test-owner/test-repo", "x", ""); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("404: %v", err)
	}
}

func TestRealProviderCommentsWithAnIssuesToken(t *testing.T) {
	p := fakeGithub(t, `{"permissions":{"issues":"write"},"repositories":["test-repo"]}`, func(r *http.Request, body map[string]any) (int, string) {
		if r.Method != "POST" || r.URL.Path != "/repos/test-owner/test-repo/issues/5/comments" || body["body"] != "hi" {
			t.Fatalf("wrong comment %s %s %v", r.Method, r.URL, body)
		}
		return 201, `{"id":77}`
	})
	if id, err := p.Comment(context.Background(), "test-owner/test-repo", 5, "hi"); err != nil || id != 77 {
		t.Fatalf("%d %v", id, err)
	}
}

func TestRealProviderCreatesABranchFromTheDefaultBranch(t *testing.T) {
	const head = "0123456789abcdef0123456789abcdef01234567"
	var steps []string
	p := fakeGithub(t, `{"permissions":{"contents":"write"},"repositories":["test-repo"]}`, func(r *http.Request, body map[string]any) (int, string) {
		steps = append(steps, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/repos/test-owner/test-repo":
			return 200, `{"default_branch":"trunk"}`
		case "/repos/test-owner/test-repo/git/ref/heads/trunk":
			return 200, `{"object":{"sha":"` + head + `"}}`
		case "/repos/test-owner/test-repo/git/refs":
			if body["ref"] != "refs/heads/agent/dev/x" || body["sha"] != head {
				t.Fatalf("ref body %v", body)
			}
			return 201, `{}`
		}
		t.Fatalf("unexpected %s %s", r.Method, r.URL)
		return 500, ""
	})
	sha, err := p.CreateBranch(context.Background(), "test-owner/test-repo", "agent/dev/x", "")
	if err != nil || sha != head || len(steps) != 3 {
		t.Fatalf("%s %v %v", sha, err, steps)
	}
	meta := fakeGithub(t, `{"permissions":{"metadata":"read"},"repositories":["test-repo"]}`, func(*http.Request, map[string]any) (int, string) { return 200, `{"default_branch":"trunk"}` })
	if def, err := meta.DefaultBranch(context.Background(), "test-owner/test-repo"); err != nil || def != "trunk" {
		t.Fatalf("%s %v", def, err)
	}
}

func TestRealProviderCommitsFastForwardOnly(t *testing.T) {
	const head, next = "0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef"
	moved := false
	newProvider := func() *realProvider {
		return fakeGithub(t, `{"permissions":{"contents":"write"},"repositories":["test-repo"]}`, func(r *http.Request, body map[string]any) (int, string) {
			switch r.Method + " " + r.URL.EscapedPath() {
			case "GET /repos/test-owner/test-repo/git/ref/heads/agent/dev/x":
				return 200, `{"object":{"sha":"` + head + `"}}`
			case "GET /repos/test-owner/test-repo/git/commits/" + head:
				return 200, `{"tree":{"sha":"tree0"}}`
			case "POST /repos/test-owner/test-repo/git/trees":
				entries := body["tree"].([]any)
				if body["base_tree"] != "tree0" || len(entries) != 2 || entries[0].(map[string]any)["content"] != "new" || entries[1].(map[string]any)["sha"] != nil {
					t.Fatalf("tree %v", body)
				}
				return 201, `{"sha":"tree1"}`
			case "POST /repos/test-owner/test-repo/git/commits":
				if body["tree"] != "tree1" || body["parents"].([]any)[0] != head {
					t.Fatalf("commit %v", body)
				}
				return 201, `{"sha":"` + next + `"}`
			case "PATCH /repos/test-owner/test-repo/git/refs/heads/agent/dev/x":
				if body["sha"] != next || body["force"] != false {
					t.Fatalf("ref update %v", body)
				}
				if moved {
					return 422, `{"message":"SECRET not a fast forward"}`
				}
				return 200, `{}`
			}
			t.Fatalf("unexpected %s %s", r.Method, r.URL)
			return 500, ""
		})
	}
	changes := []fileChange{{Path: "README.md", Content: "new"}, {Path: "old.txt", Delete: true}}
	if sha, err := newProvider().Commit(context.Background(), "test-owner/test-repo", "agent/dev/x", "m", changes); err != nil || sha != next {
		t.Fatalf("%s %v", sha, err)
	}
	moved = true
	_, err := newProvider().Commit(context.Background(), "test-owner/test-repo", "agent/dev/x", "m", changes)
	var pre precondition
	if !asPrecondition(err, &pre) || strings.Contains(pre.msg, "SECRET") {
		t.Fatalf("moved branch: %v", err)
	}
}

func TestRealProviderOpensAPullRequest(t *testing.T) {
	p := fakeGithub(t, `{"permissions":{"pull_requests":"write"},"repositories":["test-repo"]}`, func(r *http.Request, body map[string]any) (int, string) {
		if r.Method != "POST" || r.URL.Path != "/repos/test-owner/test-repo/pulls" || body["head"] != "agent/dev/x" || body["base"] != "main" || body["title"] != "T" {
			t.Fatalf("wrong pull %s %s %v", r.Method, r.URL, body)
		}
		return 201, `{"number":12}`
	})
	if n, err := p.OpenPull(context.Background(), "test-owner/test-repo", "agent/dev/x", "main", "T", "B"); err != nil || n != 12 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestRealProviderReadsAndReviewsPullRequests(t *testing.T) {
	const head = "0123456789abcdef0123456789abcdef01234567"
	reader := fakeGithub(t, `{"permissions":{"pull_requests":"read"},"repositories":["test-repo"]}`, func(r *http.Request, _ map[string]any) (int, string) {
		if r.Method != "GET" || r.URL.Path != "/repos/test-owner/test-repo/pulls/12" {
			t.Fatalf("wrong read %s %s", r.Method, r.URL)
		}
		return 200, `{"state":"open","mergeable_state":"clean","head":{"ref":"agent/dev/x","sha":"` + head + `"},"base":{"ref":"main"},"user":{"type":"Bot"}}`
	})
	pr, err := reader.Pull(context.Background(), "test-owner/test-repo", 12)
	if err != nil || pr.HeadRef != "agent/dev/x" || !pr.AuthorIsApp || !pr.Open || pr.MergeableState != "clean" {
		t.Fatalf("%+v %v", pr, err)
	}
	reviewer := fakeGithub(t, `{"permissions":{"pull_requests":"write"},"repositories":["test-repo"]}`, func(r *http.Request, body map[string]any) (int, string) {
		if r.Method != "POST" || r.URL.Path != "/repos/test-owner/test-repo/pulls/12/reviews" || body["event"] != "COMMENT" || body["body"] != "hi" {
			t.Fatalf("wrong review %s %s %v", r.Method, r.URL, body)
		}
		return 200, `{"id":9}`
	})
	if id, err := reviewer.Review(context.Background(), "test-owner/test-repo", 12, "COMMENT", "hi", false); err != nil || id != 9 {
		t.Fatalf("%d %v", id, err)
	}
}
