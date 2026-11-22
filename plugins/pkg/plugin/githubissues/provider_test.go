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
