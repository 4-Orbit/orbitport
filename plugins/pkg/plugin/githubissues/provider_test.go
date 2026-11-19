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
