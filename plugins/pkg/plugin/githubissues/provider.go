package githubissues

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

// Credentials stay in this plugin. The browser and console server never see
// the App key, JWT or repository-scoped installation token.
type realProvider struct {
	appID          string
	installationID string
	key            *rsa.PrivateKey
	client         *http.Client
	now            func() time.Time
}

func newRealProvider() (*realProvider, error) {
	appID := os.Getenv("ORBITPORT_GITHUB_APP_ID")
	installationID := os.Getenv("ORBITPORT_GITHUB_INSTALLATION_ID")
	digits := regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	if !digits.MatchString(appID) || !digits.MatchString(installationID) {
		return nil, fmt.Errorf("real GitHub mode requires App and installation ids")
	}
	// File-mounted PEM is for the local demo; do not put it in the repository.
	pem, err := os.ReadFile(os.Getenv("ORBITPORT_GITHUB_PRIVATE_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("GitHub App key file unavailable")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub App RSA key")
	}
	return &realProvider{appID: appID, installationID: installationID, key: key, now: time.Now,
		client: &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// token mints an installation token narrowed to one repository and exactly
// the given permissions. It is used for one operation and thrown away.
func (p *realProvider) token(ctx context.Context, repo string, perms map[string]string) (string, error) {
	if !repoRE.MatchString(repo) {
		return "", fmt.Errorf("invalid repository")
	}
	now := p.now()
	appToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer: p.appID, IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).SignedString(p.key)
	if err != nil {
		return "", fmt.Errorf("app signing failed")
	}
	name := repo[len(ownerOf(repo))+1:]
	var issued struct {
		Token string `json:"token"`
	}
	if err := p.request(ctx, http.MethodPost, "/app/installations/"+p.installationID+"/access_tokens", appToken,
		map[string]any{"repositories": []string{name}, "permissions": perms}, &issued, http.StatusCreated); err != nil {
		return "", err
	}
	if issued.Token == "" {
		return "", fmt.Errorf("installation token unavailable")
	}
	return issued.Token, nil
}

func (p *realProvider) Create(ctx context.Context, repo, title, body string) (int64, error) {
	token, err := p.token(ctx, repo, map[string]string{"issues": "write"})
	if err != nil {
		return 0, err
	}
	var issue struct {
		Number int64 `json:"number"`
	}
	if err := p.request(ctx, http.MethodPost, "/repos/"+repo+"/issues", token, map[string]string{"title": title, "body": body}, &issue, http.StatusCreated); err != nil {
		return 0, err
	}
	if issue.Number <= 0 {
		return 0, fmt.Errorf("invalid issue response")
	}
	return issue.Number, nil
}

func ownerOf(repo string) string {
	for i, c := range repo {
		if c == '/' {
			return repo[:i]
		}
	}
	return ""
}

// request makes one call to api.github.com. body nil sends no body; into nil
// discards the response. Only the listed statuses count as success; anything
// else is a refusal whose text is never passed on (it is untrusted).
func (p *realProvider) request(ctx context.Context, method, path, token string, body, into any, ok ...int) error {
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, reader)
	if err != nil {
		return fmt.Errorf("GitHub request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "orbitport-github-issues")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// No redirects, no automatic retries, fixed host and validated repo path.
	res, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub request failed; outcome may be unknown")
	}
	defer func() { _ = res.Body.Close() }()
	accepted := false
	for _, code := range ok {
		accepted = accepted || res.StatusCode == code
	}
	if !accepted {
		return refusal{status: res.StatusCode}
	}
	if into == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4*1024*1024)).Decode(into); err != nil {
		return fmt.Errorf("invalid GitHub response")
	}
	return nil
}

// refusal is a non-success GitHub status, without GitHub's message.
type refusal struct{ status int }

func (r refusal) Error() string { return fmt.Sprintf("GitHub request refused (HTTP %d)", r.status) }

// escapePath escapes each segment of a repository path for a URL.
func escapePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// notFound turns GitHub's 404 into a safe, stated refusal.
func notFound(err error, what string) error {
	if r, ok := err.(refusal); ok && r.status == http.StatusNotFound {
		return precondition{what + " not found"}
	}
	return err
}

// maxDirEntries bounds a directory listing.
const maxDirEntries = 1000

func (p *realProvider) ReadContents(ctx context.Context, repo, path, ref string) (contents, error) {
	token, err := p.token(ctx, repo, map[string]string{"contents": "read"})
	if err != nil {
		return contents{}, err
	}
	target := "/repos/" + repo + "/contents/" + escapePath(path)
	if ref != "" {
		target += "?ref=" + url.QueryEscape(ref)
	}
	var raw json.RawMessage
	if err := p.request(ctx, http.MethodGet, target, token, nil, &raw, http.StatusOK); err != nil {
		return contents{}, notFound(err, "path")
	}
	if len(raw) > 0 && raw[0] == '[' {
		var list []entry
		if err := json.Unmarshal(raw, &list); err != nil {
			return contents{}, fmt.Errorf("invalid GitHub response")
		}
		if len(list) > maxDirEntries {
			list = list[:maxDirEntries]
		}
		return contents{Type: "dir", Path: path, Entries: list}, nil
	}
	var file struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		Size     int64  `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || file.Type != "file" {
		return contents{}, precondition{"not a file or directory"}
	}
	out := contents{Type: "file", Path: file.Path, Size: file.Size}
	if file.Encoding != "base64" {
		return out, precondition{"file too large to read through the API"}
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if err != nil {
		return contents{}, fmt.Errorf("invalid GitHub response")
	}
	if utf8.Valid(data) {
		out.Content = string(data)
	} else {
		out.Binary = true
	}
	return out, nil
}
