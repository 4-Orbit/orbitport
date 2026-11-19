package githubissues

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

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

func (p *realProvider) Create(ctx context.Context, repo, title, body string) (int64, error) {
	if !repoRE.MatchString(repo) {
		return 0, fmt.Errorf("invalid repository")
	}
	now := p.now()
	appToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer: p.appID, IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).SignedString(p.key)
	if err != nil {
		return 0, fmt.Errorf("app signing failed")
	}
	name := repo[len(ownerOf(repo))+1:]
	var issued struct {
		Token string `json:"token"`
	}
	if err := p.post(ctx, "/app/installations/"+p.installationID+"/access_tokens", appToken,
		map[string]any{"repositories": []string{name}, "permissions": map[string]string{"issues": "write"}}, &issued); err != nil {
		return 0, err
	}
	if issued.Token == "" {
		return 0, fmt.Errorf("installation token unavailable")
	}
	var issue struct {
		Number int64 `json:"number"`
	}
	if err := p.post(ctx, "/repos/"+repo+"/issues", issued.Token, map[string]string{"title": title, "body": body}, &issue); err != nil {
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

func (p *realProvider) post(ctx context.Context, path, token string, body, into any) error {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.github.com"+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("GitHub request failed")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "orbitport-github-issues")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	// No redirects, no automatic retries, fixed host and validated repo path.
	res, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("GitHub request failed; outcome may be unknown")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("GitHub request refused")
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1024*1024)).Decode(into); err != nil {
		return fmt.Errorf("invalid GitHub response")
	}
	return nil
}
