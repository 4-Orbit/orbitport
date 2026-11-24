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
	"sort"
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
// appJWT signs a short-lived JWT as the App itself.
func (p *realProvider) appJWT() (string, error) {
	now := p.now()
	t, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer: p.appID, IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).SignedString(p.key)
	if err != nil {
		return "", fmt.Errorf("app signing failed")
	}
	return t, nil
}

// Installation reads the installation's granted permissions. It uses the
// App JWT and mints no installation token.
func (p *realProvider) Installation(ctx context.Context) (map[string]string, error) {
	appToken, err := p.appJWT()
	if err != nil {
		return nil, err
	}
	var inst struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := p.request(ctx, http.MethodGet, "/app/installations/"+p.installationID, appToken, nil, &inst, http.StatusOK); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range inst.Permissions {
		if errorTokenRE.MatchString(k) && (v == "read" || v == "write" || v == "admin") {
			out[k] = v
		}
	}
	return out, nil
}

func (p *realProvider) token(ctx context.Context, repo string, perms map[string]string) (string, error) {
	if !repoRE.MatchString(repo) {
		return "", fmt.Errorf("invalid repository")
	}
	appToken, err := p.appJWT()
	if err != nil {
		return "", err
	}
	name := repo[len(ownerOf(repo))+1:]
	var issued struct {
		Token string `json:"token"`
	}
	if err := p.request(ctx, http.MethodPost, "/app/installations/"+p.installationID+"/access_tokens", appToken,
		map[string]any{"repositories": []string{name}, "permissions": perms}, &issued, http.StatusCreated); err != nil {
		// 422 (or 403/404): the installation doesn't grant these permissions
		// or this repository. Nothing was written, so say what's missing.
		if r, ok := err.(refusal); ok && (r.status == http.StatusUnprocessableEntity || r.status == http.StatusForbidden || r.status == http.StatusNotFound) {
			return "", precondition{fmt.Sprintf("GitHub didn't issue a token with %s for %s (HTTP %d): give the GitHub App that permission and accept it on the installation", describePerms(perms), repo, r.status)}
		}
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

// describePerms renders {"contents":"write"} as "contents: write".
func describePerms(perms map[string]string) string {
	names := make([]string, 0, len(perms))
	for k, v := range perms {
		names = append(names, k+": "+v)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
		return refusal{status: res.StatusCode, detail: validationDetail(res.Body)}
	}
	if into == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 4*1024*1024)).Decode(into); err != nil {
		return fmt.Errorf("invalid GitHub response")
	}
	return nil
}

// refusal is a non-success GitHub status. detail is the plugin's own
// classification of GitHub's validation errors (never GitHub's text).
type refusal struct {
	status int
	detail string
}

func (r refusal) Error() string {
	if r.detail != "" {
		return fmt.Sprintf("GitHub request refused (HTTP %d: %s)", r.status, r.detail)
	}
	return fmt.Sprintf("GitHub request refused (HTTP %d)", r.status)
}

var errorTokenRE = regexp.MustCompile(`^[a-z_]{1,32}$`)

// validationDetail classifies a GitHub error body using only well-known
// phrases and GitHub's own field and code identifiers, so no free text
// from GitHub is ever passed on.
func validationDetail(body io.Reader) string {
	var e struct {
		Message string `json:"message"`
		Errors  []struct {
			Field   string `json:"field"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.NewDecoder(io.LimitReader(body, 64*1024)).Decode(&e) != nil {
		return ""
	}
	texts := []string{e.Message}
	for _, item := range e.Errors {
		texts = append(texts, item.Message)
	}
	for _, t := range texts {
		switch {
		case strings.Contains(t, "A pull request already exists"):
			return "a pull request is already open for this branch"
		case strings.Contains(t, "No commits between"):
			return "the branch has no commits that aren't on the base"
		case strings.Contains(t, "Reference already exists"):
			return "that branch already exists"
		}
	}
	var parts []string
	for _, item := range e.Errors {
		if errorTokenRE.MatchString(item.Field) && errorTokenRE.MatchString(item.Code) {
			parts = append(parts, item.Field+" "+item.Code)
		}
	}
	return strings.Join(parts, ", ")
}

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

func (p *realProvider) Comment(ctx context.Context, repo string, number int64, body string) (int64, error) {
	var comment struct {
		ID int64 `json:"id"`
	}
	post := func(perms map[string]string) error {
		token, err := p.token(ctx, repo, perms)
		if err != nil {
			return err
		}
		return p.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/issues/%d/comments", repo, number), token, map[string]string{"body": body}, &comment, http.StatusCreated)
	}
	err := post(map[string]string{"issues": "write"})
	// A pull request's conversation counts as the pull request: GitHub
	// answers 403 to an issues-only token and creates nothing, so asking
	// again with pull_requests: write can't duplicate the comment.
	if r, ok := err.(refusal); ok && r.status == http.StatusForbidden {
		err = post(map[string]string{"pull_requests": "write"})
	}
	if err != nil {
		return 0, notFound(err, "issue")
	}
	if comment.ID <= 0 {
		return 0, fmt.Errorf("invalid comment response")
	}
	return comment.ID, nil
}

// exists turns GitHub's 422 for an existing name into a stated refusal.
func exists(err error, what string) error {
	if r, ok := err.(refusal); ok && r.status == http.StatusUnprocessableEntity {
		return precondition{what + " already exists or is invalid"}
	}
	return err
}

var commitIDRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (p *realProvider) DefaultBranch(ctx context.Context, repo string) (string, error) {
	token, err := p.token(ctx, repo, map[string]string{"metadata": "read"})
	if err != nil {
		return "", err
	}
	var meta struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := p.request(ctx, http.MethodGet, "/repos/"+repo, token, nil, &meta, http.StatusOK); err != nil {
		return "", err
	}
	if meta.DefaultBranch == "" {
		return "", fmt.Errorf("invalid repository response")
	}
	return meta.DefaultBranch, nil
}

// headOf returns the commit a branch points to.
func (p *realProvider) headOf(ctx context.Context, repo, token, branch string) (string, error) {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := p.request(ctx, http.MethodGet, "/repos/"+repo+"/git/ref/heads/"+escapePath(branch), token, nil, &ref, http.StatusOK); err != nil {
		return "", notFound(err, "branch")
	}
	if !commitIDRE.MatchString(ref.Object.SHA) {
		return "", fmt.Errorf("invalid ref response")
	}
	return ref.Object.SHA, nil
}

func (p *realProvider) CreateBranch(ctx context.Context, repo, branch, from string) (string, error) {
	token, err := p.token(ctx, repo, map[string]string{"contents": "write"})
	if err != nil {
		return "", err
	}
	sha := from
	if !commitIDRE.MatchString(from) {
		if from == "" {
			var meta struct {
				DefaultBranch string `json:"default_branch"`
			}
			if err := p.request(ctx, http.MethodGet, "/repos/"+repo, token, nil, &meta, http.StatusOK); err != nil {
				return "", err
			}
			from = meta.DefaultBranch
		}
		if sha, err = p.headOf(ctx, repo, token, from); err != nil {
			return "", err
		}
	}
	if err := p.request(ctx, http.MethodPost, "/repos/"+repo+"/git/refs", token, map[string]string{"ref": "refs/heads/" + branch, "sha": sha}, nil, http.StatusCreated); err != nil {
		return "", exists(err, "branch")
	}
	return sha, nil
}

func (p *realProvider) Commit(ctx context.Context, repo, branch, message string, changes []fileChange) (string, error) {
	token, err := p.token(ctx, repo, map[string]string{"contents": "write"})
	if err != nil {
		return "", err
	}
	head, err := p.headOf(ctx, repo, token, branch)
	if err != nil {
		return "", err
	}
	var parent struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := p.request(ctx, http.MethodGet, "/repos/"+repo+"/git/commits/"+head, token, nil, &parent, http.StatusOK); err != nil {
		return "", err
	}
	entries := make([]map[string]any, 0, len(changes))
	for _, ch := range changes {
		e := map[string]any{"path": ch.Path, "mode": "100644", "type": "blob"}
		if ch.Delete {
			e["sha"] = nil
		} else {
			e["content"] = ch.Content
		}
		entries = append(entries, e)
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if err := p.request(ctx, http.MethodPost, "/repos/"+repo+"/git/trees", token, map[string]any{"base_tree": parent.Tree.SHA, "tree": entries}, &tree, http.StatusCreated); err != nil {
		// A delete of a path that doesn't exist is GitHub's 422.
		return "", exists(err, "a file change")
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := p.request(ctx, http.MethodPost, "/repos/"+repo+"/git/commits", token, map[string]any{"message": message, "tree": tree.SHA, "parents": []string{head}}, &commit, http.StatusCreated); err != nil {
		return "", err
	}
	if !commitIDRE.MatchString(commit.SHA) {
		return "", fmt.Errorf("invalid commit response")
	}
	// Fast-forward only: if the branch moved since head was read, GitHub
	// refuses and nothing is overwritten.
	if err := p.request(ctx, http.MethodPatch, "/repos/"+repo+"/git/refs/heads/"+escapePath(branch), token, map[string]any{"sha": commit.SHA, "force": false}, nil, http.StatusOK); err != nil {
		if r, ok := err.(refusal); ok && r.status == http.StatusUnprocessableEntity {
			return "", precondition{"the branch moved while committing; read it again and retry"}
		}
		return "", err
	}
	return commit.SHA, nil
}

func (p *realProvider) OpenPull(ctx context.Context, repo, head, base, title, body string) (int64, error) {
	token, err := p.token(ctx, repo, map[string]string{"pull_requests": "write", "contents": "read"})
	if err != nil {
		return 0, err
	}
	var pull struct {
		Number int64 `json:"number"`
	}
	if err := p.request(ctx, http.MethodPost, "/repos/"+repo+"/pulls", token, map[string]string{"title": title, "head": head, "base": base, "body": body}, &pull, http.StatusCreated); err != nil {
		if r, ok := err.(refusal); ok && r.status == http.StatusUnprocessableEntity {
			if r.detail == "" {
				r.detail = "GitHub gave no reason"
			}
			return 0, precondition{"GitHub refused the pull request: " + r.detail}
		}
		return 0, notFound(err, "branch")
	}
	if pull.Number <= 0 {
		return 0, fmt.Errorf("invalid pull request response")
	}
	return pull.Number, nil
}

func (p *realProvider) Pull(ctx context.Context, repo string, number int64) (pullInfo, error) {
	token, err := p.token(ctx, repo, map[string]string{"pull_requests": "read", "contents": "read"})
	if err != nil {
		return pullInfo{}, err
	}
	var pr struct {
		State          string `json:"state"`
		MergeableState string `json:"mergeable_state"`
		Head           struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		User struct {
			Type string `json:"type"`
		} `json:"user"`
	}
	if err := p.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%d", repo, number), token, nil, &pr, http.StatusOK); err != nil {
		return pullInfo{}, notFound(err, "pull request")
	}
	if !commitIDRE.MatchString(pr.Head.SHA) || pr.Head.Ref == "" {
		return pullInfo{}, fmt.Errorf("invalid pull request response")
	}
	return pullInfo{HeadRef: pr.Head.Ref, HeadSHA: pr.Head.SHA, BaseRef: pr.Base.Ref, Open: pr.State == "open", AuthorIsApp: pr.User.Type == "Bot", MergeableState: pr.MergeableState}, nil
}

func (p *realProvider) Review(ctx context.Context, repo string, number int64, event, body string, _ bool) (int64, error) {
	token, err := p.token(ctx, repo, map[string]string{"pull_requests": "write", "contents": "read"})
	if err != nil {
		return 0, err
	}
	payload := map[string]string{"event": event}
	if body != "" {
		payload["body"] = body
	}
	var review struct {
		ID int64 `json:"id"`
	}
	if err := p.request(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/pulls/%d/reviews", repo, number), token, payload, &review, http.StatusOK); err != nil {
		if r, ok := err.(refusal); ok && r.status == http.StatusUnprocessableEntity {
			return 0, precondition{"GitHub refused the review"}
		}
		return 0, notFound(err, "pull request")
	}
	return review.ID, nil
}

func (p *realProvider) HumanApprovals(ctx context.Context, repo string, number int64, head string) (int64, error) {
	token, err := p.token(ctx, repo, map[string]string{"pull_requests": "read", "contents": "read"})
	if err != nil {
		return 0, err
	}
	var reviews []struct {
		State    string `json:"state"`
		CommitID string `json:"commit_id"`
		User     struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"user"`
	}
	if err := p.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%d/reviews?per_page=100", repo, number), token, nil, &reviews, http.StatusOK); err != nil {
		return 0, notFound(err, "pull request")
	}
	// Reviews come oldest first; a person's latest decisive review counts.
	latest := map[string]bool{}
	for _, r := range reviews {
		if r.User.Type != "User" || r.User.Login == "" {
			continue
		}
		switch r.State {
		case "APPROVED":
			latest[r.User.Login] = r.CommitID == head
		case "CHANGES_REQUESTED", "DISMISSED":
			latest[r.User.Login] = false
		}
	}
	var n int64
	for _, approved := range latest {
		if approved {
			n++
		}
	}
	return n, nil
}

func (p *realProvider) Merge(ctx context.Context, repo string, number int64, head, method string) (string, error) {
	token, err := p.token(ctx, repo, map[string]string{"contents": "write", "pull_requests": "write"})
	if err != nil {
		return "", err
	}
	var merged struct {
		SHA    string `json:"sha"`
		Merged bool   `json:"merged"`
	}
	if err := p.request(ctx, http.MethodPut, fmt.Sprintf("/repos/%s/pulls/%d/merge", repo, number), token, map[string]string{"sha": head, "merge_method": method}, &merged, http.StatusOK); err != nil {
		if r, ok := err.(refusal); ok && (r.status == http.StatusMethodNotAllowed || r.status == http.StatusConflict || r.status == http.StatusUnprocessableEntity) {
			return "", precondition{"GitHub refused the merge: the pull request isn't mergeable (branch protection, conflicts or a newer head)"}
		}
		return "", err
	}
	if !merged.Merged || !commitIDRE.MatchString(merged.SHA) {
		return "", fmt.Errorf("invalid merge response")
	}
	return merged.SHA, nil
}

func (p *realProvider) OpenPulls(ctx context.Context, repo string) ([]pullSummary, error) {
	token, err := p.token(ctx, repo, map[string]string{"pull_requests": "read", "contents": "read"})
	if err != nil {
		return nil, err
	}
	var pulls []struct {
		Number int64  `json:"number"`
		Title  string `json:"title"`
		Head   struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		User struct {
			Type string `json:"type"`
		} `json:"user"`
	}
	if err := p.request(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls?state=open&per_page=%d", repo, maxListedPulls), token, nil, &pulls, http.StatusOK); err != nil {
		return nil, err
	}
	out := make([]pullSummary, 0, len(pulls))
	for _, pr := range pulls {
		out = append(out, pullSummary{Number: pr.Number, Title: pr.Title, HeadBranch: pr.Head.Ref, HeadSHA: pr.Head.SHA, BaseBranch: pr.Base.Ref, AuthorIsApp: pr.User.Type == "Bot"})
	}
	return out, nil
}
