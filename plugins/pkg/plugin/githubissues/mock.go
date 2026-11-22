package githubissues

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// mockRepo is mock mode's in-memory repository: it lets every operation run
// end to end, with real authorization and audit, without contacting GitHub.
// It starts with a default branch "main" holding a few files (including a
// deliberate typo, for agent demos). State lives in memory and is lost when
// the plugin restarts.
type mockRepo struct {
	mu sync.Mutex
	// next is the next issue or pull request number (they share numbers, as
	// on GitHub); issues holds each issue's comment count.
	next          int64
	issues        map[int64]int
	comments      int64
	defaultBranch string
	// branches maps a branch name to its files (path -> content); heads
	// maps it to its latest commit id.
	branches map[string]map[string]string
	heads    map[string]string
	commits  int
	pulls    map[int64]*mockPull
}

// mockPull is an open or merged pull request. Agents' pull requests are
// opened by the App, so their author is a bot, as on GitHub.
type mockPull struct {
	head, base string
	merged     bool
	// reviews are the latest review per reviewer: human (an account-token
	// stand-in for a person) or the App.
	reviews []mockReview
}

type mockReview struct {
	event string
	human bool
	sha   string
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		next:          1,
		issues:        map[int64]int{},
		pulls:         map[int64]*mockPull{},
		defaultBranch: "main",
		heads:         map[string]string{"main": mockSHA(0)},
		branches: map[string]map[string]string{
			"main": {
				"README.md":         "# Orbitport test repository\n\nThis repository is used to tryy Orbitport's governed GitHub agents.\nEvery agent action here is checked by Cedar policy first.\n",
				"docs/guide.md":     "# Guide\n\nAgents propose changes on branches named agent/<agent-id>/<name>.\n",
				"src/hello.py":      "def greet(name):\n    return \"Hello, \" + name\n",
				"secrets/README.md": "Nothing real here. Policies usually keep agents out of secrets/.\n",
			},
		},
	}
}

func (m *mockRepo) Create(context.Context, string, string, string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.next
	m.next++
	m.issues[n] = 0
	return n, nil
}

func (m *mockRepo) Comment(_ context.Context, _ string, number int64, _ string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.issues[number]; !ok {
		return 0, precondition{"issue not found"}
	}
	m.issues[number]++
	m.comments++
	return m.comments, nil
}

func (m *mockRepo) ReadContents(_ context.Context, _ string, path, ref string) (contents, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ref == "" {
		ref = m.defaultBranch
	}
	files, ok := m.branches[ref]
	if !ok {
		return contents{}, precondition{"ref not found"}
	}
	if content, ok := files[path]; ok {
		return contents{Type: "file", Path: path, Size: int64(len(content)), Content: content}, nil
	}
	prefix := ""
	if path != "" {
		prefix = path + "/"
	}
	seen := map[string]entry{}
	for p, content := range files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		name, _, nested := strings.Cut(rest, "/")
		e := entry{Name: name, Path: prefix + name, Type: "file", Size: int64(len(content))}
		if nested {
			e = entry{Name: name, Path: prefix + name, Type: "dir"}
		}
		seen[name] = e
	}
	if len(seen) == 0 {
		return contents{}, precondition{"path not found"}
	}
	out := contents{Type: "dir", Path: path}
	for _, e := range seen {
		out.Entries = append(out.Entries, e)
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Name < out.Entries[j].Name })
	return out, nil
}

// mockSHA is a stable fake commit id.
func mockSHA(n int) string {
	return fmt.Sprintf("%040x", n+0xc0ffee)
}

func (m *mockRepo) DefaultBranch(context.Context, string) (string, error) {
	return m.defaultBranch, nil
}

func (m *mockRepo) CreateBranch(_ context.Context, _ string, branch, from string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.branches[branch]; ok {
		return "", precondition{"branch already exists or is invalid"}
	}
	if from == "" {
		from = m.defaultBranch
	}
	files, ok := m.branches[from]
	if !ok {
		for name, head := range m.heads {
			if head == from {
				files, ok = m.branches[name], true
				break
			}
		}
	}
	if !ok {
		return "", precondition{"branch not found"}
	}
	copied := make(map[string]string, len(files))
	for path, content := range files {
		copied[path] = content
	}
	head := m.heads[from]
	if head == "" {
		head = from
	}
	m.branches[branch], m.heads[branch] = copied, head
	return head, nil
}

func (m *mockRepo) Commit(_ context.Context, _ string, branch, _ string, changes []fileChange) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	files, ok := m.branches[branch]
	if !ok {
		return "", precondition{"branch not found"}
	}
	for _, ch := range changes {
		if ch.Delete {
			if _, ok := files[ch.Path]; !ok {
				return "", precondition{"a file change already exists or is invalid"}
			}
		}
	}
	for _, ch := range changes {
		if ch.Delete {
			delete(files, ch.Path)
		} else {
			files[ch.Path] = ch.Content
		}
	}
	m.commits++
	m.heads[branch] = mockSHA(m.commits)
	return m.heads[branch], nil
}

func (m *mockRepo) OpenPull(_ context.Context, _ string, head, base, _, _ string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.branches[head]; !ok {
		return 0, precondition{"branch not found"}
	}
	if _, ok := m.branches[base]; !ok {
		return 0, precondition{"branch not found"}
	}
	if m.heads[head] == m.heads[base] {
		return 0, precondition{"GitHub refused the pull request: one may already be open for this branch, or it has no changes"}
	}
	for _, pr := range m.pulls {
		if pr.head == head && !pr.merged {
			return 0, precondition{"GitHub refused the pull request: one may already be open for this branch, or it has no changes"}
		}
	}
	n := m.next
	m.next++
	m.issues[n] = 0
	m.pulls[n] = &mockPull{head: head, base: base}
	return n, nil
}

func (m *mockRepo) Pull(_ context.Context, _ string, number int64) (pullInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.pulls[number]
	if !ok {
		return pullInfo{}, precondition{"pull request not found"}
	}
	state := "clean"
	if m.heads[pr.head] == m.heads[pr.base] {
		state = "unknown"
	}
	return pullInfo{HeadRef: pr.head, HeadSHA: m.heads[pr.head], BaseRef: pr.base, Open: !pr.merged, AuthorIsApp: true, MergeableState: state}, nil
}

func (m *mockRepo) Review(_ context.Context, _ string, number int64, event, _ string, human bool) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.pulls[number]
	if !ok || pr.merged {
		return 0, precondition{"pull request not found"}
	}
	pr.reviews = append(pr.reviews, mockReview{event: event, human: human, sha: m.heads[pr.head]})
	return int64(len(pr.reviews)), nil
}

func (m *mockRepo) HumanApprovals(_ context.Context, _ string, number int64, head string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.pulls[number]
	if !ok {
		return 0, precondition{"pull request not found"}
	}
	var n int64
	for _, r := range pr.reviews {
		if r.human && r.event == "APPROVE" && r.sha == head {
			n++
		}
	}
	return n, nil
}

func (m *mockRepo) Merge(_ context.Context, _ string, number int64, head, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pr, ok := m.pulls[number]
	if !ok || pr.merged {
		return "", precondition{"pull request not found"}
	}
	if m.heads[pr.head] != head {
		return "", precondition{"GitHub refused the merge: the pull request isn't mergeable (branch protection, conflicts or a newer head)"}
	}
	base := m.branches[pr.base]
	for path := range base {
		if _, ok := m.branches[pr.head][path]; !ok {
			delete(base, path)
		}
	}
	for path, content := range m.branches[pr.head] {
		base[path] = content
	}
	m.commits++
	m.heads[pr.base] = mockSHA(m.commits)
	pr.merged = true
	return m.heads[pr.base], nil
}
