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
}

func newMockRepo() *mockRepo {
	return &mockRepo{
		next:          1,
		issues:        map[int64]int{},
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
