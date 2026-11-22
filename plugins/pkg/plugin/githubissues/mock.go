package githubissues

import (
	"context"
	"sync"
)

// mockRepo is mock mode's in-memory repository: it lets every operation run
// end to end, with real authorization and audit, without contacting GitHub.
// It starts with a default branch "main" holding a few files. State lives in
// memory and is lost when the plugin restarts.
type mockRepo struct {
	mu     sync.Mutex
	issues int64
}

func newMockRepo() *mockRepo {
	return &mockRepo{}
}

func (m *mockRepo) Create(context.Context, string, string, string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.issues++
	return m.issues, nil
}
