package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/spacecomputer-io/orbitport/plugins/internal/openbao"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
)

var errNotFound = errors.New("not found")

// Version is one immutable saved policy bundle.
type Version struct {
	Version   int64           `json:"version"`
	Policies  string          `json:"policies"`
	Entities  json.RawMessage `json:"entities"`
	Message   string          `json:"message"`
	Author    string          `json:"author"`
	CreatedAt string          `json:"createdAt"`
}

// VersionInfo is a version without its content, for listings.
type VersionInfo struct {
	Version   int64  `json:"version"`
	Message   string `json:"message"`
	Author    string `json:"author"`
	CreatedAt string `json:"createdAt"`
	Active    bool   `json:"active"`
}

// Active records which version a tenant enforces.
type Active struct {
	Version     int64  `json:"version"`
	ActivatedAt string `json:"activatedAt"`
	ActivatedBy string `json:"activatedBy"`
}

// Store persists versions, the active pointer and the test suite per tenant.
// Versions are append-only; activation only moves the pointer, so rollback
// is activating an earlier version.
type Store interface {
	SaveVersion(ctx context.Context, tenant string, v Version) (int64, error)
	GetVersion(ctx context.Context, tenant string, version int64) (*Version, error)
	ListVersions(ctx context.Context, tenant string, limit int) ([]VersionInfo, error)
	GetActive(ctx context.Context, tenant string) (*Active, error)
	SetActive(ctx context.Context, tenant string, a Active) error
	GetTests(ctx context.Context, tenant string) ([]authz.TestCase, error)
	PutTests(ctx context.Context, tenant string, cases []authz.TestCase) error
}

// tenantKey makes the tenant path-safe and stable, like the KMS namespace.
func tenantKey(tenant string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenant)))
	return "tenant_" + hex.EncodeToString(sum[:16])
}

// memStore is an in-process store for tests and for running without OpenBao.
type memStore struct {
	mu       sync.Mutex
	versions map[string][]Version
	active   map[string]Active
	tests    map[string][]authz.TestCase
}

func newMemStore() *memStore {
	return &memStore{versions: map[string][]Version{}, active: map[string]Active{}, tests: map[string][]authz.TestCase{}}
}

func (m *memStore) SaveVersion(_ context.Context, tenant string, v Version) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tenantKey(tenant)
	v.Version = int64(len(m.versions[k]) + 1)
	m.versions[k] = append(m.versions[k], v)
	return v.Version, nil
}

func (m *memStore) GetVersion(_ context.Context, tenant string, version int64) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.versions[tenantKey(tenant)]
	if version < 1 || version > int64(len(list)) {
		return nil, errNotFound
	}
	v := list[version-1]
	return &v, nil
}

func (m *memStore) ListVersions(_ context.Context, tenant string, limit int) ([]VersionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tenantKey(tenant)
	active := m.active[k].Version
	var out []VersionInfo
	list := m.versions[k]
	for i := len(list) - 1; i >= 0 && len(out) < limit; i-- {
		v := list[i]
		out = append(out, VersionInfo{Version: v.Version, Message: v.Message, Author: v.Author, CreatedAt: v.CreatedAt, Active: v.Version == active})
	}
	return out, nil
}

func (m *memStore) GetActive(_ context.Context, tenant string) (*Active, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.active[tenantKey(tenant)]
	if !ok {
		return nil, errNotFound
	}
	return &a, nil
}

func (m *memStore) SetActive(_ context.Context, tenant string, a Active) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[tenantKey(tenant)] = a
	return nil
}

func (m *memStore) GetTests(_ context.Context, tenant string) ([]authz.TestCase, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]authz.TestCase(nil), m.tests[tenantKey(tenant)]...), nil
}

func (m *memStore) PutTests(_ context.Context, tenant string, cases []authz.TestCase) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tests[tenantKey(tenant)] = append([]authz.TestCase(nil), cases...)
	return nil
}

// baoStore keeps everything in an OpenBao KV v2 mount behind the proxy:
//
//	<mount>/data/tenants/<key>/meta           {"latest": n}   (CAS-guarded counter)
//	<mount>/data/tenants/<key>/versions/<n>   Version
//	<mount>/data/tenants/<key>/active         Active
//	<mount>/data/tenants/<key>/tests          {"cases": [...]}
type baoStore struct {
	client  *openbao.Client
	baseURL string
	mount   string
	saveMu  sync.Mutex
}

func newBaoStore(baseURL, mount string, timeout time.Duration) *baoStore {
	return &baoStore{
		client:  openbao.NewClient(&http.Client{Timeout: timeout}, logger),
		baseURL: strings.TrimRight(baseURL, "/"),
		mount:   strings.Trim(mount, "/"),
	}
}

func (s *baoStore) url(tenant string, parts ...string) string {
	u, _ := url.Parse(s.baseURL)
	all := append([]string{u.Path, "v1", s.mount, "data", "tenants", tenantKey(tenant)}, parts...)
	u.Path = path.Join(all...)
	return u.String()
}

type kvRead[T any] struct {
	Data struct {
		Data     T `json:"data"`
		Metadata struct {
			Version int `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

func readKV[T any](ctx context.Context, s *baoStore, target string) (*T, int, error) {
	var resp kvRead[T]
	if err := s.client.Get(ctx, target, &resp); err != nil {
		var se *openbao.StatusError
		if errors.As(err, &se) && se.StatusCode == http.StatusNotFound {
			return nil, 0, errNotFound
		}
		return nil, 0, err
	}
	return &resp.Data.Data, resp.Data.Metadata.Version, nil
}

func (s *baoStore) writeKV(ctx context.Context, target string, data any, cas *int) error {
	payload := map[string]any{"data": data}
	if cas != nil {
		payload["options"] = map[string]any{"cas": *cas}
	}
	return s.client.Post(ctx, target, payload, nil)
}

// packed stores a document as one JSON string. OpenBao refuses KV writes
// whose JSON has too many strings, which a test suite or a large entity store
// easily exceeds; a single encoded field sidesteps that limit.
type packed struct {
	JSON string `json:"json"`
}

func (s *baoStore) writePacked(ctx context.Context, target string, v any, cas *int) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.writeKV(ctx, target, packed{JSON: string(raw)}, cas)
}

func readPacked[T any](ctx context.Context, s *baoStore, target string) (*T, error) {
	doc, _, err := readKV[packed](ctx, s, target)
	if err != nil {
		return nil, err
	}
	var out T
	if err := json.Unmarshal([]byte(doc.JSON), &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", target, err)
	}
	return &out, nil
}

type metaDoc struct {
	Latest int64 `json:"latest"`
}

func (s *baoStore) SaveVersion(ctx context.Context, tenant string, v Version) (int64, error) {
	// The CAS on meta makes concurrent saves across replicas safe; the mutex
	// just avoids pointless retries within one process.
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	for attempt := 0; attempt < 5; attempt++ {
		meta, kvVersion, err := readKV[metaDoc](ctx, s, s.url(tenant, "meta"))
		if errors.Is(err, errNotFound) {
			meta, kvVersion = &metaDoc{}, 0
		} else if err != nil {
			return 0, err
		}
		next := meta.Latest + 1
		cas := kvVersion
		if err := s.writeKV(ctx, s.url(tenant, "meta"), metaDoc{Latest: next}, &cas); err != nil {
			var se *openbao.StatusError
			if errors.As(err, &se) && se.StatusCode == http.StatusBadRequest {
				continue // lost the CAS race; re-read
			}
			return 0, err
		}
		v.Version = next
		zero := 0
		if err := s.writePacked(ctx, s.url(tenant, "versions", fmt.Sprint(next)), v, &zero); err != nil {
			return 0, err
		}
		return next, nil
	}
	return 0, fmt.Errorf("could not allocate a policy version")
}

func (s *baoStore) GetVersion(ctx context.Context, tenant string, version int64) (*Version, error) {
	if version < 1 {
		return nil, errNotFound
	}
	return readPacked[Version](ctx, s, s.url(tenant, "versions", fmt.Sprint(version)))
}

func (s *baoStore) ListVersions(ctx context.Context, tenant string, limit int) ([]VersionInfo, error) {
	meta, _, err := readKV[metaDoc](ctx, s, s.url(tenant, "meta"))
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	activeVersion := int64(0)
	if a, err := s.GetActive(ctx, tenant); err == nil {
		activeVersion = a.Version
	}
	var out []VersionInfo
	for n := meta.Latest; n >= 1 && len(out) < limit; n-- {
		v, err := s.GetVersion(ctx, tenant, n)
		if err != nil {
			continue
		}
		out = append(out, VersionInfo{Version: v.Version, Message: v.Message, Author: v.Author, CreatedAt: v.CreatedAt, Active: v.Version == activeVersion})
	}
	return out, nil
}

func (s *baoStore) GetActive(ctx context.Context, tenant string) (*Active, error) {
	a, _, err := readKV[Active](ctx, s, s.url(tenant, "active"))
	return a, err
}

func (s *baoStore) SetActive(ctx context.Context, tenant string, a Active) error {
	return s.writeKV(ctx, s.url(tenant, "active"), a, nil)
}

type testsDoc struct {
	Cases []authz.TestCase `json:"cases"`
}

func (s *baoStore) GetTests(ctx context.Context, tenant string) ([]authz.TestCase, error) {
	doc, err := readPacked[testsDoc](ctx, s, s.url(tenant, "tests"))
	if errors.Is(err, errNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return doc.Cases, nil
}

func (s *baoStore) PutTests(ctx context.Context, tenant string, cases []authz.TestCase) error {
	if cases == nil {
		cases = []authz.TestCase{}
	}
	return s.writePacked(ctx, s.url(tenant, "tests"), testsDoc{Cases: cases}, nil)
}

// auditLog keeps the newest events per tenant in memory and optionally
// appends every event to <dir>/<tenant key>.jsonl.
type auditLog struct {
	mu   sync.Mutex
	ring map[string][]authz.AuditEvent
	size int
	dir  string
}

func newAuditLog(size int, dir string) *auditLog {
	if size <= 0 {
		size = 2000
	}
	return &auditLog{ring: map[string][]authz.AuditEvent{}, size: size, dir: dir}
}

func (a *auditLog) add(ev authz.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := tenantKey(ev.Tenant)
	list := append(a.ring[k], ev)
	if len(list) > a.size {
		list = list[len(list)-a.size:]
	}
	a.ring[k] = list
	if a.dir != "" {
		appendJSONL(a.dir, k, ev)
	}
}

type auditFilter struct {
	Limit    int    `json:"limit"`
	AgentID  string `json:"agentId"`
	Decision string `json:"decision"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

func (a *auditLog) list(tenant string, f auditFilter) []authz.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	src := a.ring[tenantKey(tenant)]
	out := []authz.AuditEvent{}
	for i := len(src) - 1; i >= 0 && len(out) < f.Limit; i-- {
		ev := src[i]
		if f.AgentID != "" && ev.Principal != authz.AuditUID("Agent", f.AgentID) {
			continue
		}
		if f.Decision != "" && string(ev.Decision) != f.Decision {
			continue
		}
		if f.Action != "" && ev.Action != authz.AuditUID("Action", f.Action) {
			continue
		}
		if f.Resource != "" && !strings.HasSuffix(ev.Resource, `::"`+f.Resource+`"`) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// summary counts decisions over the retained window.
func (a *auditLog) summary(tenant string) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]int{"total": 0, "allow": 0, "deny": 0, "kmsCalled": 0, "errors": 0}
	for _, ev := range a.ring[tenantKey(tenant)] {
		out["total"]++
		if ev.Decision == authz.Allow {
			out["allow"]++
		} else {
			out["deny"]++
		}
		if ev.KmsCalled {
			out["kmsCalled"]++
		}
		if len(ev.AuthzErrors) > 0 {
			out["errors"]++
		}
	}
	return out
}
