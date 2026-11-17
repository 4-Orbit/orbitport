package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
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
	// ListVersions returns up to limit versions numbered below `before`
	// (0 = start from the newest), newest first, and the `before` value for
	// the next page (0 = no more).
	ListVersions(ctx context.Context, tenant string, before int64, limit int) ([]VersionInfo, int64, error)
	// FindByContent returns the newest version whose content hash is hash,
	// or 0. Callers must still compare contents before trusting a match.
	FindByContent(ctx context.Context, tenant string, hash string) (int64, error)
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

// contentHash identifies a version's content: its exact policy text and its
// entities compared order-independently. Used to find duplicates.
func contentHash(policies string, entities json.RawMessage) string {
	sum := sha256.Sum256([]byte(policies + "\x00" + canonicalEntities(entities)))
	return hex.EncodeToString(sum[:])
}

// canonicalEntities renders an entity list order-independently, so the same
// agents and roles compare equal however they were written.
func canonicalEntities(raw json.RawMessage) string {
	var list []any
	if len(bytes.TrimSpace(raw)) == 0 || json.Unmarshal(raw, &list) != nil {
		list = []any{}
	}
	items := make([]string, 0, len(list))
	for _, e := range list {
		b, _ := json.Marshal(e)
		items = append(items, string(b))
	}
	sort.Strings(items)
	return strings.Join(items, "\n")
}

// pageStart turns a `before` cursor into the first version to read.
func pageStart(latest, before int64) int64 {
	if before <= 0 || before > latest+1 {
		return latest
	}
	return before - 1
}

// memStore is an in-process store for tests and for running without OpenBao.
type memStore struct {
	mu       sync.Mutex
	hashes   map[string]map[string]int64
	versions map[string][]Version
	active   map[string]Active
	tests    map[string][]authz.TestCase
}

func newMemStore() *memStore {
	return &memStore{hashes: map[string]map[string]int64{}, versions: map[string][]Version{}, active: map[string]Active{}, tests: map[string][]authz.TestCase{}}
}

func (m *memStore) SaveVersion(_ context.Context, tenant string, v Version) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tenantKey(tenant)
	v.Version = int64(len(m.versions[k]) + 1)
	m.versions[k] = append(m.versions[k], v)
	if m.hashes[k] == nil {
		m.hashes[k] = map[string]int64{}
	}
	m.hashes[k][contentHash(v.Policies, v.Entities)] = v.Version
	return v.Version, nil
}

func (m *memStore) FindByContent(_ context.Context, tenant, hash string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hashes[tenantKey(tenant)][hash], nil
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

func (m *memStore) ListVersions(_ context.Context, tenant string, before int64, limit int) ([]VersionInfo, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := tenantKey(tenant)
	active := m.active[k].Version
	out := []VersionInfo{}
	list := m.versions[k]
	n := pageStart(int64(len(list)), before)
	for ; n >= 1 && len(out) < limit; n-- {
		v := list[n-1]
		out = append(out, VersionInfo{Version: v.Version, Message: v.Message, Author: v.Author, CreatedAt: v.CreatedAt, Active: v.Version == active})
	}
	next := int64(0)
	if n >= 1 {
		next = n + 1
	}
	return out, next, nil
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

// Content-hash index: hashes/<sha256> -> {version}, newest version wins.
// hashindex marks that every version up to UpTo has been indexed; stores
// written before the index existed are back-filled on first lookup.
type hashDoc struct {
	Version int64 `json:"version"`
}

type hashIndexDoc struct {
	UpTo int64 `json:"upTo"`
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
		// Best effort: a missing entry is repaired by the back-fill.
		if err := s.writeKV(ctx, s.url(tenant, "hashes", contentHash(v.Policies, v.Entities)), hashDoc{Version: next}, nil); err != nil {
			logger.Warnf("content index not updated for v%d: %v", next, err)
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

func (s *baoStore) latest(ctx context.Context, tenant string) (int64, error) {
	meta, _, err := readKV[metaDoc](ctx, s, s.url(tenant, "meta"))
	if errors.Is(err, errNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return meta.Latest, nil
}

func (s *baoStore) ListVersions(ctx context.Context, tenant string, before int64, limit int) ([]VersionInfo, int64, error) {
	latest, err := s.latest(ctx, tenant)
	if err != nil {
		return nil, 0, err
	}
	activeVersion := int64(0)
	if a, err := s.GetActive(ctx, tenant); err == nil {
		activeVersion = a.Version
	}
	out := []VersionInfo{}
	n := pageStart(latest, before)
	for ; n >= 1 && len(out) < limit; n-- {
		v, err := s.GetVersion(ctx, tenant, n)
		if err != nil {
			continue
		}
		out = append(out, VersionInfo{Version: v.Version, Message: v.Message, Author: v.Author, CreatedAt: v.CreatedAt, Active: v.Version == activeVersion})
	}
	next := int64(0)
	if n >= 1 {
		next = n + 1
	}
	return out, next, nil
}

func (s *baoStore) FindByContent(ctx context.Context, tenant, hash string) (int64, error) {
	if err := s.ensureIndex(ctx, tenant); err != nil {
		return 0, err
	}
	doc, _, err := readKV[hashDoc](ctx, s, s.url(tenant, "hashes", hash))
	if errors.Is(err, errNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return doc.Version, nil
}

// ensureIndex back-fills content-hash entries for versions saved before the
// index existed (or whose entry failed to write), oldest first so the newest
// version wins, then records how far the index is complete.
func (s *baoStore) ensureIndex(ctx context.Context, tenant string) error {
	latest, err := s.latest(ctx, tenant)
	if err != nil || latest == 0 {
		return err
	}
	mark, _, err := readKV[hashIndexDoc](ctx, s, s.url(tenant, "hashindex"))
	if err != nil && !errors.Is(err, errNotFound) {
		return err
	}
	from := int64(1)
	if mark != nil {
		if mark.UpTo >= latest {
			return nil
		}
		from = mark.UpTo + 1
	}
	for n := from; n <= latest; n++ {
		v, err := s.GetVersion(ctx, tenant, n)
		if err != nil {
			continue
		}
		if err := s.writeKV(ctx, s.url(tenant, "hashes", contentHash(v.Policies, v.Entities)), hashDoc{Version: n}, nil); err != nil {
			return err
		}
	}
	return s.writeKV(ctx, s.url(tenant, "hashindex"), hashIndexDoc{UpTo: latest}, nil)
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
	ring map[string][]storedEvent
	// seq is the per-tenant sequence of the last stored event. Cursors are
	// sequence numbers, so they stay valid while the ring drops old events.
	seq  map[string]int64
	size int
	dir  string
}

type storedEvent struct {
	seq int64
	ev  authz.AuditEvent
}

func newAuditLog(size int, dir string) *auditLog {
	if size <= 0 {
		size = 2000
	}
	return &auditLog{ring: map[string][]storedEvent{}, seq: map[string]int64{}, size: size, dir: dir}
}

func (a *auditLog) add(ev authz.AuditEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := tenantKey(ev.Tenant)
	a.seq[k]++
	list := append(a.ring[k], storedEvent{seq: a.seq[k], ev: ev})
	if len(list) > a.size {
		list = list[len(list)-a.size:]
	}
	a.ring[k] = list
	if a.dir != "" {
		appendJSONL(a.dir, k, ev)
	}
}

type auditFilter struct {
	// Opaque; nextCursor from the previous page. Empty = newest events.
	Cursor   string `json:"cursor"`
	Limit    int    `json:"limit"`
	AgentID  string `json:"agentId"`
	Decision string `json:"decision"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	// The short token hash (authz.HashJTI) of the credential that made the
	// request: finds the events of one token, such as a console run.
	JtiHash string `json:"jtiHash"`
}

const (
	defaultAuditPage = 50
	maxAuditPage     = 200
)

// list returns matching events newest first, at most f.Limit, older than the
// cursor, and the cursor for the next page ("" = no older matches). Filters
// apply before paging, so every matching event is reachable.
func (a *auditLog) list(tenant string, f auditFilter) ([]authz.AuditEvent, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f.Limit <= 0 {
		f.Limit = defaultAuditPage
	}
	if f.Limit > maxAuditPage {
		f.Limit = maxAuditPage
	}
	before := int64(1<<62 - 1)
	if f.Cursor != "" {
		if n, err := strconv.ParseInt(f.Cursor, 10, 64); err == nil && n > 0 {
			before = n
		}
	}
	src := a.ring[tenantKey(tenant)]
	out := []authz.AuditEvent{}
	lastSeq := int64(0)
	i := len(src) - 1
	for ; i >= 0 && len(out) < f.Limit; i-- {
		se := src[i]
		if se.seq >= before || !f.matches(se.ev) {
			continue
		}
		out = append(out, se.ev)
		lastSeq = se.seq
	}
	// More exist only if an older event also matches.
	for ; i >= 0; i-- {
		if src[i].seq < before && f.matches(src[i].ev) {
			return out, strconv.FormatInt(lastSeq, 10)
		}
	}
	return out, ""
}

func (f auditFilter) matches(ev authz.AuditEvent) bool {
	if f.AgentID != "" && ev.Principal != authz.AuditUID("Agent", f.AgentID) {
		return false
	}
	if f.Decision != "" && string(ev.Decision) != f.Decision {
		return false
	}
	if f.Action != "" && ev.Action != authz.AuditUID("Action", f.Action) {
		return false
	}
	if f.Resource != "" && !strings.HasSuffix(ev.Resource, `::"`+f.Resource+`"`) {
		return false
	}
	if f.JtiHash != "" && ev.JtiHash != f.JtiHash {
		return false
	}
	return true
}

// summary counts decisions over the retained window.
func (a *auditLog) summary(tenant string) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]int{"total": 0, "allow": 0, "deny": 0, "kmsCalled": 0, "errors": 0}
	for _, se := range a.ring[tenantKey(tenant)] {
		ev := se.ev
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
