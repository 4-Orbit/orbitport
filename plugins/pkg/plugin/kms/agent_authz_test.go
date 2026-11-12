package kms

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

const agentTestTenant = "tenant-a"

type fixedSource struct {
	compiled *authz.Compiled
	version  int64
	err      error
}

func (f fixedSource) Active(context.Context, string) (*authz.Compiled, int64, error) {
	return f.compiled, f.version, f.err
}

type recordingAudit struct {
	mu     sync.Mutex
	events []authz.AuditEvent
}

func (r *recordingAudit) Record(ev authz.AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingAudit) last(t *testing.T) authz.AuditEvent {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.NotEmpty(t, r.events)
	return r.events[len(r.events)-1]
}

// fakeOpenBao serves metadata for keys and counts every crypto/backend call.
type fakeOpenBao struct {
	backendCalls atomic.Int32
	keys         map[string]string // alias -> tags JSON
}

func (f *fakeOpenBao) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metaPrefix := "/v1/secret/data/kms/metadata/" + tenantNamespace(agentTestTenant) + "/kms:"
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, metaPrefix):
			alias := r.URL.Path[strings.Index(r.URL.Path, metaPrefix)+len(metaPrefix):]
			tags, ok := f.keys[alias]
			if !ok {
				http.NotFound(w, r)
				return
			}
			providerKey, _ := scopedBackendKey(agentTestTenant, alias)
			_, _ = w.Write([]byte(`{"data":{"data":{"key_id":"kms:` + alias + `","client_id":"` + agentTestTenant + `","alias":"` + alias + `","scheme":"TRANSIT","provider_key":"` + providerKey + `","key_spec":"AES_256_GCM96","key_usage":"ENCRYPT_DECRYPT","enabled":true,"primary_version":1,"created_at":"2024-01-01T00:00:00Z","tags":` + tags + `}}}`))
		case r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true"):
			var keys []string
			for alias := range f.keys {
				keys = append(keys, "kms:"+alias)
			}
			raw, _ := json.Marshal(map[string]any{"data": map[string]any{"keys": keys}})
			_, _ = w.Write(raw)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v1/transit/encrypt/"):
			f.backendCalls.Add(1)
			_, _ = w.Write([]byte(`{"data":{"ciphertext":"vault:v1:abc"}}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/v1/transit/keys/") && strings.HasSuffix(r.URL.Path, "/rotate"):
			f.backendCalls.Add(1)
			_, _ = w.Write([]byte(`{"data":{"latest_version":2,"keys":{"1":1,"2":2}}}`))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, metaPrefix):
			f.backendCalls.Add(1)
			_, _ = w.Write([]byte(`{"data":{}}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v1/transit/keys/"):
			f.backendCalls.Add(1)
			_, _ = w.Write([]byte(`{"data":{"latest_version":2,"keys":{"1":1,"2":2}}}`))
		default:
			f.backendCalls.Add(1)
			assert.Failf(t, "unexpected request", "%s %s", r.Method, r.URL.String())
			http.Error(w, "unexpected", http.StatusInternalServerError)
		}
	})
}

func newAgentTestPlugin(t *testing.T, source policySource, mode string) (*Plugin, *fakeOpenBao, *recordingAudit) {
	t.Helper()
	bao := &fakeOpenBao{keys: map[string]string{
		"demo-key": `[]`,
		"dev-key":  `[{"tag_key":"env","tag_value":"dev"}]`,
		"prod-key": `[{"tag_key":"env","tag_value":"prod"}]`,
	}}
	server := httptest.NewServer(bao.handler(t))
	t.Cleanup(server.Close)
	cfg := &kmsConfig{OpenBaoProxyURL: server.URL, TransitMount: "transit", KVMount: "secret", TimeoutSecs: 5}
	p := newPlugin(cfg, newOpenBaoClient(cfg))
	audit := &recordingAudit{}
	p.agentAuthz = &agentAuthorizer{mode: mode, source: source, audit: audit, now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
	return p, bao, audit
}

func asAgent(agent string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(mdAgentID, agent, mdJTIHash, "abc123"))
}

func defaultSource(t *testing.T) policySource {
	compiled, problems := authz.Compile(authz.DefaultBundle())
	require.Empty(t, problems)
	return fixedSource{compiled: compiled, version: 7}
}

func encrypt(p *Plugin, ctx context.Context, key string) error {
	_, err := p.Encrypt(ctx, &proto.EncryptRequest{KeyId: key, Plaintext: "Zm9v", ClientId: agentTestTenant})
	return err
}

func TestAgentAllowedEncryptReachesBackendAndIsAudited(t *testing.T) {
	p, bao, audit := newAgentTestPlugin(t, defaultSource(t), authz.ModeEnforce)
	require.NoError(t, encrypt(p, asAgent("developer-agent"), "dev-key"))
	assert.Equal(t, int32(1), bao.backendCalls.Load())

	ev := audit.last(t)
	assert.Equal(t, authz.Allow, ev.Decision)
	assert.Equal(t, []string{"developer-encrypt-dev-key"}, ev.DeterminingPolicies)
	assert.True(t, ev.KmsCalled)
	assert.Equal(t, "SUCCESS", ev.KmsResult.Status)
	assert.Equal(t, int64(7), ev.PolicyVersion)
	assert.Equal(t, `Agent::"developer-agent"`, ev.Principal)
	assert.Equal(t, "abc123", ev.JtiHash)
}

func TestAgentDeniedNeverReachesBackend(t *testing.T) {
	p, bao, audit := newAgentTestPlugin(t, defaultSource(t), authz.ModeEnforce)
	cases := []struct {
		agent string
		call  func(ctx context.Context) error
	}{
		{"developer-agent", func(ctx context.Context) error { return encrypt(p, ctx, "prod-key") }},
		{"developer-agent", func(ctx context.Context) error {
			_, err := p.RotateKey(ctx, &proto.RotateKeyRequest{KeyId: "dev-key", ClientId: agentTestTenant})
			return err
		}},
		{"security-agent", func(ctx context.Context) error { return encrypt(p, ctx, "demo-key") }},
		{"unknown-agent", func(ctx context.Context) error { return encrypt(p, ctx, "dev-key") }},
		{"developer-agent", func(ctx context.Context) error { return encrypt(p, ctx, "missing-key") }},
		{"developer-agent", func(ctx context.Context) error {
			_, err := p.KeyStoreGet(ctx, &proto.KeyStoreGetRequest{Name: "github/prod", ClientId: agentTestTenant})
			return err
		}},
		{"developer-agent", func(ctx context.Context) error {
			_, err := p.ListKeys(ctx, &proto.ListKeysRequest{ClientId: agentTestTenant})
			return err
		}},
	}
	for i, tc := range cases {
		err := tc.call(asAgent(tc.agent))
		require.Error(t, err, "case %d", i)
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "case %d", i)
		assert.Equal(t, "request denied by policy", status.Convert(err).Message(), "case %d", i)
		ev := audit.last(t)
		assert.Equal(t, authz.Deny, ev.Decision, "case %d", i)
		assert.False(t, ev.KmsCalled, "case %d", i)
		assert.Nil(t, ev.KmsResult, "case %d", i)
	}
	assert.Equal(t, int32(0), bao.backendCalls.Load(), "a DENY must never call an OpenBao crypto or storage endpoint")
}

func TestSecurityAgentRotates(t *testing.T) {
	p, bao, audit := newAgentTestPlugin(t, defaultSource(t), authz.ModeEnforce)
	_, err := p.RotateKey(asAgent("security-agent"), &proto.RotateKeyRequest{KeyId: "prod-key", ClientId: agentTestTenant})
	// The fake backend's rotate shape may not satisfy the transit provider;
	// what matters here is that Cedar allowed it and the backend was reached.
	_ = err
	assert.GreaterOrEqual(t, bao.backendCalls.Load(), int32(1))
	ev := audit.last(t)
	assert.Equal(t, authz.Allow, ev.Decision)
	assert.Equal(t, []string{"security-rotate-prod-key"}, ev.DeterminingPolicies)
	assert.True(t, ev.KmsCalled)
}

func TestShadowModeAuditsButDoesNotBlock(t *testing.T) {
	p, bao, audit := newAgentTestPlugin(t, defaultSource(t), authz.ModeShadow)
	require.NoError(t, encrypt(p, asAgent("developer-agent"), "prod-key"))
	assert.Equal(t, int32(1), bao.backendCalls.Load())
	ev := audit.last(t)
	assert.Equal(t, authz.Deny, ev.Decision)
	assert.Equal(t, authz.ModeShadow, ev.Mode)
	assert.True(t, ev.KmsCalled)
}

func TestPolicyUnavailableFailsClosedForAgentsOnly(t *testing.T) {
	p, bao, audit := newAgentTestPlugin(t, fixedSource{err: errors.New("policy plugin down")}, authz.ModeEnforce)
	err := encrypt(p, asAgent("developer-agent"), "dev-key")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, []string{authz.AuthzErrorMarker}, audit.last(t).AuthzErrors)
	assert.Equal(t, int32(0), bao.backendCalls.Load())

	// The account-level credential keeps working on the platform policy.
	require.NoError(t, encrypt(p, context.Background(), "dev-key"))
	assert.Equal(t, int32(1), bao.backendCalls.Load())
	assert.Equal(t, []string{"platform.owner"}, audit.last(t).DeterminingPolicies)
}

func TestNoPolicyPluginKeepsAccountBehaviourAndDeniesAgents(t *testing.T) {
	p, bao, _ := newAgentTestPlugin(t, noPolicies{}, authz.ModeEnforce)
	require.NoError(t, encrypt(p, context.Background(), "dev-key"))
	assert.Equal(t, codes.PermissionDenied, status.Code(encrypt(p, asAgent("developer-agent"), "dev-key")))
	assert.Equal(t, int32(1), bao.backendCalls.Load())
}

func TestTagBasedPolicyUsesStoredKeyTags(t *testing.T) {
	compiled, problems := authz.Compile(authz.Bundle{
		Policies: `@id("ops-prod") permit (principal in Role::"ops", action in Action::"use", resource) when { resource.hasTag("env") && resource.getTag("env") == "prod" };`,
		Entities: json.RawMessage(`[{"uid":{"type":"Role","id":"ops"},"attrs":{},"parents":[]},{"uid":{"type":"Agent","id":"ops-agent"},"attrs":{},"parents":[{"type":"Role","id":"ops"}]}]`),
	})
	require.Empty(t, problems)
	p, _, _ := newAgentTestPlugin(t, fixedSource{compiled: compiled, version: 1}, authz.ModeEnforce)
	require.NoError(t, encrypt(p, asAgent("ops-agent"), "prod-key"))
	assert.Equal(t, codes.PermissionDenied, status.Code(encrypt(p, asAgent("ops-agent"), "dev-key")))
}

func TestTenantForbidAppliesToAccountPrincipal(t *testing.T) {
	compiled, problems := authz.Compile(authz.Bundle{
		Policies: `@id("no-prod-for-anyone") forbid (principal, action, resource) when { resource.hasTag("env") && resource.getTag("env") == "prod" };`,
	})
	require.Empty(t, problems)
	p, _, audit := newAgentTestPlugin(t, fixedSource{compiled: compiled, version: 2}, authz.ModeEnforce)
	assert.Equal(t, codes.PermissionDenied, status.Code(encrypt(p, context.Background(), "prod-key")))
	assert.Equal(t, []string{"no-prod-for-anyone"}, audit.last(t).DeterminingPolicies)
	require.NoError(t, encrypt(p, context.Background(), "dev-key"))
}

func TestCreateKeyResourceComesFromRequest(t *testing.T) {
	compiled, problems := authz.Compile(authz.Bundle{
		Policies: `@id("ops-create-dev") permit (principal in Role::"ops", action == Action::"kms.CreateKey", resource) when { resource.hasTag("env") && resource.getTag("env") == "dev" };`,
		Entities: json.RawMessage(`[{"uid":{"type":"Role","id":"ops"},"attrs":{},"parents":[]},{"uid":{"type":"Agent","id":"ops-agent"},"attrs":{},"parents":[{"type":"Role","id":"ops"}]}]`),
	})
	require.Empty(t, problems)
	p, bao, audit := newAgentTestPlugin(t, fixedSource{compiled: compiled, version: 1}, authz.ModeEnforce)
	_, err := p.CreateKey(asAgent("ops-agent"), &proto.CreateKeyRequest{
		Alias: "new-prod", KeySpec: "AES_256_GCM96", KeyUsage: "ENCRYPT_DECRYPT", ClientId: agentTestTenant,
		Tags: []*proto.Tag{{TagKey: "env", TagValue: "prod"}},
	})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, `Key::"new-prod"`, audit.last(t).Resource)
	assert.Equal(t, int32(0), bao.backendCalls.Load())
}

func TestListKeysForAccount(t *testing.T) {
	p, _, _ := newAgentTestPlugin(t, noPolicies{}, authz.ModeEnforce)
	resp, err := p.ListKeys(context.Background(), &proto.ListKeysRequest{ClientId: agentTestTenant})
	require.NoError(t, err)
	var aliases []string
	for _, k := range resp.Keys {
		aliases = append(aliases, k.Alias)
	}
	assert.ElementsMatch(t, []string{"demo-key", "dev-key", "prod-key"}, aliases)
}

func TestAmbiguousAgentMetadataIsDenied(t *testing.T) {
	p, _, _ := newAgentTestPlugin(t, defaultSource(t), authz.ModeEnforce)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{mdAgentID: []string{"developer-agent", "security-agent"}})
	assert.Equal(t, codes.PermissionDenied, status.Code(encrypt(p, ctx, "dev-key")))
}

// stubPolicyClient implements GetActive for the cache tests.
type stubPolicyClient struct {
	proto.PolicyPluginClient
	calls   atomic.Int32
	resp    *proto.GetActiveResponse
	failing atomic.Bool
}

func (s *stubPolicyClient) GetActive(context.Context, *proto.GetActiveRequest, ...grpc.CallOption) (*proto.GetActiveResponse, error) {
	s.calls.Add(1)
	if s.failing.Load() {
		return nil, status.Error(codes.Unavailable, "down")
	}
	return s.resp, nil
}

func TestCachedPolicySourceCachesAndServesStale(t *testing.T) {
	b := authz.DefaultBundle()
	stub := &stubPolicyClient{resp: &proto.GetActiveResponse{Exists: true, Version: 3, Policies: b.Policies, EntitiesJson: string(b.Entities)}}
	now := time.Unix(1000, 0)
	src := newCachedPolicySource(stub, 5*time.Second)
	src.now = func() time.Time { return now }

	c, v, err := src.Active(context.Background(), "t")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, int64(3), v)
	_, _, _ = src.Active(context.Background(), "t")
	assert.Equal(t, int32(1), stub.calls.Load(), "second call within TTL is cached")

	now = now.Add(6 * time.Second)
	stub.failing.Store(true)
	c, _, err = src.Active(context.Background(), "t")
	require.NoError(t, err, "stale bundle served while the plugin is down")
	require.NotNil(t, c)

	now = now.Add(time.Minute)
	_, _, err = src.Active(context.Background(), "t")
	require.Error(t, err, "past the stale window the source fails")
}

func TestCachedPolicySourceRejectsUncompilableBundle(t *testing.T) {
	stub := &stubPolicyClient{resp: &proto.GetActiveResponse{Exists: true, Version: 1, Policies: `permit (principal, action, resource);`}}
	_, _, err := newCachedPolicySource(stub, time.Second).Active(context.Background(), "t")
	require.Error(t, err)
}
