package kms

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

// Metadata keys set by the gateway on every KMS call. Customer HTTP headers
// are never forwarded as gRPC metadata, so only the gateway can set these.
const (
	mdAgentID = "x-orbitport-agent-id"
	mdJTIHash = "x-orbitport-jti-hash"
)

// errPolicyDenied is the only message a caller sees for a policy DENY. The
// determining policy ids stay in the audit log.
var errPolicyDenied = status.Error(codes.PermissionDenied, "request denied by policy")

// policySource supplies a tenant's active compiled policy bundle.
type policySource interface {
	// Active returns the tenant's compiled bundle (nil when the tenant has
	// none) and its version. An error means the bundle is unknown.
	Active(ctx context.Context, tenant string) (*authz.Compiled, int64, error)
}

// auditSink records decisions. It must never block or fail a request.
type auditSink interface {
	Record(authz.AuditEvent)
}

type agentAuthorizer struct {
	mode   string
	source policySource
	audit  auditSink
	now    func() time.Time
}

func newAgentAuthorizer(cfg *kmsConfig) (*agentAuthorizer, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.AuthzMode))
	if mode != authz.ModeEnforce && mode != authz.ModeShadow {
		return nil, fmt.Errorf("ORBITPORT_KMS_AUTHZ_MODE must be %q or %q", authz.ModeEnforce, authz.ModeShadow)
	}
	a := &agentAuthorizer{mode: mode, source: noPolicies{}, audit: logAudit{}, now: time.Now}
	if cfg.PolicyPlugin != "" {
		conn, err := grpc.NewClient(strings.TrimPrefix(strings.TrimPrefix(cfg.PolicyPlugin, "http://"), "grpc://"),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("connect policy plugin: %w", err)
		}
		client := proto.NewPolicyPluginClient(conn)
		a.source = newCachedPolicySource(client, time.Duration(cfg.PolicyCacheTTLSecs)*time.Second)
		a.audit = newRemoteAudit(client)
		logger.Infof("agent authorization: mode=%s policy plugin=%s cache_ttl=%ds", mode, cfg.PolicyPlugin, cfg.PolicyCacheTTLSecs)
	} else {
		logger.Warnf("agent authorization: mode=%s, no ORBITPORT_KMS_POLICY_PLUGIN: account credentials keep full access, agent credentials are denied", mode)
	}
	return a, nil
}

// noPolicies is the source used without a policy plugin: no tenant has a
// bundle, so only the platform policy applies.
type noPolicies struct{}

func (noPolicies) Active(context.Context, string) (*authz.Compiled, int64, error) { return nil, 0, nil }

// logAudit writes events to the plugin log as single JSON lines.
type logAudit struct{}

func (logAudit) Record(ev authz.AuditEvent) {
	raw, _ := json.Marshal(ev)
	logger.Infof("audit %s", raw)
}

// principalFromContext builds the Cedar principal from the account tenant
// and the gateway-set agent metadata.
func principalFromContext(ctx context.Context, tenant string) (authz.Principal, string) {
	p := authz.Principal{Tenant: tenant}
	jtiHash := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(mdAgentID); len(v) == 1 {
			p.AgentID = strings.TrimSpace(v[0])
		} else if len(v) > 1 {
			// Ambiguous identity: treat as an unknown agent so it is denied.
			p.AgentID = "ambiguous"
		}
		if v := md.Get(mdJTIHash); len(v) == 1 {
			jtiHash = v[0]
		}
	}
	return p, jtiHash
}

// resourceResolver produces the Cedar resource for a call. It runs only
// after the decision is needed and may read key metadata, never key material.
type resourceResolver func(ctx context.Context) authz.Resource

// guard authorizes one RPC, runs it only on ALLOW (or in shadow mode), and
// records exactly one audit event.
func guard[T any](p *Plugin, ctx context.Context, tenant, action string, resolve resourceResolver, call func() (T, error)) (T, error) {
	var zero T
	a := p.agentAuthz
	if a == nil || strings.TrimSpace(tenant) == "" {
		// No tenant: the handler rejects the request with InvalidArgument
		// before touching OpenBao. Nothing to authorize.
		return call()
	}
	principal, jtiHash := principalFromContext(ctx, tenant)

	compiled, version, err := a.source.Active(ctx, tenant)
	var res authz.Result
	var resource authz.Resource
	switch {
	case err != nil && principal.IsAgent():
		logger.Warnf("agent authorization: policy unavailable for tenant, failing closed: %v", err)
		resource = authz.Resource{ID: "unresolved"}
		res = authz.Result{Decision: authz.Deny, DeterminingPolicies: []string{}, Errored: true}
	case err != nil:
		// Account principals fall back to the platform policy alone.
		logger.Warnf("agent authorization: policy unavailable for tenant, using platform policy: %v", err)
		compiled, version = nil, 0
		fallthrough
	default:
		if !principal.IsAgent() && compiled == nil {
			// Only platform.owner can apply: the decision cannot depend on
			// key attributes, so skip the metadata read.
			resource = authz.Resource{ID: "unresolved"}
		} else {
			resource = resolve(ctx)
		}
		if resource.ID == "" {
			resource.ID = "unresolved"
		}
		res = authz.Evaluate(compiled, authz.Request{Principal: principal, Action: action, Resource: resource}, a.now())
	}
	if len(res.Diagnostics) > 0 {
		logger.Warnf("agent authorization diagnostics action=%s: %v", action, res.Diagnostics)
	}

	ev := authz.NewAuditEvent(a.now().UTC().Format(time.RFC3339Nano), newRequestID(), authz.Request{Principal: principal, Action: action, Resource: resource}, res, version, a.mode)
	ev.JtiHash = jtiHash

	if res.Decision != authz.Allow && a.mode == authz.ModeEnforce {
		a.audit.Record(ev)
		return zero, errPolicyDenied
	}

	out, callErr := call()
	ev.KmsCalled = true
	ev.KmsOperation = action
	if callErr != nil {
		ev.KmsResult = &authz.KmsResult{Status: "ERROR", ErrorCode: status.Code(callErr).String()}
	} else {
		ev.KmsResult = &authz.KmsResult{Status: "SUCCESS"}
	}
	a.audit.Record(ev)
	return out, callErr
}

func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// keyResource resolves a key reference to the Cedar Key resource, reading the
// key's metadata for scheme, spec, usage and tags. A missing or foreign key
// yields a resource with empty attributes so the decision, not the lookup,
// determines what an unauthorized caller learns.
func (p *Plugin) keyResource(tenant, keyRef string) resourceResolver {
	return func(ctx context.Context) authz.Resource {
		keyID, alias, err := resolveKeyRef(keyRef)
		if err != nil {
			return authz.Resource{Type: "Key", ID: "invalid"}
		}
		res := authz.Resource{Type: "Key", ID: alias}
		md, err := p.client.getMetadata(ctx, tenant, keyID)
		if err != nil {
			return res
		}
		res.Attrs = map[string]string{"scheme": md.Scheme, "keySpec": md.KeySpec, "keyUsage": md.KeyUsage}
		res.Tags = tagsOf(md.Tags)
		return res
	}
}

func tagsOf(tags []*pluginTag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		if t != nil && t.TagKey != "" {
			out[t.TagKey] = t.TagValue
		}
	}
	return out
}

func staticResource(r authz.Resource) resourceResolver {
	return func(context.Context) authz.Resource { return r }
}

// cachedPolicySource caches each tenant's compiled bundle for ttl. A failed
// refresh serves the previous bundle for up to staleFor before failing.
type cachedPolicySource struct {
	client   proto.PolicyPluginClient
	ttl      time.Duration
	staleFor time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]cachedBundle
}

type cachedBundle struct {
	compiled  *authz.Compiled
	version   int64
	fetchedAt time.Time
}

func newCachedPolicySource(client proto.PolicyPluginClient, ttl time.Duration) *cachedPolicySource {
	return &cachedPolicySource{client: client, ttl: ttl, staleFor: 10 * ttl, now: time.Now, entries: map[string]cachedBundle{}}
}

func (c *cachedPolicySource) Active(ctx context.Context, tenant string) (*authz.Compiled, int64, error) {
	now := c.now()
	c.mu.Lock()
	entry, ok := c.entries[tenant]
	c.mu.Unlock()
	if ok && now.Sub(entry.fetchedAt) < c.ttl {
		return entry.compiled, entry.version, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	resp, err := c.client.GetActive(fetchCtx, &proto.GetActiveRequest{KmsTenant: tenant})
	if err != nil {
		if ok && now.Sub(entry.fetchedAt) < c.staleFor {
			return entry.compiled, entry.version, nil
		}
		return nil, 0, err
	}
	next := cachedBundle{fetchedAt: now}
	if resp.Exists {
		if ok && entry.version == resp.Version && entry.compiled != nil {
			next.compiled = entry.compiled
		} else {
			compiled, problems := authz.Compile(authz.Bundle{Policies: resp.Policies, Entities: json.RawMessage(resp.EntitiesJson)})
			if compiled == nil {
				// The store validates on write, so this means corruption or a
				// schema change. Fail closed rather than run without policy.
				return nil, 0, fmt.Errorf("active policy version %d does not compile: %v", resp.Version, problems)
			}
			next.compiled = compiled
		}
		next.version = resp.Version
	}
	c.mu.Lock()
	c.entries[tenant] = next
	c.mu.Unlock()
	return next.compiled, next.version, nil
}

// remoteAudit ships events to the policy plugin in batches from a bounded
// queue. A full queue or an unreachable plugin falls back to the log.
type remoteAudit struct {
	client proto.PolicyPluginClient
	queue  chan authz.AuditEvent
}

func newRemoteAudit(client proto.PolicyPluginClient) *remoteAudit {
	r := &remoteAudit{client: client, queue: make(chan authz.AuditEvent, 1024)}
	go r.run()
	return r
}

func (r *remoteAudit) Record(ev authz.AuditEvent) {
	select {
	case r.queue <- ev:
	default:
		logAudit{}.Record(ev)
	}
}

func (r *remoteAudit) run() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var batch []authz.AuditEvent
	flush := func() {
		if len(batch) == 0 {
			return
		}
		lines := make([]string, 0, len(batch))
		for _, ev := range batch {
			raw, _ := json.Marshal(ev)
			lines = append(lines, string(raw))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := r.client.RecordAudit(ctx, &proto.RecordAuditRequest{EventsJson: lines})
		cancel()
		if err != nil {
			logger.Warnf("audit: policy plugin unreachable, logging %d events locally: %v", len(batch), err)
			for _, ev := range batch {
				logAudit{}.Record(ev)
			}
		}
		batch = batch[:0]
	}
	for {
		select {
		case ev := <-r.queue:
			batch = append(batch, ev)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
