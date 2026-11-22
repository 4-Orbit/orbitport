// Package policy is the 4Orbit policy plugin: a per-tenant, versioned Cedar
// policy store with validation, simulation, test suites and decision audit.
// It powers the console's policy playground and feeds the KMS plugin the
// active bundle. Decisions use the same engine as enforcement
// (pkg/core/authz), so the playground cannot disagree with the KMS.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spacecomputer-io/orbitport/plugins/pkg/core/authz"
	"github.com/spacecomputer-io/orbitport/plugins/pkg/utils"
	proto "github.com/spacecomputer-io/orbitport/plugins/proto/plugins"
)

var logger = utils.GetLogger("orbitport:policy")

const (
	maxParamsBytes   = 512 * 1024
	maxAuditBatch    = 500
	maxVersionsList  = 100
	minAgentTokenTTL = 60
	maxAgentTokenTTL = 86400
)

type config struct {
	OpenBaoProxyURL string
	Mount           string
	TimeoutSecs     int
	AuditDir        string
	AuditRingSize   int
}

func readConfig() config {
	viper.SetDefault("POLICY_OPENBAO_PROXY_URL", "")
	viper.SetDefault("POLICY_MOUNT", "orbitport-policy")
	viper.SetDefault("POLICY_TIMEOUT_SECS", 10)
	viper.SetDefault("POLICY_AUDIT_DIR", "")
	viper.SetDefault("POLICY_AUDIT_RING", 2000)
	return config{
		OpenBaoProxyURL: strings.TrimSpace(viper.GetString("POLICY_OPENBAO_PROXY_URL")),
		Mount:           strings.TrimSpace(viper.GetString("POLICY_MOUNT")),
		TimeoutSecs:     viper.GetInt("POLICY_TIMEOUT_SECS"),
		AuditDir:        strings.TrimSpace(viper.GetString("POLICY_AUDIT_DIR")),
		AuditRingSize:   viper.GetInt("POLICY_AUDIT_RING"),
	}
}

// Plugin implements proto.PolicyPluginServer.
type Plugin struct {
	proto.UnimplementedPolicyPluginServer

	store Store
	audit *auditLog
	now   func() time.Time
}

// NewPlugin builds the plugin from ORBITPORT_POLICY_* settings.
func NewPlugin() (*Plugin, error) {
	cfg := readConfig()
	var store Store
	if cfg.OpenBaoProxyURL == "" {
		logger.Warn("ORBITPORT_POLICY_OPENBAO_PROXY_URL not set: policies are kept IN MEMORY and lost on restart (dev only)")
		store = newMemStore()
	} else {
		store = newBaoStore(cfg.OpenBaoProxyURL, cfg.Mount, time.Duration(cfg.TimeoutSecs)*time.Second)
		logger.Infof("policy store: OpenBao KV v2 mount %q via %s", cfg.Mount, cfg.OpenBaoProxyURL)
	}
	if cfg.AuditDir != "" {
		logger.Infof("audit: appending JSONL to %s", cfg.AuditDir)
	}
	return newPlugin(store, newAuditLog(cfg.AuditRingSize, cfg.AuditDir)), nil
}

func newPlugin(store Store, audit *auditLog) *Plugin {
	return &Plugin{store: store, audit: audit, now: time.Now}
}

// GetActive serves the active bundle to enforcing plugins.
func (p *Plugin) GetActive(ctx context.Context, req *proto.GetActiveRequest) (*proto.GetActiveResponse, error) {
	if strings.TrimSpace(req.KmsTenant) == "" {
		return nil, status.Error(codes.InvalidArgument, "kms_tenant is required")
	}
	v, err := p.activeVersion(ctx, req.KmsTenant)
	if errors.Is(err, errNotFound) {
		return &proto.GetActiveResponse{Exists: false}, nil
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "policy store unavailable")
	}
	return &proto.GetActiveResponse{Exists: true, Version: v.Version, Policies: v.Policies, EntitiesJson: string(v.Entities)}, nil
}

// RecordAudit accepts decision events from enforcing plugins.
func (p *Plugin) RecordAudit(_ context.Context, req *proto.RecordAuditRequest) (*proto.RecordAuditResponse, error) {
	if len(req.EventsJson) > maxAuditBatch {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d events per batch", maxAuditBatch)
	}
	var accepted uint32
	for _, line := range req.EventsJson {
		var ev authz.AuditEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Tenant == "" {
			continue
		}
		p.audit.add(ev)
		accepted++
	}
	return &proto.RecordAuditResponse{Accepted: accepted}, nil
}

// methods maps each policy.* JSON-RPC method to the Cedar action that
// authorizes it and its handler.
type handler func(ctx context.Context, c *call) (any, error)

type methodSpec struct {
	action string
	run    handler
}

func (p *Plugin) methods() map[string]methodSpec {
	return map[string]methodSpec{
		"policy.GetSchema":       {"policy.Read", p.getSchema},
		"policy.GetActive":       {"policy.Read", p.getActive},
		"policy.ListVersions":    {"policy.Read", p.listVersions},
		"policy.GetVersion":      {"policy.Read", p.getVersion},
		"policy.GetTests":        {"policy.Read", p.getTests},
		"policy.GetTemplate":     {"policy.Read", p.getTemplate},
		"policy.ListAudit":       {"policy.Read", p.listAudit},
		"policy.Validate":        {"policy.Simulate", p.validate},
		"policy.Simulate":        {"policy.Simulate", p.simulate},
		"policy.Matrix":          {"policy.Simulate", p.matrix},
		"policy.Diff":            {"policy.Simulate", p.diff},
		"policy.Explain":         {"policy.Simulate", p.explain},
		"policy.RunTests":        {"policy.Simulate", p.runTests},
		"policy.SaveDraft":       {"policy.Write", p.saveDraft},
		"policy.PutTests":        {"policy.Write", p.putTests},
		"policy.LoadTemplate":    {"policy.Write", p.loadTemplate},
		"policy.Activate":        {"policy.Activate", p.activate},
		"policy.IssueAgentToken": {"policy.IssueAgentToken", p.issueAgentToken},
	}
}

// Methods lists the supported policy.* methods (the gateway allowlist).
func Methods() []string {
	p := &Plugin{}
	out := make([]string, 0)
	for m := range p.methods() {
		out = append(out, m)
	}
	return out
}

type call struct {
	principal authz.Principal
	jtiHash   string
	params    json.RawMessage
}

func (c *call) decode(into any) error {
	if len(bytes.TrimSpace(c.params)) == 0 || string(bytes.TrimSpace(c.params)) == "null" {
		c.params = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(c.params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid params: %v", err)
	}
	return nil
}

func (c *call) author() string {
	if c.principal.IsAgent() {
		return "agent:" + c.principal.AgentID
	}
	if c.jtiHash != "" {
		return "account (token " + c.jtiHash + ")"
	}
	return "account"
}

// Call runs one policy.* method.
func (p *Plugin) Call(ctx context.Context, req *proto.CallRequest) (*proto.CallResponse, error) {
	spec, ok := p.methods()[req.Method]
	if !ok {
		return nil, status.Errorf(codes.Unimplemented, "unknown method %q", req.Method)
	}
	tenant := strings.TrimSpace(req.KmsTenant)
	if tenant == "" {
		return nil, status.Error(codes.InvalidArgument, "kms_tenant is required")
	}
	if len(req.ParamsJson) > maxParamsBytes {
		return nil, status.Errorf(codes.InvalidArgument, "params exceed %d bytes", maxParamsBytes)
	}
	principal := authz.Principal{Tenant: tenant, AgentID: strings.TrimSpace(req.AgentId)}

	// Policy administration is governed by the platform policy only, so a
	// tenant policy can never lock the account out of fixing its own policy
	// and no tenant policy can let an agent in.
	areq := authz.Request{Principal: principal, Action: spec.action, Resource: authz.Resource{Type: "PolicySet", ID: "active"}}
	res := authz.Evaluate(nil, areq, p.now())
	if res.Decision != authz.Allow {
		ev := authz.NewAuditEvent(p.now().UTC().Format(time.RFC3339Nano), newID(), areq, res, 0, authz.ModeEnforce)
		ev.JtiHash = req.JtiHash
		p.audit.add(ev)
		return nil, status.Error(codes.PermissionDenied, "request denied by policy")
	}

	out, err := spec.run(ctx, &call{principal: principal, jtiHash: req.JtiHash, params: json.RawMessage(req.ParamsJson)})
	if err != nil {
		if _, isStatus := status.FromError(err); isStatus {
			return nil, err
		}
		logger.Warnf("%s failed: %v", req.Method, err)
		return nil, status.Error(codes.Unavailable, "policy store unavailable")
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode result")
	}
	return &proto.CallResponse{ResultJson: string(raw)}, nil
}

func newID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// ---- sources ---------------------------------------------------------------

// source selects what to evaluate: a saved version, an unsaved draft, or
// (neither set) the active version.
type source struct {
	Version int64         `json:"version,omitempty"`
	Draft   *authz.Bundle `json:"draft,omitempty"`
}

type resolved struct {
	compiled *authz.Compiled
	version  int64 // 0 = draft or none
	label    string
}

func (p *Plugin) resolve(ctx context.Context, tenant string, s *source) (*resolved, error) {
	if s != nil && s.Draft != nil {
		compiled, problems := authz.Compile(*s.Draft)
		if compiled == nil {
			return nil, problemError(problems)
		}
		return &resolved{compiled: compiled, label: "draft"}, nil
	}
	var v *Version
	var err error
	if s != nil && s.Version > 0 {
		v, err = p.store.GetVersion(ctx, tenant, s.Version)
		if errors.Is(err, errNotFound) {
			return nil, status.Errorf(codes.NotFound, "version %d not found", s.Version)
		}
	} else {
		v, err = p.activeVersion(ctx, tenant)
		if errors.Is(err, errNotFound) {
			return &resolved{label: "none (platform policy only)"}, nil
		}
	}
	if err != nil {
		return nil, err
	}
	compiled, problems := authz.Compile(authz.Bundle{Policies: v.Policies, Entities: v.Entities})
	if compiled == nil {
		return nil, problemError(problems)
	}
	return &resolved{compiled: compiled, version: v.Version, label: fmt.Sprintf("v%d", v.Version)}, nil
}

func (p *Plugin) activeVersion(ctx context.Context, tenant string) (*Version, error) {
	a, err := p.store.GetActive(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return p.store.GetVersion(ctx, tenant, a.Version)
}

func problemError(problems []authz.Problem) error {
	msgs := make([]string, 0, len(problems))
	for _, pr := range problems {
		if pr.Severity == "error" {
			m := pr.Message
			if pr.PolicyID != "" {
				m = pr.PolicyID + ": " + m
			}
			msgs = append(msgs, m)
		}
	}
	return status.Errorf(codes.InvalidArgument, "policy bundle is invalid: %s", strings.Join(msgs, "; "))
}

// simTime returns the evaluation time. Only simulation may override it; the
// result reports whether the time was simulated.
func (p *Plugin) simTime(at int64) (time.Time, bool) {
	if at != 0 {
		return time.Unix(at, 0), true
	}
	return p.now(), false
}

// ---- read methods ----------------------------------------------------------

type actionInfo struct {
	Name         string `json:"name"`
	Group        string `json:"group"`
	ResourceType string `json:"resourceType"`
	// Trusted context fields beyond currentTime (D-035), for Simulate and Tests.
	Context []authz.ContextField `json:"context,omitempty"`
}

func (p *Plugin) getSchema(context.Context, *call) (any, error) {
	actions := []actionInfo{}
	for _, a := range authz.Actions() {
		g, _ := authz.ActionGroup(a)
		actions = append(actions, actionInfo{Name: a, Group: g, ResourceType: authz.ResourceTypeFor(a), Context: authz.ContextFields(a)})
	}
	return map[string]any{
		"schema":            authz.SchemaText(),
		"platformPolicies":  authz.PlatformPolicyText(),
		"platformPolicyIds": authz.PlatformPolicyIDs(),
		"actions":           actions,
		"keyActions":        authz.KeyActions,
	}, nil
}

func (p *Plugin) getActive(ctx context.Context, c *call) (any, error) {
	v, err := p.activeVersion(ctx, c.principal.Tenant)
	if errors.Is(err, errNotFound) {
		return map[string]any{"exists": false}, nil
	}
	if err != nil {
		return nil, err
	}
	a, _ := p.store.GetActive(ctx, c.principal.Tenant)
	return map[string]any{"exists": true, "version": v, "activation": a}, nil
}

func (p *Plugin) listVersions(ctx context.Context, c *call) (any, error) {
	var params struct {
		// Opaque: pass back nextCursor from the previous page.
		Cursor string `json:"cursor,omitempty"`
		Limit  int    `json:"limit,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	before := int64(0)
	if params.Cursor != "" {
		n, err := strconv.ParseInt(params.Cursor, 10, 64)
		if err != nil || n < 1 {
			return nil, status.Error(codes.InvalidArgument, "invalid cursor")
		}
		before = n
	}
	if params.Limit <= 0 || params.Limit > maxVersionsList {
		params.Limit = maxVersionsList
	}
	list, next, err := p.store.ListVersions(ctx, c.principal.Tenant, before, params.Limit)
	if err != nil {
		return nil, err
	}
	nextCursor := ""
	if next > 0 {
		nextCursor = strconv.FormatInt(next, 10)
	}
	return map[string]any{"versions": list, "nextCursor": nextCursor}, nil
}

func (p *Plugin) getVersion(ctx context.Context, c *call) (any, error) {
	var params struct {
		Version int64 `json:"version"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	v, err := p.store.GetVersion(ctx, c.principal.Tenant, params.Version)
	if errors.Is(err, errNotFound) {
		return nil, status.Errorf(codes.NotFound, "version %d not found", params.Version)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"version": v}, nil
}

func (p *Plugin) getTests(ctx context.Context, c *call) (any, error) {
	cases, err := p.store.GetTests(ctx, c.principal.Tenant)
	if err != nil {
		return nil, err
	}
	if cases == nil {
		cases = []authz.TestCase{}
	}
	return map[string]any{"tests": cases}, nil
}

func (p *Plugin) listAudit(_ context.Context, c *call) (any, error) {
	var f auditFilter
	if err := c.decode(&f); err != nil {
		return nil, err
	}
	if f.Cursor != "" {
		if n, err := strconv.ParseInt(f.Cursor, 10, 64); err != nil || n < 1 {
			return nil, status.Error(codes.InvalidArgument, "invalid cursor")
		}
	}
	events, next := p.audit.list(c.principal.Tenant, f)
	return map[string]any{"events": events, "nextCursor": next, "summary": p.audit.summary(c.principal.Tenant)}, nil
}

// ---- simulation ------------------------------------------------------------

type bundleSummary struct {
	PolicyIDs      []string            `json:"policyIds"`
	Agents         []string            `json:"agents"`
	Roles          []string            `json:"roles"`
	AgentRoles     map[string][]string `json:"agentRoles"`
	ReferencedKeys []string            `json:"referencedKeys"`
}

func summarize(c *authz.Compiled) bundleSummary {
	s := bundleSummary{PolicyIDs: c.PolicyIDs(), Agents: c.Agents(), Roles: c.Roles(), ReferencedKeys: c.ReferencedKeys(), AgentRoles: map[string][]string{}}
	for _, a := range s.Agents {
		s.AgentRoles[a] = c.AgentRoles(a)
	}
	return s
}

func (p *Plugin) validate(_ context.Context, c *call) (any, error) {
	var b authz.Bundle
	if err := c.decode(&b); err != nil {
		return nil, err
	}
	compiled, problems := authz.Compile(b)
	if problems == nil {
		problems = []authz.Problem{}
	}
	// policies is null when the text does not parse, otherwise one entry per
	// policy (even if it fails schema validation) for the plain-language view.
	out := map[string]any{"ok": compiled != nil, "problems": problems, "policies": authz.Describe(b.Policies)}
	if compiled != nil {
		out["summary"] = summarize(compiled)
	}
	return out, nil
}

type simRequest struct {
	AgentID  string         `json:"agentId,omitempty"`
	Action   string         `json:"action"`
	Resource authz.Resource `json:"resource"`
	// A what-if value for the action's trusted context (D-035).
	Context map[string]any `json:"context,omitempty"`
}

// maxSimulateExplanations bounds the explanations one Simulate call computes;
// each costs a few evaluations per tenant permit.
const maxSimulateExplanations = 50

func (p *Plugin) simulate(ctx context.Context, c *call) (any, error) {
	var params struct {
		Source   *source      `json:"source,omitempty"`
		Requests []simRequest `json:"requests"`
		At       int64        `json:"at,omitempty"`
		// Attach an explanation to each DENY (the first 50).
		Explain bool `json:"explain,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	if len(params.Requests) == 0 || len(params.Requests) > 1000 {
		return nil, status.Error(codes.InvalidArgument, "requests must contain 1-1000 entries")
	}
	r, err := p.resolve(ctx, c.principal.Tenant, params.Source)
	if err != nil {
		return nil, err
	}
	at, simulated := p.simTime(params.At)
	results := make([]map[string]any, 0, len(params.Requests))
	explained, truncated := 0, false
	for _, sr := range params.Requests {
		sr.Resource.Tenant = "" // simulation stays inside the caller's tenant
		req := authz.Request{
			Principal: authz.Principal{Tenant: c.principal.Tenant, AgentID: sr.AgentID},
			Action:    sr.Action,
			Resource:  sr.Resource,
			Context:   sr.Context,
		}
		res := authz.Evaluate(r.compiled, req, at)
		item := map[string]any{"request": sr, "decision": res.Decision, "determiningPolicies": res.DeterminingPolicies, "errored": res.Errored}
		if res.Errored {
			// Diagnostics go only to the tenant's own operator, who wrote the
			// policy; they never reach the audit log.
			item["diagnostics"] = res.Diagnostics
		}
		if params.Explain && res.Decision == authz.Deny {
			if explained < maxSimulateExplanations {
				item["explanation"] = authz.Explain(r.compiled, req, at)
				explained++
			} else {
				truncated = true
			}
		}
		results = append(results, item)
	}
	out := map[string]any{"source": r.label, "at": at.Unix(), "simulatedTime": simulated, "results": results}
	if truncated {
		out["explanationsTruncated"] = true
	}
	return out, nil
}

// explain says why one request is (or would be) denied by a source: the
// active version by default, a saved version (for Activity, the version that
// was enforced), or a draft.
func (p *Plugin) explain(ctx context.Context, c *call) (any, error) {
	var params struct {
		Source   *source        `json:"source,omitempty"`
		AgentID  string         `json:"agentId,omitempty"`
		Action   string         `json:"action"`
		Resource authz.Resource `json:"resource"`
		Context  map[string]any `json:"context,omitempty"`
		At       int64          `json:"at,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	r, err := p.resolve(ctx, c.principal.Tenant, params.Source)
	if err != nil {
		return nil, err
	}
	at, simulated := p.simTime(params.At)
	params.Resource.Tenant = "" // explanations stay inside the caller's tenant
	e := authz.Explain(r.compiled, authz.Request{
		Principal: authz.Principal{Tenant: c.principal.Tenant, AgentID: params.AgentID},
		Action:    params.Action,
		Resource:  params.Resource,
		Context:   params.Context,
	}, at)
	return map[string]any{"source": r.label, "version": r.version, "at": at.Unix(), "simulatedTime": simulated, "explanation": e}, nil
}

type matrixParams struct {
	Source         *source          `json:"source,omitempty"`
	Keys           []authz.Resource `json:"keys,omitempty"`
	Actions        []string         `json:"actions,omitempty"`
	IncludeAccount bool             `json:"includeAccount,omitempty"`
	At             int64            `json:"at,omitempty"`
	// Paging over the merged, sorted key list and over principals. The
	// response carries totals so callers can page without dropping anything.
	KeyOffset   int `json:"keyOffset,omitempty"`
	KeyLimit    int `json:"keyLimit,omitempty"`
	AgentOffset int `json:"agentOffset,omitempty"`
	AgentLimit  int `json:"agentLimit,omitempty"`
	// Agents restricts principals to these ids ("" = the account principal).
	Agents []string `json:"agents,omitempty"`
	// OnlyAllowed drops keys on which none of the selected principals has
	// any ALLOW, before paging, so totals count only accessible keys.
	OnlyAllowed bool `json:"onlyAllowed,omitempty"`
	// KeySearch keeps keys whose id contains this text (case-insensitive).
	KeySearch string `json:"keySearch,omitempty"`
	// Summary returns per-principal counts over every key instead of cells.
	Summary bool `json:"summary,omitempty"`
}

// principalSummary is one agent's access at a glance, over every key.
type principalSummary struct {
	Principal   string         `json:"principal"`
	Roles       []string       `json:"roles"`
	AllowedKeys int            `json:"allowedKeys"`
	ByAction    map[string]int `json:"byAction"`
}

const (
	maxMatrixInputKeys = 5000
	defaultMatrixKeys  = 50
	maxMatrixKeys      = 100
	defaultMatrixAgent = 25
	maxMatrixAgents    = 50
)

// pageWindow clamps an offset/limit pair to a list of n items.
func pageWindow(n, offset, limit, def, max int) (int, int) {
	if limit <= 0 {
		limit = def
	}
	if limit > max {
		limit = max
	}
	if offset < 0 {
		offset = 0
	}
	if offset > n {
		offset = n
	}
	end := offset + limit
	if end > n {
		end = n
	}
	return offset, end
}

func checkActions(actions []string) ([]string, error) {
	if len(actions) == 0 {
		return authz.KeyActions, nil
	}
	if len(actions) > 50 {
		return nil, status.Error(codes.InvalidArgument, "at most 50 actions")
	}
	for _, a := range actions {
		if authz.ResourceTypeFor(a) != "Key" {
			return nil, status.Errorf(codes.InvalidArgument, "matrix actions must apply to keys: %q", a)
		}
	}
	return actions, nil
}

func (p *Plugin) matrix(ctx context.Context, c *call) (any, error) {
	var params matrixParams
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	actions, err := checkActions(params.Actions)
	if err != nil {
		return nil, err
	}
	if len(params.Keys) > maxMatrixInputKeys {
		return nil, status.Errorf(codes.InvalidArgument, "at most %d keys", maxMatrixInputKeys)
	}
	r, err := p.resolve(ctx, c.principal.Tenant, params.Source)
	if err != nil {
		return nil, err
	}
	at, simulated := p.simTime(params.At)
	principals := r.compiled.Agents()
	if params.IncludeAccount {
		principals = append([]string{""}, principals...)
	}
	if len(params.Agents) > 0 {
		want := map[string]bool{}
		for _, a := range params.Agents {
			want[a] = true
		}
		kept := principals[:0:0]
		for _, pr := range principals {
			if want[pr] {
				kept = append(kept, pr)
			}
		}
		principals = kept
	}
	allKeys := authz.MergeKeys(params.Keys, r.compiled.ReferencedKeys())
	if q := strings.ToLower(strings.TrimSpace(params.KeySearch)); q != "" {
		kept := allKeys[:0:0]
		for _, k := range allKeys {
			if strings.Contains(strings.ToLower(k.ID), q) {
				kept = append(kept, k)
			}
		}
		allKeys = kept
	}
	tenant := c.principal.Tenant
	allowed := func(pr string, k authz.Resource, action string) bool {
		res := authz.Evaluate(r.compiled, authz.Request{
			Principal: authz.Principal{Tenant: tenant, AgentID: pr},
			Action:    action,
			Resource:  authz.Resource{Type: authz.ResourceTypeFor(action), ID: k.ID, Attrs: k.Attrs, Tags: k.Tags},
		}, at)
		return res.Decision == authz.Allow
	}
	if params.OnlyAllowed {
		kept := allKeys[:0:0]
		for _, k := range allKeys {
		keyLoop:
			for _, pr := range principals {
				for _, action := range actions {
					if allowed(pr, k, action) {
						kept = append(kept, k)
						break keyLoop
					}
				}
			}
		}
		allKeys = kept
	}
	aFrom, aTo := pageWindow(len(principals), params.AgentOffset, params.AgentLimit, defaultMatrixAgent, maxMatrixAgents)
	totalPrincipals := len(principals)
	principals = principals[aFrom:aTo]

	if params.Summary {
		summaries := make([]principalSummary, 0, len(principals))
		for _, pr := range principals {
			s := principalSummary{Principal: pr, Roles: r.compiled.AgentRoles(pr), ByAction: map[string]int{}}
			for _, k := range allKeys {
				hasAccess := false
				for _, action := range actions {
					if allowed(pr, k, action) {
						s.ByAction[action]++
						hasAccess = true
					}
				}
				if hasAccess {
					s.AllowedKeys++
				}
			}
			summaries = append(summaries, s)
		}
		return map[string]any{
			"source": r.label, "at": at.Unix(), "simulatedTime": simulated, "actions": actions,
			"summary": summaries, "totalKeys": len(allKeys), "totalPrincipals": totalPrincipals, "agentOffset": aFrom,
		}, nil
	}

	kFrom, kTo := pageWindow(len(allKeys), params.KeyOffset, params.KeyLimit, defaultMatrixKeys, maxMatrixKeys)
	keys := allKeys[kFrom:kTo]
	cells := authz.Matrix(r.compiled, tenant, principals, actions, keys, at)
	if cells == nil {
		cells = []authz.Cell{}
	}
	agentRoles := map[string][]string{}
	for _, a := range principals {
		if a != "" {
			agentRoles[a] = r.compiled.AgentRoles(a)
		}
	}
	keyIDs := make([]string, 0, len(keys))
	for _, k := range keys {
		keyIDs = append(keyIDs, k.ID)
	}
	return map[string]any{
		"source": r.label, "at": at.Unix(), "simulatedTime": simulated,
		"principals": principals, "actions": actions, "keys": keyIDs, "agentRoles": agentRoles, "cells": cells,
		"totalKeys": len(allKeys), "keyOffset": kFrom, "totalPrincipals": totalPrincipals, "agentOffset": aFrom,
	}, nil
}

func (p *Plugin) diff(ctx context.Context, c *call) (any, error) {
	var params struct {
		From    *source          `json:"from,omitempty"`
		To      *source          `json:"to,omitempty"`
		Keys    []authz.Resource `json:"keys,omitempty"`
		Actions []string         `json:"actions,omitempty"`
		At      int64            `json:"at,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	actions, err := checkActions(params.Actions)
	if err != nil {
		return nil, err
	}
	from, err := p.resolve(ctx, c.principal.Tenant, params.From)
	if err != nil {
		return nil, err
	}
	to, err := p.resolve(ctx, c.principal.Tenant, params.To)
	if err != nil {
		return nil, err
	}
	at, simulated := p.simTime(params.At)
	changes := authz.Diff(from.compiled, to.compiled, c.principal.Tenant, actions, params.Keys, at)
	if changes == nil {
		changes = []authz.CellChange{}
	}
	return map[string]any{"from": from.label, "to": to.label, "at": at.Unix(), "simulatedTime": simulated, "changes": changes}, nil
}

func (p *Plugin) runTests(ctx context.Context, c *call) (any, error) {
	var params struct {
		Source *source          `json:"source,omitempty"`
		Tests  []authz.TestCase `json:"tests,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	r, err := p.resolve(ctx, c.principal.Tenant, params.Source)
	if err != nil {
		return nil, err
	}
	cases := params.Tests
	if cases == nil {
		cases, err = p.store.GetTests(ctx, c.principal.Tenant)
		if err != nil {
			return nil, err
		}
	}
	if err := authz.ValidateTests(cases); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return testReport(r.label, authz.RunTests(r.compiled, c.principal.Tenant, cases, p.now())), nil
}

func testReport(label string, results []authz.TestResult) map[string]any {
	failed := 0
	for _, r := range results {
		if !r.Pass {
			failed++
		}
	}
	if results == nil {
		results = []authz.TestResult{}
	}
	return map[string]any{"source": label, "total": len(results), "failed": failed, "passed": len(results) - failed, "results": results}
}

// ---- write methods ---------------------------------------------------------

func (p *Plugin) saveDraft(ctx context.Context, c *call) (any, error) {
	var params struct {
		Policies string          `json:"policies"`
		Entities json.RawMessage `json:"entities,omitempty"`
		Message  string          `json:"message,omitempty"`
		// Save even when an identical version already exists.
		AllowDuplicate bool `json:"allowDuplicate,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	return p.save(ctx, c, authz.Bundle{Policies: params.Policies, Entities: params.Entities}, params.Message, params.AllowDuplicate)
}

// save stores a bundle as a new immutable version. When an identical version
// (same policy text and same entities) already exists it returns that
// version with duplicate=true instead of piling up copies, unless
// allowDuplicate is set.
func (p *Plugin) save(ctx context.Context, c *call, b authz.Bundle, message string, allowDuplicate bool) (any, error) {
	compiled, problems := authz.Compile(b)
	if compiled == nil {
		return nil, problemError(problems)
	}
	if !allowDuplicate {
		existing, err := p.findIdentical(ctx, c.principal.Tenant, b)
		if err != nil {
			return nil, err
		}
		if existing > 0 {
			return map[string]any{"version": existing, "duplicate": true, "summary": summarize(compiled)}, nil
		}
	}
	if len(message) > 500 {
		message = message[:500]
	}
	entities := b.Entities
	if len(bytes.TrimSpace(entities)) == 0 {
		entities = json.RawMessage(`[]`)
	}
	n, err := p.store.SaveVersion(ctx, c.principal.Tenant, Version{
		Policies: b.Policies, Entities: entities, Message: message, Author: c.author(),
		CreatedAt: p.now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, err
	}
	p.auditAdmin(c, "policy.Write", fmt.Sprintf("v%d", n), n)
	return map[string]any{"version": n, "duplicate": false, "summary": summarize(compiled)}, nil
}

// findIdentical returns a saved version whose policies and entities equal b
// (entities compared as JSON values), or 0. The active version wins when it
// matches; otherwise the newest match, found through the content index so
// versions of any age are checked.
func (p *Plugin) findIdentical(ctx context.Context, tenant string, b authz.Bundle) (int64, error) {
	want := canonicalEntities(b.Entities)
	same := func(v *Version) bool { return v.Policies == b.Policies && canonicalEntities(v.Entities) == want }
	if v, err := p.activeVersion(ctx, tenant); err == nil && same(v) {
		return v.Version, nil
	}
	n, err := p.store.FindByContent(ctx, tenant, contentHash(b.Policies, b.Entities))
	if err != nil || n == 0 {
		return 0, err
	}
	// Trust the index only after comparing the real content.
	if v, err := p.store.GetVersion(ctx, tenant, n); err == nil && same(v) {
		return n, nil
	}
	return 0, nil
}

func (p *Plugin) putTests(ctx context.Context, c *call) (any, error) {
	var params struct {
		Tests []authz.TestCase `json:"tests"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	if err := authz.ValidateTests(params.Tests); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.store.PutTests(ctx, c.principal.Tenant, params.Tests); err != nil {
		return nil, err
	}
	return map[string]any{"count": len(params.Tests)}, nil
}

// getTemplate returns the 4Orbit demo organization and its test suite
// without storing anything. The console loads it into the browser draft.
func (p *Plugin) getTemplate(_ context.Context, c *call) (any, error) {
	var params struct {
		Template string `json:"template"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	if params.Template != "4orbit" {
		return nil, status.Error(codes.InvalidArgument, `template must be "4orbit"`)
	}
	b := authz.DefaultBundle()
	return map[string]any{"policies": b.Policies, "entities": b.Entities, "tests": authz.DefaultTests()}, nil
}

// loadTemplate saves the 4Orbit demo organization as a version (reusing an
// identical existing one) and installs its permission-matrix test suite. It
// does not activate. Used by the seed; the console uses getTemplate.
func (p *Plugin) loadTemplate(ctx context.Context, c *call) (any, error) {
	var params struct {
		Template string `json:"template"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	if params.Template != "4orbit" {
		return nil, status.Error(codes.InvalidArgument, `template must be "4orbit"`)
	}
	out, err := p.save(ctx, c, authz.DefaultBundle(), "4Orbit demo organization template", false)
	if err != nil {
		return nil, err
	}
	if err := p.store.PutTests(ctx, c.principal.Tenant, authz.DefaultTests()); err != nil {
		return nil, err
	}
	res := out.(map[string]any)
	res["tests"] = len(authz.DefaultTests())
	return res, nil
}

func (p *Plugin) activate(ctx context.Context, c *call) (any, error) {
	var params struct {
		Version int64 `json:"version"`
		Force   bool  `json:"force,omitempty"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	if params.Version < 1 {
		return nil, status.Error(codes.InvalidArgument, "version is required")
	}
	r, err := p.resolve(ctx, c.principal.Tenant, &source{Version: params.Version})
	if err != nil {
		return nil, err
	}
	cases, err := p.store.GetTests(ctx, c.principal.Tenant)
	if err != nil {
		return nil, err
	}
	report := testReport(r.label, authz.RunTests(r.compiled, c.principal.Tenant, cases, p.now()))
	if report["failed"].(int) > 0 && !params.Force {
		return map[string]any{"activated": false, "reason": "test suite failed", "tests": report}, nil
	}
	if err := p.store.SetActive(ctx, c.principal.Tenant, Active{
		Version: params.Version, ActivatedAt: p.now().UTC().Format(time.RFC3339), ActivatedBy: c.author(),
	}); err != nil {
		return nil, err
	}
	p.auditAdmin(c, "policy.Activate", fmt.Sprintf("v%d", params.Version), params.Version)
	return map[string]any{"activated": true, "version": params.Version, "forced": params.Force && report["failed"].(int) > 0, "tests": report}, nil
}

// issueAgentToken approves a token request; the gateway mints the PAT. The
// agent must be registered in the active bundle, so tokens exist only for
// agents an operator has declared.
func (p *Plugin) issueAgentToken(ctx context.Context, c *call) (any, error) {
	var params struct {
		AgentID    string `json:"agentId"`
		TTLSeconds int64  `json:"ttlSeconds"`
	}
	if err := c.decode(&params); err != nil {
		return nil, err
	}
	if params.TTLSeconds == 0 {
		params.TTLSeconds = 3600
	}
	if params.TTLSeconds < minAgentTokenTTL || params.TTLSeconds > maxAgentTokenTTL {
		return nil, status.Errorf(codes.InvalidArgument, "ttlSeconds must be %d-%d", minAgentTokenTTL, maxAgentTokenTTL)
	}
	r, err := p.resolve(ctx, c.principal.Tenant, nil)
	if err != nil {
		return nil, err
	}
	known := false
	for _, a := range r.compiled.Agents() {
		if a == params.AgentID {
			known = true
		}
	}
	if !known {
		return nil, status.Errorf(codes.FailedPrecondition, "agent %q is not registered in the active policy version", params.AgentID)
	}
	p.auditAdmin(c, "policy.IssueAgentToken", params.AgentID, r.version)
	return map[string]any{"agentId": params.AgentID, "ttlSeconds": params.TTLSeconds, "roles": r.compiled.AgentRoles(params.AgentID)}, nil
}

func (p *Plugin) auditAdmin(c *call, action, resource string, version int64) {
	req := authz.Request{Principal: c.principal, Action: action, Resource: authz.Resource{Type: "PolicySet", ID: resource}}
	ev := authz.NewAuditEvent(p.now().UTC().Format(time.RFC3339Nano), newID(), req, authz.Result{Decision: authz.Allow, DeterminingPolicies: []string{"platform.owner"}}, version, authz.ModeEnforce)
	ev.JtiHash = c.jtiHash
	p.audit.add(ev)
}
