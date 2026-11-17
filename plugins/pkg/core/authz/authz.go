// Package authz is the single Cedar engine used to authorize agent requests.
//
// It is shared by the KMS plugin (enforcement) and the policy plugin
// (validation, simulation and the policy playground), so a decision shown in
// the playground is the decision the KMS makes (D-028). It ports the
// semantics of 4Orbit's Prototype 1 gate (prototype-1/src/cedar.ts):
//
//   - fail closed: parse errors, evaluation errors, unknown actions, missing
//     tenant and malformed input all yield DENY;
//   - trusted time: context.currentTime always comes from the caller-supplied
//     trusted clock, and no other context exists;
//   - trusted membership: roles come from the tenant's entity store, never
//     from the request.
package authz

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
)

//go:embed schema.cedarschema
var schemaText string

//go:embed platform.cedar
var platformText string

// SchemaText is the Cedar schema every tenant policy is validated against.
func SchemaText() string { return schemaText }

// PlatformPolicyText is the embedded, non-editable platform policy.
func PlatformPolicyText() string { return platformText }

// Decision is the outcome of an authorization request.
type Decision string

const (
	Allow Decision = "ALLOW"
	Deny  Decision = "DENY"
)

// Principal identifies the caller. Tenant always comes from the account Hold;
// AgentID comes only from a verified credential. An empty AgentID means an
// account-level credential (Cedar type Account).
type Principal struct {
	Tenant  string `json:"tenant,omitempty"`
	AgentID string `json:"agentId,omitempty"`
}

// IsAgent reports whether the principal is an agent.
func (p Principal) IsAgent() bool { return p.AgentID != "" }

// Resource is the protected object. Attrs and Tags are only honoured for the
// attributes the schema declares for Type; anything else is ignored.
type Resource struct {
	Type   string            `json:"type"`
	ID     string            `json:"id"`
	Tenant string            `json:"tenant,omitempty"`
	Attrs  map[string]string `json:"attrs,omitempty"`
	Tags   map[string]string `json:"tags,omitempty"`
}

// Request is one authorization question.
type Request struct {
	Principal Principal `json:"principal"`
	Action    string    `json:"action"`
	Resource  Resource  `json:"resource"`
}

// Result is the decision plus the policies that determined it. Diagnostics
// may contain policy text or request values and must stay in logs; audit
// records keep only the AUTHORIZATION_ERROR marker.
type Result struct {
	Decision            Decision `json:"decision"`
	DeterminingPolicies []string `json:"determiningPolicies"`
	Errored             bool     `json:"errored,omitempty"`
	Diagnostics         []string `json:"-"`
}

// Bundle is a tenant's editable policy set: Cedar policy text plus the trusted
// entity store (roles, agents and memberships) in Cedar JSON entity format.
type Bundle struct {
	Policies string          `json:"policies"`
	Entities json.RawMessage `json:"entities,omitempty"`
}

// Problem is a validation finding with an optional source position.
type Problem struct {
	Severity string `json:"severity"`
	PolicyID string `json:"policyId,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
	Message  string `json:"message"`
}

const (
	MaxPolicyBytes   = 256 * 1024
	MaxPolicies      = 500
	MaxEntities      = 1000
	maxResourceIDLen = 256
)

var (
	policyIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	// Same shape as 4Orbit's auditUid identifier check.
	entityIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	keyRefRe   = regexp.MustCompile(`Key::"([^"\\]{1,256})"`)
)

// Action groups, mirroring the schema. The engine refuses any action that is
// not listed here before Cedar runs.
var actionGroups = map[string]string{
	"kms.Encrypt":            "use",
	"kms.Decrypt":            "use",
	"kms.Sign":               "use",
	"kms.GenerateDataKey":    "use",
	"kms.Encapsulate":        "use",
	"kms.Decapsulate":        "use",
	"kms.RotateKey":          "rotate",
	"kms.GetKeyMetadata":     "read",
	"kms.GetPublicKey":       "read",
	"kms.ListKeys":           "read",
	"kms.CreateKey":          "admin",
	"kms_keystore.Put":       "keystore",
	"kms_keystore.Get":       "keystore",
	"kms_keystore.Delete":    "keystore",
	"kms_keystore.List":      "keystore",
	"policy.Read":            "policy",
	"policy.Write":           "policy",
	"policy.Activate":        "policy",
	"policy.Simulate":        "policy",
	"policy.IssueAgentToken": "policy",
}

// Resource type each action applies to.
var actionResource = map[string]string{
	"kms.ListKeys":           "KeyNamespace",
	"kms_keystore.Put":       "KeyStoreKey",
	"kms_keystore.Get":       "KeyStoreKey",
	"kms_keystore.Delete":    "KeyStoreKey",
	"kms_keystore.List":      "KeyStoreNamespace",
	"policy.Read":            "PolicySet",
	"policy.Write":           "PolicySet",
	"policy.Activate":        "PolicySet",
	"policy.Simulate":        "PolicySet",
	"policy.IssueAgentToken": "PolicySet",
}

// KeyActions are the per-key KMS actions, in display order. The playground
// matrix uses them as columns.
var KeyActions = []string{
	"kms.Encrypt", "kms.Decrypt", "kms.Sign", "kms.GenerateDataKey",
	"kms.Encapsulate", "kms.Decapsulate", "kms.RotateKey",
	"kms.GetKeyMetadata", "kms.GetPublicKey", "kms.CreateKey",
}

// Actions returns every known action, sorted.
func Actions() []string {
	out := make([]string, 0, len(actionGroups))
	for a := range actionGroups {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// ActionGroup returns the 4Orbit vocabulary group of an action.
func ActionGroup(action string) (string, bool) {
	g, ok := actionGroups[action]
	return g, ok
}

// ResourceTypeFor returns the resource type an action applies to.
func ResourceTypeFor(action string) string {
	if t, ok := actionResource[action]; ok {
		return t
	}
	return "Key"
}

var (
	platformSet     *cedar.PolicySet
	platformIDs     []string
	actionEntities  cedar.EntityMap
	schemaValidator *validate.Validator
)

func init() {
	var s schema.Schema
	s.SetFilename("schema.cedarschema")
	if err := s.UnmarshalCedar([]byte(schemaText)); err != nil {
		panic(fmt.Sprintf("authz: embedded schema does not parse: %v", err))
	}
	resolved, err := s.Resolve()
	if err != nil {
		panic(fmt.Sprintf("authz: embedded schema does not resolve: %v", err))
	}
	schemaValidator = validate.New(resolved, validate.WithStrict())

	parsed, err := cedar.NewPolicySetFromBytes("platform.cedar", []byte(platformText))
	if err != nil {
		panic(fmt.Sprintf("authz: embedded platform policy does not parse: %v", err))
	}
	platformSet = cedar.NewPolicySet()
	for _, p := range parsed.All() {
		id := string(p.Annotations()["id"])
		if !strings.HasPrefix(id, "platform.") {
			panic("authz: platform policy without platform.* @id")
		}
		platformSet.Add(cedar.PolicyID(id), p)
		platformIDs = append(platformIDs, id)
	}
	sort.Strings(platformIDs)

	actionEntities = cedar.EntityMap{}
	groups := map[string]bool{}
	for action, group := range actionGroups {
		groups[group] = true
		uid := cedar.NewEntityUID("Action", cedar.String(action))
		actionEntities[uid] = cedar.Entity{
			UID:        uid,
			Parents:    cedar.NewEntityUIDSet(cedar.NewEntityUID("Action", cedar.String(group))),
			Attributes: cedar.NewRecord(nil),
			Tags:       cedar.NewRecord(nil),
		}
	}
	for group := range groups {
		uid := cedar.NewEntityUID("Action", cedar.String(group))
		actionEntities[uid] = cedar.Entity{UID: uid, Parents: cedar.NewEntityUIDSet(), Attributes: cedar.NewRecord(nil), Tags: cedar.NewRecord(nil)}
	}
}

// PlatformPolicyIDs lists the @id of every platform policy.
func PlatformPolicyIDs() []string { return append([]string(nil), platformIDs...) }

// Compiled is a validated tenant bundle ready for evaluation.
type Compiled struct {
	set       *cedar.PolicySet
	entities  cedar.EntityMap
	policyIDs []string
	agents    []string
	roles     []string
	keyRefs   []string
}

// PolicyIDs returns the tenant policy @ids in source order.
func (c *Compiled) PolicyIDs() []string {
	if c == nil {
		return []string{}
	}
	return append([]string{}, c.policyIDs...)
}

// Agents returns the agent IDs declared in the entity store, sorted.
func (c *Compiled) Agents() []string {
	if c == nil {
		return []string{}
	}
	return append([]string{}, c.agents...)
}

// Roles returns the role IDs declared in the entity store, sorted.
func (c *Compiled) Roles() []string {
	if c == nil {
		return []string{}
	}
	return append([]string{}, c.roles...)
}

// AgentRoles returns the roles an agent belongs to in the trusted store.
func (c *Compiled) AgentRoles(agentID string) []string {
	if c == nil {
		return []string{}
	}
	e, ok := c.entities[cedar.NewEntityUID("Agent", cedar.String(agentID))]
	if !ok {
		return []string{}
	}
	roles := []string{}
	for p := range e.Parents.All() {
		roles = append(roles, string(p.ID))
	}
	sort.Strings(roles)
	return roles
}

// ReferencedKeys returns Key IDs mentioned literally in the tenant policies.
func (c *Compiled) ReferencedKeys() []string {
	if c == nil {
		return []string{}
	}
	return append([]string{}, c.keyRefs...)
}

// Validate reports every problem with a bundle. An empty result means the
// bundle compiles.
func Validate(b Bundle) []Problem {
	_, problems := Compile(b)
	return problems
}

// Compile parses and validates a tenant bundle. It returns nil when any
// error-severity problem was found. Warnings do not block compilation.
func Compile(b Bundle) (*Compiled, []Problem) {
	var problems []Problem
	addErr := func(p Problem) {
		p.Severity = "error"
		problems = append(problems, p)
	}

	if len(b.Policies) > MaxPolicyBytes {
		addErr(Problem{Message: fmt.Sprintf("policy text exceeds %d bytes", MaxPolicyBytes)})
		return nil, problems
	}

	c := &Compiled{set: cedar.NewPolicySet(), entities: cedar.EntityMap{}}
	for _, id := range platformIDs {
		c.set.Add(cedar.PolicyID(id), platformSet.Get(cedar.PolicyID(id)))
	}

	parsed, err := cedar.NewPolicySetFromBytes("tenant.cedar", []byte(b.Policies))
	if err != nil {
		line, col := positionFromError(err.Error())
		addErr(Problem{Line: line, Column: col, Message: "parse error: " + trimFilename(err.Error())})
		return nil, problems
	}

	type positioned struct {
		id     string
		policy *cedar.Policy
		line   int
		col    int
	}
	var ordered []positioned
	for _, p := range parsed.All() {
		pos := p.Position()
		ordered = append(ordered, positioned{id: string(p.Annotations()["id"]), policy: p, line: pos.Line, col: pos.Column})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].line != ordered[j].line {
			return ordered[i].line < ordered[j].line
		}
		return ordered[i].col < ordered[j].col
	})
	if len(ordered) > MaxPolicies {
		addErr(Problem{Message: fmt.Sprintf("more than %d policies", MaxPolicies)})
		return nil, problems
	}

	seen := map[string]bool{}
	for _, p := range ordered {
		switch {
		case p.id == "":
			addErr(Problem{Line: p.line, Column: p.col, Message: `policy has no @id("...") annotation; every tenant policy needs a stable id`})
			continue
		case !policyIDRe.MatchString(p.id):
			addErr(Problem{PolicyID: p.id, Line: p.line, Column: p.col, Message: "@id must be 1-128 characters of A-Z a-z 0-9 . _ : - and start with a letter or digit"})
			continue
		case strings.HasPrefix(p.id, "platform."):
			addErr(Problem{PolicyID: p.id, Line: p.line, Column: p.col, Message: `@id prefix "platform." is reserved`})
			continue
		case seen[p.id]:
			addErr(Problem{PolicyID: p.id, Line: p.line, Column: p.col, Message: "duplicate @id"})
			continue
		}
		seen[p.id] = true
		if err := schemaValidator.Policy(p.id, (*xast.Policy)(p.policy.AST())); err != nil {
			for _, msg := range splitErrors(err) {
				addErr(Problem{PolicyID: p.id, Line: p.line, Column: p.col, Message: msg})
			}
			continue
		}
		c.set.Add(cedar.PolicyID(p.id), p.policy)
		c.policyIDs = append(c.policyIDs, p.id)
	}

	for _, m := range keyRefRe.FindAllStringSubmatch(b.Policies, -1) {
		c.keyRefs = appendUnique(c.keyRefs, m[1])
	}
	sort.Strings(c.keyRefs)

	entityProblems := c.loadEntities(b.Entities)
	for _, p := range entityProblems {
		addErr(p)
	}

	for _, p := range problems {
		if p.Severity == "error" {
			return nil, problems
		}
	}
	return c, problems
}

func (c *Compiled) loadEntities(raw json.RawMessage) []Problem {
	var problems []Problem
	if len(strings.TrimSpace(string(raw))) == 0 || string(raw) == "null" {
		return nil
	}
	var entities cedar.EntityMap
	if err := json.Unmarshal(raw, &entities); err != nil {
		return []Problem{{Message: "entities: " + err.Error()}}
	}
	if len(entities) > MaxEntities {
		return []Problem{{Message: fmt.Sprintf("entities: more than %d entities", MaxEntities)}}
	}
	for uid, e := range entities {
		where := fmt.Sprintf("entities: %s", uid.String())
		id := string(uid.ID)
		if !entityIDRe.MatchString(id) {
			problems = append(problems, Problem{Message: where + ": id must be 1-64 characters of a-z 0-9 _ - and start with a letter or digit"})
			continue
		}
		if e.Attributes.Len() > 0 || e.Tags.Len() > 0 {
			problems = append(problems, Problem{Message: where + ": attrs and tags are not supported; tenant is set by the platform"})
			continue
		}
		switch uid.Type {
		case "Role":
			if e.Parents.Len() > 0 {
				problems = append(problems, Problem{Message: where + ": roles cannot have parents"})
				continue
			}
			c.roles = append(c.roles, id)
		case "Agent":
			bad := false
			for p := range e.Parents.All() {
				if p.Type != "Role" {
					problems = append(problems, Problem{Message: where + ": an agent's parents must be Role entities"})
					bad = true
					break
				}
				if _, ok := entities[p]; !ok {
					problems = append(problems, Problem{Message: where + fmt.Sprintf(": parent role %q is not declared", string(p.ID))})
					bad = true
					break
				}
			}
			if bad {
				continue
			}
			c.agents = append(c.agents, id)
		default:
			problems = append(problems, Problem{Message: where + ": only Role and Agent entities may be declared; keys come from the KMS"})
			continue
		}
		c.entities[uid] = cedar.Entity{UID: uid, Parents: e.Parents, Attributes: cedar.NewRecord(nil), Tags: cedar.NewRecord(nil)}
	}
	sort.Strings(c.agents)
	sort.Strings(c.roles)
	return problems
}

// Evaluate authorizes one request at the trusted time now. A nil Compiled
// means the tenant has no policy set: only the platform policy applies, so
// account principals keep working and every agent is denied.
func Evaluate(c *Compiled, req Request, now time.Time) Result {
	if _, ok := actionGroups[req.Action]; !ok {
		return denyErr("unknown action")
	}
	tenant := strings.TrimSpace(req.Principal.Tenant)
	if tenant == "" {
		return denyErr("missing tenant")
	}
	if req.Principal.IsAgent() && !entityIDRe.MatchString(req.Principal.AgentID) {
		return denyErr("malformed agent id")
	}
	wantType := ResourceTypeFor(req.Action)
	if req.Resource.Type == "" {
		req.Resource.Type = wantType
	}
	if req.Resource.Type != wantType {
		return denyErr("resource type does not match action")
	}
	if req.Resource.ID == "" || len(req.Resource.ID) > maxResourceIDLen {
		return denyErr("malformed resource id")
	}

	set := platformSet
	base := cedar.EntityMap{}
	if c != nil {
		set = c.set
		base = c.entities
	}

	overlay := cedar.EntityMap{}
	var principalUID cedar.EntityUID
	if req.Principal.IsAgent() {
		principalUID = cedar.NewEntityUID("Agent", cedar.String(req.Principal.AgentID))
		parents := cedar.NewEntityUIDSet()
		if e, ok := base[principalUID]; ok {
			parents = e.Parents
		}
		overlay[principalUID] = cedar.Entity{
			UID:        principalUID,
			Parents:    parents,
			Attributes: cedar.NewRecord(cedar.RecordMap{"tenant": cedar.String(tenant)}),
			Tags:       cedar.NewRecord(nil),
		}
	} else {
		principalUID = cedar.NewEntityUID("Account", cedar.String(tenant))
		overlay[principalUID] = cedar.Entity{
			UID:        principalUID,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: cedar.NewRecord(cedar.RecordMap{"tenant": cedar.String(tenant)}),
			Tags:       cedar.NewRecord(nil),
		}
	}

	resourceTenant := req.Resource.Tenant
	if resourceTenant == "" {
		resourceTenant = tenant
	}
	attrs := cedar.RecordMap{"tenant": cedar.String(resourceTenant)}
	tags := cedar.RecordMap{}
	switch req.Resource.Type {
	case "Key":
		for _, k := range []string{"scheme", "keySpec", "keyUsage"} {
			attrs[cedar.String(k)] = cedar.String(req.Resource.Attrs[k])
		}
		for k, v := range req.Resource.Tags {
			tags[cedar.String(k)] = cedar.String(v)
		}
	case "KeyStoreKey":
		attrs["name"] = cedar.String(req.Resource.ID)
	case "KeyStoreNamespace":
		attrs["prefix"] = cedar.String(req.Resource.ID)
	}
	resourceUID := cedar.NewEntityUID(cedar.EntityType(req.Resource.Type), cedar.String(req.Resource.ID))
	overlay[resourceUID] = cedar.Entity{
		UID:        resourceUID,
		Parents:    cedar.NewEntityUIDSet(),
		Attributes: cedar.NewRecord(attrs),
		Tags:       cedar.NewRecord(tags),
	}

	getter := layered{overlay: overlay, base: base}
	decision, diag := cedar.Authorize(set, getter, cedar.Request{
		Principal: principalUID,
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action)),
		Resource:  resourceUID,
		// The only context: trusted time, as an integer Cedar Long (US5).
		Context: cedar.NewRecord(cedar.RecordMap{"currentTime": cedar.Long(now.Unix())}),
	})

	if len(diag.Errors) > 0 {
		r := Result{Decision: Deny, DeterminingPolicies: []string{}, Errored: true}
		for _, e := range diag.Errors {
			r.Diagnostics = append(r.Diagnostics, fmt.Sprintf("%s: %s", e.PolicyID, e.Message))
		}
		return r
	}
	ids := make([]string, 0, len(diag.Reasons))
	for _, reason := range diag.Reasons {
		ids = append(ids, string(reason.PolicyID))
	}
	sort.Strings(ids)
	if decision == cedar.Allow {
		return Result{Decision: Allow, DeterminingPolicies: ids}
	}
	return Result{Decision: Deny, DeterminingPolicies: ids}
}

func denyErr(msg string) Result {
	return Result{Decision: Deny, DeterminingPolicies: []string{}, Errored: true, Diagnostics: []string{msg}}
}

// layered serves request entities first, then the tenant's trusted store and
// the static action hierarchy. Request entities never shadow actions.
type layered struct {
	overlay cedar.EntityMap
	base    cedar.EntityMap
}

func (l layered) Get(uid cedar.EntityUID) (cedar.Entity, bool) {
	if uid.Type == "Action" {
		return actionEntities.Get(uid)
	}
	if e, ok := l.overlay[uid]; ok {
		return e, true
	}
	return l.base.Get(uid)
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

var posRe = regexp.MustCompile(`:(\d+):(\d+)`)

func positionFromError(msg string) (int, int) {
	m := posRe.FindStringSubmatch(msg)
	if m == nil {
		return 0, 0
	}
	line, _ := strconv.Atoi(m[1])
	col, _ := strconv.Atoi(m[2])
	return line, col
}

func trimFilename(msg string) string {
	return strings.TrimPrefix(msg, "tenant.cedar:")
}

func splitErrors(err error) []string {
	type unwrapper interface{ Unwrap() []error }
	if u, ok := err.(unwrapper); ok {
		var out []string
		for _, e := range u.Unwrap() {
			out = append(out, splitErrors(e)...)
		}
		return out
	}
	return []string{err.Error()}
}
