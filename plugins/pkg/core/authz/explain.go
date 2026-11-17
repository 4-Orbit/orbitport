package authz

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

// Explanation kinds, in the order Explain checks them.
const (
	// The request was allowed; there is nothing to explain.
	KindAllowed = "allowed"
	// The request is malformed (unknown action, bad id) and is never evaluated.
	KindInvalidRequest = "invalidRequest"
	// No policy version is active, so only the platform policy applies.
	KindNoPolicy = "noPolicy"
	// A policy failed to evaluate; Cedar denies on error.
	KindErrored = "errored"
	// The agent is not declared in the bundle's entities.
	KindUnknownAgent = "unknownAgent"
	// A forbid matched. forbid always overrides permit.
	KindBlocked = "blocked"
	// A rule matches who, action and key, but its time window has passed.
	KindExpired = "expired"
	// A rule matches who, action and key, but its time window has not started.
	KindNotYet = "notYet"
	// A rule matches who, action and key, but its condition is false.
	KindConditionFalse = "conditionFalse"
	// A rule covers this action on this key, but not for this principal.
	KindClosest = "closest"
	// No rule covers this action on this key.
	KindNoRule = "noRule"
)

// maxCandidates bounds how many near-miss rules an explanation lists.
const maxCandidates = 3

// Explanation says why a request was denied. It is computed by the same
// engine as enforcement: every claim below comes from asking cedar.Authorize
// about one policy at a time, with parts of its scope or its conditions
// removed. Nothing here re-implements Cedar's matching rules.
type Explanation struct {
	Decision            Decision `json:"decision"`
	Kind                string   `json:"kind"`
	DeterminingPolicies []string `json:"determiningPolicies"`
	// Only for invalidRequest: why the request was rejected.
	Message string `json:"message,omitempty"`
	// Only for errored: policies that failed to evaluate. Error details stay
	// in server logs, as in audit events.
	ErroredPolicies []string `json:"erroredPolicies,omitempty"`
	// The forbids that matched (blocked).
	BlockedBy []Blocker `json:"blockedBy,omitempty"`
	// Tenant permits closest to allowing this request, best first.
	Candidates []Candidate `json:"candidates,omitempty"`
	// The agent's roles in the evaluated bundle (agents only).
	AgentRoles []string `json:"agentRoles,omitempty"`
}

// Blocker is a forbid that matched the request.
type Blocker struct {
	PolicyID string `json:"policyId"`
	// Platform policies are embedded and cannot be edited by a tenant.
	Platform bool `json:"platform"`
}

// Candidate is a permit that would allow the request if its Missing parts
// were satisfied.
type Candidate struct {
	PolicyID string `json:"policyId"`
	// Each scope part (principal, action, resource) the request does not
	// match, and "condition" when the policy's when/unless clauses are false.
	Missing []Requirement `json:"missing"`
	// Set when the condition is false only because of the time: the policy
	// would allow this exact request at another time.
	Window *TimeWindow `json:"window,omitempty"`
}

// Requirement is one part of a policy the request does not satisfy, taken
// from the policy's own scope.
type Requirement struct {
	// "principal", "action", "resource" or "condition".
	Part string `json:"part"`
	// Scope operator: "==", "in" or "is". Empty for condition.
	Op string `json:"op,omitempty"`
	// The entities the scope names (one, or several for `action in [...]`).
	Entities []EntityRef `json:"entities,omitempty"`
	// For `is`: the required entity type.
	EntityType string `json:"entityType,omitempty"`
}

// EntityRef names a Cedar entity.
type EntityRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// TimeWindow places the request outside a time-limited grant.
type TimeWindow struct {
	// "expired" (the grant ended at At) or "notYet" (it starts at At).
	Kind string `json:"kind"`
	// Unix seconds.
	At int64 `json:"at"`
}

// Explain evaluates req like Evaluate and, for a DENY, says why. c may be
// nil (no active version).
func Explain(c *Compiled, req Request, now time.Time) Explanation {
	pr, msg := prepare(c, req)
	if msg != "" {
		return Explanation{Decision: Deny, Kind: KindInvalidRequest, DeterminingPolicies: []string{}, Message: msg}
	}
	decision, diag := cedar.Authorize(pr.set, pr.entities, pr.at(now))
	ids := make([]string, 0, len(diag.Reasons))
	for _, r := range diag.Reasons {
		ids = append(ids, string(r.PolicyID))
	}
	sort.Strings(ids)
	out := Explanation{Decision: Deny, DeterminingPolicies: ids}

	if len(diag.Errors) > 0 {
		out.Kind = KindErrored
		for _, e := range diag.Errors {
			out.ErroredPolicies = appendUnique(out.ErroredPolicies, string(e.PolicyID))
		}
		sort.Strings(out.ErroredPolicies)
		out.DeterminingPolicies = []string{}
		return out
	}
	if decision == cedar.Allow {
		out.Decision = Allow
		out.Kind = KindAllowed
		return out
	}
	if req.Principal.IsAgent() {
		out.AgentRoles = c.AgentRoles(req.Principal.AgentID)
	}

	// On a DENY, Cedar's reasons are exactly the forbids that matched.
	for _, id := range ids {
		out.BlockedBy = append(out.BlockedBy, Blocker{PolicyID: id, Platform: strings.HasPrefix(id, "platform.")})
	}
	if len(out.BlockedBy) > 0 {
		out.Kind = KindBlocked
		// Show which permits the forbid overrode, if any.
		for _, cand := range candidates(c, pr, now) {
			if len(cand.Missing) == 0 {
				out.Candidates = append(out.Candidates, cand)
			}
		}
		return out
	}

	if c == nil {
		out.Kind = KindNoPolicy
		return out
	}
	if req.Principal.IsAgent() {
		if _, ok := c.entities[pr.req.Principal]; !ok {
			out.Kind = KindUnknownAgent
			return out
		}
	}

	cands := candidates(c, pr, now)
	if len(cands) > maxCandidates {
		cands = cands[:maxCandidates]
	}
	out.Candidates = cands
	out.Kind = KindNoRule
	if len(cands) > 0 {
		best := cands[0]
		switch {
		case scopeMatched(best) && best.Window != nil && best.Window.Kind == "expired":
			out.Kind = KindExpired
		case scopeMatched(best) && best.Window != nil:
			out.Kind = KindNotYet
		case scopeMatched(best):
			out.Kind = KindConditionFalse
		case coversActionAndKey(best):
			out.Kind = KindClosest
		}
	}
	return out
}

// candidates analyses every tenant permit against the request and returns
// those that cover at least the action or the key, closest first.
func candidates(c *Compiled, pr prepared, now time.Time) []Candidate {
	if c == nil {
		return nil
	}
	type ranked struct {
		Candidate
		order int
	}
	var list []ranked
	for i, id := range c.policyIDs {
		p := c.set.Get(cedar.PolicyID(id))
		if p == nil || p.Effect() != cedar.Permit {
			continue
		}
		cand, ok := analyse(id, p, pr, now)
		if !ok || (!covers(cand, "action") && !covers(cand, "resource")) {
			continue
		}
		list = append(list, ranked{cand, i})
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if sa, sb := scopeMisses(a.Candidate), scopeMisses(b.Candidate); sa != sb {
			return sa < sb
		}
		// Covering this action on this key is what makes a rule "close".
		if ka, kb := coversActionAndKey(a.Candidate), coversActionAndKey(b.Candidate); ka != kb {
			return ka
		}
		if ca, cb := len(a.Missing), len(b.Missing); ca != cb {
			return ca < cb
		}
		if aa, ab := covers(a.Candidate, "action"), covers(b.Candidate, "action"); aa != ab {
			return aa
		}
		return a.order < b.order
	})
	out := make([]Candidate, 0, len(list))
	for _, r := range list {
		out = append(out, r.Candidate)
	}
	return out
}

// policyDoc is a policy in Cedar's JSON format, split into the parts
// Explain relaxes.
type policyDoc map[string]json.RawMessage

var allScope = json.RawMessage(`{"op":"All"}`)

// analyse tests each part of one permit separately: a scope part matches if
// the policy allows with only that part kept (other parts set to `All`,
// conditions removed); the condition holds if the policy allows with its
// whole scope set to `All`. Scope parts are independent of each other, so
// these tests together give exactly what is missing.
func analyse(id string, p *cedar.Policy, pr prepared, now time.Time) (Candidate, bool) {
	raw, err := p.MarshalJSON()
	if err != nil {
		return Candidate{}, false
	}
	var doc policyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Candidate{}, false
	}
	cand := Candidate{PolicyID: id, Missing: []Requirement{}}
	for _, part := range []string{"principal", "action", "resource"} {
		variant := relaxed(doc, part, false)
		if !allows(variant, pr, now) {
			cand.Missing = append(cand.Missing, requirement(part, doc[part]))
		}
	}
	if len(conditionsOf(doc)) > 0 {
		variant := relaxed(doc, "", true)
		if !allows(variant, pr, now) {
			cand.Missing = append(cand.Missing, Requirement{Part: "condition"})
			cand.Window = timeWindow(doc, pr, now)
		}
	}
	return cand, true
}

// relaxed copies doc with every scope part except keep set to `All`. With
// keepConditions false the when/unless clauses are dropped too.
func relaxed(doc policyDoc, keep string, keepConditions bool) policyDoc {
	out := policyDoc{}
	for k, v := range doc {
		out[k] = v
	}
	out["effect"] = json.RawMessage(`"permit"`)
	for _, part := range []string{"principal", "action", "resource"} {
		if part != keep {
			out[part] = allScope
		}
	}
	if !keepConditions {
		delete(out, "conditions")
	}
	return out
}

// allows evaluates a single policy (no platform policy, no other tenant
// policy) against the prepared request at time t.
func allows(doc policyDoc, pr prepared, t time.Time) bool {
	raw, err := json.Marshal(doc)
	if err != nil {
		return false
	}
	var p cedar.Policy
	if err := p.UnmarshalJSON(raw); err != nil {
		return false
	}
	set := cedar.NewPolicySet()
	set.Add("explain", &p)
	decision, diag := cedar.Authorize(set, pr.entities, pr.at(t))
	return decision == cedar.Allow && len(diag.Errors) == 0
}

func conditionsOf(doc policyDoc) []json.RawMessage {
	var conds []json.RawMessage
	_ = json.Unmarshal(doc["conditions"], &conds)
	return conds
}

// timeWindow checks whether the policy would allow this exact request at
// another time. Candidate instants are the integer literals the conditions
// compare with context.currentTime (and their neighbours); the engine, not
// this code, decides at each instant.
func timeWindow(doc policyDoc, pr prepared, now time.Time) *TimeWindow {
	var instants []int64
	for _, cond := range conditionsOf(doc) {
		var parsed any
		if json.Unmarshal(cond, &parsed) == nil {
			collectTimeLiterals(parsed, &instants)
		}
	}
	if len(instants) == 0 {
		return nil
	}
	seen := map[int64]bool{}
	var times []int64
	for _, n := range instants {
		for _, t := range []int64{n - 1, n, n + 1} {
			if !seen[t] {
				seen[t] = true
				times = append(times, t)
			}
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	allowedAt := map[int64]bool{}
	for _, t := range times {
		allowedAt[t] = allows(doc, pr, time.Unix(t, 0))
	}
	nowUnix := now.Unix()
	// A window that opens later wins: "applies from" is actionable.
	for _, t := range times {
		if t > nowUnix && allowedAt[t] {
			return &TimeWindow{Kind: "notYet", At: t}
		}
	}
	lastAllowed := int64(0)
	found := false
	for _, t := range times {
		if t < nowUnix && allowedAt[t] {
			lastAllowed, found = t, true
		}
	}
	if !found {
		return nil
	}
	for _, t := range times {
		if t > lastAllowed && !allowedAt[t] {
			return &TimeWindow{Kind: "expired", At: t}
		}
	}
	return nil
}

var comparisonOps = map[string]bool{"<": true, "<=": true, ">": true, ">=": true, "==": true, "!=": true}

// collectTimeLiterals finds integer literals compared with
// context.currentTime in a Cedar JSON expression.
func collectTimeLiterals(node any, out *[]int64) {
	switch n := node.(type) {
	case map[string]any:
		for op, v := range n {
			if comparisonOps[op] {
				if operands, ok := v.(map[string]any); ok {
					l, r := operands["left"], operands["right"]
					if isCurrentTime(l) {
						appendLiteral(r, out)
					}
					if isCurrentTime(r) {
						appendLiteral(l, out)
					}
				}
			}
			collectTimeLiterals(v, out)
		}
	case []any:
		for _, v := range n {
			collectTimeLiterals(v, out)
		}
	}
}

func isCurrentTime(node any) bool {
	m, ok := node.(map[string]any)
	if !ok {
		return false
	}
	dot, ok := m["."].(map[string]any)
	if !ok || dot["attr"] != "currentTime" {
		return false
	}
	left, ok := dot["left"].(map[string]any)
	return ok && left["Var"] == "context"
}

func appendLiteral(node any, out *[]int64) {
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if v, ok := m["Value"].(float64); ok && v == float64(int64(v)) {
		*out = append(*out, int64(v))
	}
}

// scopeJSON mirrors the scope shapes of Cedar's JSON policy format.
type scopeJSON struct {
	Op         string      `json:"op"`
	Entity     *EntityRef  `json:"entity"`
	Entities   []EntityRef `json:"entities"`
	EntityType string      `json:"entity_type"`
	In         *struct {
		Entity *EntityRef `json:"entity"`
	} `json:"in"`
}

func requirement(part string, raw json.RawMessage) Requirement {
	r := Requirement{Part: part}
	var s scopeJSON
	if json.Unmarshal(raw, &s) != nil {
		return r
	}
	r.Op = s.Op
	r.EntityType = s.EntityType
	if s.Entity != nil {
		r.Entities = append(r.Entities, *s.Entity)
	}
	r.Entities = append(r.Entities, s.Entities...)
	if s.In != nil && s.In.Entity != nil {
		r.Entities = append(r.Entities, *s.In.Entity)
	}
	return r
}

func covers(c Candidate, part string) bool {
	for _, m := range c.Missing {
		if m.Part == part {
			return false
		}
	}
	return true
}

func coversActionAndKey(c Candidate) bool { return covers(c, "action") && covers(c, "resource") }

func scopeMisses(c Candidate) int {
	n := 0
	for _, m := range c.Missing {
		if m.Part != "condition" {
			n++
		}
	}
	return n
}

func scopeMatched(c Candidate) bool { return scopeMisses(c) == 0 }
