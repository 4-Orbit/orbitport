package authz

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

//go:embed defaults/4orbit/policy.cedar
var defaultPolicy string

//go:embed defaults/4orbit/entities.json
var defaultEntities []byte

//go:embed defaults/4orbit/tests.json
var defaultTests []byte

// DefaultBundle is the 4Orbit demo organization (developer, security and
// deployment agents over demo-key, dev-key and prod-key).
func DefaultBundle() Bundle {
	return Bundle{Policies: defaultPolicy, Entities: json.RawMessage(append([]byte(nil), defaultEntities...))}
}

// DefaultTests is the 4Orbit permission matrix as a playground test suite.
func DefaultTests() []TestCase {
	var cases []TestCase
	if err := json.Unmarshal(defaultTests, &cases); err != nil {
		panic(fmt.Sprintf("authz: embedded default tests do not parse: %v", err))
	}
	return cases
}

// TestCase is one saved expectation. Tenant is filled in by the runner; At,
// when non-zero, is a simulated Unix time for this case only.
type TestCase struct {
	Name     string   `json:"name"`
	AgentID  string   `json:"agentId,omitempty"`
	Action   string   `json:"action"`
	Resource Resource `json:"resource"`
	At       int64    `json:"at,omitempty"`
	Expect   Decision `json:"expect"`
}

// TestResult is the outcome of one TestCase.
type TestResult struct {
	Name                string   `json:"name"`
	Expect              Decision `json:"expect"`
	Actual              Decision `json:"actual"`
	Pass                bool     `json:"pass"`
	DeterminingPolicies []string `json:"determiningPolicies"`
}

// MaxTestCases bounds a saved suite.
const MaxTestCases = 2000

// RunTests evaluates every case for tenant. now is used unless a case sets At.
func RunTests(c *Compiled, tenant string, cases []TestCase, now time.Time) []TestResult {
	out := make([]TestResult, 0, len(cases))
	for _, tc := range cases {
		at := now
		if tc.At != 0 {
			at = time.Unix(tc.At, 0)
		}
		res := Evaluate(c, Request{
			Principal: Principal{Tenant: tenant, AgentID: tc.AgentID},
			Action:    tc.Action,
			Resource:  tc.Resource,
		}, at)
		out = append(out, TestResult{
			Name:                tc.Name,
			Expect:              tc.Expect,
			Actual:              res.Decision,
			Pass:                res.Decision == tc.Expect,
			DeterminingPolicies: res.DeterminingPolicies,
		})
	}
	return out
}

// ValidateTests checks a suite's shape.
func ValidateTests(cases []TestCase) error {
	if len(cases) > MaxTestCases {
		return fmt.Errorf("more than %d test cases", MaxTestCases)
	}
	for i, tc := range cases {
		if tc.Expect != Allow && tc.Expect != Deny {
			return fmt.Errorf("test %d (%q): expect must be ALLOW or DENY", i, tc.Name)
		}
		if tc.Action == "" || tc.Resource.ID == "" {
			return fmt.Errorf("test %d (%q): action and resource.id are required", i, tc.Name)
		}
	}
	return nil
}

// Cell is one entry of an access matrix.
type Cell struct {
	Principal           string   `json:"principal"`
	Action              string   `json:"action"`
	Resource            string   `json:"resource"`
	Decision            Decision `json:"decision"`
	DeterminingPolicies []string `json:"determiningPolicies"`
}

// Matrix evaluates every principal x action x key. An empty principal string
// means the tenant's Account principal.
func Matrix(c *Compiled, tenant string, principals, actions []string, keys []Resource, now time.Time) []Cell {
	var cells []Cell
	for _, agent := range principals {
		for _, key := range keys {
			for _, action := range actions {
				res := Evaluate(c, Request{
					Principal: Principal{Tenant: tenant, AgentID: agent},
					Action:    action,
					Resource:  Resource{Type: ResourceTypeFor(action), ID: key.ID, Attrs: key.Attrs, Tags: key.Tags},
				}, now)
				name := agent
				if name == "" {
					name = "(account)"
				}
				cells = append(cells, Cell{Principal: name, Action: action, Resource: key.ID, Decision: res.Decision, DeterminingPolicies: res.DeterminingPolicies})
			}
		}
	}
	return cells
}

// CellChange is a matrix cell whose decision differs between two bundles.
type CellChange struct {
	Principal string   `json:"principal"`
	Action    string   `json:"action"`
	Resource  string   `json:"resource"`
	Before    Decision `json:"before"`
	After     Decision `json:"after"`
	AfterBy   []string `json:"afterPolicies"`
}

// Diff compares the matrices of two compiled bundles over the union of their
// agents and referenced keys plus extraKeys.
func Diff(before, after *Compiled, tenant string, actions []string, extraKeys []Resource, now time.Time) []CellChange {
	agentSet := map[string]bool{}
	for _, a := range append(before.Agents(), after.Agents()...) {
		agentSet[a] = true
	}
	agents := make([]string, 0, len(agentSet))
	for a := range agentSet {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	keys := MergeKeys(extraKeys, before.ReferencedKeys(), after.ReferencedKeys())
	b := Matrix(before, tenant, agents, actions, keys, now)
	a := Matrix(after, tenant, agents, actions, keys, now)
	var changes []CellChange
	for i := range b {
		if b[i].Decision != a[i].Decision {
			changes = append(changes, CellChange{Principal: b[i].Principal, Action: b[i].Action, Resource: b[i].Resource, Before: b[i].Decision, After: a[i].Decision, AfterBy: a[i].DeterminingPolicies})
		}
	}
	return changes
}

// MergeKeys unions explicit key resources with referenced key IDs, keeping
// the attributes of explicit keys.
func MergeKeys(explicit []Resource, refs ...[]string) []Resource {
	seen := map[string]bool{}
	var out []Resource
	for _, k := range explicit {
		if k.ID == "" || seen[k.ID] {
			continue
		}
		seen[k.ID] = true
		k.Type = "Key"
		out = append(out, k)
	}
	for _, list := range refs {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				out = append(out, Resource{Type: "Key", ID: id})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
