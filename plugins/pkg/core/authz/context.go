package authz

import (
	"fmt"
	"math"
	"sort"

	cedar "github.com/cedar-policy/cedar-go"
)

// Trusted context (D-035).
//
// Until GitHub operations, context.currentTime was the only context a policy
// could read. Rules such as "only agent/* branches" or "never merge your own
// pull request" need facts about the request that only GitHub knows, so some
// actions declare extra context fields. They are trusted in the same way as
// the time: the enforcing plugin computes them from GitHub, never from the
// caller's parameters. Simulation and tests supply them explicitly, as a
// what-if, and are never enforcement.
//
// Every declared field that is not optional must be present: a missing,
// unknown or mistyped field denies the request without evaluation, so a
// plugin that forgets a field can never fall back to a permissive default.

// ContextType is the Cedar type of a context field.
type ContextType string

const (
	ContextString    ContextType = "String"
	ContextBool      ContextType = "Bool"
	ContextLong      ContextType = "Long"
	ContextStringSet ContextType = "Set<String>"
	// ContextAgent is an Agent entity reference, given as an agent id, so a
	// policy can compare it with the principal: principal == context.headAgent.
	ContextAgent ContextType = "Agent"
)

// ContextField declares one context attribute of an action.
type ContextField struct {
	Name     string      `json:"name"`
	Type     ContextType `json:"type"`
	Optional bool        `json:"optional,omitempty"`
	// Doc says where enforcement takes the value from, for the console.
	Doc string `json:"doc"`
}

const (
	maxContextString = 1024
	maxContextSet    = 100
)

// actionContext lists the extra context fields of each action that has any.
// The schema declares the same fields (TestActionContextMatchesSchema).
var actionContext = map[string][]ContextField{
	"github.contents.Read": {
		{Name: "path", Type: ContextString, Doc: "The file or directory read, relative to the repository root (empty for the root)."},
	},
	"github.branch.Create": branchContext,
	"github.commit.Create": append(append([]ContextField{}, branchContext...),
		ContextField{Name: "paths", Type: ContextStringSet, Doc: "Every path the commit adds, changes or deletes."},
		ContextField{Name: "touchesWorkflows", Type: ContextBool, Doc: "Whether any of those paths is under .github/workflows/."},
	),
}

// branchContext is the context of every write to a branch.
var branchContext = []ContextField{
	{Name: "branch", Type: ContextString, Doc: "The branch written."},
	{Name: "isDefaultBranch", Type: ContextBool, Doc: "Whether that is the repository's default branch, read from GitHub."},
	{Name: "branchAgent", Type: ContextAgent, Optional: true, Doc: "The agent an agent/<agent-id>/... branch belongs to; absent for other branches."},
}

// ContextFields returns the extra context fields of an action, in order.
func ContextFields(action string) []ContextField {
	return append([]ContextField(nil), actionContext[action]...)
}

// buildContext converts caller-supplied context values to Cedar values. A
// non-empty message means the context is malformed and the request must be
// denied. JSON numbers arrive as float64 and must be whole.
func buildContext(fields []ContextField, in map[string]any) (cedar.RecordMap, string) {
	out := cedar.RecordMap{}
	declared := map[string]ContextField{}
	for _, f := range fields {
		declared[f.Name] = f
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := declared[k]; !ok {
			return nil, fmt.Sprintf("unknown context field %q", k)
		}
	}
	for _, f := range fields {
		raw, ok := in[f.Name]
		if !ok || raw == nil {
			if f.Optional {
				continue
			}
			return nil, fmt.Sprintf("missing context field %q", f.Name)
		}
		v, msg := contextValue(f, raw)
		if msg != "" {
			return nil, msg
		}
		out[cedar.String(f.Name)] = v
	}
	return out, ""
}

func contextValue(f ContextField, raw any) (cedar.Value, string) {
	bad := fmt.Sprintf("context field %q must be %s", f.Name, f.Type)
	switch f.Type {
	case ContextString:
		s, ok := raw.(string)
		if !ok || len(s) > maxContextString {
			return nil, bad
		}
		return cedar.String(s), ""
	case ContextBool:
		b, ok := raw.(bool)
		if !ok {
			return nil, bad
		}
		return cedar.Boolean(b), ""
	case ContextLong:
		switch n := raw.(type) {
		case int:
			return cedar.Long(n), ""
		case int64:
			return cedar.Long(n), ""
		case float64:
			if n != math.Trunc(n) || math.Abs(n) > 1<<53 {
				return nil, bad
			}
			return cedar.Long(int64(n)), ""
		}
		return nil, bad
	case ContextStringSet:
		var items []string
		switch list := raw.(type) {
		case []string:
			items = list
		case []any:
			for _, item := range list {
				s, ok := item.(string)
				if !ok {
					return nil, bad
				}
				items = append(items, s)
			}
		default:
			return nil, bad
		}
		if len(items) > maxContextSet {
			return nil, fmt.Sprintf("context field %q has more than %d entries", f.Name, maxContextSet)
		}
		values := make([]cedar.Value, 0, len(items))
		for _, s := range items {
			if len(s) > maxContextString {
				return nil, bad
			}
			values = append(values, cedar.String(s))
		}
		return cedar.NewSet(values...), ""
	case ContextAgent:
		id, ok := raw.(string)
		if !ok || !entityIDRe.MatchString(id) {
			return nil, bad
		}
		return cedar.NewEntityUID("Agent", cedar.String(id)), ""
	}
	return nil, bad
}
