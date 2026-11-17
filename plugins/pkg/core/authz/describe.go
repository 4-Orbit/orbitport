package authz

import (
	"encoding/json"
	"sort"
	"unicode/utf16"
	"unicode/utf8"

	cedar "github.com/cedar-policy/cedar-go"
)

// PolicyInfo describes one policy in a tenant's source text, for the console's
// plain-language view. JSON is Cedar's JSON policy format, exactly as the
// engine parsed it, so the console never re-implements Cedar parsing.
//
// Start and End are UTF-16 code-unit offsets (JavaScript string indexes) of
// the policy's full text, from its first annotation through the closing ';'.
// Replacing [Start, End) in the source replaces exactly that policy.
type PolicyInfo struct {
	ID     string          `json:"id"`
	Effect string          `json:"effect"`
	JSON   json.RawMessage `json:"json"`
	Start  int             `json:"start"`
	End    int             `json:"end"`
	Line   int             `json:"line"`
}

// Describe parses policy text and returns one PolicyInfo per policy, in
// source order. It returns nil when the text does not parse (Validate
// reports the parse error). Schema problems do not prevent describing.
func Describe(policies string) []PolicyInfo {
	parsed, err := cedar.NewPolicySetFromBytes("tenant.cedar", []byte(policies))
	if err != nil {
		return nil
	}
	out := []PolicyInfo{}
	for _, p := range parsed.All() {
		pos := p.Position()
		raw, err := p.MarshalJSON()
		if err != nil {
			continue
		}
		startByte := pos.Offset
		endByte := policyEnd(policies, startByte)
		out = append(out, PolicyInfo{
			ID:     string(p.Annotations()["id"]),
			Effect: string(effectName(p.Effect())),
			JSON:   raw,
			Start:  utf16Len(policies[:startByte]),
			End:    utf16Len(policies[:endByte]),
			Line:   pos.Line,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func effectName(e cedar.Effect) string {
	if e == cedar.Forbid {
		return "forbid"
	}
	return "permit"
}

// policyEnd returns the byte offset just past the ';' that ends the policy
// starting at start, skipping strings and comments. If no terminator is
// found it returns len(src).
func policyEnd(src string, start int) int {
	inString := false
	for i := start; i < len(src); i++ {
		c := src[i]
		switch {
		case inString:
			switch c {
			case '\\':
				i++
			case '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ';':
			return i + 1
		}
	}
	return len(src)
}

func utf16Len(s string) int {
	n := 0
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		n += len(utf16.Encode([]rune{r}))
	}
	return n
}
