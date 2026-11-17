package authz

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The console's plain-language builder writes Cedar (console/src/rules.ts).
// console/test/fixtures/rules.json holds sample rules with the Cedar the
// builder generates for them, plus "custom" policies the builder must not
// claim to represent. This test proves every one of them is valid against
// the real schema and records the engine's JSON for each, which the console
// test then converts back to a rule. Run with -update to refresh the JSON.
const consoleFixtures = "../../../../console/test/fixtures/rules.json"

type consoleFixture struct {
	Name  string          `json:"name"`
	Rule  json.RawMessage `json:"rule"`
	Cedar string          `json:"cedar"`
	JSON  json.RawMessage `json:"json"`
}

func TestConsoleRuleFixtures(t *testing.T) {
	raw, err := os.ReadFile(consoleFixtures)
	if os.IsNotExist(err) {
		t.Skip("console fixtures not present (plugins built in isolation)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []consoleFixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	changed := false
	for i, f := range fixtures {
		if _, problems := Compile(Bundle{Policies: f.Cedar}); len(problems) != 0 {
			t.Errorf("%s: builder Cedar is not valid: %+v\n%s", f.Name, problems, f.Cedar)
			continue
		}
		infos := Describe(f.Cedar)
		if len(infos) != 1 {
			t.Errorf("%s: want exactly one policy, got %d", f.Name, len(infos))
			continue
		}
		if !sameJSON(f.JSON, infos[0].JSON) {
			if *update {
				fixtures[i].JSON = infos[0].JSON
				changed = true
			} else {
				t.Errorf("%s: engine JSON changed; run with -update", f.Name)
			}
		}
	}
	if changed {
		out, _ := json.MarshalIndent(fixtures, "", "  ")
		if err := os.WriteFile(consoleFixtures, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sameJSON(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
