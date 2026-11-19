package authz

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestDescribeSpansAndJSON(t *testing.T) {
	src := "// header — with a non-ASCII dash\n@id(\"a\")\npermit (principal in Role::\"dev\", action == Action::\"kms.Encrypt\", resource == Key::\"k\")\nwhen { resource.hasTag(\"note\") && resource.getTag(\"note\") == \"a;b\" }; // trailing\n\n@id(\"b\") forbid (principal, action, resource);\n"
	infos := Describe(src)
	if len(infos) != 2 {
		t.Fatalf("want 2 policies, got %d", len(infos))
	}
	units := utf16.Encode([]rune(src))
	text := func(p PolicyInfo) string { return string(utf16.Decode(units[p.Start:p.End])) }

	a := text(infos[0])
	if !strings.HasPrefix(a, "@id(\"a\")") || !strings.HasSuffix(a, "\"a;b\" };") {
		t.Fatalf("span a wrong: %q", a)
	}
	if b := text(infos[1]); b != "@id(\"b\") forbid (principal, action, resource);" {
		t.Fatalf("span b wrong: %q", b)
	}
	if infos[0].ID != "a" || infos[0].Effect != "permit" || infos[1].Effect != "forbid" || infos[0].Line != 2 {
		t.Fatalf("metadata wrong: %+v", infos)
	}
	var parsed map[string]any
	if err := json.Unmarshal(infos[0].JSON, &parsed); err != nil || parsed["effect"] != "permit" {
		t.Fatalf("json wrong: %s", infos[0].JSON)
	}
}

func TestDescribeDefaultBundleAndParseError(t *testing.T) {
	if got := len(Describe(DefaultBundle().Policies)); got != 7 {
		t.Fatalf("default bundle: want 7 policies, got %d", got)
	}
	if Describe("@id(\"x\") permit (") != nil {
		t.Fatal("unparseable text must describe as nil")
	}
	if got := Describe(""); got == nil || len(got) != 0 {
		t.Fatalf("empty text: want empty list, got %v", got)
	}
}
