package review

import (
	"strings"
	"testing"
)

func splitLines(s string) []string {
	return strings.Split(strings.TrimRight(s, "\n"), "\n")
}

const suggestedYAML = `---
spec:
  egress:
    - toFQDNs:
        - matchName: standalone.example.com
        # cnpgen:suggest *.eu.auth0.com (2 domains: a.eu.auth0.com, b.eu.auth0.com) - re-run with --allow-domain '*.eu.auth0.com', or 'cnpgen review' to accept.
        - matchName: a.eu.auth0.com
        - matchName: b.eu.auth0.com
      toPorts:
        - ports:
            - port: "443"
`

const wildcardedYAML = `---
spec:
  egress:
    - toFQDNs:
        - matchName: standalone.example.com
        # cnpgen:wildcard *.eu.auth0.com (2 domains observed: a.eu.auth0.com, b.eu.auth0.com)
        - matchPattern: "*.eu.auth0.com"
      toPorts:
        - ports:
            - port: "443"
`

func TestFindSuggested(t *testing.T) {
	groups := Find(splitLines(suggestedYAML))
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	g := groups[0]
	if g.Suffix != "eu.auth0.com" {
		t.Errorf("suffix = %q", g.Suffix)
	}
	if g.Wildcarded {
		t.Error("expected Wildcarded=false")
	}
	if len(g.Members) != 2 || g.Members[0] != "a.eu.auth0.com" || g.Members[1] != "b.eu.auth0.com" {
		t.Errorf("members = %v", g.Members)
	}
}

func TestFindWildcarded(t *testing.T) {
	groups := Find(splitLines(wildcardedYAML))
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if !groups[0].Wildcarded {
		t.Error("expected Wildcarded=true")
	}
}

func TestToggleSuggestedToWildcard(t *testing.T) {
	lines := splitLines(suggestedYAML)
	groups := Find(lines)
	out, err := Toggle(lines, groups[0])
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out, "\n")

	if strings.Contains(got, "matchName: a.eu.auth0.com") || strings.Contains(got, "matchName: b.eu.auth0.com") {
		t.Errorf("expected matchName entries gone, got:\n%s", got)
	}
	if !strings.Contains(got, `matchPattern: "*.eu.auth0.com"`) {
		t.Errorf("expected a matchPattern entry, got:\n%s", got)
	}
	if !strings.Contains(got, "cnpgen:wildcard *.eu.auth0.com") {
		t.Errorf("expected the wildcard marker, got:\n%s", got)
	}
	if !strings.Contains(got, "matchName: standalone.example.com") {
		t.Errorf("expected the unrelated entry preserved, got:\n%s", got)
	}

	// Round-trip: toggling the result back should reproduce equivalent
	// content (found again from scratch).
	groups2 := Find(out)
	if len(groups2) != 1 || !groups2[0].Wildcarded {
		t.Fatalf("expected exactly one wildcarded group after toggle, got %+v", groups2)
	}
}

func TestToggleWildcardToSuggested(t *testing.T) {
	lines := splitLines(wildcardedYAML)
	groups := Find(lines)
	out, err := Toggle(lines, groups[0])
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out, "\n")

	if strings.Contains(got, "matchPattern:") {
		t.Errorf("expected no matchPattern entry left, got:\n%s", got)
	}
	if !strings.Contains(got, "matchName: a.eu.auth0.com") || !strings.Contains(got, "matchName: b.eu.auth0.com") {
		t.Errorf("expected both matchName entries restored, got:\n%s", got)
	}
	if !strings.Contains(got, "cnpgen:suggest *.eu.auth0.com") {
		t.Errorf("expected the suggest marker, got:\n%s", got)
	}
}

func TestToggleRoundTrip(t *testing.T) {
	lines := splitLines(suggestedYAML)
	groups := Find(lines)
	toWildcard, err := Toggle(lines, groups[0])
	if err != nil {
		t.Fatal(err)
	}
	backGroups := Find(toWildcard)
	if len(backGroups) != 1 {
		t.Fatalf("expected 1 group after first toggle, got %d", len(backGroups))
	}
	backToNames, err := Toggle(toWildcard, backGroups[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(backToNames, "\n") != strings.Join(lines, "\n") {
		t.Errorf("round trip mismatch:\nwant:\n%s\ngot:\n%s",
			strings.Join(lines, "\n"), strings.Join(backToNames, "\n"))
	}
}

func TestToggleRejectsHandEditedFile(t *testing.T) {
	lines := splitLines(suggestedYAML)
	groups := Find(lines)
	g := groups[0]
	// Simulate a hand-edit: remove one of the expected matchName lines.
	tampered := append([]string{}, lines...)
	tampered = append(tampered[:g.line+2], tampered[g.line+3:]...)
	if _, err := Toggle(tampered, g); err == nil {
		t.Error("expected an error for a file that no longer matches the marker's member list")
	}
}

const twoGroupYAML = `---
spec:
  egress:
    - toFQDNs:
        # cnpgen:suggest *.cdn.content.amplience.net (5 domains: a.cdn.content.amplience.net, b.cdn.content.amplience.net, c.cdn.content.amplience.net, d.cdn.content.amplience.net, e.cdn.content.amplience.net) - re-run with --allow-domain '*.cdn.content.amplience.net', or 'cnpgen review' to accept.
        - matchName: a.cdn.content.amplience.net
        - matchName: b.cdn.content.amplience.net
        - matchName: c.cdn.content.amplience.net
        - matchName: d.cdn.content.amplience.net
        - matchName: e.cdn.content.amplience.net
        # cnpgen:suggest *.red.rexelgroup.global (3 domains: x.red.rexelgroup.global, y.red.rexelgroup.global, z.red.rexelgroup.global) - re-run with --allow-domain '*.red.rexelgroup.global', or 'cnpgen review' to accept.
        - matchName: x.red.rexelgroup.global
        - matchName: y.red.rexelgroup.global
        - matchName: z.red.rexelgroup.global
      toPorts:
        - ports:
            - port: "443"
`

// TestToggleAllHandlesShiftingOffsets reproduces the original bug: toggling
// an earlier group shrinks the file, which used to invalidate the line
// offset Find computed for a later group in the same pass.
func TestToggleAllHandlesShiftingOffsets(t *testing.T) {
	lines := splitLines(twoGroupYAML)
	out, err := ToggleAll(lines, map[string]bool{
		"cdn.content.amplience.net": true,
		"red.rexelgroup.global":     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(out, "\n")

	if !strings.Contains(got, `matchPattern: "*.cdn.content.amplience.net"`) {
		t.Errorf("expected the first group wildcarded, got:\n%s", got)
	}
	if !strings.Contains(got, `matchPattern: "*.red.rexelgroup.global"`) {
		t.Errorf("expected the second group wildcarded, got:\n%s", got)
	}
	if strings.Contains(got, "matchName: x.red.rexelgroup.global") {
		t.Errorf("expected the second group's matchName entries gone, got:\n%s", got)
	}

	final := Find(out)
	if len(final) != 2 || !final[0].Wildcarded || !final[1].Wildcarded {
		t.Fatalf("expected both groups wildcarded on re-scan, got %+v", final)
	}
}

func TestToggleAllOnlyTogglesSelected(t *testing.T) {
	lines := splitLines(twoGroupYAML)
	out, err := ToggleAll(lines, map[string]bool{
		"cdn.content.amplience.net": true,
		"red.rexelgroup.global":     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	final := Find(out)
	if len(final) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(final))
	}
	byName := map[string]Group{}
	for _, g := range final {
		byName[g.Suffix] = g
	}
	if !byName["cdn.content.amplience.net"].Wildcarded {
		t.Error("expected cdn.content.amplience.net wildcarded")
	}
	if byName["red.rexelgroup.global"].Wildcarded {
		t.Error("expected red.rexelgroup.global left as-is")
	}
}

func TestFindNoMarkers(t *testing.T) {
	groups := Find(splitLines("---\nspec:\n  egress: []\n"))
	if len(groups) != 0 {
		t.Errorf("expected no groups, got %d", len(groups))
	}
}
