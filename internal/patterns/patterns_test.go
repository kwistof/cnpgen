package patterns

import (
	"reflect"
	"sort"
	"testing"
)

func TestCollapseSuggestsButDoesNotEmit(t *testing.T) {
	fqdns := []string{"t1.auth0.com", "t2.auth0.com", "t3.auth0.com"}
	res := Collapse(fqdns, nil, nil, false)
	if len(res.MatchPatterns) != 0 {
		t.Fatalf("expected no patterns emitted without accept/force, got %v", res.MatchPatterns)
	}
	sort.Strings(res.MatchNames)
	if !reflect.DeepEqual(res.MatchNames, fqdns) {
		t.Fatalf("expected all as matchName, got %v", res.MatchNames)
	}
	if len(res.Suggestions) != 1 || res.Suggestions[0].Suffix != "auth0.com" {
		t.Fatalf("expected one suggestion for auth0.com, got %v", res.Suggestions)
	}
}

func TestCollapseAcceptEmitsPattern(t *testing.T) {
	fqdns := []string{"t1.auth0.com", "t2.auth0.com"}
	res := Collapse(fqdns, nil, nil, true)
	if !reflect.DeepEqual(res.MatchPatterns, []string{"*.auth0.com"}) {
		t.Fatalf("expected *.auth0.com, got %v", res.MatchPatterns)
	}
	if len(res.MatchNames) != 0 {
		t.Fatalf("expected members absorbed, got names %v", res.MatchNames)
	}
}

func TestCollapseForceSingleton(t *testing.T) {
	// A forced pattern covers even a single host that wouldn't be eligible.
	res := Collapse([]string{"only.adyen.com"}, []string{"*.adyen.com"}, nil, false)
	if !reflect.DeepEqual(res.MatchPatterns, []string{"*.adyen.com"}) {
		t.Fatalf("expected forced *.adyen.com, got %v", res.MatchPatterns)
	}
}

func TestCollapsePinnedStaysExact(t *testing.T) {
	fqdns := []string{"t1.auth0.com", "t2.auth0.com"}
	res := Collapse(fqdns, nil, []string{"t1.auth0.com"}, true)
	// t1 is pinned so it never joins the group; only t2 remains, which alone
	// is below threshold -> no pattern, both stay as names.
	sort.Strings(res.MatchNames)
	if !reflect.DeepEqual(res.MatchNames, fqdns) {
		t.Fatalf("expected both exact when one pinned, got names=%v patterns=%v",
			res.MatchNames, res.MatchPatterns)
	}
}

func TestCollapseDenylist(t *testing.T) {
	// Two hosts directly under "com" must never be wildcarded.
	res := Collapse([]string{"a.com", "b.com"}, nil, nil, true)
	if len(res.MatchPatterns) != 0 {
		t.Fatalf("expected no wildcard on denylisted suffix, got %v", res.MatchPatterns)
	}
}
