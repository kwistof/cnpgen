// Package review finds the wildcard-suggestion/wildcard-applied marker
// comments cnpgen writes into a generated policy file (see
// internal/generate's suggestMarker/wildcardMarker) and lets an operator
// toggle each group between exact matchName entries and a matchPattern
// wildcard, rewriting that block of the file in place.
//
// This works purely on the file's text, independent of the generate pipeline:
// a file is regenerated wholesale by the next audit round, so there's no
// state to persist between review and generate. review only ever needs to
// exist long enough for the operator to hand-tune what's already on disk.
package review

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	suggestMarker  = "cnpgen:suggest"
	wildcardMarker = "cnpgen:wildcard"
)

// markerRE parses both comment forms:
//
//	# cnpgen:suggest *.SUFFIX (N domains: a, b, c) - ...
//	# cnpgen:wildcard *.SUFFIX (N domains observed: a, b, c)
var markerRE = regexp.MustCompile(
	`^(\s*)# (cnpgen:suggest|cnpgen:wildcard) \*\.(\S+) \(\d+ domains(?: observed)?: ([^)]*)\).*$`)

// Group is one toggleable wildcard-suggestion block found in a file.
type Group struct {
	Suffix     string   // e.g. "eu.auth0.com"
	Members    []string // observed domains under that suffix, sorted
	Wildcarded bool     // true if currently a matchPattern, false if matchName entries
	line       int      // index of the marker comment line in the file
	indent     string   // leading whitespace of the marker line
}

// Find scans YAML lines for marker comments and returns one Group per match,
// in file order.
func Find(lines []string) []Group {
	var groups []Group
	for i, line := range lines {
		m := markerRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		members := strings.Split(m[4], ", ")
		groups = append(groups, Group{
			Suffix:     m[3],
			Members:    members,
			Wildcarded: m[2] == wildcardMarker,
			line:       i,
			indent:     m[1],
		})
	}
	return groups
}

// Toggle rewrites the block belonging to g in lines, flipping it between its
// matchName-group and matchPattern forms, and returns the new line slice.
// lines must be the same slice Find was called on (g.line indexes into it):
// toggling shifts every later line's index, so a Group found before an
// earlier Toggle call must not be reused with the lines that call returned.
// Use ToggleAll to flip several groups in one file safely.
func Toggle(lines []string, g Group) ([]string, error) {
	if g.line < 0 || g.line >= len(lines) {
		return nil, fmt.Errorf("marker line %d out of range", g.line)
	}
	if g.Wildcarded {
		return toggleToNames(lines, g)
	}
	return toggleToPattern(lines, g)
}

// ToggleAll flips every group whose suffix is a key in suffixes (with a true
// value) between its matchName-group and matchPattern forms. It re-finds
// groups by suffix after each toggle rather than reusing line offsets
// computed before earlier toggles shifted the file, so it's safe to select
// several groups from one Find pass and apply them together.
func ToggleAll(lines []string, suffixes map[string]bool) ([]string, error) {
	for suffix, want := range suffixes {
		if !want {
			continue
		}
		g, ok := findBySuffix(lines, suffix)
		if !ok {
			return nil, fmt.Errorf("*.%s: marker no longer found (already toggled, or the file changed)", suffix)
		}
		out, err := Toggle(lines, g)
		if err != nil {
			return nil, fmt.Errorf("*.%s: %w", suffix, err)
		}
		lines = out
	}
	return lines, nil
}

func findBySuffix(lines []string, suffix string) (Group, bool) {
	for _, g := range Find(lines) {
		if g.Suffix == suffix {
			return g, true
		}
	}
	return Group{}, false
}

// toggleToPattern replaces a "# cnpgen:suggest ..." marker and the
// contiguous run of "- matchName: <member>" lines that follow it with a
// "# cnpgen:wildcard ..." marker and a single "- matchPattern: *.SUFFIX"
// line.
func toggleToPattern(lines []string, g Group) ([]string, error) {
	itemIndent := g.indent // matchName/matchPattern items share the marker's indent
	end := g.line + 1
	consumed := 0
	for end < len(lines) && consumed < len(g.Members) {
		name, ok := parseMatchName(lines[end], itemIndent)
		if !ok {
			break
		}
		if !containsStr(g.Members, name) {
			break
		}
		end++
		consumed++
	}
	if consumed != len(g.Members) {
		return nil, fmt.Errorf(
			"expected %d matchName entries for *.%s right after the marker, found %d: "+
				"the file may have been hand-edited since it was generated", len(g.Members), g.Suffix, consumed)
	}

	newMarker := fmt.Sprintf("%s# %s *.%s (%d domains observed: %s)",
		g.indent, wildcardMarker, g.Suffix, len(g.Members), strings.Join(g.Members, ", "))
	newEntry := fmt.Sprintf("%s- matchPattern: \"*.%s\"", itemIndent, g.Suffix)

	out := make([]string, 0, len(lines)-(end-g.line)+2)
	out = append(out, lines[:g.line]...)
	out = append(out, newMarker, newEntry)
	out = append(out, lines[end:]...)
	return out, nil
}

// toggleToNames replaces a "# cnpgen:wildcard ..." marker and the single
// "- matchPattern: *.SUFFIX" line that follows it with a "# cnpgen:suggest
// ..." marker and one "- matchName: <member>" line per observed domain.
func toggleToNames(lines []string, g Group) ([]string, error) {
	itemIndent := g.indent
	patLine := g.line + 1
	if patLine >= len(lines) {
		return nil, fmt.Errorf("expected a matchPattern entry after the marker for *.%s, found end of file", g.Suffix)
	}
	wantPattern := fmt.Sprintf("*.%s", g.Suffix)
	gotPattern, ok := parseMatchPattern(lines[patLine], itemIndent)
	if !ok || gotPattern != wantPattern {
		return nil, fmt.Errorf(
			"expected \"- matchPattern: %q\" right after the marker for *.%s, found %q: "+
				"the file may have been hand-edited since it was generated", wantPattern, g.Suffix, strings.TrimSpace(lines[patLine]))
	}

	newMarker := fmt.Sprintf("%s# %s *.%s (%d domains: %s) - re-run with --allow-domain '*.%s', or 'cnpgen review' to accept.",
		g.indent, suggestMarker, g.Suffix, len(g.Members), strings.Join(g.Members, ", "), g.Suffix)
	newEntries := make([]string, len(g.Members))
	for i, m := range g.Members {
		newEntries[i] = fmt.Sprintf("%s- matchName: %s", itemIndent, m)
	}

	out := make([]string, 0, len(lines)-2+1+len(newEntries))
	out = append(out, lines[:g.line]...)
	out = append(out, newMarker)
	out = append(out, newEntries...)
	out = append(out, lines[patLine+1:]...)
	return out, nil
}

// matchEntryRE matches a "- matchName: X" or "- matchPattern: X" list item,
// with X optionally quoted.
var matchEntryRE = regexp.MustCompile(`^(\s*)- (matchName|matchPattern): "?([^"]+)"?$`)

func parseMatchName(line, wantIndent string) (string, bool) {
	return parseMatchEntry(line, wantIndent, "matchName")
}

func parseMatchPattern(line, wantIndent string) (string, bool) {
	return parseMatchEntry(line, wantIndent, "matchPattern")
}

func parseMatchEntry(line, wantIndent, key string) (string, bool) {
	m := matchEntryRE.FindStringSubmatch(line)
	if m == nil || m[1] != wantIndent || m[2] != key {
		return "", false
	}
	return m[3], true
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Describe renders a one-line summary of a group for the review prompt.
func (g Group) Describe() string {
	state := "suggested"
	if g.Wildcarded {
		state = "wildcarded"
	}
	return fmt.Sprintf("*.%s (%s) - %d domain(s): %s",
		g.Suffix, state, len(g.Members), strings.Join(g.Members, ", "))
}

// LineNumber returns the 1-based line number of the group's marker comment,
// for user-facing messages.
func (g Group) LineNumber() int { return g.line + 1 }
