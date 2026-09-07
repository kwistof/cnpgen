package ui

import (
	"strings"
	"testing"
)

func TestWrapWidthNoWrapNeeded(t *testing.T) {
	got := wrapWidth("short", 80)
	if len(got) != 1 || got[0] != "short" {
		t.Errorf("got %v", got)
	}
}

func TestWrapWidthBreaksOnSpace(t *testing.T) {
	s := "the quick brown fox jumps over the lazy dog"
	got := wrapWidth(s, 10)
	for _, line := range got {
		if visibleWidth(line) > 10 {
			t.Errorf("line %q exceeds width 10 (visible)", line)
		}
	}
	rejoined := stripANSI(strings.Join(got, " "))
	if rejoined != s {
		t.Errorf("rejoining wrapped lines should reproduce the original words, got %v", got)
	}
}

func TestWrapWidthNoSpaceInFirstChunk(t *testing.T) {
	// A run with no space before the width limit (e.g. a long domain name)
	// must still terminate and not corrupt the first cut.
	s := "verylongdomainnamewithnobreaks.example.com and then more words"
	got := wrapWidth(s, 10)
	if len(got) < 2 {
		t.Fatalf("expected multiple lines, got %v", got)
	}
	// No line should be empty, and the hard cut shouldn't drop characters.
	rejoined := stripANSI(strings.Join(got, ""))
	rejoined = strings.ReplaceAll(rejoined, " ", "")
	original := strings.ReplaceAll(s, " ", "")
	if rejoined != original {
		t.Errorf("wrapping lost or duplicated characters:\nwant: %q\ngot:  %q", original, rejoined)
	}
}

func TestWrapWidthPreservesColorAcrossCuts(t *testing.T) {
	orig := colorEnabled
	colorEnabled = true
	defer func() { colorEnabled = orig }()

	s := Bold("this is a long bold label that will need to wrap across several lines")
	got := wrapWidth(s, 15)
	if len(got) < 2 {
		t.Fatalf("expected multiple lines, got %v", got)
	}
	for i, line := range got {
		if visibleWidth(line) > 15 {
			t.Errorf("line %d %q exceeds width 15 (visible)", i, line)
		}
		// Every wrapped line must be self-contained: no color code left open
		// (which would bleed onto whatever the terminal draws next) unless
		// it's the final, unmodified remainder.
		if i < len(got)-1 && !strings.HasSuffix(line, "\033[0m") {
			t.Errorf("line %d %q doesn't end with a reset", i, line)
		}
	}
	if stripANSI(strings.Join(got, " ")) != stripANSI(s) {
		t.Errorf("rejoining wrapped colored lines should reproduce the original text")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape:
			if r == 'm' {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestWrapWidthZeroOrNegative(t *testing.T) {
	s := "anything"
	if got := wrapWidth(s, 0); len(got) != 1 || got[0] != s {
		t.Errorf("width=0 should return the string unwrapped, got %v", got)
	}
	if got := wrapWidth(s, -5); len(got) != 1 || got[0] != s {
		t.Errorf("negative width should return the string unwrapped, got %v", got)
	}
}

func TestWrapWidthExactFit(t *testing.T) {
	s := "1234567890"
	got := wrapWidth(s, 10)
	if len(got) != 1 || got[0] != s {
		t.Errorf("a string exactly at width shouldn't wrap, got %v", got)
	}
}
