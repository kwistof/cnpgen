// Package ui holds the shared console output helpers: minimal ANSI colors
// (auto-off when stdout isn't a terminal or NO_COLOR is set) and debug/warn
// logging to stderr.
package ui

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/term"
)

var (
	// colorEnabled defaults to TTY detection, overridable either way: FORCE_COLOR
	// wins when stdout isn't a terminal (e.g. `kubectl logs`, which still renders
	// ANSI codes fine), NO_COLOR always wins over both.
	colorEnabled = (term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("FORCE_COLOR") != "") &&
		os.Getenv("NO_COLOR") == ""
	// Debug toggles [debug] logging to stderr.
	Debug bool

	printMu sync.Mutex
)

var codes = map[string]string{
	"green": "32", "yellow": "33", "red": "31",
	"cyan": "36", "blue": "34", "dim": "2", "bold": "1",
}

func color(s, name string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return "\033[" + codes[name] + "m" + s + "\033[0m"
}

// Green colors a string green.
func Green(s string) string { return color(s, "green") }

// Yellow colors a string yellow.
func Yellow(s string) string { return color(s, "yellow") }

// Red colors a string red.
func Red(s string) string { return color(s, "red") }

// Cyan colors a string cyan.
func Cyan(s string) string { return color(s, "cyan") }

// Dim colors a string dim.
func Dim(s string) string { return color(s, "dim") }

// Bold colors a string bold.
func Bold(s string) string { return color(s, "bold") }

// Log writes a [debug] line to stderr when Debug is set. Safe to call from
// multiple goroutines.
func Log(format string, args ...any) {
	if !Debug {
		return
	}
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Fprintln(os.Stderr, Dim("[debug] "+fmt.Sprintf(format, args...)))
}

// Warn writes a [warn] line to stderr. Safe to call from multiple goroutines.
func Warn(format string, args ...any) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Fprintln(os.Stderr, Yellow("[warn] "+fmt.Sprintf(format, args...)))
}
