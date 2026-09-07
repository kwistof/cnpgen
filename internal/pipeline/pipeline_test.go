package pipeline

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/kwistof/cnpgen/internal/generate"
)

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestPrintNewNotesSkipsUnchangedAcrossCalls(t *testing.T) {
	seen := map[string]struct{}{}

	p1 := &generate.Policy{Name: "hybris-front", Namespace: "webshop", ObservedNS: "webshop"}
	p1.Notes = []string{
		"could combine 3 domains into *.eu.auth0.com but didn't.",
		"resolved and allowed 2 domain(s): a.com, b.com.",
	}
	out1 := captureStdout(t, func() { PrintNewNotes([]*generate.Policy{p1}, seen) })
	if !strings.Contains(out1, "could combine 3 domains") {
		t.Errorf("round 1: expected the suggestion note, got:\n%s", out1)
	}
	if !strings.Contains(out1, "resolved and allowed 2 domain(s)") {
		t.Errorf("round 1: expected the resolved-domains note, got:\n%s", out1)
	}

	// Round 2: the suggestion note is identical; only the resolved-domains
	// note actually changed (one more domain).
	p2 := &generate.Policy{Name: "hybris-front", Namespace: "webshop", ObservedNS: "webshop"}
	p2.Notes = []string{
		"could combine 3 domains into *.eu.auth0.com but didn't.",
		"resolved and allowed 3 domain(s): a.com, b.com, c.com.",
	}
	out2 := captureStdout(t, func() { PrintNewNotes([]*generate.Policy{p2}, seen) })
	if strings.Contains(out2, "could combine 3 domains") {
		t.Errorf("round 2: unchanged suggestion note should be suppressed, got:\n%s", out2)
	}
	if !strings.Contains(out2, "resolved and allowed 3 domain(s)") {
		t.Errorf("round 2: expected the new resolved-domains note, got:\n%s", out2)
	}
}

func TestPrintNewNotesDistinguishesPoliciesByFileName(t *testing.T) {
	seen := map[string]struct{}{}
	note := "added DNS visibility (kube-dns:53), needed for toFQDNs, stays in the final policy."

	front := &generate.Policy{Name: "frontend", Namespace: "webshop", ObservedNS: "webshop"}
	front.Notes = []string{note}
	back := &generate.Policy{Name: "backend", Namespace: "webshop", ObservedNS: "webshop"}
	back.Notes = []string{note}

	out := captureStdout(t, func() { PrintNewNotes([]*generate.Policy{front, back}, seen) })
	if strings.Count(out, note) != 2 {
		t.Errorf("expected the identical note to print once per distinct policy, got:\n%s", out)
	}
}
